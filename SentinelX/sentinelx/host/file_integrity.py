"""
SentinelX – File Integrity Monitor
Monitors protected directories for file changes (create, modify, delete).
Detects ransomware-like mass modification behavior.
"""

import hashlib
import json
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sentinelx.core.engine import DetectionEngine, Event
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.config import Config, DATA_DIR
from sentinelx.utils.logger import get_logger

logger = get_logger("file_integrity")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not available – file integrity monitoring disabled")


BASELINE_FILE = DATA_DIR / "file_baseline.json"


def compute_sha256(file_path: str) -> Optional[str]:
    """Compute SHA256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class FileIntegrityHandler(FileSystemEventHandler):
    """Watchdog event handler that tracks file changes."""

    def __init__(self, monitor: "FileIntegrityMonitor"):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event: "FileSystemEvent") -> None:
        if not event.is_directory:
            self.monitor.on_file_change("created", event.src_path)

    def on_modified(self, event: "FileSystemEvent") -> None:
        if not event.is_directory:
            self.monitor.on_file_change("modified", event.src_path)

    def on_deleted(self, event: "FileSystemEvent") -> None:
        if not event.is_directory:
            self.monitor.on_file_change("deleted", event.src_path)


class FileIntegrityMonitor:
    """
    Monitors selected directories for file changes.
    Maintains SHA256 baseline and detects modifications.
    """

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.config = Config()
        self.db = DatabaseManager()
        self._running = False
        self._observer: Optional[Any] = None
        self._baseline: Dict[str, str] = {}  # path -> sha256
        self._change_timestamps: List[datetime] = []
        self._change_lock = threading.Lock()

        # Load existing baseline
        self._load_baseline()

    def _load_baseline(self) -> None:
        """Load file hash baseline from disk."""
        if BASELINE_FILE.exists():
            try:
                with open(BASELINE_FILE, "r") as f:
                    self._baseline = json.load(f)
                logger.info("Loaded baseline with %d file hashes", len(self._baseline))
            except Exception as e:
                logger.error("Failed to load baseline: %s", e)
                self._baseline = {}

    def save_baseline(self) -> None:
        """Save current baseline to disk."""
        try:
            with open(BASELINE_FILE, "w") as f:
                json.dump(self._baseline, f, indent=2)
            logger.info("Baseline saved with %d entries", len(self._baseline))
        except Exception as e:
            logger.error("Failed to save baseline: %s", e)

    def generate_baseline(self, directories: Optional[List[str]] = None) -> int:
        """Generate SHA256 baseline for all files in monitored directories."""
        if directories is None:
            directories = self.config.get("file_integrity.monitored_directories", [])

        count = 0
        for directory in directories:
            dir_path = Path(directory)
            if not dir_path.exists():
                logger.warning("Baseline directory not found: %s", directory)
                continue

            for file_path in dir_path.rglob("*"):
                if file_path.is_file():
                    file_hash = compute_sha256(str(file_path))
                    if file_hash:
                        self._baseline[str(file_path)] = file_hash
                        count += 1

        self.save_baseline()
        logger.info("Generated baseline: %d files hashed", count)
        return count

    def start(self) -> None:
        """Start the file integrity monitor."""
        if not WATCHDOG_AVAILABLE:
            logger.error("Cannot start FIM: watchdog not installed")
            return

        directories = self.config.get("file_integrity.monitored_directories", [])
        if not directories:
            logger.warning("No directories configured for file integrity monitoring")
            return

        if self._running:
            return

        self._running = True
        self._observer = Observer()
        handler = FileIntegrityHandler(self)

        for directory in directories:
            if os.path.exists(directory):
                self._observer.schedule(handler, directory, recursive=True)
                logger.info("Monitoring directory: %s", directory)
            else:
                logger.warning("Directory not found: %s", directory)

        self._observer.start()

        # Start ransomware detection thread
        self._ransomware_thread = threading.Thread(
            target=self._ransomware_check_loop, daemon=True, name="RansomwareCheck"
        )
        self._ransomware_thread.start()

        logger.info("File integrity monitor started")

    def stop(self) -> None:
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        logger.info("File integrity monitor stopped")

    def on_file_change(self, event_type: str, file_path: str) -> None:
        """Handle a file change event."""
        now = datetime.utcnow()

        with self._change_lock:
            self._change_timestamps.append(now)
            # Keep only last 60 seconds
            cutoff = now - timedelta(seconds=60)
            self._change_timestamps = [t for t in self._change_timestamps if t > cutoff]

        old_hash = self._baseline.get(file_path)
        new_hash = None

        if event_type != "deleted":
            new_hash = compute_sha256(file_path)
            if new_hash:
                self._baseline[file_path] = new_hash
        else:
            self._baseline.pop(file_path, None)

        # Determine severity
        if event_type == "deleted":
            severity = "High"
            condition = "file_deleted"
        elif event_type == "modified" and old_hash and old_hash != new_hash:
            severity = "Medium"
            condition = "file_modified"
        elif event_type == "created":
            severity = "Low"
            condition = "file_modified"
        else:
            return  # No actual change

        # Store in database
        try:
            self.db.add_file_event(
                file_path=file_path,
                event_type=event_type,
                old_hash=old_hash,
                new_hash=new_hash,
                severity=severity,
                risk_score={"Low": 10, "Medium": 30, "High": 70, "Critical": 100}.get(severity, 10),
            )
        except Exception as e:
            logger.error("DB error: %s", e)

        # Submit to engine
        self.engine.submit_event(Event(
            event_type=condition,
            source=file_path,
            details={
                "change_type": event_type,
                "old_hash": old_hash,
                "new_hash": new_hash,
            },
            timestamp=now,
        ))

        logger.debug("File %s: %s", event_type, file_path)

    def _ransomware_check_loop(self) -> None:
        """Check for mass file modification (ransomware pattern)."""
        threshold = self.config.get("file_integrity.ransomware_threshold", 50)
        window = self.config.get("file_integrity.ransomware_window", 30)

        while self._running:
            time.sleep(5)
            now = datetime.utcnow()
            cutoff = now - timedelta(seconds=window)

            with self._change_lock:
                recent_changes = len([t for t in self._change_timestamps if t > cutoff])

            if recent_changes >= threshold:
                self.engine.submit_event(Event(
                    event_type="mass_file_modification",
                    source="filesystem",
                    details={
                        "changes_count": recent_changes,
                        "window_seconds": window,
                    },
                    timestamp=now,
                ))
                logger.critical(
                    "RANSOMWARE ALERT: %d file changes in %d seconds!",
                    recent_changes,
                    window,
                )
                # Reset to avoid spam
                with self._change_lock:
                    self._change_timestamps.clear()
