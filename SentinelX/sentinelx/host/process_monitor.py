"""
SentinelX – Process Monitor
Monitors running processes for suspicious behavior using psutil.
"""

import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from sentinelx.core.engine import DetectionEngine, Event
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.config import Config
from sentinelx.utils.logger import get_logger

logger = get_logger("process_monitor")

# Suspicious process chain patterns (parent -> child)
SUSPICIOUS_CHAINS = [
    ("powershell.exe", "cmd.exe"),
    ("cmd.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("svchost.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("wscript.exe", "cmd.exe"),
    ("wscript.exe", "powershell.exe"),
    ("mshta.exe", "powershell.exe"),
]

# Reverse shell indicators
REVERSE_SHELL_CMDS = [
    "nc.exe", "ncat.exe", "netcat",
    "/c powershell -nop",
    "invoke-webrequest",
    "TCPClient",
    "bash -i",
    "socat",
]

# Common legitimate system processes
KNOWN_SYSTEM_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "winlogon.exe", "dwm.exe", "conhost.exe", "taskhost.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "dllhost.exe",
    "spoolsv.exe", "searchindexer.exe", "securityhealthservice.exe",
    "msdtc.exe", "audiodg.exe", "wudfhost.exe",
}


class ProcessMonitor:
    """
    Monitors running processes for:
    - Suspicious parent-child relationships
    - High CPU usage (sustained)
    - Reverse shell patterns
    - Unknown / unsigned executables
    """

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.config = Config()
        self.db = DatabaseManager()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Track CPU usage per PID: pid -> list of (timestamp, cpu_percent)
        self._cpu_history: Dict[int, List[Tuple[datetime, float]]] = defaultdict(list)
        self._cpu_lock = threading.Lock()

        # Known PIDs already alerted on
        self._alerted_pids: Set[int] = set()

        # CPU thresholds
        self._cpu_threshold = self.config.get("process_monitor.cpu_threshold", 80)
        self._cpu_sustained = self.config.get("process_monitor.cpu_sustained_seconds", 30)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ProcessMonitor")
        self._thread.start()
        logger.info("Process monitor started (CPU threshold: %d%%)", self._cpu_threshold)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Process monitor stopped")

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                self._scan_processes()
            except Exception as e:
                logger.error("Process scan error: %s", e)
            time.sleep(5)

    def _scan_processes(self) -> None:
        """Scan all running processes."""
        now = datetime.utcnow()

        for proc in psutil.process_iter(["pid", "name", "exe", "ppid", "cpu_percent", "cmdline"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info["name"] or "").lower()
                exe_path = info.get("exe", "") or ""
                ppid = info.get("ppid")
                cpu = info.get("cpu_percent") or 0.0
                cmdline = info.get("cmdline") or []

                # --- CPU Usage Check ---
                self._track_cpu(pid, name, exe_path, cpu, now)

                # --- Suspicious Process Chain Check ---
                if ppid:
                    self._check_process_chain(pid, name, ppid, now)

                # --- Reverse Shell Check ---
                if cmdline:
                    cmd_str = " ".join(cmdline).lower()
                    self._check_reverse_shell(pid, name, cmd_str, now)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def _track_cpu(self, pid: int, name: str, exe_path: str, cpu: float, now: datetime) -> None:
        """Track and alert on sustained high CPU usage."""
        with self._cpu_lock:
            self._cpu_history[pid].append((now, cpu))
            # Keep only last 60 seconds
            cutoff = now - timedelta(seconds=60)
            self._cpu_history[pid] = [
                (ts, c) for ts, c in self._cpu_history[pid] if ts > cutoff
            ]

            # Check for sustained high CPU
            if pid not in self._alerted_pids:
                high_entries = [
                    (ts, c) for ts, c in self._cpu_history[pid] if c > self._cpu_threshold
                ]
                if high_entries:
                    duration = (high_entries[-1][0] - high_entries[0][0]).total_seconds()
                    if duration >= self._cpu_sustained and len(high_entries) >= 3:
                        self._alerted_pids.add(pid)
                        avg_cpu = sum(c for _, c in high_entries) / len(high_entries)

                        self.engine.submit_event(Event(
                            event_type="high_cpu",
                            source=name,
                            details={
                                "pid": pid,
                                "exe": exe_path,
                                "avg_cpu": round(avg_cpu, 1),
                                "duration_seconds": round(duration),
                            },
                            timestamp=now,
                        ))

                        # Store in DB
                        try:
                            self.db.add_process_event(
                                pid=pid,
                                name=name,
                                exe_path=exe_path,
                                cpu_percent=avg_cpu,
                                threat_type="High CPU Usage",
                                severity="Medium",
                                risk_score=30,
                            )
                        except Exception:
                            pass

    def _check_process_chain(self, pid: int, name: str, ppid: int, now: datetime) -> None:
        """Check for suspicious parent-child process relationships."""
        if pid in self._alerted_pids:
            return

        try:
            parent = psutil.Process(ppid)
            parent_name = (parent.name() or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        for p_pattern, c_pattern in SUSPICIOUS_CHAINS:
            if parent_name == p_pattern.lower() and name == c_pattern.lower():
                self._alerted_pids.add(pid)

                self.engine.submit_event(Event(
                    event_type="suspicious_process_chain",
                    source=name,
                    details={
                        "pid": pid,
                        "parent_pid": ppid,
                        "parent_name": parent_name,
                        "child_name": name,
                    },
                    timestamp=now,
                ))

                try:
                    self.db.add_process_event(
                        pid=pid,
                        name=name,
                        parent_pid=ppid,
                        parent_name=parent_name,
                        threat_type="Suspicious Process Chain",
                        severity="High",
                        risk_score=70,
                    )
                except Exception:
                    pass

                logger.warning("Suspicious chain: %s (PID %d) -> %s (PID %d)", parent_name, ppid, name, pid)
                break

    def _check_reverse_shell(self, pid: int, name: str, cmd_str: str, now: datetime) -> None:
        """Check for reverse shell patterns in command lines."""
        if pid in self._alerted_pids:
            return

        for pattern in REVERSE_SHELL_CMDS:
            if pattern.lower() in cmd_str:
                self._alerted_pids.add(pid)

                self.engine.submit_event(Event(
                    event_type="reverse_shell",
                    source=name,
                    details={
                        "pid": pid,
                        "pattern": pattern,
                        "cmdline": cmd_str[:200],
                    },
                    timestamp=now,
                ))

                try:
                    self.db.add_process_event(
                        pid=pid,
                        name=name,
                        threat_type="Reverse Shell Pattern",
                        severity="Critical",
                        risk_score=100,
                    )
                except Exception:
                    pass

                logger.critical("Reverse shell pattern in PID %d (%s): %s", pid, name, pattern)
                break

    def get_process_summary(self) -> List[Dict[str, Any]]:
        """Get summary of monitored processes for the GUI."""
        result = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                mem = info.get("memory_info")
                result.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": info.get("cpu_percent", 0),
                    "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        result.sort(key=lambda x: x.get("cpu_percent", 0), reverse=True)
        return result[:50]
