"""
SentinelX – Windows Event Log Monitor
Monitors Windows Security event logs for suspicious activity.
"""

import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sentinelx.core.engine import DetectionEngine, Event
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.config import Config
from sentinelx.utils.logger import get_logger

logger = get_logger("event_log_monitor")

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    logger.warning("pywin32 not available – event log monitoring disabled")


# Monitored Windows Event IDs
EVENT_MAP = {
    4625: {"name": "Failed Login", "severity": "Medium", "condition": "failed_logins"},
    4720: {"name": "User Account Created", "severity": "High", "condition": "user_created"},
    4688: {"name": "New Process Created", "severity": "Low", "condition": "new_process"},
    4672: {"name": "Admin Privileges Assigned", "severity": "High", "condition": "admin_privilege"},
}

# PowerShell suspicious keywords
POWERSHELL_SUSPICIOUS = [
    "-encodedcommand", "-enc ", "invoke-expression", "iex ",
    "downloadstring", "downloadfile", "webclient",
    "bypass", "-nop", "-w hidden", "frombase64string",
    "invoke-webrequest", "invoke-mimikatz", "invoke-shellcode",
]


class EventLogMonitor:
    """
    Monitors Windows Security event logs for suspicious events.
    Uses pywin32 to read events in real-time.
    """

    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.config = Config()
        self.db = DatabaseManager()
        self._running = False
        self._active = False  # True once successfully reading events
        self._status_message = ""
        self._thread: Optional[threading.Thread] = None
        self._monitored_ids = set(self.config.get("event_log.monitored_event_ids", [4625, 4720, 4688, 4672]))

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def status_message(self) -> str:
        return self._status_message

    def start(self) -> None:
        if not PYWIN32_AVAILABLE:
            logger.error("Cannot start event log monitor: pywin32 not installed")
            return

        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="EventLogMonitor")
        self._thread.start()
        logger.info("Event log monitor started")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Event log monitor stopped")

    def _monitor_loop(self) -> None:
        """Main monitoring loop – polls Security event log."""
        server = None  # Local machine
        log_type = "Security"
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            handle = win32evtlog.OpenEventLog(server, log_type)
        except Exception as e:
            self._status_message = f"Cannot open Security log (run as Admin): {e}"
            self._active = False
            logger.error("Cannot open Security event log (run as Admin): %s", e)
            return

        # Track last record number to avoid re-processing
        try:
            total = win32evtlog.GetNumberOfEventLogRecords(handle)
            oldest = win32evtlog.GetOldestEventLogRecord(handle)
            last_record = oldest + total if oldest else total
        except Exception:
            last_record = 0

        self._active = True
        self._status_message = "Monitoring Security event log"
        logger.info("Event log monitor is now actively reading events")

        while self._running:
            try:
                events = win32evtlog.ReadEventLog(
                    handle,
                    win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ,
                    last_record,
                )

                for event in events:
                    event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
                    if event_id in self._monitored_ids:
                        self._process_event(event, event_id)
                    last_record = event.RecordNumber + 1

            except Exception as e:
                if "specified record" not in str(e).lower():
                    logger.debug("Event log read: %s", e)

            time.sleep(2)  # Poll every 2 seconds

        win32evtlog.CloseEventLog(handle)

    def _process_event(self, event, event_id: int) -> None:
        """Process a single Windows event."""
        event_info = EVENT_MAP.get(event_id, {})
        if not event_info:
            return

        try:
            description = win32evtlogutil.SafeFormatMessage(event, "Security")
        except Exception:
            description = f"Event ID {event_id}"

        user = ""
        try:
            sid = event.Sid
            if sid:
                user = win32security.LookupAccountSid(None, sid)[0]
        except Exception:
            user = "UNKNOWN"

        timestamp = datetime.utcnow()

        # Store in database
        try:
            self.db.add_system_event(
                event_id=event_id,
                event_source=event.SourceName or "Security",
                category=event_info["name"],
                description=description[:1000],
                user=user,
                severity=event_info["severity"],
                risk_score={"Low": 10, "Medium": 30, "High": 70, "Critical": 100}.get(
                    event_info["severity"], 10
                ),
            )
        except Exception as e:
            logger.error("DB error storing event: %s", e)

        # Check for suspicious PowerShell (Event 4688)
        if event_id == 4688:
            desc_lower = description.lower()
            if "powershell" in desc_lower:
                for keyword in POWERSHELL_SUSPICIOUS:
                    if keyword.lower() in desc_lower:
                        self.engine.submit_event(Event(
                            event_type="suspicious_powershell",
                            source=user,
                            details={
                                "event_id": event_id,
                                "keyword": keyword,
                                "description": description[:200],
                            },
                        ))
                        break

        # Submit to detection engine
        condition = event_info.get("condition", "")
        if condition:
            self.engine.submit_event(Event(
                event_type=condition,
                source=user,
                details={
                    "event_id": event_id,
                    "description": description[:200],
                },
                timestamp=timestamp,
            ))

        logger.debug("Security event: %d (%s) user=%s", event_id, event_info["name"], user)
