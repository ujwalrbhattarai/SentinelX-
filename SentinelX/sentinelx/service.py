"""
SentinelX – Windows Service Mode
Allows SentinelX to run as a Windows Service for 24/7 background monitoring.
"""

import os
import sys
import time
import logging
from typing import Optional

# Ensure package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    WIN32_SERVICE_AVAILABLE = True
except ImportError:
    WIN32_SERVICE_AVAILABLE = False

from sentinelx.utils.logger import setup_logger, get_logger
from sentinelx.utils.config import Config
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.core.engine import DetectionEngine
from sentinelx.network.sniffer import PacketSniffer
from sentinelx.network.network_analyzer import NetworkAnalyzer
from sentinelx.host.event_log_monitor import EventLogMonitor
from sentinelx.host.file_integrity import FileIntegrityMonitor
from sentinelx.host.process_monitor import ProcessMonitor

logger = get_logger("service")


if WIN32_SERVICE_AVAILABLE:

    class SentinelXService(win32serviceutil.ServiceFramework):
        """Windows Service wrapper for SentinelX monitoring engine."""

        _svc_name_ = "SentinelXService"
        _svc_display_name_ = "SentinelX Security Monitoring Service"
        _svc_description_ = (
            "SentinelX defensive cybersecurity monitoring service. "
            "Provides real-time network, process, file integrity, and event log monitoring."
        )

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self._running = False

            # Module references
            self.engine: Optional[DetectionEngine] = None
            self.sniffer: Optional[PacketSniffer] = None
            self.network_analyzer: Optional[NetworkAnalyzer] = None
            self.event_log_monitor: Optional[EventLogMonitor] = None
            self.file_integrity_monitor: Optional[FileIntegrityMonitor] = None
            self.process_monitor: Optional[ProcessMonitor] = None

        def SvcStop(self):
            """Stop the service."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            logger.info("Service stop requested")
            self._running = False
            self._stop_modules()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            """Main service entry point."""
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self._running = True
            self._main()

        def _main(self):
            """Initialize and run all monitoring modules."""
            setup_logger("sentinelx")
            logger.info("SentinelX Service starting...")

            try:
                config = Config()
                db = DatabaseManager()
                self.engine = DetectionEngine()
                self.engine.start_cleanup_loop()

                # --- Network Monitor ---
                if config.get("modules.network_monitor", True):
                    try:
                        self.network_analyzer = NetworkAnalyzer(self.engine)
                        self.sniffer = PacketSniffer()
                        self.sniffer.register_callback(self.network_analyzer.analyze_packet)
                        self.sniffer.start()
                        logger.info("[Service] Network monitor: STARTED")
                    except Exception as e:
                        logger.error("[Service] Network monitor failed: %s", e)

                # --- Event Log Monitor ---
                if config.get("modules.event_log_monitor", True):
                    try:
                        self.event_log_monitor = EventLogMonitor(self.engine)
                        self.event_log_monitor.start()
                        logger.info("[Service] Event log monitor: STARTED")
                    except Exception as e:
                        logger.error("[Service] Event log monitor failed: %s", e)

                # --- File Integrity Monitor ---
                if config.get("modules.file_integrity_monitor", True):
                    try:
                        self.file_integrity_monitor = FileIntegrityMonitor(self.engine)
                        dirs = config.get("file_integrity.monitored_directories", [])
                        if dirs:
                            self.file_integrity_monitor.start()
                            logger.info("[Service] File integrity monitor: STARTED")
                    except Exception as e:
                        logger.error("[Service] File integrity monitor failed: %s", e)

                # --- Process Monitor ---
                if config.get("modules.process_monitor", True):
                    try:
                        self.process_monitor = ProcessMonitor(self.engine)
                        self.process_monitor.start()
                        logger.info("[Service] Process monitor: STARTED")
                    except Exception as e:
                        logger.error("[Service] Process monitor failed: %s", e)

                logger.info("SentinelX Service running. Waiting for stop signal...")

                # Wait for stop event
                while self._running:
                    rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
                    if rc == win32event.WAIT_OBJECT_0:
                        break

            except Exception as e:
                logger.critical("Service fatal error: %s", e)
                servicemanager.LogErrorMsg(f"SentinelX Service error: {e}")

            logger.info("SentinelX Service stopped.")

        def _stop_modules(self):
            """Gracefully stop all modules."""
            if self.sniffer:
                self.sniffer.stop()
            if self.network_analyzer:
                self.network_analyzer.stop()
            if self.event_log_monitor:
                self.event_log_monitor.stop()
            if self.file_integrity_monitor:
                self.file_integrity_monitor.stop()
            if self.process_monitor:
                self.process_monitor.stop()
            if self.engine:
                self.engine.stop()


def install_service():
    """Install SentinelX as a Windows Service."""
    if not WIN32_SERVICE_AVAILABLE:
        print("ERROR: pywin32 is required for Windows Service mode.")
        return False
    try:
        win32serviceutil.InstallService(
            SentinelXService._svc_name_,
            SentinelXService._svc_display_name_,
            startType=win32service.SERVICE_AUTO_START,
            description=SentinelXService._svc_description_,
        )
        print(f"Service '{SentinelXService._svc_display_name_}' installed successfully.")
        return True
    except Exception as e:
        print(f"Failed to install service: {e}")
        return False


def uninstall_service():
    """Uninstall SentinelX Windows Service."""
    if not WIN32_SERVICE_AVAILABLE:
        print("ERROR: pywin32 is required.")
        return False
    try:
        win32serviceutil.RemoveService(SentinelXService._svc_name_)
        print("Service removed successfully.")
        return True
    except Exception as e:
        print(f"Failed to remove service: {e}")
        return False


def main():
    """Service entry point."""
    if not WIN32_SERVICE_AVAILABLE:
        print("ERROR: pywin32 is required for Windows Service mode.")
        print("Install it with: pip install pywin32")
        sys.exit(1)

    if len(sys.argv) == 1:
        # Started by Windows Service Manager
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentinelXService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command-line management
        win32serviceutil.HandleCommandLine(SentinelXService)


if __name__ == "__main__":
    main()
