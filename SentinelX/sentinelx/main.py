"""
SentinelX – Main Entry Point
Orchestrates all modules and launches the application.
"""

import sys
import os
import signal
import threading
from typing import Optional

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QTimer, Signal, QObject

from sentinelx.utils.logger import setup_logger, get_logger
from sentinelx.utils.config import Config
from sentinelx.database.db_manager import DatabaseManager
from sentinelx.core.engine import DetectionEngine
from sentinelx.core.threat_scoring import ThreatScorer
from sentinelx.network.sniffer import PacketSniffer
from sentinelx.network.network_analyzer import NetworkAnalyzer
from sentinelx.host.event_log_monitor import EventLogMonitor
from sentinelx.host.file_integrity import FileIntegrityMonitor
from sentinelx.host.process_monitor import ProcessMonitor
from sentinelx.auth.auth_manager import AuthManager
from sentinelx.gui.main_window import MainWindow, LoginDialog

logger = get_logger("main")


class AlertBridge(QObject):
    """Qt signal bridge for thread-safe alert notifications to GUI."""
    new_alert = Signal(dict)


class SentinelXApp:
    """
    Main application controller.
    Initializes all modules and manages their lifecycle.
    """

    def __init__(self):
        self.config = Config()
        self.db = DatabaseManager()
        self.engine = DetectionEngine()
        self.auth = AuthManager()

        # Monitoring modules
        self.sniffer: Optional[PacketSniffer] = None
        self.network_analyzer: Optional[NetworkAnalyzer] = None
        self.event_log_monitor: Optional[EventLogMonitor] = None
        self.file_integrity_monitor: Optional[FileIntegrityMonitor] = None
        self.process_monitor: Optional[ProcessMonitor] = None

        self._alert_bridge = AlertBridge()

    def start_modules(self) -> None:
        """Start all enabled monitoring modules."""
        logger.info("=" * 60)
        logger.info("SentinelX v1.0.0 – Starting monitoring modules...")
        logger.info("=" * 60)

        # Start engine cleanup loop
        self.engine.start_cleanup_loop()

        # Register alert bridge
        self.engine.register_alert_callback(
            lambda alert: self._alert_bridge.new_alert.emit(alert)
        )

        # --- Network Monitor ---
        if self.config.get("modules.network_monitor", True):
            try:
                self.network_analyzer = NetworkAnalyzer(self.engine)
                self.sniffer = PacketSniffer()
                self.sniffer.register_callback(self.network_analyzer.analyze_packet)
                self.sniffer.start()
                logger.info("[+] Network monitor: STARTED")
            except Exception as e:
                logger.error("[-] Network monitor failed: %s", e)
        else:
            logger.info("[ ] Network monitor: DISABLED")

        # --- Event Log Monitor ---
        if self.config.get("modules.event_log_monitor", True):
            try:
                self.event_log_monitor = EventLogMonitor(self.engine)
                self.event_log_monitor.start()
                logger.info("[+] Event log monitor: STARTED")
            except Exception as e:
                logger.error("[-] Event log monitor failed: %s", e)
        else:
            logger.info("[ ] Event log monitor: DISABLED")

        # --- File Integrity Monitor ---
        if self.config.get("modules.file_integrity_monitor", True):
            try:
                self.file_integrity_monitor = FileIntegrityMonitor(self.engine)
                dirs = self.config.get("file_integrity.monitored_directories", [])
                if dirs:
                    self.file_integrity_monitor.start()
                    logger.info("[+] File integrity monitor: STARTED (%d dirs)", len(dirs))
                else:
                    logger.info("[ ] File integrity monitor: No directories configured")
            except Exception as e:
                logger.error("[-] File integrity monitor failed: %s", e)
        else:
            logger.info("[ ] File integrity monitor: DISABLED")

        # --- Process Monitor ---
        if self.config.get("modules.process_monitor", True):
            try:
                self.process_monitor = ProcessMonitor(self.engine)
                self.process_monitor.start()
                logger.info("[+] Process monitor: STARTED")
            except Exception as e:
                logger.error("[-] Process monitor failed: %s", e)
        else:
            logger.info("[ ] Process monitor: DISABLED")

        logger.info("=" * 60)
        logger.info("All modules initialized. SentinelX is running.")
        logger.info("=" * 60)

    def stop_modules(self) -> None:
        """Stop all monitoring modules gracefully."""
        logger.info("Stopping all modules...")

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

        self.engine.stop()
        logger.info("All modules stopped. Goodbye.")


def main():
    """Main entry point."""
    # Set up root logger
    setup_logger("sentinelx")
    logger.info("SentinelX initializing...")

    # Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("SentinelX")
    app.setOrganizationName("SentinelX")

    # Apply global dark theme stylesheet
    app.setStyleSheet("""
        QWidget {
            font-family: 'Segoe UI', 'Arial', sans-serif;
        }
        QToolTip {
            background-color: #16213e;
            color: #e0e0e0;
            border: 1px solid #2a2a4a;
            padding: 4px;
            font-size: 11px;
        }
        QScrollBar:vertical {
            background-color: #1a1a2e;
            width: 10px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background-color: #2a2a4a;
            min-height: 20px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #3a3a5a;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar:horizontal {
            background-color: #1a1a2e;
            height: 10px;
        }
        QScrollBar::handle:horizontal {
            background-color: #2a2a4a;
            min-width: 20px;
            border-radius: 5px;
        }
    """)

    # ----- Login -----
    login = LoginDialog()
    if login.exec() != LoginDialog.Accepted or not login.authenticated:
        logger.info("Login cancelled or failed.")
        sys.exit(0)

    # ----- Initialize App -----
    sentinel = SentinelXApp()

    # ----- Launch Main Window -----
    window = MainWindow()

    # Wire alert signal to window
    sentinel._alert_bridge.new_alert.connect(window.on_new_alert, Qt.QueuedConnection)

    # Link sentinel app to dashboard for module status display
    window._dashboard.set_sentinel_app(sentinel)

    window.show()

    # Start monitoring modules after GUI is shown
    QTimer.singleShot(500, sentinel.start_modules)

    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda *_: (sentinel.stop_modules(), app.quit()))

    # Run
    exit_code = app.exec()
    sentinel.stop_modules()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
