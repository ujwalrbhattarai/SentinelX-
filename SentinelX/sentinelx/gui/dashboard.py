"""
SentinelX – Dashboard View
Professional real-time monitoring dashboard with charts and stats.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QFrame, QScrollArea, QSizePolicy, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox,
)
from PySide6.QtCore import Qt, QTimer, Signal, Slot
from PySide6.QtGui import QFont, QColor, QPainter, QPen, QBrush

import psutil

from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.logger import get_logger

logger = get_logger("dashboard")

# ── Color Palette ──────────────────────────────────────────
COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_card": "#16213e",
    "bg_card_hover": "#1a2745",
    "accent_blue": "#0f3460",
    "accent_cyan": "#00d2ff",
    "accent_green": "#00e676",
    "accent_yellow": "#ffc107",
    "accent_orange": "#ff9800",
    "accent_red": "#ff1744",
    "text_primary": "#e0e0e0",
    "text_secondary": "#9e9e9e",
    "border": "#2a2a4a",
    "critical": "#ff1744",
    "high": "#ff9800",
    "medium": "#ffc107",
    "low": "#00e676",
}


def _card_style(bg: str = COLORS["bg_card"]) -> str:
    return f"""
        QFrame {{
            background-color: {bg};
            border: 1px solid {COLORS['border']};
            border-radius: 8px;
        }}
        QLabel {{
            background: transparent;
            border: none;
            padding: 0px;
            border-radius: 0px;
        }}
    """


def _stat_label_style(color: str, size: int = 28) -> str:
    return f"color: {color}; font-size: {size}px; font-weight: bold; border: none; background: transparent;"


class StatCard(QFrame):
    """A single statistic card for the dashboard."""

    def __init__(self, title: str, value: str = "0", color: str = COLORS["accent_cyan"], parent=None):
        super().__init__(parent)
        self.setStyleSheet(_card_style())
        self.setMinimumSize(160, 100)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        self._title_label = QLabel(title)
        self._title_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; border: none;")
        self._title_label.setAlignment(Qt.AlignLeft)

        self._value_label = QLabel(value)
        self._value_label.setStyleSheet(_stat_label_style(color))
        self._value_label.setAlignment(Qt.AlignLeft)

        layout.addWidget(self._title_label)
        layout.addWidget(self._value_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


class MiniBarChart(QFrame):
    """A simple horizontal bar chart widget."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(_card_style())
        self.setMinimumHeight(180)
        self._data: List[Dict[str, Any]] = []

        layout = QVBoxLayout(self)
        self._title = QLabel("Top Suspicious IPs")
        self._title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold; border: none;")
        layout.addWidget(self._title)

        self._content = QVBoxLayout()
        layout.addLayout(self._content)
        layout.addStretch()

    def set_data(self, data: List[Dict[str, Any]]) -> None:
        """Set bar chart data: list of {'ip': ..., 'count': ...}."""
        self._data = data

        # Clear existing
        while self._content.count():
            item = self._content.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not data:
            lbl = QLabel("No suspicious IPs detected")
            lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; border: none;")
            self._content.addWidget(lbl)
            return

        max_count = max(d.get("count", 1) for d in data) or 1
        for item in data[:8]:
            row = QHBoxLayout()
            ip_label = QLabel(str(item.get("ip", "?")))
            ip_label.setFixedWidth(130)
            ip_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 11px; border: none;")

            bar = QFrame()
            ratio = item.get("count", 0) / max_count
            width = max(int(ratio * 200), 10)
            bar.setFixedSize(width, 14)
            bar.setStyleSheet(f"background-color: {COLORS['accent_red']}; border-radius: 3px; border: none;")

            count_label = QLabel(str(item.get("count", 0)))
            count_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; border: none;")

            row.addWidget(ip_label)
            row.addWidget(bar)
            row.addWidget(count_label)
            row.addStretch()

            container = QWidget()
            container.setLayout(row)
            container.setStyleSheet("border: none; background: transparent;")
            self._content.addWidget(container)


class SystemHealthWidget(QFrame):
    """Displays CPU, memory, disk usage."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(_card_style())
        self.setMinimumHeight(140)

        layout = QVBoxLayout(self)
        title = QLabel("System Health")
        title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold; border: none;")
        layout.addWidget(title)

        self._cpu_label = QLabel("CPU: ---%")
        self._mem_label = QLabel("Memory: ---%")
        self._disk_label = QLabel("Disk: ---%")

        for lbl in (self._cpu_label, self._mem_label, self._disk_label):
            lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; border: none;")
            layout.addWidget(lbl)

        self._cpu_bar = QFrame()
        self._cpu_bar.setFixedHeight(8)
        self._cpu_bar.setStyleSheet(f"background-color: {COLORS['accent_green']}; border-radius: 4px; border: none;")
        layout.addWidget(self._cpu_bar)

        layout.addStretch()

    def update_health(self) -> None:
        try:
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent if hasattr(psutil, "disk_usage") else 0
            try:
                disk = psutil.disk_usage("C:\\").percent
            except Exception:
                pass

            self._cpu_label.setText(f"CPU: {cpu:.1f}%")
            self._mem_label.setText(f"Memory: {mem:.1f}%")
            self._disk_label.setText(f"Disk: {disk:.1f}%")

            # Color CPU bar based on usage
            if cpu > 80:
                color = COLORS["accent_red"]
            elif cpu > 50:
                color = COLORS["accent_yellow"]
            else:
                color = COLORS["accent_green"]

            width = max(int(cpu * 3), 5)
            self._cpu_bar.setFixedWidth(min(width, 300))
            self._cpu_bar.setStyleSheet(f"background-color: {color}; border-radius: 4px; border: none;")
        except Exception:
            pass


class RecentAlertsTable(QFrame):
    """Displays recent alerts in a compact table."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(_card_style())
        self.setMinimumHeight(250)

        layout = QVBoxLayout(self)
        title = QLabel("Recent Alerts")
        title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold; border: none;")
        layout.addWidget(title)

        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["Time", "Severity", "Title", "Source", "Score"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: none;
                gridline-color: {COLORS['border']};
                font-size: 11px;
            }}
            QTableWidget::item {{
                padding: 4px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent_blue']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_secondary']};
                padding: 4px;
                border: 1px solid {COLORS['border']};
                font-size: 11px;
            }}
        """)
        layout.addWidget(self._table)

    def set_alerts(self, alerts: List[dict]) -> None:
        self._table.setRowCount(len(alerts))
        severity_colors = {
            "Critical": COLORS["critical"],
            "High": COLORS["high"],
            "Medium": COLORS["medium"],
            "Low": COLORS["low"],
        }

        for row, alert in enumerate(alerts[:20]):
            ts = alert.get("timestamp", "")
            if isinstance(ts, str) and "T" in ts:
                ts = ts.split("T")[1][:8]

            items = [
                ts,
                alert.get("severity", ""),
                alert.get("title", ""),
                alert.get("source", "N/A"),
                str(alert.get("risk_score", 0)),
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(str(text))
                if col == 1:
                    color = severity_colors.get(alert.get("severity", ""), COLORS["text_primary"])
                    item.setForeground(QColor(color))
                    item.setFont(QFont("", -1, QFont.Bold))
                self._table.setItem(row, col, item)


class ModuleStatusWidget(QFrame):
    """Shows which monitoring modules are active / inactive."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(_card_style())
        self.setMinimumHeight(100)

        layout = QVBoxLayout(self)
        title = QLabel("Module Status")
        title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold; border: none;")
        layout.addWidget(title)

        self._rows_layout = QVBoxLayout()
        layout.addLayout(self._rows_layout)
        layout.addStretch()

        self._labels: Dict[str, QLabel] = {}

    def set_statuses(self, statuses: Dict[str, str]) -> None:
        """statuses: module_name -> 'active' | 'inactive' | 'warning'"""
        # Clear previous labels
        while self._rows_layout.count():
            item = self._rows_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._labels.clear()

        icon_map = {"active": "🟢", "inactive": "🔴", "warning": "🟡"}
        for name, status in statuses.items():
            icon = icon_map.get(status, "⚪")
            lbl = QLabel(f" {icon}  {name}")
            color = (
                COLORS["accent_green"] if status == "active"
                else COLORS["accent_yellow"] if status == "warning"
                else COLORS["text_secondary"]
            )
            lbl.setStyleSheet(f"color: {color}; font-size: 12px; border: none;")
            self._rows_layout.addWidget(lbl)
            self._labels[name] = lbl


class DashboardView(QWidget):
    """Main dashboard widget with real-time statistics and charts."""

    alert_received = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = DatabaseManager()
        self._sentinel_app: Any = None
        self._setup_ui()

        # Refresh timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_data)
        self._timer.start(3000)

        # Initial load
        self.refresh_data()

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)

        # === Header ===
        header = QLabel("SentinelX Dashboard")
        header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 20px; font-weight: bold;")
        main_layout.addWidget(header)

        # === Stat Cards Row ===
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self._card_total = StatCard("Total Alerts (24h)", "0", COLORS["accent_cyan"])
        self._card_critical = StatCard("Critical", "0", COLORS["critical"])
        self._card_high = StatCard("High", "0", COLORS["high"])
        self._card_medium = StatCard("Medium", "0", COLORS["medium"])
        self._card_low = StatCard("Low", "0", COLORS["low"])

        for card in (self._card_total, self._card_critical, self._card_high, self._card_medium, self._card_low):
            cards_layout.addWidget(card)

        main_layout.addLayout(cards_layout)

        # === Middle Row: Top IPs + System Health + Module Status ===
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(12)

        self._top_ips = MiniBarChart()
        self._system_health = SystemHealthWidget()
        self._module_status = ModuleStatusWidget()

        mid_layout.addWidget(self._top_ips, stretch=2)
        mid_layout.addWidget(self._system_health, stretch=1)
        mid_layout.addWidget(self._module_status, stretch=1)

        main_layout.addLayout(mid_layout)

        # === Recent Alerts Table ===
        self._recent_alerts = RecentAlertsTable()
        main_layout.addWidget(self._recent_alerts, stretch=1)

    @Slot()
    def refresh_data(self) -> None:
        """Refresh all dashboard data."""
        try:
            stats = self.db.get_alert_stats(hours=24)
            self._card_total.set_value(str(stats.get("total", 0)))
            self._card_critical.set_value(str(stats.get("critical", 0)))
            self._card_high.set_value(str(stats.get("high", 0)))
            self._card_medium.set_value(str(stats.get("medium", 0)))
            self._card_low.set_value(str(stats.get("low", 0)))

            self._top_ips.set_data(stats.get("top_ips", []))

            alerts = self.db.get_alerts(limit=20)
            self._recent_alerts.set_alerts(alerts)

            self._system_health.update_health()

            # Update module status if the app controller has been linked
            if self._sentinel_app is not None:
                self._update_module_status()
        except Exception as e:
            logger.error("Dashboard refresh error: %s", e)

    def set_sentinel_app(self, app: Any) -> None:
        """Link the SentinelXApp instance so we can read module status."""
        self._sentinel_app = app

    def _update_module_status(self) -> None:
        """Read live module states from the app controller."""
        app = self._sentinel_app
        statuses: Dict[str, str] = {}

        # Network
        if app.sniffer and app.sniffer._running:
            statuses["Network Monitor"] = "active"
        else:
            statuses["Network Monitor"] = "inactive"

        # Event Log
        if app.event_log_monitor and getattr(app.event_log_monitor, "is_active", False):
            statuses["Event Log Monitor"] = "active"
        elif app.event_log_monitor and app.event_log_monitor._running:
            statuses["Event Log Monitor"] = "warning"
        else:
            statuses["Event Log Monitor"] = "inactive"

        # File Integrity
        if app.file_integrity_monitor and app.file_integrity_monitor._running:
            statuses["File Integrity Monitor"] = "active"
        else:
            statuses["File Integrity Monitor"] = "inactive"

        # Process
        if app.process_monitor and app.process_monitor._running:
            statuses["Process Monitor"] = "active"
        else:
            statuses["Process Monitor"] = "inactive"

        self._module_status.set_statuses(statuses)

    def on_new_alert(self, alert_dict: dict) -> None:
        """Called when a new alert is created."""
        self.alert_received.emit(alert_dict)
        self.refresh_data()
