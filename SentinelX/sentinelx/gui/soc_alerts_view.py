"""
SentinelX – SOC Alerts View
Dedicated view for DoS/DDoS/Flood attack alerts with real-time notifications.
SOC analysts can monitor, acknowledge, and track all denial-of-service events here.
"""

from datetime import datetime
from typing import List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
    QSizePolicy, QApplication, QMessageBox, QSplitter, QTextEdit,
)
from PySide6.QtCore import Qt, QTimer, Signal, Slot
from PySide6.QtGui import QFont, QColor

from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.logger import get_logger

logger = get_logger("soc_alerts")

COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_card": "#16213e",
    "accent_blue": "#0f3460",
    "accent_cyan": "#00d2ff",
    "accent_green": "#00e676",
    "accent_yellow": "#ffc107",
    "accent_red": "#ff1744",
    "text_primary": "#e0e0e0",
    "text_secondary": "#9e9e9e",
    "border": "#2a2a4a",
    "critical": "#ff1744",
    "high": "#ff9800",
}

DOS_KEYWORDS = ("dos", "flood", "ddos")


class SOCAlertsView(QWidget):
    """Dedicated view for monitoring DoS/DDoS/Flood alerts."""

    alert_selected = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = DatabaseManager()
        self._alerts_data: list = []
        self._unread_count = 0
        self._setup_ui()

        # Auto-refresh every 3 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_alerts)
        self._timer.start(3000)

        self.refresh_alerts()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # === Header with live counter ===
        header_layout = QHBoxLayout()

        header = QLabel("\U0001f6a8 SOC Alerts — DoS / DDoS / Flood Attacks")
        header.setStyleSheet(
            f"color: {COLORS['accent_red']}; font-size: 18px; font-weight: bold;"
        )
        header_layout.addWidget(header)

        header_layout.addStretch()

        self._lbl_count = QLabel("0 alerts")
        self._lbl_count.setStyleSheet(
            f"color: {COLORS['accent_yellow']}; font-size: 14px; font-weight: bold;"
        )
        header_layout.addWidget(self._lbl_count)

        self._lbl_unread = QLabel("")
        self._lbl_unread.setStyleSheet(
            f"color: {COLORS['accent_red']}; font-size: 13px; font-weight: bold;"
        )
        header_layout.addWidget(self._lbl_unread)

        layout.addLayout(header_layout)

        # === Info banner ===
        banner = QFrame()
        banner.setStyleSheet(f"""
            QFrame {{
                background-color: #2a1020;
                border: 1px solid {COLORS['accent_red']};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        banner_layout = QHBoxLayout(banner)
        banner_label = QLabel(
            "\u26a0\ufe0f  This panel shows only DoS, DDoS, and Flood attack alerts. "
            "SOC analysts should monitor this view for service availability threats."
        )
        banner_label.setStyleSheet(f"color: {COLORS['accent_yellow']}; font-size: 12px;")
        banner_label.setWordWrap(True)
        banner_layout.addWidget(banner_label)
        layout.addWidget(banner)

        # === Action buttons ===
        btn_layout = QHBoxLayout()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setCursor(Qt.PointingHandCursor)
        btn_refresh.setStyleSheet(self._btn_style())
        btn_refresh.clicked.connect(self.refresh_alerts)
        btn_layout.addWidget(btn_refresh)

        btn_ack_all = QPushButton("Acknowledge All")
        btn_ack_all.setCursor(Qt.PointingHandCursor)
        btn_ack_all.setStyleSheet(self._btn_style("#ff9800"))
        btn_ack_all.clicked.connect(self._acknowledge_all)
        btn_layout.addWidget(btn_ack_all)

        btn_copy = QPushButton("Copy Selected")
        btn_copy.setCursor(Qt.PointingHandCursor)
        btn_copy.setStyleSheet(self._btn_style())
        btn_copy.clicked.connect(self._copy_selected)
        btn_layout.addWidget(btn_copy)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # === Splitter: table top, detail bottom ===
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(5)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
                border-radius: 2px;
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent_cyan']};
            }}
        """)

        # --- Alerts Table ---
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Severity", "Attack Type", "Source IP",
            "Target IP", "Score", "Ack",
        ])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                gridline-color: {COLORS['border']};
                font-size: 12px;
            }}
            QTableWidget::item {{
                padding: 4px 6px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent_blue']};
            }}
            QHeaderView::section {{
                background-color: #2a1020;
                color: {COLORS['accent_red']};
                padding: 6px;
                border: 1px solid {COLORS['border']};
                font-weight: bold;
                font-size: 11px;
            }}
        """)
        self._table.cellClicked.connect(self._on_cell_clicked)
        splitter.addWidget(self._table)

        # --- Detail Panel ---
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
        """)
        detail_layout = QVBoxLayout(detail_frame)

        detail_header = QLabel("Alert Details")
        detail_header.setStyleSheet(
            f"color: {COLORS['accent_cyan']}; font-size: 14px; font-weight: bold;"
        )
        detail_layout.addWidget(detail_header)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px;
                font-size: 12px;
                font-family: Consolas, monospace;
            }}
        """)
        detail_layout.addWidget(self._detail_text)

        splitter.addWidget(detail_frame)
        splitter.setSizes([400, 200])

        layout.addWidget(splitter, stretch=1)

    def refresh_alerts(self) -> None:
        """Fetch DoS/flood alerts from the database."""
        try:
            all_alerts = self.db.get_alerts(limit=500)
            dos_alerts = [
                a for a in all_alerts
                if any(kw in (a.get("title", "") or "").lower() for kw in DOS_KEYWORDS)
            ]
            self._alerts_data = dos_alerts

            # Count unacknowledged
            self._unread_count = sum(
                1 for a in dos_alerts if not a.get("acknowledged")
            )

            self._lbl_count.setText(f"{len(dos_alerts)} alerts")
            if self._unread_count > 0:
                self._lbl_unread.setText(f"({self._unread_count} unacknowledged)")
                self._lbl_unread.setStyleSheet(
                    f"color: {COLORS['accent_red']}; font-size: 13px; font-weight: bold;"
                )
            else:
                self._lbl_unread.setText("(all acknowledged)")
                self._lbl_unread.setStyleSheet(
                    f"color: {COLORS['accent_green']}; font-size: 13px;"
                )

            self._populate_table(dos_alerts)
        except Exception as e:
            logger.error("SOC alerts refresh error: %s", e)

    def _populate_table(self, alerts: list) -> None:
        # Block signals during rebuild to avoid losing selection/detail
        self._table.blockSignals(True)
        selected_id = None
        current = self._table.currentRow()
        if 0 <= current < len(self._alerts_data):
            selected_id = self._alerts_data[current].get("id")

        self._table.setRowCount(len(alerts))
        restore_row = -1
        for row, alert in enumerate(alerts):
            if alert.get("id") == selected_id:
                restore_row = row
            is_acked = alert.get("acknowledged", False)
            items = [
                str(alert.get("id", "")),
                str(alert.get("timestamp", ""))[:19],
                alert.get("severity", ""),
                alert.get("title", ""),
                str(alert.get("source", "N/A")),
                str(alert.get("destination", "N/A")),
                str(alert.get("risk_score", 0)),
                "Yes" if is_acked else "NO",
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                # Severity coloring
                if col == 2:
                    color = COLORS["critical"] if text == "Critical" else COLORS.get("high", COLORS["text_primary"])
                    item.setForeground(QColor(color))
                    item.setFont(QFont("", -1, QFont.Bold))
                # Ack status coloring
                elif col == 7:
                    if text == "NO":
                        item.setForeground(QColor(COLORS["accent_red"]))
                        item.setFont(QFont("", -1, QFont.Bold))
                    else:
                        item.setForeground(QColor(COLORS["accent_green"]))
                # Dim acknowledged rows
                elif is_acked:
                    item.setForeground(QColor(COLORS["text_secondary"]))

                self._table.setItem(row, col, item)

        # Restore selection
        self._table.blockSignals(False)
        if restore_row >= 0:
            self._table.setCurrentCell(restore_row, 0)

    def _on_cell_clicked(self, row: int, col: int) -> None:
        if row < 0 or row >= len(self._alerts_data):
            return
        alert = self._alerts_data[row]
        self._show_detail(alert)

    def _show_detail(self, alert: dict) -> None:
        lines = [
            f"<b style='color:{COLORS['accent_red']};font-size:14px;'>"
            f"\U0001f6a8 {alert.get('title', 'Unknown')}</b><br>",
            f"<b>Alert ID:</b> {alert.get('id', 'N/A')}",
            f"<b>Timestamp:</b> {alert.get('timestamp', 'N/A')}",
            f"<b>Severity:</b> <span style='color:{COLORS['critical']};'>"
            f"{alert.get('severity', 'N/A')}</span>",
            f"<b>Risk Score:</b> {alert.get('risk_score', 'N/A')}",
            f"<b>Source IP:</b> {alert.get('source', 'N/A')}",
            f"<b>Destination IP:</b> {alert.get('destination', 'N/A')}",
            f"<b>Module:</b> {alert.get('module', 'N/A')}",
            f"<b>Acknowledged:</b> {'Yes' if alert.get('acknowledged') else 'No'}",
            f"<b>False Positive:</b> {'Yes' if alert.get('false_positive') else 'No'}",
            f"<br><b>Description:</b><br>{alert.get('description', 'N/A')}",
        ]
        self._detail_text.setHtml("<br>".join(lines))

    def _acknowledge_all(self) -> None:
        unacked = [a for a in self._alerts_data if not a.get("acknowledged")]
        if not unacked:
            QMessageBox.information(self, "SOC Alerts", "All DoS/Flood alerts are already acknowledged.")
            return

        for a in unacked:
            aid = a.get("id")
            if aid:
                self.db.acknowledge_alert(aid)

        self.refresh_alerts()
        QMessageBox.information(
            self, "SOC Alerts",
            f"Acknowledged {len(unacked)} DoS/Flood alerts.",
        )

    def _copy_selected(self) -> None:
        rows = set()
        for item in self._table.selectedItems():
            rows.add(item.row())

        if not rows:
            return

        lines = []
        for row in sorted(rows):
            if row < len(self._alerts_data):
                a = self._alerts_data[row]
                lines.append(
                    f"[{a.get('severity')}] {a.get('title')} | "
                    f"Source: {a.get('source')} -> {a.get('destination')} | "
                    f"Score: {a.get('risk_score')} | {a.get('timestamp')}"
                )

        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText("\n".join(lines))

    def on_new_dos_alert(self, alert_dict: dict) -> None:
        """Called when a new DoS/flood alert arrives in real time."""
        self.refresh_alerts()

    def get_unread_count(self) -> int:
        return self._unread_count

    def _btn_style(self, bg: str = COLORS["accent_blue"]) -> str:
        return f"""
            QPushButton {{
                background-color: {bg};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #1a4a80;
            }}
        """
