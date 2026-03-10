"""
SentinelX – Alerts View & Threat Explorer
Provides filterable alert table and detailed threat investigation view.
"""

import csv
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
    QComboBox, QLineEdit, QDateEdit, QSplitter, QTextEdit,
    QFileDialog, QMessageBox, QSizePolicy, QGroupBox, QFormLayout,
    QDialog, QDialogButtonBox, QApplication, QScrollArea,
)
from PySide6.QtCore import Qt, QDate, Signal, Slot, QEvent
from PySide6.QtGui import QFont, QColor, QKeySequence, QShortcut

from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.logger import get_logger

logger = get_logger("alerts_view")

COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_card": "#16213e",
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

SEVERITY_COLORS = {
    "Critical": COLORS["critical"],
    "High": COLORS["high"],
    "Medium": COLORS["medium"],
    "Low": COLORS["low"],
}

BTN_STYLE = f"""
    QPushButton {{
        background-color: {COLORS['accent_blue']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        padding: 6px 14px;
        font-size: 12px;
    }}
    QPushButton:hover {{
        background-color: #1a4a80;
    }}
    QPushButton:pressed {{
        background-color: #0a2a50;
    }}
"""


class AlertsView(QWidget):
    """Alert management view with filtering, search, and export."""

    alert_selected = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = DatabaseManager()
        self._alerts_data: List[dict] = []
        self._setup_ui()
        self.refresh_alerts()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # === Header ===
        header = QLabel("Alert Management")
        header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 18px; font-weight: bold;")
        layout.addWidget(header)

        # === Filter Bar ===
        filter_frame = QFrame()
        filter_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setSpacing(8)

        # Search box
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search alerts...")
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
            }}
        """)
        self._search.returnPressed.connect(self.refresh_alerts)
        filter_layout.addWidget(self._search, stretch=2)

        # Severity filter
        self._severity_filter = QComboBox()
        self._severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self._severity_filter.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
                min-width: 120px;
            }}
            QComboBox::drop-down {{ border: none; }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                selection-background-color: {COLORS['accent_blue']};
            }}
        """)
        self._severity_filter.currentIndexChanged.connect(self.refresh_alerts)
        filter_layout.addWidget(self._severity_filter)

        # Type filter
        self._type_filter = QComboBox()
        self._type_filter.addItems(["All Types", "network", "host", "file", "process"])
        self._type_filter.setStyleSheet(self._severity_filter.styleSheet())
        self._type_filter.currentIndexChanged.connect(self.refresh_alerts)
        filter_layout.addWidget(self._type_filter)

        # Date filter
        self._date_filter = QComboBox()
        self._date_filter.addItems(["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"])
        self._date_filter.setStyleSheet(self._severity_filter.styleSheet())
        self._date_filter.currentIndexChanged.connect(self.refresh_alerts)
        filter_layout.addWidget(self._date_filter)

        # Buttons
        btn_refresh = QPushButton("Refresh")
        btn_refresh.setStyleSheet(BTN_STYLE)
        btn_refresh.clicked.connect(self.refresh_alerts)
        filter_layout.addWidget(btn_refresh)

        btn_csv = QPushButton("Export CSV")
        btn_csv.setStyleSheet(BTN_STYLE)
        btn_csv.clicked.connect(self.export_csv)
        filter_layout.addWidget(btn_csv)

        layout.addWidget(filter_frame)

        # === Alerts Table ===
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "ID", "Timestamp", "Severity", "Type", "Title", "Source", "Score", "Ack"
        ])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().resizeSection(0, 50)
        self._table.horizontalHeader().resizeSection(1, 140)
        self._table.horizontalHeader().resizeSection(2, 80)
        self._table.horizontalHeader().resizeSection(3, 80)
        self._table.horizontalHeader().resizeSection(6, 60)
        self._table.horizontalHeader().resizeSection(7, 50)
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
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_secondary']};
                padding: 6px;
                border: 1px solid {COLORS['border']};
                font-weight: bold;
                font-size: 11px;
            }}
        """)
        self._table.cellClicked.connect(self._on_row_clicked)
        layout.addWidget(self._table, stretch=1)

    @Slot()
    def refresh_alerts(self) -> None:
        """Reload alerts with current filters."""
        severity = self._severity_filter.currentText()
        if severity == "All Severities":
            severity = None

        alert_type = self._type_filter.currentText()
        if alert_type == "All Types":
            alert_type = None

        search = self._search.text().strip() or None

        date_choice = self._date_filter.currentText()
        since = None
        if date_choice == "Last 24 Hours":
            since = datetime.utcnow() - timedelta(hours=24)
        elif date_choice == "Last 7 Days":
            since = datetime.utcnow() - timedelta(days=7)
        elif date_choice == "Last 30 Days":
            since = datetime.utcnow() - timedelta(days=30)

        try:
            self._alerts_data = self.db.get_alerts(
                severity=severity,
                alert_type=alert_type,
                since=since,
                search=search,
                limit=1000,
            )
        except Exception as e:
            logger.error("Failed to load alerts: %s", e)
            self._alerts_data = []

        self._populate_table()

    def _populate_table(self) -> None:
        self._table.setRowCount(len(self._alerts_data))
        for row, alert in enumerate(self._alerts_data):
            is_acked = alert.get("acknowledged", False)
            is_fp = alert.get("false_positive", False)

            # Determine row background color
            if is_fp:
                row_bg = QColor("#2a1a2a")  # dim purple/gray for false positives
                row_fg = QColor(COLORS["text_secondary"])
            elif is_acked:
                row_bg = QColor("#0a2a1a")  # dark green tint for acknowledged
                row_fg = QColor(COLORS["text_primary"])
            else:
                row_bg = None
                row_fg = None

            ack_text = "FP" if is_fp else ("✓" if is_acked else "")

            items_data = [
                str(alert.get("id", "")),
                alert.get("timestamp", ""),
                alert.get("severity", ""),
                alert.get("alert_type", ""),
                alert.get("title", ""),
                alert.get("source", "N/A"),
                str(alert.get("risk_score", 0)),
                ack_text,
            ]
            for col, text in enumerate(items_data):
                item = QTableWidgetItem(str(text))
                if col == 2:  # Severity column
                    color = SEVERITY_COLORS.get(alert.get("severity", ""), COLORS["text_primary"])
                    item.setForeground(QColor(color))
                    item.setFont(QFont("", -1, QFont.Bold))
                elif col == 7:  # Ack column
                    if is_fp:
                        item.setForeground(QColor("#b388ff"))  # purple for FP
                        item.setFont(QFont("", -1, QFont.Bold))
                    elif is_acked:
                        item.setForeground(QColor(COLORS["accent_green"]))
                        item.setFont(QFont("", -1, QFont.Bold))
                if row_bg:
                    item.setBackground(row_bg)
                if row_fg and col != 2 and col != 7:
                    item.setForeground(row_fg)
                self._table.setItem(row, col, item)

    @Slot(int, int)
    def _on_row_clicked(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._alerts_data):
            self.alert_selected.emit(self._alerts_data[row])

    def export_csv(self) -> None:
        """Export current alerts to CSV file."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts to CSV", "sentinelx_alerts.csv", "CSV Files (*.csv)"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "id", "timestamp", "severity", "alert_type", "title",
                    "description", "source", "destination", "risk_score",
                    "acknowledged", "false_positive",
                ])
                writer.writeheader()
                writer.writerows(self._alerts_data)
            QMessageBox.information(self, "Export Complete", f"Exported {len(self._alerts_data)} alerts to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))


class ThreatExplorerView(QWidget):
    """Detailed view for investigating a specific alert."""

    alert_updated = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = DatabaseManager()
        self._current_alert: Optional[dict] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QLabel("Threat Explorer")
        header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 18px; font-weight: bold;")
        layout.addWidget(header)

        # === Splitter: detail (top) | related events (bottom) ===
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
                border-radius: 3px;
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent_cyan']};
            }}
        """)

        # ── Top panel: alert detail + description + buttons (scrollable) ──
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(8)

        # Alert detail card
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 16px;
            }}
        """)
        detail_layout = QFormLayout(detail_frame)
        detail_layout.setSpacing(8)

        label_style = f"color: {COLORS['text_secondary']}; font-size: 12px; border: none;"
        value_style = f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold; border: none;"

        self._lbl_id = QLabel("—")
        self._lbl_severity = QLabel("—")
        self._lbl_type = QLabel("—")
        self._lbl_title = QLabel("—")
        self._lbl_source = QLabel("—")
        self._lbl_dest = QLabel("—")
        self._lbl_score = QLabel("—")
        self._lbl_time = QLabel("—")

        for lbl in (self._lbl_id, self._lbl_severity, self._lbl_type, self._lbl_title,
                     self._lbl_source, self._lbl_dest, self._lbl_score, self._lbl_time):
            lbl.setStyleSheet(value_style)
            lbl.setWordWrap(True)

        fields = [
            ("Alert ID:", self._lbl_id),
            ("Severity:", self._lbl_severity),
            ("Type:", self._lbl_type),
            ("Title:", self._lbl_title),
            ("Source:", self._lbl_source),
            ("Destination:", self._lbl_dest),
            ("Risk Score:", self._lbl_score),
            ("Timestamp:", self._lbl_time),
        ]
        for label_text, widget in fields:
            lbl = QLabel(label_text)
            lbl.setStyleSheet(label_style)
            detail_layout.addRow(lbl, widget)

        top_layout.addWidget(detail_frame)

        # Description
        self._description = QTextEdit()
        self._description.setReadOnly(True)
        self._description.setMaximumHeight(120)
        self._description.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px;
                font-size: 12px;
            }}
        """)
        top_layout.addWidget(self._description)

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_ack = QPushButton("Acknowledge")
        btn_ack.setStyleSheet(BTN_STYLE)
        btn_ack.clicked.connect(self._acknowledge)
        btn_layout.addWidget(btn_ack)

        btn_fp = QPushButton("Mark False Positive")
        btn_fp.setStyleSheet(BTN_STYLE.replace(COLORS['accent_blue'], '#4a3000'))
        btn_fp.clicked.connect(self._mark_false_positive)
        btn_layout.addWidget(btn_fp)

        btn_forward = QPushButton("\u27a4  Forward Alert")
        btn_forward.setStyleSheet(BTN_STYLE.replace(COLORS['accent_blue'], '#1b5e20'))
        btn_forward.clicked.connect(self._forward_alert)
        btn_layout.addWidget(btn_forward)

        btn_layout.addStretch()
        top_layout.addLayout(btn_layout)

        # Wrap top panel in a scroll area
        top_scroll = QScrollArea()
        top_scroll.setWidget(top_widget)
        top_scroll.setWidgetResizable(True)
        top_scroll.setFrameShape(QFrame.NoFrame)
        top_scroll.setStyleSheet(f"background: transparent; border: none;")

        splitter.addWidget(top_scroll)

        # ── Bottom panel: related events table ──
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(4)

        related_label = QLabel("Threat Details")
        related_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 14px; font-weight: bold;")
        bottom_layout.addWidget(related_label)

        self._details_table = QTableWidget()
        self._details_table.setColumnCount(2)
        self._details_table.setHorizontalHeaderLabels(["Property", "Value"])
        self._details_table.horizontalHeader().setStretchLastSection(True)
        self._details_table.horizontalHeader().resizeSection(0, 160)
        self._details_table.verticalHeader().setVisible(False)
        self._details_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._details_table.setSelectionBehavior(QTableWidget.SelectItems)
        self._details_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self._details_table.setWordWrap(True)
        self._details_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                gridline-color: {COLORS['border']};
                font-size: 12px;
            }}
            QTableWidget::item {{
                padding: 6px 8px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_secondary']};
                padding: 6px;
                border: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
        self._details_table.installEventFilter(self)
        bottom_layout.addWidget(self._details_table, stretch=1)

        splitter.addWidget(bottom_widget)

        # Set initial splitter sizes (60% detail, 40% related)
        splitter.setSizes([400, 250])

        layout.addWidget(splitter, stretch=1)

        # Placeholder
        self._placeholder = QLabel("Select an alert from the Alerts view to investigate.")
        self._placeholder.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        self._placeholder.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._placeholder)

    def eventFilter(self, obj, event):
        """Handle Ctrl+C to copy selected cell values from the details table."""
        if obj is self._details_table and event.type() == QEvent.KeyPress:
            if event.matches(QKeySequence.Copy):
                selected = self._details_table.selectedItems()
                if selected:
                    text = "\n".join(item.text() for item in selected)
                    clipboard = QApplication.clipboard()
                    if clipboard:
                        clipboard.setText(text)
                return False
        return super().eventFilter(obj, event)

    def show_alert(self, alert: dict) -> None:
        """Display details for a specific alert."""
        self._current_alert = alert
        self._placeholder.hide()

        self._lbl_id.setText(str(alert.get("id", "—")))
        sev = alert.get("severity", "—")
        color = SEVERITY_COLORS.get(sev, COLORS["text_primary"])
        self._lbl_severity.setText(sev)
        self._lbl_severity.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: bold; border: none;")

        # Show status badge
        is_fp = alert.get("false_positive", False)
        is_acked = alert.get("acknowledged", False)
        if is_fp:
            status = "  [FALSE POSITIVE]"
            self._lbl_title.setStyleSheet(f"color: #b388ff; font-size: 13px; font-weight: bold; border: none;")
        elif is_acked:
            status = "  [ACKNOWLEDGED]"
            self._lbl_title.setStyleSheet(f"color: {COLORS['accent_green']}; font-size: 13px; font-weight: bold; border: none;")
        else:
            status = ""
            self._lbl_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold; border: none;")

        self._lbl_type.setText(alert.get("alert_type", "—"))
        self._lbl_title.setText(alert.get("title", "—") + status)
        self._lbl_source.setText(alert.get("source", "N/A"))
        self._lbl_dest.setText(alert.get("destination", "N/A"))
        self._lbl_score.setText(str(alert.get("risk_score", "—")))
        self._lbl_time.setText(alert.get("timestamp", "—"))
        self._description.setPlainText(alert.get("description", ""))

        # Load full details for this alert
        self._load_details(alert)

    # ── Threat enrichment maps ──
    _MITRE_MAP = {
        "port_scan": ("TA0043 – Reconnaissance", "T1046 – Network Service Discovery"),
        "syn_flood": ("TA0040 – Impact", "T1498 – Network Denial of Service"),
        "arp_spoof": ("TA0006 – Credential Access", "T1557 – Adversary-in-the-Middle"),
        "brute_force": ("TA0006 – Credential Access", "T1110 – Brute Force"),
        "reverse_shell": ("TA0011 – Command & Control", "T1059 – Command & Scripting"),
        "ransomware": ("TA0040 – Impact", "T1486 – Data Encrypted for Impact"),
        "mass_modification": ("TA0040 – Impact", "T1486 – Data Encrypted for Impact"),
        "file_modified": ("TA0005 – Defense Evasion", "T1565 – Data Manipulation"),
        "file_deleted": ("TA0040 – Impact", "T1485 – Data Destruction"),
        "suspicious_process": ("TA0002 – Execution", "T1059 – Command & Scripting"),
        "powershell": ("TA0002 – Execution", "T1059.001 – PowerShell"),
        "privilege_escalation": ("TA0004 – Privilege Escalation", "T1078 – Valid Accounts"),
        "user_created": ("TA0003 – Persistence", "T1136 – Create Account"),
        "dns_tunnel": ("TA0010 – Exfiltration", "T1048 – Exfiltration Over Alternative Protocol"),
        "suspicious_outbound": ("TA0011 – Command & Control", "T1071 – Application Layer Protocol"),
        "c2": ("TA0011 – Command & Control", "T1071 – Application Layer Protocol"),
    }

    _ACTION_MAP = {
        "Critical": "Immediate isolation recommended. Escalate to SOC / Incident Response team.",
        "High": "Investigate immediately. Block source if confirmed malicious.",
        "Medium": "Review within 4 hours. Monitor for recurrence.",
        "Low": "Log for audit. No immediate action required.",
    }

    _CATEGORY_MAP = {
        "network": "Network Intrusion / Anomaly",
        "host": "Host-Based Threat / Authentication",
        "file": "File System Integrity Violation",
        "process": "Process Execution Anomaly",
    }

    def _parse_event_details(self, description: str) -> dict:
        """Extract key=value pairs from the engine's '| Details:' suffix."""
        parsed = {}
        if "| Details:" in description:
            raw = description.split("| Details:", 1)[1].strip()
            for token in raw.split(", "):
                if "=" in token:
                    k, v = token.split("=", 1)
                    parsed[k.strip()] = v.strip()
        return parsed

    def _match_mitre(self, alert: dict) -> tuple:
        """Return (tactic, technique) for this alert."""
        title_lower = (alert.get("title") or "").lower()
        tags_text = title_lower + " " + (alert.get("description") or "").lower()
        for keyword, mapping in self._MITRE_MAP.items():
            if keyword.replace("_", " ") in tags_text or keyword in tags_text:
                return mapping
        return ("—", "—")

    def _load_details(self, alert: dict) -> None:
        """Populate the Threat Details table with comprehensive alert info."""
        desc_raw = str(alert.get("description", ""))
        base_desc = desc_raw.split("| Details:")[0].strip() if "| Details:" in desc_raw else desc_raw
        event_details = self._parse_event_details(desc_raw)
        tactic, technique = self._match_mitre(alert)
        severity = str(alert.get("severity", "—"))
        module = str(alert.get("module", "unknown"))
        category = self._CATEGORY_MAP.get(module, "General")
        recommended = self._ACTION_MAP.get(severity, "Review when possible.")

        # Compute time-ago string
        ts_str = str(alert.get("timestamp", ""))
        time_ago = "—"
        try:
            ts_dt = datetime.fromisoformat(ts_str)
            delta = datetime.utcnow() - ts_dt
            if delta.days > 0:
                time_ago = f"{delta.days}d {delta.seconds // 3600}h ago"
            elif delta.seconds >= 3600:
                time_ago = f"{delta.seconds // 3600}h {(delta.seconds % 3600) // 60}m ago"
            else:
                time_ago = f"{delta.seconds // 60}m ago"
        except Exception:
            pass

        # ── Build comprehensive detail rows ──
        details = [
            # --- Identity ---
            ("\u2501 ALERT IDENTITY", ""),
            ("Alert ID", str(alert.get("id", "—"))),
            ("Timestamp", ts_str),
            ("Time Ago", time_ago),
            ("Title", str(alert.get("title", "—"))),
            ("Alert Type", str(alert.get("alert_type", "—"))),
            ("Threat Category", category),
            # --- Severity & Risk ---
            ("\u2501 SEVERITY & RISK", ""),
            ("Severity", severity),
            ("Risk Score", str(alert.get("risk_score", "—"))),
            ("Acknowledged", "Yes" if alert.get("acknowledged") else "No"),
            ("False Positive", "Yes" if alert.get("false_positive") else "No"),
            # --- Network / Source ---
            ("\u2501 SOURCE & DESTINATION", ""),
            ("Source IP / Entity", str(alert.get("source", "N/A"))),
            ("Destination IP / Entity", str(alert.get("destination", "N/A"))),
            ("Detection Module", module),
        ]

        # Inject parsed event details (ports, PID, commands, hashes, etc.)
        if event_details:
            details.append(("\u2501 EVENT DETAILS", ""))
            label_map = {
                "destination_port": "Destination Port",
                "unique_ports": "Unique Ports Scanned",
                "syn_count": "SYN Packet Count",
                "request_count": "Request Count",
                "protocol": "Protocol",
                "method": "HTTP Method",
                "uri": "Request URI",
                "event_id": "Windows Event ID",
                "pid": "Process ID (PID)",
                "parent": "Parent Process",
                "child": "Child Process",
                "command": "Command Line",
                "old_hash": "Previous File Hash",
                "new_hash": "Current File Hash",
                "file_path": "Affected File Path",
                "modifications": "Modification Count",
                "description": "Event Description",
            }
            for k, v in event_details.items():
                details.append((label_map.get(k, k.replace("_", " ").title()), v))

        # MITRE ATT&CK mapping
        details.append(("\u2501 MITRE ATT&CK", ""))
        details.append(("Tactic", tactic))
        details.append(("Technique", technique))

        # Recommended action
        details.append(("\u2501 RESPONSE", ""))
        details.append(("Recommended Action", recommended))

        # Full description last
        details.append(("\u2501 DESCRIPTION", ""))
        details.append(("Description", base_desc))

        # ── Render to table ──
        self._details_table.setRowCount(len(details))
        sev_color_map = {
            "Critical": COLORS["critical"],
            "High": COLORS["high"],
            "Medium": COLORS["medium"],
            "Low": COLORS["low"],
        }

        for row, (key, value) in enumerate(details):
            # Section headers
            is_section = key.startswith("\u2501")

            key_item = QTableWidgetItem(key)
            val_item = QTableWidgetItem(value)

            if is_section:
                key_item.setForeground(QColor(COLORS["accent_yellow"]))
                key_item.setFont(QFont("", -1, QFont.Bold))
                val_item.setForeground(QColor(COLORS["accent_yellow"]))
                key_item.setBackground(QColor("#1e2a4a"))
                val_item.setBackground(QColor("#1e2a4a"))
            else:
                key_item.setForeground(QColor(COLORS["accent_cyan"]))
                key_item.setFont(QFont("", -1, QFont.Bold))

                # Color-code specific rows
                if key == "Severity":
                    color = sev_color_map.get(value, COLORS["text_primary"])
                    val_item.setForeground(QColor(color))
                    val_item.setFont(QFont("", -1, QFont.Bold))
                elif key == "Acknowledged":
                    color = COLORS["accent_green"] if value == "Yes" else COLORS["accent_red"]
                    val_item.setForeground(QColor(color))
                elif key == "False Positive":
                    color = "#b388ff" if value == "Yes" else COLORS["text_primary"]
                    val_item.setForeground(QColor(color))
                elif key == "Risk Score":
                    try:
                        score = int(value)
                        if score >= 80:
                            val_item.setForeground(QColor(COLORS["critical"]))
                        elif score >= 50:
                            val_item.setForeground(QColor(COLORS["high"]))
                        else:
                            val_item.setForeground(QColor(COLORS["accent_green"]))
                    except ValueError:
                        pass
                elif key in ("Source IP / Entity", "Destination IP / Entity"):
                    val_item.setForeground(QColor("#80deea"))
                    val_item.setFont(QFont("Consolas", -1))
                elif key in ("Destination Port", "Process ID (PID)", "Command Line",
                             "Parent Process", "Child Process"):
                    val_item.setForeground(QColor("#ffab91"))
                    val_item.setFont(QFont("Consolas", -1))
                elif key in ("Tactic", "Technique"):
                    val_item.setForeground(QColor("#ce93d8"))
                elif key == "Recommended Action":
                    val_item.setForeground(QColor(COLORS["accent_yellow"]))
                    val_item.setFont(QFont("", -1, QFont.Bold))

            self._details_table.setItem(row, 0, key_item)
            self._details_table.setItem(row, 1, val_item)

        self._details_table.resizeRowsToContents()

    def _acknowledge(self) -> None:
        if self._current_alert:
            alert_id = self._current_alert.get("id")
            if alert_id:
                self.db.acknowledge_alert(alert_id)
                # Refresh the displayed alert from DB
                updated = self.db.get_alert_by_id(alert_id)
                if updated:
                    self._current_alert = updated
                    self.show_alert(updated)
                self.alert_updated.emit()
                QMessageBox.information(self, "Acknowledged", f"Alert #{alert_id} acknowledged.")

    def _mark_false_positive(self) -> None:
        if self._current_alert:
            alert_id = self._current_alert.get("id")
            if alert_id:
                self.db.mark_false_positive(alert_id)
                # Refresh the displayed alert from DB
                updated = self.db.get_alert_by_id(alert_id)
                if updated:
                    self._current_alert = updated
                    self.show_alert(updated)
                self.alert_updated.emit()
                QMessageBox.information(self, "False Positive", f"Alert #{alert_id} marked as false positive.")

    def _forward_alert(self) -> None:
        """Open the forward-alert dialog."""
        if not self._current_alert:
            QMessageBox.warning(self, "No Alert", "Select an alert first.")
            return
        dlg = ForwardAlertDialog(self._current_alert, parent=self)
        dlg.exec()


class ForwardAlertDialog(QDialog):
    """Dialog to forward an alert to a cybersecurity team / professional."""

    TEAMS = [
        ("SOC Analyst (Tier 1)",        "soc-tier1@org.local",     "Initial triage, monitoring, and escalation"),
        ("SOC Analyst (Tier 2)",        "soc-tier2@org.local",     "Deep-dive investigation and correlation"),
        ("SOC Analyst (Tier 3)",        "soc-tier3@org.local",     "Advanced threat hunting and forensics"),
        ("Blue Team",                   "blue-team@org.local",     "Defensive operations and hardening"),
        ("Red Team",                    "red-team@org.local",      "Offensive testing and validation"),
        ("Purple Team",                 "purple-team@org.local",   "Collaborative attack/defense exercises"),
        ("Incident Response (IR)",      "ir-team@org.local",       "Containment, eradication, and recovery"),
        ("Threat Intelligence",         "threat-intel@org.local",  "IOC enrichment and threat landscape"),
        ("Cybersecurity Engineer",      "sec-engineer@org.local",  "Security architecture and tool tuning"),
        ("Network Security Engineer",   "netsec@org.local",        "Firewall, IDS/IPS, and network defense"),
        ("Endpoint Security",           "endpoint-sec@org.local",  "EDR management and endpoint protection"),
        ("Malware Analyst",             "malware-team@org.local",  "Reverse engineering and malware triage"),
        ("Forensics Team",              "forensics@org.local",     "Digital evidence collection and analysis"),
        ("Vulnerability Management",    "vuln-mgmt@org.local",     "Patch prioritisation and vuln tracking"),
        ("CISO / Security Manager",     "ciso@org.local",          "Executive escalation and risk decisions"),
        ("Compliance / GRC",            "grc@org.local",           "Regulatory reporting and audit trail"),
        ("IT Operations / SysAdmin",    "it-ops@org.local",        "System isolation and remediation support"),
        ("Custom Recipient\u2026",       "",                        "Enter a custom email address"),
    ]

    def __init__(self, alert: dict, parent=None):
        super().__init__(parent)
        self._alert = alert
        self.setWindowTitle("Forward Alert")
        self.setMinimumSize(620, 520)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
            }}
        """)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        header = QLabel(f"Forward Alert #{self._alert.get('id')} — {self._alert.get('title', '')}")
        header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 15px; font-weight: bold;")
        header.setWordWrap(True)
        layout.addWidget(header)

        sev = self._alert.get("severity", "")
        sev_color = SEVERITY_COLORS.get(sev, COLORS['text_primary'])
        info = QLabel(f"Severity: <span style='color:{sev_color};font-weight:bold;'>{sev}</span>  |  "
                      f"Score: {self._alert.get('risk_score', '—')}  |  "
                      f"Source: {self._alert.get('source', 'N/A')}")
        info.setTextFormat(Qt.RichText)
        info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(info)

        # Team selection table
        self._team_table = QTableWidget()
        self._team_table.setColumnCount(3)
        self._team_table.setHorizontalHeaderLabels(["Team / Role", "Contact", "Responsibility"])
        self._team_table.horizontalHeader().setStretchLastSection(True)
        self._team_table.horizontalHeader().resizeSection(0, 200)
        self._team_table.horizontalHeader().resizeSection(1, 170)
        self._team_table.verticalHeader().setVisible(False)
        self._team_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._team_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._team_table.setSelectionMode(QTableWidget.SingleSelection)
        self._team_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_card']};
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
                background-color: {COLORS['bg_dark']};
                color: {COLORS['accent_cyan']};
                padding: 6px;
                border: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)

        self._team_table.setRowCount(len(self.TEAMS))
        for row, (name, contact, role) in enumerate(self.TEAMS):
            self._team_table.setItem(row, 0, QTableWidgetItem(name))
            self._team_table.setItem(row, 1, QTableWidgetItem(contact))
            self._team_table.setItem(row, 2, QTableWidgetItem(role))
        self._team_table.resizeRowsToContents()
        layout.addWidget(self._team_table, stretch=1)

        # Optional notes
        notes_label = QLabel("Additional Notes (optional):")
        notes_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(notes_label)

        self._notes = QTextEdit()
        self._notes.setMaximumHeight(70)
        self._notes.setPlaceholderText("Add context, urgency notes, or instructions for the recipient\u2026")
        self._notes.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
            }}
        """)
        layout.addWidget(self._notes)

        # Custom email input (shown only when "Custom Recipient" selected)
        self._custom_row = QHBoxLayout()
        self._custom_label = QLabel("Custom Email:")
        self._custom_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        self._custom_input = QLineEdit()
        self._custom_input.setPlaceholderText("analyst@example.com")
        self._custom_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
            }}
        """)
        self._custom_row.addWidget(self._custom_label)
        self._custom_row.addWidget(self._custom_input, stretch=1)
        self._custom_label.hide()
        self._custom_input.hide()
        layout.addLayout(self._custom_row)

        self._team_table.selectionModel().selectionChanged.connect(self._on_team_selected)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_forward = QPushButton("Forward")
        btn_forward.setStyleSheet(BTN_STYLE.replace(COLORS['accent_blue'], '#1b5e20'))
        btn_forward.clicked.connect(self._do_forward)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setStyleSheet(BTN_STYLE)
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_forward)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

    def _on_team_selected(self) -> None:
        rows = self._team_table.selectionModel().selectedRows()
        if rows:
            idx = rows[0].row()
            is_custom = idx == len(self.TEAMS) - 1
            self._custom_label.setVisible(is_custom)
            self._custom_input.setVisible(is_custom)

    def _do_forward(self) -> None:
        rows = self._team_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.warning(self, "No Team Selected", "Please select a team or role to forward to.")
            return
        idx = rows[0].row()
        team_name = self.TEAMS[idx][0]
        contact = self.TEAMS[idx][1]

        if idx == len(self.TEAMS) - 1:
            contact = self._custom_input.text().strip()
            if not contact:
                QMessageBox.warning(self, "No Email", "Enter a custom email address.")
                return
            team_name = f"Custom ({contact})"

        notes = self._notes.toPlainText().strip()
        alert_id = self._alert.get("id", "?")
        title = self._alert.get("title", "")

        # Build the forwarding summary
        summary = (
            f"Alert #{alert_id} — {title}\n"
            f"Severity: {self._alert.get('severity')}  |  Score: {self._alert.get('risk_score')}\n"
            f"Source: {self._alert.get('source', 'N/A')}  →  Dest: {self._alert.get('destination', 'N/A')}\n"
            f"Module: {self._alert.get('module', 'N/A')}\n"
            f"Description: {self._alert.get('description', '')}\n"
        )
        if notes:
            summary += f"\nAnalyst Notes: {notes}\n"

        # Copy to clipboard for the user to paste into email / ticket
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(summary)

        logger.info("Alert #%s forwarded to %s (%s)", alert_id, team_name, contact)

        QMessageBox.information(
            self,
            "Alert Forwarded",
            f"Alert #{alert_id} forwarded to:\n\n"
            f"  {team_name}\n  {contact}\n\n"
            "Full alert details have been copied to your clipboard.\n"
            "Paste into your email client, SOAR platform, or ticketing system.",
        )
        self.accept()
