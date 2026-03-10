"""
SentinelX – Main Window
Professional GUI main window with sidebar navigation and login system.
"""

import sys
import threading
import time
from typing import Optional

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QStackedWidget, QApplication,
    QDialog, QLineEdit, QFormLayout, QDialogButtonBox,
    QMessageBox, QSystemTrayIcon, QMenu, QSizePolicy, QSpacerItem,
    QGraphicsOpacityEffect,
)
from PySide6.QtCore import Qt, QSize, Signal, Slot, QTimer, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QIcon, QAction, QFont, QColor, QScreen, QPainter

from sentinelx.auth.auth_manager import AuthManager
from sentinelx.gui.dashboard import DashboardView
from sentinelx.gui.alerts_view import AlertsView, ThreatExplorerView
from sentinelx.gui.ip_analytics_view import IPAnalyticsView
from sentinelx.gui.reports_view import ReportsView
from sentinelx.gui.settings_view import SettingsView
from sentinelx.gui.soc_alerts_view import SOCAlertsView
from sentinelx.utils.logger import get_logger

logger = get_logger("main_window")

# ── Theme Colors ──────────────────────────────────────────
COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_sidebar": "#0f0f23",
    "bg_card": "#16213e",
    "accent_blue": "#0f3460",
    "accent_cyan": "#00d2ff",
    "accent_green": "#00e676",
    "text_primary": "#e0e0e0",
    "text_secondary": "#9e9e9e",
    "border": "#2a2a4a",
    "sidebar_hover": "#1a1a3a",
    "sidebar_active": "#0f3460",
}

# Overlay singleton – only one at a time, with cooldown
_active_overlay: Optional[QWidget] = None
_overlay_last_shown: float = 0.0
_OVERLAY_COOLDOWN = 8  # seconds between overlays

# Auto-forward routing: keywords in alert title → department
_AUTO_FORWARD_MAP = [
    # DDoS / Flood attacks → Cybersecurity Expert
    (("dos", "ddos", "syn flood", "http flood", "flood"), "Cybersecurity Expert"),
    # Suspicious IP / outbound / reconnaissance → Senior SOC Analyst
    (("suspicious outbound", "suspicious ip", "port scan", "arp spoof"),
     "Senior SOC Analyst"),
    # Network-related → Network Engineer
    (("dns", "network"), "Network Engineer"),
    # Ransomware / reverse shell / brute force → Incident Response Team
    (("ransomware", "reverse shell", "brute force", "privilege escalation",
      "powershell"), "Incident Response Team"),
]


def _resolve_department(alert_dict: dict) -> str:
    """Determine the correct department for auto-forwarding based on alert title."""
    title = alert_dict.get("title", "").lower()
    for keywords, dept in _AUTO_FORWARD_MAP:
        if any(kw in title for kw in keywords):
            return dept
    return "Incident Response Team"


# Department options for manual forwarding
_DEPARTMENTS = [
    "Senior SOC Analyst",
    "Cybersecurity Expert",
    "Network Engineer",
    "Incident Response Team",
    "IT Infrastructure",
    "Application Security",
    "Management / CISO",
]


class ForwardConfirmationToast(QWidget):
    """Small toast notification confirming an alert was auto-forwarded."""

    def __init__(self, department: str, title: str, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(520, 120)

        # Position at bottom-right of primary screen
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            self.move(geo.right() - 530, geo.bottom() - 130)

        self._build(department, title)

        # Auto-close after 8 seconds
        QTimer.singleShot(8000, self._close)

    def _build(self, department: str, title: str) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        card = QFrame()
        card.setStyleSheet(
            "QFrame { background: #16213e; border: 2px solid #00b0ff;"
            " border-radius: 12px; }"
        )
        lay = QVBoxLayout(card)
        lay.setContentsMargins(20, 14, 20, 14)
        lay.setSpacing(6)

        header = QLabel("📤  ALERT AUTO-FORWARDED")
        header.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        header.setStyleSheet("color: #00b0ff;")
        lay.addWidget(header)

        detail = QLabel(f"\"{title}\" → {department}")
        detail.setWordWrap(True)
        detail.setFont(QFont("Segoe UI", 11))
        detail.setStyleSheet("color: #e0e0e0;")
        lay.addWidget(detail)

        hint = QLabel("No action was taken — alert was automatically escalated.")
        hint.setFont(QFont("Segoe UI", 9))
        hint.setStyleSheet("color: #9e9e9e;")
        lay.addWidget(hint)

        root.addWidget(card)

    def mousePressEvent(self, event):
        self._close()

    def _close(self):
        self.close()
        self.deleteLater()


class FullScreenAlertOverlay(QWidget):
    """Full-screen overlay warning with action buttons for critical alerts."""

    def __init__(self, alert_dict: dict, parent=None):
        super().__init__(parent)
        self._remaining = 30  # must be set before any UI/timer setup
        self._alert = alert_dict
        self._alert_id = alert_dict.get("id")
        self._user_acted = False  # tracks if user clicked any action

        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.BypassWindowManagerHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, False)

        screen = QApplication.primaryScreen()
        if screen:
            self.setGeometry(screen.geometry())

        self._status_label = None  # set in _build_ui
        self._build_ui(alert_dict)

        threading.Thread(target=self._play_alert_sound, daemon=True).start()

        # Auto-forward after 30 seconds if user takes no action
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._auto_forward)
        self._timer.start(30000)

        # Countdown ticker — updates the notice label every second
        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start()

    # ── UI ──────────────────────────────────────────────────

    def _build_ui(self, alert_dict: dict) -> None:
        severity = alert_dict.get("severity", "Unknown")
        title = alert_dict.get("title", "Threat Detected")
        desc = alert_dict.get("description", "")
        source = alert_dict.get("source", "N/A")
        dest = alert_dict.get("destination", "N/A")
        risk = alert_dict.get("risk_score", 0)

        accent = "#ff1744" if severity == "Critical" else (
            "#ff9100" if severity == "High" else "#ffea00"
        )
        self._accent = accent

        # Determine the auto-forward target so we can show it
        self._target_dept = _resolve_department(alert_dict)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        bg = QWidget(self)
        bg.setStyleSheet("background: rgba(10, 10, 20, 0.92);")
        root.addWidget(bg)

        inner = QVBoxLayout(bg)
        inner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        inner.setSpacing(18)

        # Card
        card = QFrame()
        card.setFixedWidth(780)
        card.setStyleSheet(
            f"QFrame {{ background: #16213e; border: 2px solid {accent};"
            f" border-radius: 18px; }}"
        )
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(40, 28, 40, 28)
        card_lay.setSpacing(10)

        # Severity badge
        badge = QLabel(f"⚠  {severity.upper()}  ⚠")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        badge.setStyleSheet(
            f"color: {accent}; background: rgba(0,0,0,0.3);"
            f" border-radius: 8px; padding: 8px 20px;"
        )
        card_lay.addWidget(badge)

        # Title
        lbl_title = QLabel(title)
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_title.setWordWrap(True)
        lbl_title.setFont(QFont("Segoe UI", 17, QFont.Weight.Bold))
        lbl_title.setStyleSheet(f"color: {accent};")
        card_lay.addWidget(lbl_title)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {accent};")
        card_lay.addWidget(sep)

        # Details
        for lbl_text, val_text in (
            ("Source IP", source),
            ("Target IP", dest),
            ("Risk Score", f"{risk} / 100"),
        ):
            row = QHBoxLayout()
            lbl = QLabel(lbl_text + ":")
            lbl.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
            lbl.setStyleSheet("color: #9e9e9e;")
            val = QLabel(str(val_text))
            val.setFont(QFont("Segoe UI", 13))
            val.setStyleSheet("color: #e0e0e0;")
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)
            card_lay.addLayout(row)

        # Description
        if desc:
            lbl_desc = QLabel(desc[:300])
            lbl_desc.setWordWrap(True)
            lbl_desc.setFont(QFont("Segoe UI", 11))
            lbl_desc.setStyleSheet("color: #b0bec5; padding-top: 4px;")
            card_lay.addWidget(lbl_desc)

        # Auto-forward notice (with live countdown)
        self._auto_notice = QLabel()
        self._update_countdown_text()
        self._auto_notice.setWordWrap(True)
        self._auto_notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._auto_notice.setFont(QFont("Segoe UI", 10))
        self._auto_notice.setStyleSheet("color: #ffab40; padding: 6px 0;")
        card_lay.addWidget(self._auto_notice)

        # ── Action buttons ──────────────────────────────────
        card_lay.addSpacing(4)
        actions_label = QLabel("ACTIONS")
        actions_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        actions_label.setStyleSheet("color: #9e9e9e; letter-spacing: 2px;")
        actions_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_lay.addWidget(actions_label)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        btn_style = (
            "QPushButton {{ background: {bg}; color: {fg}; border: none;"
            " border-radius: 8px; padding: 10px 6px; font-size: 12px;"
            " font-weight: bold; }}"
            "QPushButton:hover {{ background: {hover}; }}"
        )

        # 1) Acknowledge
        btn_ack = QPushButton("✔  ACKNOWLEDGE")
        btn_ack.setFixedHeight(42)
        btn_ack.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_ack.setStyleSheet(btn_style.format(
            bg="#00e676", fg="#000", hover="#69f0ae"
        ))
        btn_ack.clicked.connect(self._on_acknowledge)
        btn_row.addWidget(btn_ack)

        # 2) Forward to Department
        btn_fwd = QPushButton("📤  FORWARD")
        btn_fwd.setFixedHeight(42)
        btn_fwd.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_fwd.setStyleSheet(btn_style.format(
            bg="#00b0ff", fg="#000", hover="#40c4ff"
        ))
        btn_fwd.clicked.connect(self._on_forward)
        btn_row.addWidget(btn_fwd)

        # 3) Mark as False Positive
        btn_fp = QPushButton("✘  FALSE POSITIVE")
        btn_fp.setFixedHeight(42)
        btn_fp.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_fp.setStyleSheet(btn_style.format(
            bg="#ffd600", fg="#000", hover="#ffff00"
        ))
        btn_fp.clicked.connect(self._on_false_positive)
        btn_row.addWidget(btn_fp)

        # 4) Dismiss (no DB action)
        btn_dismiss = QPushButton("✕  DISMISS")
        btn_dismiss.setFixedHeight(42)
        btn_dismiss.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_dismiss.setStyleSheet(btn_style.format(
            bg="#ff1744", fg="#fff", hover="#ff5252"
        ))
        btn_dismiss.clicked.connect(self._on_dismiss_clicked)
        btn_row.addWidget(btn_dismiss)

        card_lay.addLayout(btn_row)

        # Status feedback label
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self._status_label.setStyleSheet("color: #00e676; padding-top: 4px;")
        self._status_label.hide()
        card_lay.addWidget(self._status_label)

        inner.addWidget(card, alignment=Qt.AlignmentFlag.AlignCenter)

    # ── Actions ─────────────────────────────────────────────

    def _update_countdown_text(self) -> None:
        self._auto_notice.setText(
            f"\u23f3 If no action is taken, this alert will be auto-forwarded to "
            f"{self._target_dept} in {self._remaining} seconds."
        )

    def _tick(self) -> None:
        self._remaining -= 1
        if self._remaining < 0:
            self._remaining = 0
        self._update_countdown_text()

    def _get_db(self):
        from sentinelx.database.db_manager import DatabaseManager
        return DatabaseManager()

    def _show_status(self, text: str, color: str = "#00e676") -> None:
        """Show status text and close after 2 seconds."""
        self._user_acted = True
        self._timer.stop()
        self._tick_timer.stop()
        self._status_label.setText(text)
        self._status_label.setStyleSheet(f"color: {color}; padding-top: 4px;")
        self._status_label.show()
        QTimer.singleShot(2000, self._dismiss)

    def _on_acknowledge(self) -> None:
        if self._alert_id:
            self._get_db().acknowledge_alert(self._alert_id)
        self._show_status("✔  Alert Acknowledged — No forwarding.")

    def _on_false_positive(self) -> None:
        if self._alert_id:
            self._get_db().mark_false_positive(self._alert_id)
        self._show_status("✘  Marked as False Positive — No forwarding.", "#ffd600")

    def _on_dismiss_clicked(self) -> None:
        """User explicitly dismissed — mark acted so no auto-forward."""
        self._user_acted = True
        self._timer.stop()
        self._tick_timer.stop()
        self._dismiss()

    def _on_forward(self) -> None:
        """Show department picker, then forward."""
        self._timer.stop()
        self._tick_timer.stop()

        dialog = QDialog(self)
        dialog.setWindowTitle("Forward Alert")
        dialog.setFixedWidth(420)
        dialog.setStyleSheet(
            "QDialog { background: #16213e; border: 1px solid #0f3460;"
            " border-radius: 12px; }"
            "QLabel { color: #e0e0e0; font-size: 13px; }"
            "QPushButton { background: #0f3460; color: #e0e0e0; border: none;"
            " border-radius: 6px; padding: 10px; font-size: 12px;"
            " font-weight: bold; }"
            "QPushButton:hover { background: #00d2ff; color: #000; }"
        )
        lay = QVBoxLayout(dialog)
        lay.setSpacing(10)
        lay.setContentsMargins(24, 20, 24, 20)

        header = QLabel("Select Department to Forward:")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(header)

        for dept in _DEPARTMENTS:
            btn = QPushButton(dept)
            btn.setFixedHeight(40)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(
                lambda checked, d=dept: self._do_forward(d, dialog)
            )
            lay.addWidget(btn)

        cancel = QPushButton("Cancel")
        cancel.setFixedHeight(36)
        cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel.setStyleSheet(
            "QPushButton { background: #2a2a4a; color: #9e9e9e; }"
            "QPushButton:hover { background: #ff1744; color: #fff; }"
        )
        cancel.clicked.connect(dialog.reject)
        lay.addWidget(cancel)

        dialog.exec()
        # Restart auto-forward timer if dialog was cancelled and user hasn't acted
        if not self._user_acted and not self._timer.isActive():
            self._timer.start(15000)

    def _do_forward(self, department: str, dialog: QDialog) -> None:
        dialog.accept()
        if self._alert_id:
            self._get_db().forward_alert(self._alert_id, department)
        self._show_status(f"📤  Forwarded to {department}", "#00b0ff")

    def _auto_forward(self) -> None:
        """Called when timeout expires and user took no action."""
        self._tick_timer.stop()
        if self._user_acted:
            return
        dept = self._target_dept
        if self._alert_id:
            self._get_db().forward_alert(self._alert_id, dept)
        # Show brief status on overlay then dismiss
        self._status_label.setText(f"📤  Auto-forwarded to {dept}")
        self._status_label.setStyleSheet("color: #00b0ff; padding-top: 4px;")
        self._status_label.show()
        # Show a small toast confirmation that persists after overlay closes
        toast = ForwardConfirmationToast(
            dept, self._alert.get("title", "Alert"), parent=None
        )
        toast.show()
        QTimer.singleShot(2500, self._dismiss)

    # ── Sound & dismiss ─────────────────────────────────────

    @staticmethod
    def _play_alert_sound() -> None:
        try:
            import winsound
            winsound.Beep(1200, 300)
            winsound.Beep(900, 300)
            winsound.Beep(1200, 400)
        except Exception:
            pass

    def mousePressEvent(self, event):
        pass

    def _dismiss(self):
        global _active_overlay
        if _active_overlay is self:
            _active_overlay = None
        self.close()
        self.deleteLater()


class LoginDialog(QDialog):
    """Login dialog with username/password fields."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SentinelX – Login")
        self.setFixedSize(380, 260)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_dark']};
            }}
            QLabel {{
                color: {COLORS['text_primary']};
                font-size: 13px;
            }}
            QLineEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 8px;
                font-size: 13px;
            }}
            QPushButton {{
                background-color: {COLORS['accent_blue']};
                color: {COLORS['text_primary']};
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 13px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #1a4a80;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(30, 20, 30, 20)

        # Logo / title
        title = QLabel("SentinelX")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 24px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel("Defensive Cybersecurity Suite")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        layout.addWidget(subtitle)

        layout.addSpacing(10)

        self._username = QLineEdit()
        self._username.setPlaceholderText("Username")
        layout.addWidget(self._username)

        self._password = QLineEdit()
        self._password.setPlaceholderText("Password")
        self._password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self._password)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet(f"color: #ff1744; font-size: 11px;")
        self._error_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._error_label)

        btn_login = QPushButton("Sign In")
        btn_login.clicked.connect(self._attempt_login)
        layout.addWidget(btn_login)

        self._password.returnPressed.connect(self._attempt_login)
        self._username.returnPressed.connect(lambda: self._password.setFocus())

        self.authenticated = False
        self._username.setFocus()

    def _attempt_login(self) -> None:
        username = self._username.text().strip()
        password = self._password.text()

        if not username or not password:
            self._error_label.setText("Please enter username and password.")
            return

        auth = AuthManager()
        success, message = auth.authenticate(username, password)

        if success:
            self.authenticated = True
            self.accept()
        else:
            self._error_label.setText(message)
            self._password.clear()
            self._password.setFocus()


class SidebarButton(QPushButton):
    """A styled navigation button for the sidebar."""

    def __init__(self, text: str, icon_char: str = "", parent=None):
        super().__init__(parent)
        display = f"  {icon_char}  {text}" if icon_char else f"  {text}"
        self.setText(display)
        self.setFixedHeight(44)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(True)
        self._update_style(False)

    def _update_style(self, active: bool) -> None:
        bg = COLORS["sidebar_active"] if active else "transparent"
        border_left = f"3px solid {COLORS['accent_cyan']}" if active else "3px solid transparent"
        text_color = COLORS["accent_cyan"] if active else COLORS["text_secondary"]

        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {text_color};
                border: none;
                border-left: {border_left};
                text-align: left;
                padding-left: 12px;
                font-size: 13px;
                font-weight: {'bold' if active else 'normal'};
            }}
            QPushButton:hover {{
                background-color: {COLORS['sidebar_hover']};
            }}
        """)

    def setChecked(self, checked: bool) -> None:
        super().setChecked(checked)
        self._update_style(checked)


class MainWindow(QMainWindow):
    """Main application window with sidebar navigation."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentinelX – Defensive Cybersecurity Suite")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)

        self._setup_ui()
        self._setup_tray()

        # Navigate to dashboard
        self._navigate(0)

        # DB-polling for new critical alerts (catches external engines too)
        from sentinelx.database.db_manager import DatabaseManager
        self._poll_db = DatabaseManager()
        self._last_seen_alert_id = self._poll_db.get_max_alert_id()
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_for_new_alerts)
        self._poll_timer.start(2000)  # every 2 seconds

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        central.setStyleSheet(f"background-color: {COLORS['bg_dark']};")

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # === Sidebar ===
        sidebar = QFrame()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_sidebar']};
                border-right: 1px solid {COLORS['border']};
            }}
        """)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(2)

        # Brand
        brand_frame = QFrame()
        brand_frame.setFixedHeight(60)
        brand_frame.setStyleSheet(f"border: none; border-bottom: 1px solid {COLORS['border']};")
        brand_layout = QHBoxLayout(brand_frame)
        brand_label = QLabel("🛡️ SentinelX")
        brand_label.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 18px; font-weight: bold; border: none;")
        brand_layout.addWidget(brand_label)
        sidebar_layout.addWidget(brand_frame)

        sidebar_layout.addSpacing(12)

        # Nav buttons
        self._nav_buttons: list[SidebarButton] = []
        nav_items = [
            ("Dashboard", "📊"),
            ("Alerts", "🚨"),
            ("SOC Alerts", "🔔"),
            ("Threat Explorer", "🔍"),
            ("IP Analytics", "🌐"),
            ("Reports", "📄"),
            ("Settings", "⚙️"),
        ]

        for i, (label, icon) in enumerate(nav_items):
            btn = SidebarButton(label, icon)
            btn.clicked.connect(lambda checked, idx=i: self._navigate(idx))
            sidebar_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # User info at bottom
        auth = AuthManager()
        user_frame = QFrame()
        user_frame.setFixedHeight(50)
        user_frame.setStyleSheet(f"border: none; border-top: 1px solid {COLORS['border']};")
        user_layout = QHBoxLayout(user_frame)
        user_label = QLabel(f"👤 {auth.current_user or 'Unknown'} ({auth.current_role or ''})")
        user_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; border: none;")
        user_layout.addWidget(user_label)

        btn_logout = QPushButton("Logout")
        btn_logout.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {COLORS['text_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 10px;
            }}
            QPushButton:hover {{ color: #ff1744; border-color: #ff1744; }}
        """)
        btn_logout.clicked.connect(self._logout)
        user_layout.addWidget(btn_logout)
        sidebar_layout.addWidget(user_frame)

        main_layout.addWidget(sidebar)

        # === Content Area ===
        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"background-color: {COLORS['bg_dark']};")

        self._dashboard = DashboardView()
        self._alerts = AlertsView()
        self._soc_alerts = SOCAlertsView()
        self._threat_explorer = ThreatExplorerView()
        self._ip_analytics = IPAnalyticsView()
        self._reports = ReportsView()
        self._settings = SettingsView()

        self._stack.addWidget(self._dashboard)
        self._stack.addWidget(self._alerts)
        self._stack.addWidget(self._soc_alerts)
        self._stack.addWidget(self._threat_explorer)
        self._stack.addWidget(self._ip_analytics)
        self._stack.addWidget(self._reports)
        self._stack.addWidget(self._settings)

        # Wire up alerts -> threat explorer
        self._alerts.alert_selected.connect(self._show_threat_detail)
        # Wire up threat explorer -> alerts (refresh after acknowledge/false positive)
        self._threat_explorer.alert_updated.connect(self._alerts.refresh_alerts)
        self._threat_explorer.alert_updated.connect(self._soc_alerts.refresh_alerts)

        main_layout.addWidget(self._stack)

    def _navigate(self, index: int) -> None:
        """Navigate to a page by index."""
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        self._stack.setCurrentIndex(index)

    @Slot(dict)
    def _show_threat_detail(self, alert: dict) -> None:
        """Show threat explorer for a selected alert."""
        self._threat_explorer.show_alert(alert)
        self._navigate(3)

    def show_reports(self) -> None:
        """Navigate to the Reports tab."""
        self._navigate(5)

    def _logout(self) -> None:
        auth = AuthManager()
        auth.logout()
        QMessageBox.information(self, "Logged Out", "You have been logged out.")
        QApplication.quit()

    def _setup_tray(self) -> None:
        """Set up system tray icon."""
        self._tray = QSystemTrayIcon(self)
        self._tray.setToolTip("SentinelX – Running")

        tray_menu = QMenu()
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        tray_menu.addAction(quit_action)

        self._tray.setContextMenu(tray_menu)
        # Tray icon will be set if icon file exists, otherwise skip
        try:
            self._tray.show()
        except Exception:
            pass

    def closeEvent(self, event) -> None:
        """Minimize to tray instead of closing."""
        if self._tray.isVisible():
            self.hide()
            self._tray.showMessage(
                "SentinelX",
                "Running in background. Right-click tray icon to quit.",
                QSystemTrayIcon.Information,
                2000,
            )
            event.ignore()
        else:
            event.accept()

    def on_new_alert(self, alert_dict: dict) -> None:
        """Handle new alert from engine (called from main thread via signal)."""
        self._dashboard.on_new_alert(alert_dict)
        severity = alert_dict.get("severity", "")
        title = alert_dict.get("title", "Unknown threat detected")

        # Full-screen overlay for Critical, High, and suspicious IP alerts
        suspicious_kw = ("suspicious", "port scan", "arp spoof")
        if severity in ("Critical", "High") or any(kw in title.lower() for kw in suspicious_kw):
            self._show_fullscreen_warning(alert_dict)

        # Also refresh SOC alerts for DoS/flood
        dos_keywords = ("dos", "flood", "ddos")
        if severity == "Critical" and any(kw in title.lower() for kw in dos_keywords):
            self._soc_alerts.on_new_dos_alert(alert_dict)

    def _show_fullscreen_warning(self, alert_dict: dict) -> None:
        """Show a full-screen overlay warning (one at a time, with cooldown)."""
        global _active_overlay, _overlay_last_shown
        now = time.time()
        # Skip if an overlay is already visible or cooldown hasn't elapsed
        if _active_overlay is not None or (now - _overlay_last_shown) < _OVERLAY_COOLDOWN:
            return
        _overlay_last_shown = now
        overlay = FullScreenAlertOverlay(alert_dict)
        _active_overlay = overlay
        overlay.showFullScreen()
        overlay.raise_()
        overlay.activateWindow()

    def _poll_for_new_alerts(self) -> None:
        """Poll DB for new Critical/High alerts and show overlay."""
        try:
            new_alerts = self._poll_db.get_new_critical_alerts(self._last_seen_alert_id)
            if not new_alerts:
                return
            logger.info("DB poll found %d new alert(s), watermark was %d",
                        len(new_alerts), self._last_seen_alert_id)
            # Update watermark to the latest id
            self._last_seen_alert_id = max(a["id"] for a in new_alerts)
            # Show overlay for the first (most urgent) new alert
            self._show_fullscreen_warning(new_alerts[0])
        except Exception as exc:
            logger.error("DB poll error: %s", exc)

    def _show_soc_notification(self, alert_dict: dict) -> None:
        """Show a persistent SOC notification dialog for critical DoS/flood attacks."""
        title = alert_dict.get("title", "Critical Threat")
        source = alert_dict.get("source", "Unknown")
        destination = alert_dict.get("destination", "Unknown")
        score = alert_dict.get("risk_score", "N/A")
        desc = alert_dict.get("description", "")

        msg = QMessageBox(self)
        msg.setWindowTitle("\U0001f6a8 SOC ALERT \u2013 Immediate Action Required")
        msg.setIcon(QMessageBox.Critical)
        msg.setText(
            f"<b style='color:#ff1744;font-size:14px;'>\U0001f6a8 {title}</b>"
        )
        msg.setInformativeText(
            f"<b>Source IP:</b> {source}<br>"
            f"<b>Target IP:</b> {destination}<br>"
            f"<b>Risk Score:</b> {score}<br><br>"
            f"<b>Details:</b> {desc[:200]}<br><br>"
            f"<i>This alert requires immediate SOC investigation.<br>"
            f"The attacker may be disrupting service availability.</i>"
        )
        msg.setStandardButtons(QMessageBox.Ok)
        msg.button(QMessageBox.Ok).setText("Acknowledged by SOC")
        msg.setWindowModality(Qt.NonModal)
        msg.setStyleSheet(f"""
            QMessageBox {{
                background-color: {COLORS['bg_dark']};
            }}
            QMessageBox QLabel {{
                color: {COLORS['text_primary']};
                font-size: 12px;
            }}
            QPushButton {{
                background-color: #ff1744;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #d50000;
            }}
        """)
        msg.show()
        msg.raise_()
        msg.activateWindow()

    def _play_alert_sound(self) -> None:
        """Play an audible alert sound for critical DoS/flood events."""
        try:
            import winsound
            # Three short urgent beeps
            for _ in range(3):
                winsound.Beep(1000, 200)
        except Exception:
            QApplication.beep()

    def _show_windows_toast(self, alert_dict: dict) -> None:
        """Show a native Windows toast notification (like battery-low) for alerts."""
        try:
            from winotify import Notification
            severity = alert_dict.get("severity", "Alert")
            title = alert_dict.get("title", "Threat Detected")
            source = alert_dict.get("source", "Unknown")
            destination = alert_dict.get("destination", "N/A")
            score = alert_dict.get("risk_score", "N/A")

            toast = Notification(
                app_id="SentinelX IDS",
                title=f"SentinelX — {severity}: {title}",
                msg=(
                    f"Source: {source}\n"
                    f"Target: {destination}\n"
                    f"Risk Score: {score}"
                ),
                duration="long" if severity == "Critical" else "short",
            )
            if severity == "Critical":
                toast.set_audio("ms-winsoundevent:Notification.Looping.Alarm", loop=False)
            else:
                toast.set_audio("ms-winsoundevent:Notification.Default", loop=False)
            toast.show()
        except Exception as e:
            logger.error("Windows toast notification error: %s", e)
