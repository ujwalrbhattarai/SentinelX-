"""
SentinelX – Settings View
Configuration panel for modules, thresholds, directories, and IP whitelists.
"""

from typing import Any, Dict, List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QLineEdit, QSpinBox, QCheckBox,
    QListWidget, QListWidgetItem, QFileDialog, QMessageBox,
    QGroupBox, QFormLayout, QScrollArea, QSizePolicy, QTabWidget,
    QComboBox, QTextEdit,
)
from PySide6.QtCore import Qt, Signal

from sentinelx.utils.config import Config
from sentinelx.utils.logger import get_logger

logger = get_logger("settings_view")

COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_card": "#16213e",
    "accent_blue": "#0f3460",
    "accent_cyan": "#00d2ff",
    "text_primary": "#e0e0e0",
    "text_secondary": "#9e9e9e",
    "border": "#2a2a4a",
    "accent_green": "#00e676",
    "accent_red": "#ff1744",
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
    QPushButton:hover {{ background-color: #1a4a80; }}
"""

INPUT_STYLE = f"""
    QLineEdit, QSpinBox {{
        background-color: {COLORS['bg_dark']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        padding: 6px;
        font-size: 12px;
    }}
"""

GROUP_STYLE = f"""
    QGroupBox {{
        color: {COLORS['accent_cyan']};
        font-size: 13px;
        font-weight: bold;
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        margin-top: 8px;
        padding-top: 16px;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 12px;
        padding: 0 4px;
    }}
"""

CHECK_STYLE = f"""
    QCheckBox {{
        color: {COLORS['text_primary']};
        font-size: 12px;
        spacing: 6px;
    }}
    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border: 1px solid {COLORS['border']};
        border-radius: 3px;
        background-color: {COLORS['bg_dark']};
    }}
    QCheckBox::indicator:checked {{
        background-color: {COLORS['accent_cyan']};
    }}
"""

LIST_STYLE = f"""
    QListWidget {{
        background-color: {COLORS['bg_dark']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        font-size: 12px;
    }}
    QListWidget::item:selected {{
        background-color: {COLORS['accent_blue']};
    }}
"""


class SettingsView(QWidget):
    """Settings configuration panel with tabs for each module."""

    settings_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = Config()
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        header = QLabel("Settings")
        header.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 18px; font-weight: bold;")
        layout.addWidget(header)

        # Tab widget
        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                background-color: {COLORS['bg_card']};
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_secondary']};
                padding: 8px 16px;
                border: 1px solid {COLORS['border']};
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-size: 12px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['accent_cyan']};
                font-weight: bold;
            }}
        """)

        tabs.addTab(self._create_modules_tab(), "Modules")
        tabs.addTab(self._create_network_tab(), "Network")
        tabs.addTab(self._create_eventlog_tab(), "Event Log")
        tabs.addTab(self._create_fim_tab(), "File Integrity")
        tabs.addTab(self._create_process_tab(), "Process")
        tabs.addTab(self._create_general_tab(), "General")

        layout.addWidget(tabs)

        # Save / Reset buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_save = QPushButton("Save Settings")
        btn_save.setStyleSheet(BTN_STYLE.replace(COLORS['accent_blue'], '#004d00'))
        btn_save.clicked.connect(self._save_settings)
        btn_layout.addWidget(btn_save)

        btn_reset = QPushButton("Reset to Defaults")
        btn_reset.setStyleSheet(BTN_STYLE.replace(COLORS['accent_blue'], '#4d0000'))
        btn_reset.clicked.connect(self._reset_settings)
        btn_layout.addWidget(btn_reset)

        layout.addLayout(btn_layout)

    def _create_modules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(8)

        group = QGroupBox("Enable / Disable Modules")
        group.setStyleSheet(GROUP_STYLE)
        form = QVBoxLayout(group)

        self._chk_network = QCheckBox("Network Monitor (packet capture & analysis)")
        self._chk_eventlog = QCheckBox("Windows Event Log Monitor")
        self._chk_fim = QCheckBox("File Integrity Monitor")
        self._chk_process = QCheckBox("Process Monitor")

        for chk in (self._chk_network, self._chk_eventlog, self._chk_fim, self._chk_process):
            chk.setStyleSheet(CHECK_STYLE)
            form.addWidget(chk)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _create_network_tab(self) -> QWidget:
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(widget)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: transparent; }}")

        layout = QVBoxLayout(widget)

        group = QGroupBox("Network Detection Thresholds")
        group.setStyleSheet(GROUP_STYLE)
        form = QFormLayout(group)
        form.setSpacing(8)

        self._spin_port_scan_threshold = QSpinBox()
        self._spin_port_scan_threshold.setRange(1, 1000)
        self._spin_port_scan_threshold.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Port Scan Threshold (ports):"), self._spin_port_scan_threshold)

        self._spin_port_scan_window = QSpinBox()
        self._spin_port_scan_window.setRange(1, 300)
        self._spin_port_scan_window.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Port Scan Window (sec):"), self._spin_port_scan_window)

        self._spin_syn_threshold = QSpinBox()
        self._spin_syn_threshold.setRange(10, 10000)
        self._spin_syn_threshold.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("SYN Flood Threshold:"), self._spin_syn_threshold)

        self._spin_dns_threshold = QSpinBox()
        self._spin_dns_threshold.setRange(5, 1000)
        self._spin_dns_threshold.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("DNS Request Threshold:"), self._spin_dns_threshold)

        layout.addWidget(group)

        # Whitelist IPs
        wl_group = QGroupBox("IP Whitelist")
        wl_group.setStyleSheet(GROUP_STYLE)
        wl_layout = QVBoxLayout(wl_group)

        self._whitelist_list = QListWidget()
        self._whitelist_list.setStyleSheet(LIST_STYLE)
        self._whitelist_list.setMaximumHeight(150)
        wl_layout.addWidget(self._whitelist_list)

        ip_row = QHBoxLayout()
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("Enter IP address...")
        self._ip_input.setStyleSheet(INPUT_STYLE)
        ip_row.addWidget(self._ip_input)

        btn_add_ip = QPushButton("Add")
        btn_add_ip.setStyleSheet(BTN_STYLE)
        btn_add_ip.clicked.connect(self._add_whitelist_ip)
        ip_row.addWidget(btn_add_ip)

        btn_remove_ip = QPushButton("Remove")
        btn_remove_ip.setStyleSheet(BTN_STYLE)
        btn_remove_ip.clicked.connect(self._remove_whitelist_ip)
        ip_row.addWidget(btn_remove_ip)

        wl_layout.addLayout(ip_row)
        layout.addWidget(wl_group)
        layout.addStretch()

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.addWidget(scroll)
        return container

    def _create_eventlog_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox("Event Log Settings")
        group.setStyleSheet(GROUP_STYLE)
        form = QFormLayout(group)

        self._spin_login_threshold = QSpinBox()
        self._spin_login_threshold.setRange(1, 100)
        self._spin_login_threshold.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Failed Login Threshold:"), self._spin_login_threshold)

        self._spin_login_window = QSpinBox()
        self._spin_login_window.setRange(10, 600)
        self._spin_login_window.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Failed Login Window (sec):"), self._spin_login_window)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _create_fim_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Monitored directories
        dir_group = QGroupBox("Monitored Directories")
        dir_group.setStyleSheet(GROUP_STYLE)
        dir_layout = QVBoxLayout(dir_group)

        self._dir_list = QListWidget()
        self._dir_list.setStyleSheet(LIST_STYLE)
        self._dir_list.setMaximumHeight(150)
        dir_layout.addWidget(self._dir_list)

        dir_btn_row = QHBoxLayout()
        btn_add_dir = QPushButton("Add Directory")
        btn_add_dir.setStyleSheet(BTN_STYLE)
        btn_add_dir.clicked.connect(self._add_directory)
        dir_btn_row.addWidget(btn_add_dir)

        btn_remove_dir = QPushButton("Remove")
        btn_remove_dir.setStyleSheet(BTN_STYLE)
        btn_remove_dir.clicked.connect(self._remove_directory)
        dir_btn_row.addWidget(btn_remove_dir)

        dir_btn_row.addStretch()
        dir_layout.addLayout(dir_btn_row)
        layout.addWidget(dir_group)

        # Ransomware thresholds
        rw_group = QGroupBox("Ransomware Detection")
        rw_group.setStyleSheet(GROUP_STYLE)
        form = QFormLayout(rw_group)

        self._spin_ransomware_threshold = QSpinBox()
        self._spin_ransomware_threshold.setRange(5, 1000)
        self._spin_ransomware_threshold.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("File Change Threshold:"), self._spin_ransomware_threshold)

        self._spin_ransomware_window = QSpinBox()
        self._spin_ransomware_window.setRange(5, 300)
        self._spin_ransomware_window.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Time Window (sec):"), self._spin_ransomware_window)

        layout.addWidget(rw_group)
        layout.addStretch()
        return widget

    def _create_process_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox("Process Monitor Settings")
        group.setStyleSheet(GROUP_STYLE)
        form = QFormLayout(group)

        self._spin_cpu_threshold = QSpinBox()
        self._spin_cpu_threshold.setRange(10, 100)
        self._spin_cpu_threshold.setSuffix("%")
        self._spin_cpu_threshold.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("CPU Alert Threshold:"), self._spin_cpu_threshold)

        self._spin_cpu_sustained = QSpinBox()
        self._spin_cpu_sustained.setRange(5, 300)
        self._spin_cpu_sustained.setSuffix(" sec")
        self._spin_cpu_sustained.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Sustained Duration:"), self._spin_cpu_sustained)

        layout.addWidget(group)
        layout.addStretch()
        return widget

    def _create_general_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox("Application Settings")
        group.setStyleSheet(GROUP_STYLE)
        form = QFormLayout(group)

        self._combo_theme = QComboBox()
        self._combo_theme.addItems(["dark", "light"])
        self._combo_theme.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px;
            }}
        """)
        form.addRow(self._styled_label("Theme:"), self._combo_theme)

        self._spin_refresh = QSpinBox()
        self._spin_refresh.setRange(500, 30000)
        self._spin_refresh.setSuffix(" ms")
        self._spin_refresh.setStyleSheet(INPUT_STYLE)
        form.addRow(self._styled_label("Dashboard Refresh:"), self._spin_refresh)

        self._chk_autostart = QCheckBox("Auto-start on Windows boot")
        self._chk_autostart.setStyleSheet(CHECK_STYLE)
        form.addRow(self._chk_autostart)

        layout.addWidget(group)

        # License info
        lic_group = QGroupBox("License")
        lic_group.setStyleSheet(GROUP_STYLE)
        lic_form = QFormLayout(lic_group)

        self._lbl_edition = QLabel("Free")
        self._lbl_edition.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 13px; font-weight: bold;")
        lic_form.addRow(self._styled_label("Edition:"), self._lbl_edition)

        self._license_input = QLineEdit()
        self._license_input.setPlaceholderText("Enter license key...")
        self._license_input.setStyleSheet(INPUT_STYLE)
        lic_form.addRow(self._styled_label("License Key:"), self._license_input)

        btn_activate = QPushButton("Activate License")
        btn_activate.setStyleSheet(BTN_STYLE)
        btn_activate.clicked.connect(self._activate_license)
        lic_form.addRow(btn_activate)

        layout.addWidget(lic_group)
        layout.addStretch()
        return widget

    def _styled_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 12px;")
        return lbl

    def _load_settings(self) -> None:
        """Load current settings into UI controls."""
        cfg = self.config

        # Modules
        self._chk_network.setChecked(cfg.get("modules.network_monitor", True))
        self._chk_eventlog.setChecked(cfg.get("modules.event_log_monitor", True))
        self._chk_fim.setChecked(cfg.get("modules.file_integrity_monitor", True))
        self._chk_process.setChecked(cfg.get("modules.process_monitor", True))

        # Network
        self._spin_port_scan_threshold.setValue(cfg.get("network.port_scan_threshold", 10))
        self._spin_port_scan_window.setValue(cfg.get("network.port_scan_window", 10))
        self._spin_syn_threshold.setValue(cfg.get("network.syn_flood_threshold", 100))
        self._spin_dns_threshold.setValue(cfg.get("network.dns_request_threshold", 50))

        self._whitelist_list.clear()
        for ip in cfg.get("network.whitelist_ips", []):
            self._whitelist_list.addItem(ip)

        # Event log
        self._spin_login_threshold.setValue(cfg.get("event_log.failed_login_threshold", 5))
        self._spin_login_window.setValue(cfg.get("event_log.failed_login_window", 60))

        # FIM
        self._dir_list.clear()
        for d in cfg.get("file_integrity.monitored_directories", []):
            self._dir_list.addItem(d)
        self._spin_ransomware_threshold.setValue(cfg.get("file_integrity.ransomware_threshold", 50))
        self._spin_ransomware_window.setValue(cfg.get("file_integrity.ransomware_window", 30))

        # Process
        self._spin_cpu_threshold.setValue(cfg.get("process_monitor.cpu_threshold", 80))
        self._spin_cpu_sustained.setValue(cfg.get("process_monitor.cpu_sustained_seconds", 30))

        # General
        self._combo_theme.setCurrentText(cfg.get("gui.theme", "dark"))
        self._spin_refresh.setValue(cfg.get("gui.refresh_interval_ms", 2000))
        self._chk_autostart.setChecked(cfg.get("auto_start", False))

        # License
        edition = cfg.get("licensing.edition", "free")
        self._lbl_edition.setText(edition.capitalize())
        self._license_input.setText(cfg.get("licensing.license_key", ""))

    def _save_settings(self) -> None:
        cfg = self.config

        cfg.set("modules.network_monitor", self._chk_network.isChecked())
        cfg.set("modules.event_log_monitor", self._chk_eventlog.isChecked())
        cfg.set("modules.file_integrity_monitor", self._chk_fim.isChecked())
        cfg.set("modules.process_monitor", self._chk_process.isChecked())

        cfg.set("network.port_scan_threshold", self._spin_port_scan_threshold.value())
        cfg.set("network.port_scan_window", self._spin_port_scan_window.value())
        cfg.set("network.syn_flood_threshold", self._spin_syn_threshold.value())
        cfg.set("network.dns_request_threshold", self._spin_dns_threshold.value())

        ips = [self._whitelist_list.item(i).text() for i in range(self._whitelist_list.count())]
        cfg.set("network.whitelist_ips", ips)

        cfg.set("event_log.failed_login_threshold", self._spin_login_threshold.value())
        cfg.set("event_log.failed_login_window", self._spin_login_window.value())

        dirs = [self._dir_list.item(i).text() for i in range(self._dir_list.count())]
        cfg.set("file_integrity.monitored_directories", dirs)
        cfg.set("file_integrity.ransomware_threshold", self._spin_ransomware_threshold.value())
        cfg.set("file_integrity.ransomware_window", self._spin_ransomware_window.value())

        cfg.set("process_monitor.cpu_threshold", self._spin_cpu_threshold.value())
        cfg.set("process_monitor.cpu_sustained_seconds", self._spin_cpu_sustained.value())

        cfg.set("gui.theme", self._combo_theme.currentText())
        cfg.set("gui.refresh_interval_ms", self._spin_refresh.value())
        cfg.set("auto_start", self._chk_autostart.isChecked())

        self.settings_changed.emit()
        QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
        logger.info("Settings saved")

    def _reset_settings(self) -> None:
        reply = QMessageBox.question(
            self, "Reset Settings", "Reset all settings to defaults?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.config.reset()
            self._load_settings()
            QMessageBox.information(self, "Reset", "Settings reset to defaults.")

    def _add_whitelist_ip(self) -> None:
        ip = self._ip_input.text().strip()
        if ip:
            self._whitelist_list.addItem(ip)
            self._ip_input.clear()

    def _remove_whitelist_ip(self) -> None:
        item = self._whitelist_list.currentItem()
        if item:
            self._whitelist_list.takeItem(self._whitelist_list.row(item))

    def _add_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Monitor")
        if path:
            self._dir_list.addItem(path)

    def _remove_directory(self) -> None:
        item = self._dir_list.currentItem()
        if item:
            self._dir_list.takeItem(self._dir_list.row(item))

    def _activate_license(self) -> None:
        key = self._license_input.text().strip()
        if not key:
            QMessageBox.warning(self, "License", "Please enter a license key.")
            return
        # Basic validation (in production, validate against a server)
        if len(key) >= 16 and "-" in key:
            self.config.set("licensing.edition", "pro")
            self.config.set("licensing.license_key", key)
            self._lbl_edition.setText("Pro")
            QMessageBox.information(self, "License Activated", "Pro license activated!")
        else:
            QMessageBox.warning(self, "Invalid Key", "The license key format is invalid.")
