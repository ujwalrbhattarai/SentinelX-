"""
SentinelX – Reports View
GUI panel for generating PDF/CSV reports during a selectable period.
"""

import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QProgressBar, QSizePolicy, QDateEdit,
    QGroupBox, QGridLayout, QAbstractItemView, QTimeEdit,
)
from PySide6.QtCore import Qt, QThread, Signal, QDate, QTime

from sentinelx.utils.config import REPORT_DIR
from sentinelx.utils.logger import get_logger

logger = get_logger("reports_view")

# ── Theme (consistent with main_window) ──────────────────
COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_card": "#16213e",
    "accent_blue": "#0f3460",
    "accent_cyan": "#00d2ff",
    "accent_green": "#00e676",
    "text_primary": "#e0e0e0",
    "text_secondary": "#9e9e9e",
    "border": "#2a2a4a",
}


class _ReportWorker(QThread):
    """Background thread for report generation."""

    finished = Signal(str)   # filepath or empty string on failure
    error = Signal(str)

    def __init__(self, report_type: str, date: datetime = None,
                 start_dt: datetime = None, end_dt: datetime = None,
                 start_hour: int = 0, start_minute: int = 0,
                 end_hour: int = 23, end_minute: int = 59):
        super().__init__()
        self.report_type = report_type
        self.date = date
        self.start_dt = start_dt
        self.end_dt = end_dt
        self.start_hour = start_hour
        self.start_minute = start_minute
        self.end_hour = end_hour
        self.end_minute = end_minute

    def run(self) -> None:
        try:
            from sentinelx.reporting.report_generator import ReportGenerator
            gen = ReportGenerator()

            if self.report_type == "daily":
                path = gen.generate_daily_report(self.date)
            elif self.report_type == "weekly":
                path = gen.generate_weekly_report(self.date)
            elif self.report_type == "time_range":
                # Use new API: pass start_dt and end_dt if provided
                if self.start_dt and self.end_dt:
                    path = gen.generate_time_range_report(self.start_dt, self.end_dt)
                else:
                    # fallback for legacy usage
                    path = gen.generate_time_range_report_legacy(
                        self.date,
                        self.start_hour, self.start_minute,
                        self.end_hour, self.end_minute,
                    )
            else:
                path = None

            self.finished.emit(path or "")
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)
            self.error.emit(str(exc))


class _ExportWorker(QThread):
    """Background thread for CSV export."""

    finished = Signal(str, int)   # filepath, row count
    error = Signal(str)

    def __init__(self, export_type: str, filepath: str, start_dt: datetime, end_dt: datetime):
        super().__init__()
        self.export_type = export_type
        self.filepath = filepath
        self.start_dt = start_dt
        self.end_dt = end_dt

    def run(self) -> None:
        try:
            from sentinelx.reporting.report_generator import ReportGenerator
            gen = ReportGenerator()

            if self.export_type == "alerts":
                count = gen.export_alerts_csv(self.filepath, since=self.start_dt, until=self.end_dt)
            elif self.export_type == "timeline":
                count = gen.export_timeline_csv(self.filepath, since=self.start_dt, until=self.end_dt)
            else:
                count = 0

            self.finished.emit(self.filepath, count)
        except Exception as exc:
            logger.error("Export failed: %s", exc)
            self.error.emit(str(exc))


class ReportsView(QWidget):
    """Reports generation and history panel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[_ReportWorker] = None
        self._export_worker: Optional[_ExportWorker] = None
        self._setup_ui()
        self._refresh_history()

    # ── UI Setup ──────────────────────────────────────────

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(16)

        # Header
        header = QLabel("Reports")
        header.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: 22px; font-weight: bold;"
        )
        layout.addWidget(header)

        # ── Generate Section ──
        gen_group = QGroupBox("Generate Report")
        gen_group.setStyleSheet(f"""
            QGroupBox {{
                color: {COLORS['text_primary']};
                font-size: 14px;
                font-weight: bold;
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                margin-top: 10px;
                padding: 16px 12px 12px 12px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 6px;
            }}
        """)
        gen_layout = QGridLayout(gen_group)

        # Report type combo
        lbl_type = QLabel("Report Type:")
        lbl_type.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        gen_layout.addWidget(lbl_type, 0, 0)

        self._combo_type = QComboBox()
        self._combo_type.addItems(["Daily Summary", "Weekly Summary", "Time Range"])
        self._combo_type.setStyleSheet(self._combo_style())
        self._combo_type.currentIndexChanged.connect(self._on_report_type_changed)
        gen_layout.addWidget(self._combo_type, 0, 1)


        # Date picker for Daily/Weekly
        lbl_date = QLabel("Report Date:")
        lbl_date.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        gen_layout.addWidget(lbl_date, 1, 0)

        self._date_edit = QDateEdit()
        self._date_edit.setCalendarPopup(True)
        self._date_edit.setDate(QDate.currentDate())
        self._date_edit.setStyleSheet(f"""
            QDateEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-size: 12px;
            }}
        """)
        gen_layout.addWidget(self._date_edit, 1, 1)

        # From/To Date/Time for Time Range
        lbl_from_date = QLabel("From Date:")
        lbl_from_date.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        gen_layout.addWidget(lbl_from_date, 2, 0)
        self._from_date_edit = QDateEdit()
        self._from_date_edit.setCalendarPopup(True)
        self._from_date_edit.setDate(QDate.currentDate())
        self._from_date_edit.setStyleSheet(self._date_edit.styleSheet())
        gen_layout.addWidget(self._from_date_edit, 2, 1)
        lbl_from_time = QLabel("From Time:")
        lbl_from_time.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        gen_layout.addWidget(lbl_from_time, 2, 2)
        self._from_time = QTimeEdit()
        self._from_time.setDisplayFormat("HH:mm")
        self._from_time.setTime(QTime(0, 0))
        self._from_time.setStyleSheet(f"""
            QTimeEdit {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-size: 12px;
            }}
        """)
        gen_layout.addWidget(self._from_time, 2, 3)
        lbl_to_date = QLabel("To Date:")
        lbl_to_date.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        gen_layout.addWidget(lbl_to_date, 3, 0)
        self._to_date_edit = QDateEdit()
        self._to_date_edit.setCalendarPopup(True)
        self._to_date_edit.setDate(QDate.currentDate())
        self._to_date_edit.setStyleSheet(self._date_edit.styleSheet())
        gen_layout.addWidget(self._to_date_edit, 3, 1)
        lbl_to_time = QLabel("To Time:")
        lbl_to_time.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        gen_layout.addWidget(lbl_to_time, 3, 2)
        self._to_time = QTimeEdit()
        self._to_time.setDisplayFormat("HH:mm")
        self._to_time.setTime(QTime(23, 59))
        self._to_time.setStyleSheet(self._from_time.styleSheet())
        gen_layout.addWidget(self._to_time, 3, 3)
        # Hide from/to fields unless "Time Range" is selected
        for w in [lbl_from_date, self._from_date_edit, lbl_from_time, self._from_time,
                  lbl_to_date, self._to_date_edit, lbl_to_time, self._to_time]:
            w.setVisible(False)
        self._time_range_widgets = [lbl_from_date, self._from_date_edit, lbl_from_time, self._from_time,
                                    lbl_to_date, self._to_date_edit, lbl_to_time, self._to_time]
        self._date_widgets = [lbl_date, self._date_edit]

        # Generate button
        self._btn_generate = QPushButton("Generate PDF Report")
        self._btn_generate.setCursor(Qt.PointingHandCursor)
        self._btn_generate.setStyleSheet(self._action_btn_style())
        self._btn_generate.clicked.connect(self._generate_report)
        gen_layout.addWidget(self._btn_generate, 0, 4)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setVisible(False)
        self._progress.setFixedHeight(6)
        self._progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS['bg_card']};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['accent_cyan']};
                border-radius: 3px;
            }}
        """)
        gen_layout.addWidget(self._progress, 2, 0, 1, 5)

        layout.addWidget(gen_group)

        # ── Export Section ──
        export_group = QGroupBox("Export Data (CSV)")
        export_group.setStyleSheet(gen_group.styleSheet())
        export_layout = QGridLayout(export_group)

        # From/To Date/Time pickers for CSV export
        lbl_csv_from_date = QLabel("From Date:")
        lbl_csv_from_date.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        export_layout.addWidget(lbl_csv_from_date, 0, 0)
        self._csv_from_date = QDateEdit()
        self._csv_from_date.setCalendarPopup(True)
        self._csv_from_date.setDate(QDate.currentDate())
        self._csv_from_date.setStyleSheet(self._date_edit.styleSheet())
        export_layout.addWidget(self._csv_from_date, 0, 1)
        lbl_csv_from_time = QLabel("From Time:")
        lbl_csv_from_time.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        export_layout.addWidget(lbl_csv_from_time, 0, 2)
        self._csv_from_time = QTimeEdit()
        self._csv_from_time.setDisplayFormat("HH:mm")
        self._csv_from_time.setTime(QTime(0, 0))
        self._csv_from_time.setStyleSheet(self._from_time.styleSheet())
        export_layout.addWidget(self._csv_from_time, 0, 3)
        lbl_csv_to_date = QLabel("To Date:")
        lbl_csv_to_date.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        export_layout.addWidget(lbl_csv_to_date, 1, 0)
        self._csv_to_date = QDateEdit()
        self._csv_to_date.setCalendarPopup(True)
        self._csv_to_date.setDate(QDate.currentDate())
        self._csv_to_date.setStyleSheet(self._date_edit.styleSheet())
        export_layout.addWidget(self._csv_to_date, 1, 1)
        lbl_csv_to_time = QLabel("To Time:")
        lbl_csv_to_time.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        export_layout.addWidget(lbl_csv_to_time, 1, 2)
        self._csv_to_time = QTimeEdit()
        self._csv_to_time.setDisplayFormat("HH:mm")
        self._csv_to_time.setTime(QTime(23, 59))
        self._csv_to_time.setStyleSheet(self._from_time.styleSheet())
        export_layout.addWidget(self._csv_to_time, 1, 3)

        btn_export_alerts = QPushButton("Export Alerts CSV")
        btn_export_alerts.setCursor(Qt.PointingHandCursor)
        btn_export_alerts.setStyleSheet(self._secondary_btn_style())
        btn_export_alerts.clicked.connect(lambda: self._export_csv("alerts"))
        export_layout.addWidget(btn_export_alerts, 2, 0, 1, 2)

        btn_export_timeline = QPushButton("Export Timeline CSV")
        btn_export_timeline.setCursor(Qt.PointingHandCursor)
        btn_export_timeline.setStyleSheet(self._secondary_btn_style())
        btn_export_timeline.clicked.connect(lambda: self._export_csv("timeline"))
        export_layout.addWidget(btn_export_timeline, 2, 2, 1, 2)

        layout.addWidget(export_group)

        # ── Report History ──
        hist_label = QLabel("Report History")
        hist_label.setStyleSheet(
            f"color: {COLORS['text_primary']}; font-size: 16px; font-weight: bold;"
        )
        layout.addWidget(hist_label)

        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Filename", "Type", "Generated", "Size"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet(self._table_style())
        self._table.doubleClicked.connect(self._open_report)
        layout.addWidget(self._table, 1)

        # Bottom bar
        bottom = QHBoxLayout()
        btn_open_dir = QPushButton("Open Reports Folder")
        btn_open_dir.setCursor(Qt.PointingHandCursor)
        btn_open_dir.setStyleSheet(self._secondary_btn_style())
        btn_open_dir.clicked.connect(self._open_reports_dir)
        bottom.addWidget(btn_open_dir)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setCursor(Qt.PointingHandCursor)
        btn_refresh.setStyleSheet(self._secondary_btn_style())
        btn_refresh.clicked.connect(self._refresh_history)
        bottom.addWidget(btn_refresh)

        bottom.addStretch()
        layout.addLayout(bottom)

    # ── Actions ───────────────────────────────────────────

    def _on_report_type_changed(self, index: int) -> None:
        """Show/hide date or from/to date/time pickers based on report type selection."""
        is_time_range = index == 2  # "Time Range"
        for w in getattr(self, '_time_range_widgets', []):
            w.setVisible(is_time_range)
        for w in getattr(self, '_date_widgets', []):
            w.setVisible(not is_time_range)

    def _get_hours_from_period(self) -> int:
        mapping = {
            "Last 24 Hours": 24,
            "Last 7 Days": 168,
            "Last 30 Days": 720,
            "All Time": 87600,  # ~10 years
        }
        return mapping.get(self._combo_period.currentText(), 24)

    def _generate_report(self) -> None:
        idx = self._combo_type.currentIndex()
        if idx == 0:
            # Daily
            qdate = self._date_edit.date()
            date = datetime(qdate.year(), qdate.month(), qdate.day())
            report_type = "daily"
            self._btn_generate.setEnabled(False)
            self._progress.setVisible(True)
            self._worker = _ReportWorker(report_type, date)
        elif idx == 1:
            # Weekly
            qdate = self._date_edit.date()
            date = datetime(qdate.year(), qdate.month(), qdate.day())
            report_type = "weekly"
            self._btn_generate.setEnabled(False)
            self._progress.setVisible(True)
            self._worker = _ReportWorker(report_type, date)
        else:
            # Time Range
            fqdate = self._from_date_edit.date()
            fqtime = self._from_time.time()
            tqdate = self._to_date_edit.date()
            tqtime = self._to_time.time()
            start_dt = datetime(fqdate.year(), fqdate.month(), fqdate.day(), fqtime.hour(), fqtime.minute())
            end_dt = datetime(tqdate.year(), tqdate.month(), tqdate.day(), tqtime.hour(), tqtime.minute())
            if end_dt <= start_dt:
                QMessageBox.warning(self, "Invalid Time Range", "End datetime must be after start datetime.")
                return
            report_type = "time_range"
            self._btn_generate.setEnabled(False)
            self._progress.setVisible(True)
            self._worker = _ReportWorker(report_type, None, start_dt, end_dt)
        self._worker.finished.connect(self._on_report_done)
        self._worker.error.connect(self._on_report_error)
        self._worker.start()

    def _on_report_done(self, filepath: str) -> None:
        self._btn_generate.setEnabled(True)
        self._progress.setVisible(False)

        if filepath:
            self._refresh_history()
            QMessageBox.information(
                self, "Report Ready",
                f"Report generated successfully:\n{filepath}",
            )
        else:
            QMessageBox.warning(
                self, "Report Failed",
                "Report generation failed. Check that reportlab is installed.",
            )

    def _on_report_error(self, message: str) -> None:
        self._btn_generate.setEnabled(True)
        self._progress.setVisible(False)
        QMessageBox.critical(self, "Error", f"Report generation error:\n{message}")

    def _export_csv(self, export_type: str) -> None:
        # Get from/to datetimes
        fqdate = self._csv_from_date.date()
        fqtime = self._csv_from_time.time()
        tqdate = self._csv_to_date.date()
        tqtime = self._csv_to_time.time()
        start_dt = datetime(fqdate.year(), fqdate.month(), fqdate.day(), fqtime.hour(), fqtime.minute())
        end_dt = datetime(tqdate.year(), tqdate.month(), tqdate.day(), tqtime.hour(), tqtime.minute())
        if end_dt <= start_dt:
            QMessageBox.warning(self, "Invalid Time Range", "End datetime must be after start datetime.")
            return
        default_name = f"{export_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath, _ = QFileDialog.getSaveFileName(
            self, f"Export {export_type.title()} CSV",
            str(REPORT_DIR / default_name),
            "CSV Files (*.csv)",
        )
        if not filepath:
            return

        self._export_worker = _ExportWorker(export_type, filepath, start_dt, end_dt)
        self._export_worker.finished.connect(self._on_export_done)
        self._export_worker.error.connect(self._on_export_error)
        self._export_worker.start()

    def _on_export_done(self, filepath: str, count: int) -> None:
        QMessageBox.information(
            self, "Export Complete",
            f"Exported {count} rows to:\n{filepath}",
        )

    def _on_export_error(self, message: str) -> None:
        QMessageBox.critical(self, "Export Error", f"Export failed:\n{message}")

    def _refresh_history(self) -> None:
        """Scan the reports directory and populate the history table."""
        self._table.setRowCount(0)

        if not REPORT_DIR.exists():
            return

        files = sorted(REPORT_DIR.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True)
        # Exclude temp files
        files = [f for f in files if not f.name.startswith("_temp")]

        self._table.setRowCount(len(files))
        for row, fpath in enumerate(files):
            stat = fpath.stat()
            name_item = QTableWidgetItem(fpath.name)
            name_item.setData(Qt.UserRole, str(fpath))

            # Determine type
            if "timerange" in fpath.name:
                rtype = "Time Range"
            elif "daily" in fpath.name:
                rtype = "Daily"
            elif "weekly" in fpath.name:
                rtype = "Weekly"
            elif fpath.suffix == ".csv":
                rtype = "CSV Export"
            else:
                rtype = "Other"

            type_item = QTableWidgetItem(rtype)
            date_item = QTableWidgetItem(
                datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            )
            size_kb = stat.st_size / 1024
            size_item = QTableWidgetItem(f"{size_kb:.1f} KB")

            for item in (name_item, type_item, date_item, size_item):
                item.setForeground(Qt.white)

            self._table.setItem(row, 0, name_item)
            self._table.setItem(row, 1, type_item)
            self._table.setItem(row, 2, date_item)
            self._table.setItem(row, 3, size_item)

    def _open_report(self) -> None:
        """Open the selected report file with the default application."""
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        filepath = item.data(Qt.UserRole)
        if filepath and os.path.exists(filepath):
            os.startfile(filepath)

    def _open_reports_dir(self) -> None:
        """Open the reports directory in Windows Explorer."""
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(REPORT_DIR))

    # ── Styles ────────────────────────────────────────────

    def _combo_style(self) -> str:
        return f"""
            QComboBox {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 6px 10px;
                font-size: 12px;
                min-width: 140px;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                selection-background-color: {COLORS['accent_blue']};
            }}
        """

    def _action_btn_style(self) -> str:
        return f"""
            QPushButton {{
                background-color: {COLORS['accent_blue']};
                color: {COLORS['text_primary']};
                border: none;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #1a4a80;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['border']};
                color: {COLORS['text_secondary']};
            }}
        """

    def _secondary_btn_style(self) -> str:
        return f"""
            QPushButton {{
                background-color: transparent;
                color: {COLORS['accent_cyan']};
                border: 1px solid {COLORS['accent_cyan']};
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_blue']};
            }}
        """

    def _table_style(self) -> str:
        return f"""
            QTableWidget {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                gridline-color: {COLORS['border']};
                font-size: 12px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['accent_blue']};
                color: {COLORS['text_primary']};
                padding: 6px;
                border: none;
                font-weight: bold;
                font-size: 12px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent_blue']};
            }}
        """
