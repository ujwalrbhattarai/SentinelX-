"""
SentinelX – IP Analytics View
Live interactive graphs showing IP request counts, suspicious IPs, severity breakdowns.
Uses embedded matplotlib canvases for real-time chart updates.
"""

from datetime import datetime
from typing import Any, Dict, List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QPushButton, QScrollArea, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor

try:
    import matplotlib
    matplotlib.use("QtAgg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False

from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.logger import get_logger

logger = get_logger("ip_analytics")

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

SEV_COLORS_MPL = {
    "Critical": "#ff1744",
    "High": "#ff9800",
    "Medium": "#ffc107",
    "Low": "#00e676",
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

COMBO_STYLE = f"""
    QComboBox {{
        background-color: {COLORS['bg_card']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 12px;
        min-width: 120px;
    }}
    QComboBox::drop-down {{ border: none; }}
    QComboBox QAbstractItemView {{
        background-color: {COLORS['bg_card']};
        color: {COLORS['text_primary']};
        selection-background-color: {COLORS['accent_blue']};
    }}
"""


def _card_style() -> str:
    return f"""
        QFrame {{
            background-color: {COLORS['bg_card']};
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


class LiveChart(QFrame):
    """A QFrame housing a live matplotlib FigureCanvas."""

    def __init__(self, title_text: str, figsize=(6, 3.2), parent=None):
        super().__init__(parent)
        self.setStyleSheet(_card_style())
        self.setMinimumHeight(320)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        lbl = QLabel(title_text)
        lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold;")
        layout.addWidget(lbl)

        if MATPLOTLIB_OK:
            self.figure = Figure(figsize=figsize, dpi=100,
                                 facecolor=COLORS["bg_card"])
            self.canvas = FigureCanvas(self.figure)
            self.canvas.setStyleSheet("background: transparent; border: none;")
            self.canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            layout.addWidget(self.canvas, stretch=1)
        else:
            self.figure = None
            self.canvas = None
            fallback = QLabel("matplotlib not available")
            fallback.setAlignment(Qt.AlignCenter)
            fallback.setStyleSheet(f"color: {COLORS['text_secondary']};")
            layout.addWidget(fallback, stretch=1)

    def clear(self):
        if self.figure:
            self.figure.clear()

    def draw(self):
        if self.canvas:
            self.canvas.draw_idle()

    def add_subplot(self, *args, **kwargs):
        if self.figure:
            return self.figure.add_subplot(*args, **kwargs)
        return None


class IPAnalyticsView(QWidget):
    """Full-page IP analytics with live graphs and tables."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = DatabaseManager()
        self._analytics: Dict[str, Any] = {}
        self._setup_ui()

        # Auto-refresh every 30 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(30_000)

        self.refresh()

    # ── UI setup ──

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Header row
        header_row = QHBoxLayout()
        title = QLabel("IP Analytics")
        title.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 18px; font-weight: bold;")
        header_row.addWidget(title)
        header_row.addStretch()

        range_label = QLabel("Time Range:")
        range_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        header_row.addWidget(range_label)

        self._range_combo = QComboBox()
        self._range_combo.addItems(["Last 1 Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days"])
        self._range_combo.setCurrentIndex(2)
        self._range_combo.setStyleSheet(COMBO_STYLE)
        self._range_combo.currentIndexChanged.connect(self.refresh)
        header_row.addWidget(self._range_combo)

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setStyleSheet(BTN_STYLE)
        btn_refresh.clicked.connect(self.refresh)
        header_row.addWidget(btn_refresh)

        root.addLayout(header_row)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")

        content = QWidget()
        self._content_layout = QVBoxLayout(content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(10)

        # ── Row 1: Summary cards ──
        summary_row = QHBoxLayout()
        self._card_total_ips = self._make_stat_card("Total Unique IPs", "0")
        self._card_suspicious = self._make_stat_card("Suspicious IPs", "0")
        self._card_critical_ips = self._make_stat_card("Critical-Severity IPs", "0")
        self._card_top_offender = self._make_stat_card("Top Offender", "—")
        summary_row.addWidget(self._card_total_ips)
        summary_row.addWidget(self._card_suspicious)
        summary_row.addWidget(self._card_critical_ips)
        summary_row.addWidget(self._card_top_offender)
        self._content_layout.addLayout(summary_row)

        # ── Row 2: Bar chart + Pie chart side by side ──
        charts_row = QHBoxLayout()
        self._bar_chart = LiveChart("Requests per IP (Top 15)", figsize=(8, 4.5))
        self._pie_chart = LiveChart("Severity Distribution by IP", figsize=(5, 4))
        charts_row.addWidget(self._bar_chart, stretch=3)
        charts_row.addWidget(self._pie_chart, stretch=2)
        self._content_layout.addLayout(charts_row)

        # ── Row 3: Destination IPs bar chart ──
        self._dest_chart = LiveChart("Top Targeted Destination IPs", figsize=(10, 3.5))
        self._content_layout.addWidget(self._dest_chart)

        # ── Row 4: IP detail table ──
        table_frame = QFrame()
        table_frame.setStyleSheet(_card_style())
        table_frame.setMinimumHeight(280)
        table_layout = QVBoxLayout(table_frame)
        table_title = QLabel("IP Detailed Breakdown")
        table_title.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; font-weight: bold;")
        table_layout.addWidget(table_title)

        self._ip_table = QTableWidget()
        self._ip_table.setColumnCount(8)
        self._ip_table.setHorizontalHeaderLabels([
            "IP Address", "Total Alerts", "Critical", "High", "Medium", "Low",
            "Max Risk Score", "Alert Types",
        ])
        self._ip_table.horizontalHeader().setStretchLastSection(True)
        self._ip_table.horizontalHeader().resizeSection(0, 150)
        self._ip_table.verticalHeader().setVisible(False)
        self._ip_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._ip_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                gridline-color: {COLORS['border']};
                font-size: 12px;
            }}
            QTableWidget::item {{ padding: 4px 6px; }}
            QHeaderView::section {{
                background-color: {COLORS['bg_card']};
                color: {COLORS['accent_cyan']};
                padding: 6px;
                border: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
        table_layout.addWidget(self._ip_table, stretch=1)
        self._content_layout.addWidget(table_frame)
        self._content_layout.addStretch()

        scroll.setWidget(content)
        root.addWidget(scroll, stretch=1)

    # ── Helpers ──

    def _make_stat_card(self, label: str, value: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(_card_style())
        card.setMinimumHeight(80)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)

        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        layout.addWidget(lbl)

        val = QLabel(value)
        val.setObjectName("card_value")
        val.setStyleSheet(f"color: {COLORS['accent_cyan']}; font-size: 22px; font-weight: bold;")
        layout.addWidget(val)

        return card

    def _update_card(self, card: QFrame, value: str) -> None:
        val_label = card.findChild(QLabel, "card_value")
        if val_label:
            val_label.setText(value)

    def _get_hours(self) -> int:
        idx = self._range_combo.currentIndex()
        return [1, 6, 24, 168][idx]

    # ── Data refresh ──

    def refresh(self) -> None:
        hours = self._get_hours()
        try:
            self._analytics = self.db.get_ip_analytics(hours=hours)
        except Exception as e:
            logger.error("Failed to load IP analytics: %s", e)
            return

        self._update_summary()
        if MATPLOTLIB_OK:
            self._update_bar_chart()
            self._update_pie_chart()
            self._update_dest_chart()
        self._update_table()

    def _update_summary(self) -> None:
        sources = self._analytics.get("top_sources", [])
        sev_map = self._analytics.get("severity_map", {})

        total_ips = len(sources)
        suspicious = sum(1 for ip in sev_map if sev_map[ip].get("Critical", 0) + sev_map[ip].get("High", 0) > 0)
        critical_ips = sum(1 for ip in sev_map if sev_map[ip].get("Critical", 0) > 0)
        top = sources[0]["ip"] if sources else "—"

        self._update_card(self._card_total_ips, str(total_ips))
        self._update_card(self._card_suspicious, str(suspicious))
        self._update_card(self._card_critical_ips, str(critical_ips))
        self._update_card(self._card_top_offender, str(top))

    # ── Live Charts ──

    def _update_bar_chart(self) -> None:
        self._bar_chart.clear()
        sources = self._analytics.get("top_sources", [])[:15]
        if not sources:
            ax = self._bar_chart.add_subplot(111)
            ax.set_facecolor(COLORS["bg_dark"])
            ax.text(0.5, 0.5, "No IP data available", transform=ax.transAxes,
                    ha="center", va="center", color=COLORS["text_secondary"], fontsize=11)
            ax.set_xticks([])
            ax.set_yticks([])
            self._bar_chart.draw()
            return

        sev_map = self._analytics.get("severity_map", {})
        ips = [s["ip"] for s in sources]
        crits = [sev_map.get(ip, {}).get("Critical", 0) for ip in ips]
        highs = [sev_map.get(ip, {}).get("High", 0) for ip in ips]
        meds = [sev_map.get(ip, {}).get("Medium", 0) for ip in ips]
        lows = [sev_map.get(ip, {}).get("Low", 0) for ip in ips]

        ax = self._bar_chart.add_subplot(111)
        ax.set_facecolor(COLORS["bg_dark"])

        y = range(len(ips))
        bar_h = 0.55

        left = [0] * len(ips)
        for data, color, label in [
            (crits, SEV_COLORS_MPL["Critical"], "Critical"),
            (highs, SEV_COLORS_MPL["High"], "High"),
            (meds, SEV_COLORS_MPL["Medium"], "Medium"),
            (lows, SEV_COLORS_MPL["Low"], "Low"),
        ]:
            ax.barh(y, data, height=bar_h, left=left, color=color, label=label, edgecolor="none")
            left = [l + d for l, d in zip(left, data)]

        # Value labels at end of each bar
        for i, total in enumerate(left):
            if total > 0:
                ax.text(total + 0.3, i, str(int(total)), va="center",
                        fontsize=7, color=COLORS["text_primary"])

        ax.set_yticks(list(y))
        ax.set_yticklabels(ips, fontsize=7, color=COLORS["text_primary"])
        ax.invert_yaxis()
        ax.set_xlabel("Alert Count", fontsize=8, color=COLORS["text_secondary"])
        ax.tick_params(axis="x", colors=COLORS["text_secondary"], labelsize=7)

        # Extra x margin so labels aren't clipped
        max_val = max(left) if left else 1
        ax.set_xlim(0, max_val * 1.15)

        ax.legend(fontsize=7, loc="lower right", facecolor=COLORS["bg_card"],
                  edgecolor=COLORS["border"], labelcolor=COLORS["text_primary"])
        for spine in ax.spines.values():
            spine.set_color(COLORS["border"])

        self._bar_chart.figure.subplots_adjust(left=0.28, right=0.95, top=0.95, bottom=0.12)
        self._bar_chart.draw()

    def _update_pie_chart(self) -> None:
        self._pie_chart.clear()
        sev_map = self._analytics.get("severity_map", {})
        totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for ip_sevs in sev_map.values():
            for sev, cnt in ip_sevs.items():
                if sev in totals:
                    totals[sev] += cnt

        non_zero = {k: v for k, v in totals.items() if v > 0}
        if not non_zero:
            ax = self._pie_chart.add_subplot(111)
            ax.set_facecolor(COLORS["bg_card"])
            ax.text(0.5, 0.5, "No severity data", transform=ax.transAxes,
                    ha="center", va="center", color=COLORS["text_secondary"], fontsize=11)
            ax.set_xticks([])
            ax.set_yticks([])
            self._pie_chart.draw()
            return

        labels = list(non_zero.keys())
        sizes = list(non_zero.values())
        colors = [SEV_COLORS_MPL[s] for s in labels]

        ax = self._pie_chart.add_subplot(111)
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=colors, autopct="%1.0f%%",
            startangle=140, pctdistance=0.55, labeldistance=1.15,
            textprops={"color": COLORS["text_primary"], "fontsize": 8},
        )
        for at in autotexts:
            at.set_fontsize(8)
            at.set_color("#ffffff")

        self._pie_chart.figure.subplots_adjust(left=0.05, right=0.95, top=0.92, bottom=0.08)
        self._pie_chart.draw()

    def _update_dest_chart(self) -> None:
        self._dest_chart.clear()
        dests = self._analytics.get("top_destinations", [])[:12]
        if not dests:
            ax = self._dest_chart.add_subplot(111)
            ax.set_facecolor(COLORS["bg_dark"])
            ax.text(0.5, 0.5, "No destination IP data", transform=ax.transAxes,
                    ha="center", va="center", color=COLORS["text_secondary"], fontsize=11)
            ax.set_xticks([])
            ax.set_yticks([])
            self._dest_chart.draw()
            return

        ips = [d["ip"] for d in dests]
        counts = [d["count"] for d in dests]

        ax = self._dest_chart.add_subplot(111)
        ax.set_facecolor(COLORS["bg_dark"])

        bars = ax.bar(range(len(ips)), counts, color=COLORS["accent_cyan"],
                      edgecolor="none", width=0.55)

        ax.set_xticks(range(len(ips)))
        ax.set_xticklabels(ips, rotation=30, ha="right", fontsize=7, color=COLORS["text_primary"])
        ax.set_ylabel("Alert Count", fontsize=8, color=COLORS["text_secondary"])
        ax.tick_params(axis="y", colors=COLORS["text_secondary"], labelsize=7)

        max_cnt = max(counts) if counts else 1
        ax.set_ylim(0, max_cnt * 1.2)

        for spine in ax.spines.values():
            spine.set_color(COLORS["border"])

        for bar, cnt in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_cnt * 0.02,
                    str(cnt), ha="center", va="bottom", fontsize=7,
                    color=COLORS["text_primary"])

        self._dest_chart.figure.subplots_adjust(left=0.06, right=0.97, top=0.95, bottom=0.22)
        self._dest_chart.draw()

    # ── Table ──

    def _update_table(self) -> None:
        sources = self._analytics.get("top_sources", [])
        sev_map = self._analytics.get("severity_map", {})
        type_map = self._analytics.get("type_map", {})
        risk_map = self._analytics.get("risk_map", {})

        self._ip_table.setRowCount(len(sources))
        for row, item in enumerate(sources):
            ip = item["ip"]
            count = item["count"]
            sevs = sev_map.get(ip, {})
            types = type_map.get(ip, {})
            max_risk = risk_map.get(ip, 0)
            type_str = ", ".join(f"{t}({c})" for t, c in types.items())

            crit = sevs.get("Critical", 0)
            high = sevs.get("High", 0)
            med = sevs.get("Medium", 0)
            low = sevs.get("Low", 0)

            cells = [ip, str(count), str(crit), str(high), str(med), str(low),
                     str(max_risk), type_str]

            for col, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                if col == 0:
                    if crit > 0:
                        cell.setForeground(QColor(COLORS["critical"]))
                    elif high > 0:
                        cell.setForeground(QColor(COLORS["high"]))
                    else:
                        cell.setForeground(QColor("#80deea"))
                    cell.setFont(QFont("Consolas", -1))
                elif col == 2 and crit > 0:
                    cell.setForeground(QColor(COLORS["critical"]))
                    cell.setFont(QFont("", -1, QFont.Bold))
                elif col == 3 and high > 0:
                    cell.setForeground(QColor(COLORS["high"]))
                elif col == 6:
                    if max_risk >= 80:
                        cell.setForeground(QColor(COLORS["critical"]))
                    elif max_risk >= 50:
                        cell.setForeground(QColor(COLORS["high"]))
                    else:
                        cell.setForeground(QColor(COLORS["accent_green"]))
                self._ip_table.setItem(row, col, cell)

            if crit > 0:
                for col in range(8):
                    it = self._ip_table.item(row, col)
                    if it:
                        it.setBackground(QColor(40, 15, 15))

        self._ip_table.resizeRowsToContents()
