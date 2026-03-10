"""
SentinelX – Reporting System
Generates PDF and CSV security reports with summaries and timelines.
"""

import csv
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinelx.database.db_manager import DatabaseManager
from sentinelx.utils.config import REPORT_DIR, Config
from sentinelx.utils.logger import get_logger

logger = get_logger("reporting")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not available – PDF reports disabled")

try:
    import matplotlib
    if not matplotlib.get_backend():
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class ReportGenerator:
    """Generates security reports in PDF and CSV formats."""

    def __init__(self):
        self.db = DatabaseManager()
        self.config = Config()
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def generate_daily_report(self, date: Optional[datetime] = None) -> Optional[str]:
        """Generate a daily summary PDF report."""
        if date is None:
            date = datetime.utcnow()
        since = date.replace(hour=0, minute=0, second=0, microsecond=0)
        until = since + timedelta(days=1)
        now_str = datetime.utcnow().strftime('%H%M%S')
        title = f"Daily Security Report — {since.strftime('%Y-%m-%d')}"
        filename = f"daily_report_{since.strftime('%Y%m%d')}_{now_str}.pdf"
        return self._generate_pdf_report(title, since, until, filename)

    def generate_weekly_report(self, date: Optional[datetime] = None) -> Optional[str]:
        """Generate a weekly summary PDF report."""
        if date is None:
            date = datetime.utcnow()
        until = date.replace(hour=23, minute=59, second=59)
        since = until - timedelta(days=7)
        now_str = datetime.utcnow().strftime('%H%M%S')
        title = f"Weekly Security Report — {since.strftime('%Y-%m-%d')} to {until.strftime('%Y-%m-%d')}"
        filename = f"weekly_report_{since.strftime('%Y%m%d')}_{now_str}.pdf"
        return self._generate_pdf_report(title, since, until, filename)
    def generate_time_range_report(self, since: datetime, until: datetime) -> Optional[str]:
        """Generate a PDF report for an arbitrary datetime range (may span multiple days)."""
        if until <= since:
            logger.error("End datetime must be after start datetime")
            return None
        now_str = datetime.utcnow().strftime('%H%M%S')
        title = (
            f"Time-Range Security Report \u2014 {since.strftime('%Y-%m-%d %H:%M')} to {until.strftime('%Y-%m-%d %H:%M')}"
        )
        filename = (
            f"timerange_report_{since.strftime('%Y%m%d_%H%M')}_to_{until.strftime('%Y%m%d_%H%M')}_{now_str}.pdf"
        )
        return self._generate_pdf_report(title, since, until, filename)

    # Legacy API for backward compatibility (single date + time window)
    def generate_time_range_report_legacy(
        self,
        date: datetime,
        start_hour: int,
        start_minute: int,
        end_hour: int,
        end_minute: int,
    ) -> Optional[str]:
        since = date.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0)
        until = date.replace(hour=end_hour, minute=end_minute, second=59, microsecond=0)
        return self.generate_time_range_report(since, until)
    def _generate_pdf_report(
        self, title: str, since: datetime, until: datetime, filename: str
    ) -> Optional[str]:
        """Generate a PDF report for a given period."""
        if not REPORTLAB_AVAILABLE:
            logger.error("Cannot generate PDF: reportlab not installed")
            return None

        filepath = REPORT_DIR / filename
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50,
        )

        styles = getSampleStyleSheet()
        elements = []

        # ----- Title -----
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=22,
            spaceAfter=6,
            textColor=colors.HexColor("#0f3460"),
        )
        elements.append(Paragraph("SentinelX Security Report", title_style))
        elements.append(Spacer(1, 4))

        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=colors.grey,
            alignment=TA_CENTER,
        )
        elements.append(Paragraph(title, subtitle_style))
        elements.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style
        ))
        elements.append(Spacer(1, 24))

        # ----- Summary Stats -----
        stats = self.db.get_alert_stats(
            hours=int((until - since).total_seconds() / 3600)
        )

        summary_data = [
            ["Metric", "Count"],
            ["Total Alerts", str(stats.get("total", 0))],
            ["Critical", str(stats.get("critical", 0))],
            ["High", str(stats.get("high", 0))],
            ["Medium", str(stats.get("medium", 0))],
            ["Low", str(stats.get("low", 0))],
            ["Acknowledged", str(stats.get("acknowledged", 0))],
            ["Unacknowledged", str(stats.get("unacknowledged", 0))],
            ["False Positives", str(stats.get("false_positive", 0))],
        ]

        section_style = ParagraphStyle(
            "Section",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#0f3460"),
            spaceAfter=8,
        )
        elements.append(Paragraph("Executive Summary", section_style))

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        # ----- Chart (if matplotlib available) -----
        if MATPLOTLIB_AVAILABLE:
            chart_path = self._generate_severity_chart(stats)
            if chart_path:
                elements.append(Paragraph("Alert Distribution", section_style))
                elements.append(Image(chart_path, width=4 * inch, height=3 * inch))
                elements.append(Spacer(1, 20))

        # ----- Top Suspicious IPs -----
        top_ips = stats.get("top_ips", [])
        if top_ips:
            elements.append(Paragraph("Top Suspicious IPs", section_style))
            ip_data = [["IP Address", "Alert Count"]]
            for ip_info in top_ips[:10]:
                ip_data.append([ip_info.get("ip", ""), str(ip_info.get("count", 0))])

            ip_table = Table(ip_data, colWidths=[3 * inch, 2 * inch])
            ip_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]))
            elements.append(ip_table)
            elements.append(Spacer(1, 20))

        # ----- All Alerts Detail -----
        elements.append(PageBreak())
        elements.append(Paragraph("All Alerts Detail", section_style))

        alerts = self.db.get_alerts(since=since, limit=200)

        if alerts:
            alert_data = [["#", "Time", "Severity", "Title", "Source", "Score", "Ack", "FP"]]
            for a in alerts:
                ack = "Yes" if a.get("acknowledged") else "No"
                fp = "Yes" if a.get("false_positive") else "No"
                alert_data.append([
                    str(a.get("id", "")),
                    str(a.get("timestamp", ""))[:19],
                    a.get("severity", ""),
                    a.get("title", "")[:35],
                    str(a.get("source", "N/A"))[:18],
                    str(a.get("risk_score", 0)),
                    ack,
                    fp,
                ])

            alert_table = Table(
                alert_data,
                colWidths=[0.4 * inch, 1.1 * inch, 0.7 * inch, 1.9 * inch, 1.1 * inch, 0.5 * inch, 0.4 * inch, 0.4 * inch],
            )

            # Color rows based on severity and ack/FP status
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]

            sev_colors = {
                "Critical": colors.HexColor("#ffe0e0"),
                "High": colors.HexColor("#fff3e0"),
                "Medium": colors.HexColor("#fff9e0"),
                "Low": colors.HexColor("#e0f7e0"),
            }

            for i, a in enumerate(alerts):
                row_idx = i + 1  # +1 for header
                if a.get("false_positive"):
                    style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#e8e0f0")))
                    style_cmds.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.grey))
                elif a.get("acknowledged"):
                    style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#e0f0e8")))
                else:
                    bg = sev_colors.get(a.get("severity", ""), colors.white)
                    style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))

            alert_table.setStyle(TableStyle(style_cmds))
            elements.append(alert_table)
        else:
            elements.append(Paragraph(
                "No alerts recorded in this period.",
                styles["Normal"],
            ))

        # ----- Build PDF -----
        try:
            doc.build(elements)
            logger.info("Report generated: %s", filepath)
            return str(filepath)
        except Exception as e:
            logger.error("Failed to generate report: %s", e)
            return None

    def _generate_severity_chart(self, stats: dict) -> Optional[str]:
        """Generate a pie chart of alert severities."""
        try:
            labels = []
            sizes = []
            chart_colors = []
            color_map = {
                "Critical": "#ff1744",
                "High": "#ff9800",
                "Medium": "#ffc107",
                "Low": "#00e676",
            }

            for sev in ("Critical", "High", "Medium", "Low"):
                count = stats.get(sev.lower(), 0)
                if count > 0:
                    labels.append(f"{sev} ({count})")
                    sizes.append(count)
                    chart_colors.append(color_map[sev])

            if not sizes:
                return None

            fig, ax = plt.subplots(figsize=(5, 4))
            ax.pie(sizes, labels=labels, colors=chart_colors, autopct="%1.0f%%", startangle=90)
            ax.set_title("Alert Severity Distribution", fontsize=12, fontweight="bold")

            chart_path = str(REPORT_DIR / "_temp_chart.png")
            fig.savefig(chart_path, dpi=100, bbox_inches="tight", transparent=True)
            plt.close(fig)
            return chart_path
        except Exception as e:
            logger.error("Chart generation failed: %s", e)
            return None

    def export_alerts_csv(self, filepath: str, since: Optional[datetime] = None, until: Optional[datetime] = None, limit: int = 10000) -> int:
        """Export alerts to CSV for a custom time window. Returns row count."""
        alerts = self.db.get_alerts(since=since, until=until, limit=limit)

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "id", "timestamp", "severity", "alert_type", "title",
                "description", "source", "destination", "risk_score",
                "acknowledged", "false_positive",
            ])
            writer.writeheader()
            writer.writerows(alerts)

        logger.info("Exported %d alerts to %s", len(alerts), filepath)
        return len(alerts)

    def export_timeline_csv(self, filepath: str, since: Optional[datetime] = None, until: Optional[datetime] = None) -> int:
        """Export alert timeline data to CSV for a custom time window."""
        timeline = self.db.get_alert_timeline(since=since, until=until)

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["time", "Critical", "High", "Medium", "Low"])
            writer.writeheader()
            writer.writerows(timeline)

        logger.info("Exported timeline (%d buckets) to %s", len(timeline), filepath)
        return len(timeline)
