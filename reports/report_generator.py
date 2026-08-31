import csv
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


# ============================================================
# Project Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

REPORTS_DIR = BASE_DIR

CSV_FILE = REPORTS_DIR / "firewall_security_report.csv"

PDF_FILE = REPORTS_DIR / "firewall_security_report.pdf"


# ============================================================
# CSV REPORT
# ============================================================

def generate_csv_report(events, alerts):
    """
    Generate a CSV report containing firewall events.
    """

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        # ----------------------------------------------------
        # Report Header
        # ----------------------------------------------------

        writer.writerow([
            "Firewall Security Report"
        ])

        writer.writerow([
            "Generated",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ])

        writer.writerow([])

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        total = len(events)

        accepted = sum(
            1
            for event in events
            if event["action"] == "ACCEPT"
        )

        dropped = sum(
            1
            for event in events
            if event["action"] == "DROP"
        )

        writer.writerow([
            "SUMMARY"
        ])

        writer.writerow([
            "Total Events",
            total
        ])

        writer.writerow([
            "Accepted Events",
            accepted
        ])

        writer.writerow([
            "Dropped Events",
            dropped
        ])

        writer.writerow([
            "Security Alerts",
            len(alerts)
        ])

        writer.writerow([])

        # ----------------------------------------------------
        # Security Alerts
        # ----------------------------------------------------

        writer.writerow([
            "SECURITY ALERTS"
        ])

        writer.writerow([
            "Alert Type",
            "Severity",
            "Source IP",
            "Description"
        ])

        for alert in alerts:

            writer.writerow([
                alert.get("type", ""),
                alert.get("severity", ""),
                alert.get("src_ip", ""),
                alert.get("description", "")
            ])

        writer.writerow([])

        # ----------------------------------------------------
        # Firewall Events
        # ----------------------------------------------------

        writer.writerow([
            "FIREWALL EVENTS"
        ])

        writer.writerow([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol",
            "Action"
        ])

        for event in events:

            writer.writerow([
                event["timestamp"],
                event["src_ip"],
                event["dst_ip"],
                event["src_port"],
                event["dst_port"],
                event["protocol"],
                event["action"]
            ])

    return CSV_FILE


# ============================================================
# PDF REPORT
# ============================================================

def generate_pdf_report(events, alerts):
    """
    Generate a professional PDF security report.
    """

    # --------------------------------------------------------
    # Calculate summary statistics
    # --------------------------------------------------------

    total_events = len(events)

    accepted = sum(
        1
        for event in events
        if event["action"] == "ACCEPT"
    )

    dropped = sum(
        1
        for event in events
        if event["action"] == "DROP"
    )

    # --------------------------------------------------------
    # PDF Document
    # --------------------------------------------------------

    document = SimpleDocTemplate(
        str(PDF_FILE),

        pagesize=A4,

        rightMargin=15 * mm,

        leftMargin=15 * mm,

        topMargin=15 * mm,

        bottomMargin=15 * mm
    )

    # --------------------------------------------------------
    # Styles
    # --------------------------------------------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",

        parent=styles["Title"],

        fontSize=22,

        leading=26,

        alignment=TA_CENTER,

        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",

        parent=styles["Normal"],

        fontSize=10,

        alignment=TA_CENTER,

        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "ReportHeading",

        parent=styles["Heading2"],

        fontSize=15,

        spaceBefore=12,

        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",

        parent=styles["BodyText"],

        fontSize=9,

        leading=13
    )

    alert_style = ParagraphStyle(
        "AlertText",

        parent=styles["BodyText"],

        fontSize=8,

        leading=11
    )

    # --------------------------------------------------------
    # Story
    # --------------------------------------------------------

    story = []

    # --------------------------------------------------------
    # Title
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "FIREWALL SECURITY ANALYSIS REPORT",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Firewall Log Analyzer | Network Defense",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            subtitle_style
        )
    )

    # --------------------------------------------------------
    # Executive Summary
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "1. Executive Summary",
            heading_style
        )
    )

    summary_text = (
        f"The firewall log analyzer processed "
        f"<b>{total_events}</b> network events. "
        f"<b>{accepted}</b> events were accepted and "
        f"<b>{dropped}</b> events were blocked. "
        f"The detection engine identified "
        f"<b>{len(alerts)}</b> security alerts "
        f"requiring further review."
    )

    story.append(
        Paragraph(
            summary_text,
            body_style
        )
    )

    story.append(Spacer(1, 8))

    # --------------------------------------------------------
    # Summary Table
    # --------------------------------------------------------

    summary_data = [
        ["Metric", "Value"],

        ["Total Events", str(total_events)],

        ["Accepted Events", str(accepted)],

        ["Dropped Events", str(dropped)],

        ["Security Alerts", str(len(alerts))]
    ]

    summary_table = Table(
        summary_data,

        colWidths=[
            90 * mm,
            50 * mm
        ]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#081D3A")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(summary_table)

    # --------------------------------------------------------
    # Security Findings
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "2. Security Findings",
            heading_style
        )
    )

    if alerts:

        alert_data = [
            [
                "Severity",
                "Alert Type",
                "Source IP",
                "Description"
            ]
        ]

        for alert in alerts:

            description = alert.get(
                "description",
                ""
            )

            alert_data.append([
                alert.get("severity", ""),
                alert.get("type", ""),
                alert.get("src_ip", ""),
                Paragraph(
                    description,
                    alert_style
                )
            ])

        alert_table = Table(
            alert_data,

            colWidths=[
                25 * mm,
                38 * mm,
                35 * mm,
                75 * mm
            ],

            repeatRows=1
        )

        alert_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#081D3A")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    5
                )
            ])
        )

        story.append(alert_table)

    else:

        story.append(
            Paragraph(
                "No security alerts were identified.",
                body_style
            )
        )

    # --------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "3. Recommendations",
            heading_style
        )
    )

    recommendations = [
        "Investigate source IP addresses generating repeated "
        "blocked connections.",

        "Review firewall rules protecting SSH, RDP, Telnet, "
        "and other sensitive services.",

        "Monitor repeated connection attempts across multiple "
        "destination ports.",

        "Consider implementing IP reputation and threat "
        "intelligence enrichment.",

        "Continue monitoring firewall logs for recurring "
        "patterns and anomalous behavior."
    ]

    for number, recommendation in enumerate(
        recommendations,
        start=1
    ):

        story.append(
            Paragraph(
                f"{number}. {recommendation}",
                body_style
            )
        )

        story.append(
            Spacer(1, 4)
        )

    # --------------------------------------------------------
    # Firewall Event Summary
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "4. Firewall Event Log",
            heading_style
        )
    )

    event_data = [
        [
            "Timestamp",
            "Source",
            "Destination",
            "D.Port",
            "Protocol",
            "Action"
        ]
    ]

    for event in events:

        event_data.append([
            str(event["timestamp"]),
            event["src_ip"],
            event["dst_ip"],
            str(event["dst_port"]),
            event["protocol"],
            event["action"]
        ])

    event_table = Table(
        event_data,

        colWidths=[
            30 * mm,
            32 * mm,
            32 * mm,
            17 * mm,
            22 * mm,
            22 * mm
        ],

        repeatRows=1
    )

    event_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#081D3A")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                6.5
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.3,
                colors.grey
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                4
            )
        ])
    )

    story.append(event_table)

    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "Firewall Log Analyzer | "
            "#CyberBuildsBySusan",
            subtitle_style
        )
    )

    # --------------------------------------------------------
    # Build PDF
    # --------------------------------------------------------

    document.build(story)

    return PDF_FILE