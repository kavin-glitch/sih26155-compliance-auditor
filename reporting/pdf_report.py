from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)

SEVERITY_COLOR = {
    "High": colors.HexColor("#c0392b"),
    "Medium": colors.HexColor("#d68910"),
    "Low": colors.HexColor("#7f8c8d"),
}
STATUS_COLOR = {
    "PASS": colors.HexColor("#1e8449"),
    "FAIL": colors.HexColor("#c0392b"),
}


def generate_device_report(path, device_name, vendor, framework, findings, summary):
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=18 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18, spaceAfter=4)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, leading=12)

    elements = []
    elements.append(Paragraph("Network Device Compliance Report", title_style))
    elements.append(Paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    elements.append(Spacer(1, 10))

    meta = [
        ["Device Name", device_name],
        ["Detected Vendor", vendor.capitalize()],
        ["Framework", framework],
        ["Overall Compliance", f"{summary['compliance_pct']}%  ({summary['passed']}/{summary['total']} controls passed)"],
        ["Failures by Severity", f"High: {summary['fails_by_severity'].get('High',0)}  |  "
                                  f"Medium: {summary['fails_by_severity'].get('Medium',0)}  |  "
                                  f"Low: {summary['fails_by_severity'].get('Low',0)}"],
    ]
    meta_table = Table(meta, colWidths=[130, 360])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Compliance Findings", styles["Heading2"]))
    elements.append(Spacer(1, 6))

    for f in findings:
        status_p = Paragraph(f"<font color='{STATUS_COLOR[f['status']].hexval()}'><b>{f['status']}</b></font>", body)
        sev_p = Paragraph(f"<font color='{SEVERITY_COLOR[f['severity']].hexval()}'><b>{f['severity']}</b></font>", body)
        header_row = [f["id"], Paragraph(f"<b>{f['name']}</b>", body), sev_p, status_p]
        block_table = Table([header_row], colWidths=[45, 220, 60, 60])
        block_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f6f7") if f['status'] == "PASS" else colors.HexColor("#fdf2f0")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(block_table)

        detail = [f"<b>Description:</b> {f['description']}",
                  f"<b>Evidence:</b> {f['evidence']}",
                  f"<b>Detected:</b> {f.get('detected_text','')}",
                  f"<b>Expected:</b> {f.get('expected_text','')}"]

        if f["status"] == "FAIL":
            detail.append(f"<b>Why it matters:</b> {f.get('why','')}")
            ap = f.get("attack_path") or []
            if ap:
                chain = " -> ".join(ap)
                detail.append(f"<b>Attack path:</b> {chain}")
            remediation_html = f['remediation'].replace(chr(10), "<br/>")
            meaning = f.get("remediation_meaning", "")
            meaning_html = f"<br/><i>{meaning}</i>" if meaning else ""
            detail.append(f"<b>Remediation:</b><br/>{remediation_html}{meaning_html}")

        elements.append(Paragraph("<br/>".join(detail), small))
        elements.append(Spacer(1, 8))

    doc.build(elements)
    return path


def generate_dashboard_report(path, device_summaries):
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=18 * mm)
    styles = getSampleStyleSheet()
    elements = [Paragraph("Organization-Wide Compliance Dashboard", styles["Title"]),
                Paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]),
                Spacer(1, 14)]

    rows = [["Device", "Vendor", "Compliance %", "Passed", "Failed", "High-Sev Fails"]]
    for d in device_summaries:
        s = d["summary"]
        rows.append([d["name"], d["vendor"].capitalize(), f"{s['compliance_pct']}%",
                     s["passed"], s["failed"], s["fails_by_severity"].get("High", 0)])

    table = Table(rows, colWidths=[110, 80, 80, 60, 60, 90])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(table)
    doc.build(elements)
    return path