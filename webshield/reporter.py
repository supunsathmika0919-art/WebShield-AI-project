"""JSON, HTML, and PDF report writers."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from webshield.analyzer import prioritize_findings
from webshield.redaction import redact_report

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")


def _safe_report(report: dict[str, Any]) -> dict[str, Any]:
    safe_report = redact_report(report)
    if isinstance(safe_report, dict):
        findings = safe_report.get("findings", [])
        if isinstance(findings, list):
            safe_report["findings"] = prioritize_findings(findings)
    return safe_report


def safe_report_stem(hostname: str, now: datetime | None = None) -> str:
    safe_host = re.sub(r"[^A-Za-z0-9.-]+", "_", hostname).strip(".-") or "target"
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S%fZ")
    return f"webshield_{safe_host}_{timestamp}"


def write_json_report(report: dict[str, Any], output_dir: Path, stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{stem}.json"
    safe_report = _safe_report(report)
    path.write_text(json.dumps(safe_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def render_html(report: dict[str, Any]) -> str:
    report = _safe_report(report)
    findings = report.get("findings", [])
    rows = []
    for finding in findings:
        rows.append(
            "<article class=\"finding\">"
            f"<h3>{html.escape(str(finding.get('title', 'Finding')))}</h3>"
            f"<p><strong>{html.escape(str(finding.get('severity', '')))}</strong> "
            f"· {html.escape(str(finding.get('id', '')))}</p>"
            f"<p><strong>Status:</strong> {html.escape(str(finding.get('status', 'potential')))}; "
            f"<strong>Confidence:</strong> {html.escape(str(finding.get('confidence', 'Not calibrated')))}; "
            f"<strong>Priority rank:</strong> {html.escape(str(finding.get('priority_rank', '')))}</p>"
            f"<p><strong>Priority rationale:</strong> "
            f"{html.escape(str(finding.get('priority_reason', 'Rule-based ordering')))}</p>"
            f"<p><strong>Resource:</strong> {html.escape(str(finding.get('affected_resource', '')))}</p>"
            f"<p><strong>Evidence:</strong> {html.escape(str(finding.get('evidence', '')))}</p>"
            f"<p>{html.escape(str(finding.get('explanation', '')))}</p>"
            f"<p><strong>Remediation:</strong> {html.escape(str(finding.get('remediation', '')))}</p>"
            f"<p><strong>References:</strong> {html.escape(', '.join(finding.get('references', [])))}</p>"
            "</article>"
        )
    counts = report.get("severity_counts", {})
    count_list = "".join(
        f"<li>{html.escape(severity)}: {int(counts.get(severity, 0))}</li>"
        for severity in SEVERITIES
    )
    target = report.get("target", {})
    checks_performed = report.get("checks_performed", [])
    checks_skipped = report.get("checks_skipped", [])
    errors = report.get("errors", [])
    crawl = report.get("crawl")
    crawl_html = ""
    if isinstance(crawl, dict):
        page_items = "".join(
            "<li>"
            f"{html.escape(str(page.get('url', '')))} — HTTP "
            f"{html.escape(str(page.get('status', '')))}, depth "
            f"{html.escape(str(page.get('depth', '')))}, query names: "
            f"{html.escape(', '.join(page.get('query_parameters', [])) or 'none')}"
            "</li>"
            for page in crawl.get("pages", [])
        )
        form_items = "".join(
            "<li>"
            f"{html.escape(str(form.get('page_url', '')))} — "
            f"{html.escape(str(form.get('method', '')))} to "
            f"{html.escape(str(form.get('action', '')))}; fields: "
            f"{html.escape(', '.join(form.get('field_names', [])) or 'none')}; "
            f"submitted: {html.escape(str(form.get('submitted', False)))}"
            "</li>"
            for form in crawl.get("forms", [])
        )
        crawl_html = (
            f"<h2>Crawl summary</h2><p>Requests: {html.escape(str(crawl.get('request_count', 0)))}; "
            f"excluded: {html.escape(str(crawl.get('excluded_count', 0)))}</p>"
            f"<h3>Discovered pages</h3><ul>{page_items or '<li>None</li>'}</ul>"
            f"<h3>Inspected forms (not submitted)</h3><ul>{form_items or '<li>None</li>'}</ul>"
        )
    title = html.escape(str(report.get("tool", "WebShield AI")))
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{title} report</title><style>"
        "body{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#172033}"
        ".finding{border:1px solid #ccd4e0;border-radius:8px;padding:1rem;margin:1rem 0}"
        "h1,h2{color:#15345b}code{overflow-wrap:anywhere}"
        "</style></head><body>"
        f"<h1>{title} scan report</h1>"
        f"<p><strong>Scanned:</strong> {html.escape(str(report.get('scanned_at', '')))}</p>"
        f"<p><strong>Version:</strong> {html.escape(str(report.get('version', '')))}</p>"
        f"<p><strong>Target:</strong> {html.escape(str(target.get('url', '')))}</p>"
        f"<p><strong>Origin:</strong> {html.escape(str(target.get('origin', '')))}</p>"
        f"<p><strong>Scope:</strong> {html.escape(str(target.get('scope', '')))}</p>"
        f"<p><strong>Approved paths:</strong> {html.escape(', '.join(target.get('approved_paths', [])))}</p>"
        f"<p><strong>Status:</strong> {html.escape(str(report.get('status', '')))}; "
        f"HTTP {html.escape(str(report.get('http_status', 'unavailable')))}</p>"
        f"<h2>Severity counts</h2><ul>{count_list}</ul>"
        f"<h2>Checks performed</h2><ul>{''.join(f'<li>{html.escape(str(item))}</li>' for item in checks_performed) or '<li>None</li>'}</ul>"
        f"<h2>Checks skipped</h2><ul>{''.join(f'<li>{html.escape(str(item))}</li>' for item in checks_skipped) or '<li>None</li>'}</ul>"
        f"<h2>Errors</h2><ul>{''.join(f'<li>{html.escape(str(item))}</li>' for item in errors) or '<li>None</li>'}</ul>"
        f"{crawl_html}"
        f"<h2>Findings ({len(findings)})</h2>"
        + ("".join(rows) if rows else "<p>No findings were reported.</p>")
        + f"<p>{html.escape(str(report.get('limitations', '')))}</p>"
        "</body></html>"
    )


def write_html_report(report: dict[str, Any], output_dir: Path, stem: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{stem}.html"
    path.write_text(render_html(report), encoding="utf-8")
    return path


def write_pdf_report(report: dict[str, Any], output_dir: Path, stem: str) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as error:
        raise RuntimeError(
            "PDF reporting requires ReportLab. Install project dependencies with "
            "'python -m pip install -r requirements.txt'."
        ) from error

    report = _safe_report(report)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{stem}.pdf"
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER))
    story = [
        Paragraph("WebShield AI scan report", styles["ReportTitle"]),
        Spacer(1, 0.15 * inch),
        Paragraph(f"<b>Scanned:</b> {escape(str(report.get('scanned_at', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Version:</b> {escape(str(report.get('version', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Target:</b> {escape(str(report.get('target', {}).get('url', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Origin:</b> {escape(str(report.get('target', {}).get('origin', '')))}", styles["BodyText"]),
        Paragraph(f"<b>Scope:</b> {escape(str(report.get('target', {}).get('scope', '')))}", styles["BodyText"]),
        Paragraph(
            f"<b>Approved paths:</b> {escape(', '.join(report.get('target', {}).get('approved_paths', [])))}",
            styles["BodyText"],
        ),
        Paragraph(
            f"<b>Status:</b> {escape(str(report.get('status', '')))}; "
            f"<b>HTTP:</b> {escape(str(report.get('http_status', 'unavailable')))}",
            styles["BodyText"],
        ),
        Spacer(1, 0.12 * inch),
    ]
    counts = report.get("severity_counts", {})
    table_data = [["Severity", "Count"]] + [
        [severity, str(counts.get(severity, 0))] for severity in SEVERITIES
    ]
    table = Table(table_data, colWidths=[2.2 * inch, 1.0 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#15345b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([Paragraph("Severity counts", styles["Heading2"]), table, Spacer(1, 0.15 * inch)])
    for section_title, items in (
        ("Checks performed", report.get("checks_performed", [])),
        ("Checks skipped", report.get("checks_skipped", [])),
        ("Errors", report.get("errors", [])),
    ):
        story.append(Paragraph(section_title, styles["Heading2"]))
        story.append(
            Paragraph(
                escape("; ".join(str(item) for item in items) if items else "None"),
                styles["BodyText"],
            )
        )
    crawl = report.get("crawl")
    if isinstance(crawl, dict):
        story.append(Paragraph("Crawl summary", styles["Heading2"]))
        story.append(Paragraph(
            f"<b>Requests:</b> {escape(str(crawl.get('request_count', 0)))}; "
            f"<b>Excluded:</b> {escape(str(crawl.get('excluded_count', 0)))}",
            styles["BodyText"],
        ))
        story.append(Paragraph("Discovered pages", styles["Heading3"]))
        for page in crawl.get("pages", []):
            story.append(Paragraph(
                f"{escape(str(page.get('url', '')))} — HTTP "
                f"{escape(str(page.get('status', '')))}, depth "
                f"{escape(str(page.get('depth', '')))}, query names: "
                f"{escape(', '.join(page.get('query_parameters', [])) or 'none')}",
                styles["BodyText"],
            ))
        story.append(Paragraph("Inspected forms (not submitted)", styles["Heading3"]))
        for form in crawl.get("forms", []):
            story.append(Paragraph(
                f"{escape(str(form.get('page_url', '')))} — "
                f"{escape(str(form.get('method', '')))} to "
                f"{escape(str(form.get('action', '')))}; fields: "
                f"{escape(', '.join(form.get('field_names', [])) or 'none')}",
                styles["BodyText"],
            ))
    story.append(Paragraph("Findings", styles["Heading2"]))
    findings = report.get("findings", [])
    if not findings:
        story.append(Paragraph("No findings were reported.", styles["BodyText"]))
    for finding in findings:
        fields = (
            ("Title", finding.get("title", "")),
            ("Severity / ID", f"{finding.get('severity', '')} / {finding.get('id', '')}"),
            ("Status / Confidence", f"{finding.get('status', 'potential')} / {finding.get('confidence', 'Not calibrated')}"),
            ("Priority rank", finding.get("priority_rank", "")),
            ("Priority rationale", finding.get("priority_reason", "Rule-based ordering")),
            ("Resource", finding.get("affected_resource", "")),
            ("Evidence", finding.get("evidence", "")),
            ("Explanation", finding.get("explanation", "")),
            ("Remediation", finding.get("remediation", "")),
            ("References", ", ".join(finding.get("references", []))),
        )
        story.append(Paragraph(escape(str(finding.get("title", "Finding")), {"'": "&#x27;"}), styles["Heading3"]))
        for label, value in fields[1:]:
            story.append(Paragraph(f"<b>{escape(label)}:</b> {escape(str(value))}", styles["BodyText"]))
        story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(escape(str(report.get("limitations", "")), {"'": "&#x27;"}), styles["Italic"]))
    SimpleDocTemplate(
        str(path), pagesize=letter, rightMargin=0.65 * inch, leftMargin=0.65 * inch,
        topMargin=0.65 * inch, bottomMargin=0.65 * inch,
    ).build(story)
    return path


def write_reports(
    report: dict[str, Any], formats: list[str], output_dir: Path
) -> list[Path]:
    stem = safe_report_stem(report["target"]["hostname"])
    writers = {
        "json": write_json_report,
        "html": write_html_report,
        "pdf": write_pdf_report,
    }
    return [writers[report_format](report, output_dir, stem) for report_format in formats]
