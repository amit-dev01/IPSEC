"""PDF rendering with ReportLab. Every dynamic string is XML-escaped before
being placed in a Paragraph; no uploaded content is ever rendered as markup.
"""

import html
import io
import json
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _e(value: Any) -> str:
    if value is None:
        return "—"
    if not isinstance(value, str):
        value = json.dumps(value, default=str)[:500]
    return html.escape(value)


def render_pdf(report: dict[str, Any]) -> bytes:
    styles = getSampleStyleSheet()
    h1, h2, body = styles["Title"], styles["Heading2"], styles["BodyText"]
    story: list = [Paragraph("IPsec Analysis Report", h1)]
    ex = report["executive_summary"]
    story.append(Paragraph("Executive summary", h2))
    story.append(Paragraph(_e(ex["headline"]), body))
    rows = [
        ["Assessment status", _e(ex["assessment_status"])],
        ["Risk score (0-100)", _e(ex["risk_score"])],
        ["Security score (0-100)", _e(ex["security_score"])],
        ["Coverage", _e(ex["coverage"])],
        ["Findings", _e(ex["finding_counts"])],
    ]
    story.append(_table(rows))
    story.append(Paragraph(_e(ex["note"]), body))

    story.append(Paragraph("Observed protocol facts (packet-observed)", h2))
    for f in report["packet_observed_facts"][:60]:
        story.append(
            Paragraph(
                f"<b>{_e(f['fact'])}</b>: {_e(f['value'])} (confidence {_e(f['confidence'])})",
                body,
            )
        )
    if report["manifest_and_analyst_facts"]:
        story.append(Paragraph("Manifest / analyst-supplied facts", h2))
        for f in report["manifest_and_analyst_facts"][:40]:
            story.append(Paragraph(f"<b>{_e(f['fact'])}</b>: {_e(f['value'])}", body))

    story.append(Paragraph("Likely traffic categories (probabilistic)", h2))
    pred = report["model_inferred"]["prediction"] or {}
    story.append(
        Paragraph(
            f"Status: {_e(pred.get('status'))}; "
            f"category: {_e(pred.get('predicted_category'))}; "
            f"confidence: {_e(pred.get('confidence'))}. "
            f"{_e(report['model_inferred']['disclaimer'])}",
            body,
        )
    )

    story.append(Paragraph("Findings", h2))
    if report["findings"]:
        rows = [["Severity", "Rule", "Recommendation"]]
        for f in report["findings"]:
            rows.append([_e(f["severity"]), _e(f["rule_id"]), _e(f["recommendation"])])
        story.append(_table(rows))
    else:
        story.append(Paragraph("No findings.", body))

    story.append(Paragraph("Unknowns and limitations", h2))
    for u in report["unknowns_and_limitations"]["unknowns"][:40]:
        story.append(Paragraph(f"<b>{_e(u['fact'])}</b>: unknown — {_e(u['limitation'])}", body))
    story.append(Paragraph("Versions and timestamps", h2))
    story.append(
        _table(
            [
                ["Pipeline", _e(report["versions"]["pipeline_version"])],
                ["Parser", _e(report["versions"]["parser_version"])],
                ["TShark", _e(report["versions"]["tshark_version"])],
                ["Model", _e(report["versions"]["model_version"])],
                ["Policy", _e(report["versions"]["policy_version"])],
                ["Generated", _e(report["generated_at"])],
                ["Finished", _e(report["timestamps"]["finished_at"])],
            ]
        )
    )
    story.append(Spacer(1, 6 * mm))
    story.append(
        Paragraph(
            "This report contains metadata only: no packet payloads, secrets, or "
            "storage paths. Unknown settings are gaps, not passes.",
            body,
        )
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="IPsec Analysis Report")
    doc.build(story)
    return buf.getvalue()


def _table(rows: list[list[str]]) -> Table:
    t = Table(rows, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return t
