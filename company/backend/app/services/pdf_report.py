"""Builds the downloadable PDF version of Security Logs: a formatted report
with the company's branding, a summary of the period, and the full table of
Warning/Critical events — the record a company would keep or hand to an
auditor, rather than a screenshot of the portal.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as _esc

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.security_log import SecurityLogItem

# AegisGuard/resources/logo.png, from this file's location, so it doesn't depend
# on the process's working directory the way the static mount does. The portal
# uses logoNonBackground.png (white text, for its dark theme), but a PDF page is
# white, so this is the full-color mark made to sit on a light background.
_LOGO_PATH = Path(__file__).resolve().parents[4] / "resources" / "logo.png"

_INK = colors.HexColor("#111726")
_MUTED = colors.HexColor("#5b6478")
_BORDER = colors.HexColor("#dbe0ea")
_CRITICAL = colors.HexColor("#c0273c")
_WARNING = colors.HexColor("#b4790a")
_HEADER_BG = colors.HexColor("#111726")

_styles = getSampleStyleSheet()
_TITLE = ParagraphStyle("AGTitle", parent=_styles["Title"], fontName="Helvetica-Bold", fontSize=20, textColor=_INK, spaceAfter=2)
_SUBTITLE = ParagraphStyle("AGSubtitle", parent=_styles["Normal"], fontName="Helvetica", fontSize=10, textColor=_MUTED)
_H2 = ParagraphStyle("AGH2", parent=_styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, textColor=_INK, spaceBefore=14, spaceAfter=6)
_BODY = ParagraphStyle("AGBody", parent=_styles["Normal"], fontName="Helvetica", fontSize=8.5, textColor=_INK, leading=11)
_BODY_MUTED = ParagraphStyle("AGBodyMuted", parent=_BODY, textColor=_MUTED, fontSize=7.5)
_FOOTER = ParagraphStyle("AGFooter", parent=_styles["Normal"], fontName="Helvetica", fontSize=7.5, textColor=_MUTED)


def _period_covered(items: list[SecurityLogItem]) -> str:
    """The actual span of the events in the report, not a filter setting:
    accurate whatever combination of filters produced this list."""
    if not items:
        return "—"
    times = [i.timestamp.astimezone(timezone.utc) for i in items]
    earliest, latest = min(times), max(times)
    if earliest.date() == latest.date():
        return earliest.strftime("%Y-%m-%d")
    return f"{earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')}"


def _summary_table(items: list[SecurityLogItem], generated_at: datetime) -> Table:
    critical = sum(1 for i in items if i.severity == "critical")
    warning = sum(1 for i in items if i.severity == "warning")
    endpoints = len({i.endpoint_name for i in items})
    scored = [i.risk_score for i in items if i.risk_score is not None]
    peak = max(scored) if scored else None
    rows = [
        ["Period covered", _period_covered(items), "Report generated", generated_at.strftime("%Y-%m-%d %H:%M UTC")],
        ["Total events listed", str(len(items)), "Endpoints involved", str(endpoints)],
        ["Critical events", str(critical), "Warning events", str(warning)],
        ["Peak behavioral risk score", str(peak) if peak is not None else "—", "", ""],
    ]
    table = Table(rows, colWidths=[42 * mm, 42 * mm, 42 * mm, 42 * mm])
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (-1, -1), _INK),
                ("TEXTCOLOR", (1, 0), (1, -1), _MUTED),
                ("TEXTCOLOR", (3, 0), (3, -1), _MUTED),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _severity_cell(severity: str) -> Paragraph:
    color = _CRITICAL if severity == "critical" else _WARNING
    style = ParagraphStyle("sev", parent=_BODY, textColor=color, fontName="Helvetica-Bold")
    return Paragraph(severity.capitalize(), style)


def _events_table(items: list[SecurityLogItem]) -> Table:
    # Descriptions, usernames etc. come from Wazuh/Windows event data, not from
    # anyone typing into the report, but may still contain '&', '<', or similar
    # — escaped here so they can't be mistaken for Paragraph's own mini-markup.
    header = ["Time", "Endpoint", "User", "Event", "Severity", "Risk", "Description"]
    rows = [header]
    for item in items:
        description = _esc(item.description or "")
        if item.risk_reason:
            description = f"{description}<br/><font color='#5b6478' size='7'>{_esc(item.risk_reason)}</font>"
        rows.append(
            [
                Paragraph(item.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M"), _BODY),
                Paragraph(_esc(item.endpoint_name), _BODY),
                Paragraph(_esc(item.user) if item.user else "—", _BODY),
                Paragraph(_esc(item.event_type) if item.event_type else "—", _BODY),
                _severity_cell(item.severity),
                Paragraph(str(item.risk_score) if item.risk_score is not None else "—", _BODY),
                Paragraph(description, _BODY),
            ]
        )
    table = Table(rows, colWidths=[22 * mm, 24 * mm, 20 * mm, 24 * mm, 16 * mm, 12 * mm, 50 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6fa")]),
                ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _header_footer(company_name: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(_MUTED)
        canvas.drawString(20 * mm, 12 * mm, f"AegisGuard Security Report — {company_name} — confidential")
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Page {doc.page}")
        canvas.restoreState()

    return draw


def build(company_name: str, items: list[SecurityLogItem], filters_summary: str | None = None) -> bytes:
    """The PDF, as bytes, for the Security Logs page's Download PDF Report
    button. `items` is exactly what the page was showing (its filters already
    applied, Info-level events already excluded) — this only formats it."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title=f"AegisGuard Security Report — {company_name}",
    )
    generated_at = datetime.now(timezone.utc)
    story = []

    if _LOGO_PATH.exists():
        # Fit the logo to a fixed width, keeping its aspect ratio.
        from PIL import Image as PILImage

        with PILImage.open(_LOGO_PATH) as im:
            ratio = im.height / im.width
        width = 30 * mm
        story.append(Image(str(_LOGO_PATH), width=width, height=width * ratio))
        story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Security Report", _TITLE))
    story.append(Paragraph(f"{company_name} &middot; prepared by AegisGuard", _SUBTITLE))
    story.append(Spacer(1, 6 * mm))
    story.append(_summary_table(items, generated_at))
    story.append(
        Paragraph(
            "This report lists Warning and Critical security events AegisGuard recorded for this company's "
            "monitored computers. Informational events (routine logons, configuration scans) are never "
            "included; the full log is available in the portal.",
            _BODY_MUTED,
        )
    )
    if filters_summary:
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(f"<b>Filtered by:</b> {_esc(filters_summary)}", _BODY_MUTED))
    story.append(PageBreak())
    story.append(Paragraph("Event Log", _H2))
    if items:
        story.append(_events_table(items))
    else:
        story.append(Paragraph("No events matched the report's filters.", _BODY_MUTED))

    draw = _header_footer(company_name)
    doc.build(story, onFirstPage=draw, onLaterPages=draw)
    return buffer.getvalue()
