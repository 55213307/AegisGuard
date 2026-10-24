from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_password_changed
from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.schemas.security_log import SecurityLogItem, SecurityLogListResponse, SecurityReportRequest
from app.services import pdf_report

router = APIRouter(prefix="/api/security-logs", tags=["security logs"])

# Cap the table payload so a noisy fleet can't flood the browser. CSV and PDF
# export both work from what the page already has — see SecurityReportRequest.
LIST_LIMIT = 1000
# A security log that matters is a Warning or Critical; routine activity
# (logons, configuration scans) is left out of this page entirely.
_REPORTABLE_SEVERITIES = ("Warning", "Critical")


def _query(db: Session, company_id: int, days: int):
    """This company's Warning/Critical events within the day window, newest
    first, joined to their endpoint so each row carries the computer's name."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return (
        db.query(SecurityEvent, Endpoint.endpoint_name)
        .outerjoin(Endpoint, Endpoint.id == SecurityEvent.endpoint_id)
        .filter(
            SecurityEvent.unique_id == company_id,
            SecurityEvent.event_time >= since,
            SecurityEvent.severity.in_(_REPORTABLE_SEVERITIES),
        )
        .order_by(SecurityEvent.event_time.desc())
    )


def _to_item(event: SecurityEvent, endpoint_name: str | None) -> SecurityLogItem:
    return SecurityLogItem(
        timestamp=event.event_time,
        endpoint_name=endpoint_name or "—",
        user=event.event_user,
        event_type=event.event_type,
        severity=(event.severity or "info").lower(),
        description=event.rule_description,
        risk_score=event.risk_score,
        risk_reason=event.risk_reason,
    )


@router.get("", response_model=SecurityLogListResponse)
def list_logs(
    days: int = Query(7, ge=1, le=365),
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> SecurityLogListResponse:
    rows = _query(db, principal.company_id, days).limit(LIST_LIMIT).all()
    items = [_to_item(event, name) for event, name in rows]
    return SecurityLogListResponse(items=items, total=len(items))


@router.post("/report")
def download_report(
    payload: SecurityReportRequest,
    principal: Principal = Depends(require_password_changed),
) -> Response:
    """The Security Logs page as a formatted PDF: the company's name and
    AegisGuard's logo, a summary of the period, and exactly the rows the page
    sends — whatever its own search/severity/type/risk/date filters currently
    show, not a fresh query, so the report always matches what's on screen."""
    pdf_bytes = pdf_report.build(principal.company_name, payload.items, filters_summary=payload.filters_summary)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    company_slug = "".join(c if c.isalnum() else "-" for c in principal.company_name.lower()).strip("-") or "company"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="aegisguard-security-report-{company_slug}-{stamp}.pdf"'},
    )
