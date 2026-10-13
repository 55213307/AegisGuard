from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_password_changed
from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.schemas.security_log import SecurityLogItem, SecurityLogListResponse

router = APIRouter(prefix="/api/security-logs", tags=["security logs"])

# Cap the table payload so a noisy fleet can't flood the browser. Export has
# no cap — it streams the full range as CSV.
LIST_LIMIT = 1000


def _query(db: Session, company_id: int, days: int):
    """Security events for this company within the day window, newest first,
    joined to their endpoint so each row carries the computer's name."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return (
        db.query(SecurityEvent, Endpoint.endpoint_name)
        .outerjoin(Endpoint, Endpoint.id == SecurityEvent.endpoint_id)
        .filter(
            SecurityEvent.unique_id == company_id,
            SecurityEvent.event_time >= since,
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
