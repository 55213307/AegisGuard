from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_password_changed
from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.schemas.anomaly import AnomalyAlert, AnomalyFeed
from app.services.ml.model import ANOMALY_RISK_THRESHOLD

router = APIRouter(prefix="/api/anomalies", tags=["anomalies"])

FEED_LIMIT = 20


@router.get("/feed", response_model=AnomalyFeed)
def feed(
    after_id: int | None = Query(default=None, ge=0),
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> AnomalyFeed:
    """Behavior anomalies newer than the cursor, oldest first, for the portal's
    pop-up alerts. The pages poll this every few seconds."""
    latest_id = (
        db.query(func.max(SecurityEvent.id)).filter(SecurityEvent.unique_id == principal.company_id).scalar() or 0
    )
    if after_id is None:
        return AnomalyFeed(latest_id=latest_id, items=[])

    rows = (
        db.query(SecurityEvent, Endpoint.endpoint_name, Endpoint.employee_id)
        .outerjoin(Endpoint, Endpoint.id == SecurityEvent.endpoint_id)
        .filter(
            SecurityEvent.unique_id == principal.company_id,
            SecurityEvent.id > after_id,
            SecurityEvent.risk_score >= ANOMALY_RISK_THRESHOLD,
        )
        .order_by(SecurityEvent.id.asc())
        .limit(FEED_LIMIT)
        .all()
    )
    items = [
        AnomalyAlert(
            id=event.id,
            event_time=event.event_time,
            account_id=employee_id,
            endpoint_name=endpoint_name or "—",
            severity=event.severity,
            risk_score=event.risk_score,
            risk_reason=event.risk_reason,
            description=event.rule_description,
        )
        for event, endpoint_name, employee_id in rows
    ]
    # A full page may leave more behind: continue from the last one returned
    # rather than skipping ahead to the newest event.
    next_id = items[-1].id if len(items) == FEED_LIMIT else max(latest_id, after_id)
    return AnomalyFeed(latest_id=next_id, items=items)
