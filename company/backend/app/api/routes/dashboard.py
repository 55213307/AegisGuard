from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_password_changed
from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.schemas.dashboard import (
    DashboardResponse,
    DashboardStats,
    RecentAlert,
    ServiceStatus,
    TimelinePoint,
)
from app.services import platform_status, wazuh
from app.services.ml.model import ANOMALY_RISK_THRESHOLD

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardResponse)
def dashboard(
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    company_id = principal.company_id
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    endpoints = db.query(Endpoint).filter(Endpoint.unique_id == company_id).all()
    endpoint_names = {e.id: e.endpoint_name for e in endpoints}

    events = db.query(SecurityEvent).filter(SecurityEvent.unique_id == company_id)
    events_24h = events.filter(SecurityEvent.event_time >= day_ago).count()
    critical_24h = events.filter(
        SecurityEvent.event_time >= day_ago, SecurityEvent.severity == "Critical"
    ).count()

    anomaly_events = events.filter(SecurityEvent.risk_score >= ANOMALY_RISK_THRESHOLD)
    anomalies_24h = anomaly_events.filter(SecurityEvent.event_time >= day_ago).count()

    # Online/offline from Wazuh. If the manager is unreachable, we still render
    # the rest of the dashboard and flag the service below.
    online = offline = 0
    agent_ids = [e.wazuh_agent_id for e in endpoints]
    try:
        info = wazuh.get_agents_info(agent_ids) if agent_ids else {}
        for endpoint in endpoints:
            if (info.get(endpoint.wazuh_agent_id) or {}).get("status") == "active":
                online += 1
            else:
                offline += 1
    except wazuh.WazuhError:
        pass  # shown by the Wazuh Manager service below; the counts stay zero

    # Alerts per day, last 7 days (DB date() uses the session timezone, so the
    # buckets match the timestamps the user sees).
    today = db.query(func.current_date()).scalar()
    day_counts = dict(
        db.query(func.date(SecurityEvent.event_time), func.count())
        .filter(SecurityEvent.unique_id == company_id, SecurityEvent.event_time >= week_ago)
        .group_by(func.date(SecurityEvent.event_time))
        .all()
    )
    timeline = [
        TimelinePoint(date=(today - timedelta(days=offset)).isoformat(),
                      count=day_counts.get(today - timedelta(days=offset), 0))
        for offset in range(6, -1, -1)
    ]

    severity_7d = {"Info": 0, "Warning": 0, "Critical": 0}
    for sev, count in (
        db.query(SecurityEvent.severity, func.count())
        .filter(SecurityEvent.unique_id == company_id, SecurityEvent.event_time >= week_ago)
        .group_by(SecurityEvent.severity)
        .all()
    ):
        if sev in severity_7d:
            severity_7d[sev] = count

    recent = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.unique_id == company_id)
        .order_by(SecurityEvent.event_time.desc())
        .limit(8)
        .all()
    )
    def to_alert(e: SecurityEvent) -> RecentAlert:
        return RecentAlert(
            event_time=e.event_time,
            endpoint_name=endpoint_names.get(e.endpoint_id, "—"),
            severity=e.severity,
            event_type=e.event_type,
            rule_description=e.rule_description,
            risk_score=e.risk_score,
            risk_reason=e.risk_reason,
        )

    recent_alerts = [to_alert(e) for e in recent]
    anomalies = [
        to_alert(e)
        for e in anomaly_events.filter(SecurityEvent.event_time >= week_ago)
        .order_by(SecurityEvent.event_time.desc())
        .limit(6)
        .all()
    ]

    last_event_time = recent[0].event_time if recent else None

    # Each service is checked now, not assumed (see services/platform_status.py).
    services = {
        "api_server": platform_status.api_server(now),
        "database": platform_status.database(db),
        "wazuh_manager": platform_status.wazuh_manager(),
        "ingestion": platform_status.ingestion(last_event_time, now),
        "behavior_model": platform_status.behavior_model([(e.id, e.created_time) for e in endpoints], now),
    }

    return DashboardResponse(
        stats=DashboardStats(
            total_endpoints=len(endpoints),
            online=online,
            offline=offline,
            events_24h=events_24h,
            critical_24h=critical_24h,
            anomalies_24h=anomalies_24h,
            platform_status=platform_status.overall(services),
        ),
        severity_7d=severity_7d,
        timeline_7d=timeline,
        services=services,
        recent_alerts=recent_alerts,
        anomalies=anomalies,
    )
