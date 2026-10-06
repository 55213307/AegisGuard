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
from app.services import wazuh

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

    # Online/offline from Wazuh. If the manager is unreachable, we still render
    # the rest of the dashboard and flag the service below.
    online = offline = 0
    wazuh_ok = True
    agent_ids = [e.wazuh_agent_id for e in endpoints]
    try:
        info = wazuh.get_agents_info(agent_ids) if agent_ids else {}
        for endpoint in endpoints:
            if (info.get(endpoint.wazuh_agent_id) or {}).get("status") == "active":
                online += 1
            else:
                offline += 1
    except wazuh.WazuhError:
        wazuh_ok = False

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
    recent_alerts = [
        RecentAlert(
            event_time=e.event_time,
            endpoint_name=endpoint_names.get(e.endpoint_id, "—"),
            severity=e.severity,
            event_type=e.event_type,
            rule_description=e.rule_description,
        )
        for e in recent
    ]

    last_event_time = recent[0].event_time if recent else None
    ingestion_active = last_event_time is not None and last_event_time >= now - timedelta(hours=1)

    services = {
        "api_server": ServiceStatus(status="ok", label="Operational"),
        "database": ServiceStatus(status="ok", label="Operational"),
        "wazuh_manager": ServiceStatus(
            status="ok" if wazuh_ok else "warn",
            label="Connected" if wazuh_ok else "Unreachable",
        ),
        "ingestion": ServiceStatus(
            status="ok" if ingestion_active else "warn",
            label="Active" if ingestion_active else "No recent events",
        ),
    }

    return DashboardResponse(
        stats=DashboardStats(
            total_endpoints=len(endpoints),
            online=online,
            offline=offline,
            events_24h=events_24h,
            critical_24h=critical_24h,
            platform_status="Operational" if wazuh_ok else "Degraded",
        ),
        severity_7d=severity_7d,
        timeline_7d=timeline,
        services=services,
        recent_alerts=recent_alerts,
    )
