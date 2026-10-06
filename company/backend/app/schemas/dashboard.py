from datetime import datetime

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_endpoints: int
    online: int
    offline: int
    events_24h: int
    critical_24h: int
    platform_status: str


class TimelinePoint(BaseModel):
    date: str
    count: int


class ServiceStatus(BaseModel):
    status: str  # ok / warn / down
    label: str


class RecentAlert(BaseModel):
    event_time: datetime
    endpoint_name: str
    severity: str
    event_type: str | None
    rule_description: str | None


class DashboardResponse(BaseModel):
    stats: DashboardStats
    severity_7d: dict[str, int]
    timeline_7d: list[TimelinePoint]
    services: dict[str, ServiceStatus]
    recent_alerts: list[RecentAlert]
