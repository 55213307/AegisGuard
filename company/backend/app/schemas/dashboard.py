from datetime import datetime

from pydantic import BaseModel


class DashboardStats(BaseModel):
    total_endpoints: int
    online: int
    offline: int
    events_24h: int
    critical_24h: int
    anomalies_24h: int
    platform_status: str


class TimelinePoint(BaseModel):
    date: str
    count: int


class ServiceStatus(BaseModel):
    status: str  # ok / warn / down / unknown
    label: str
    detail: str | None = None  # what is wrong (or a useful fact when nothing is)


class RecentAlert(BaseModel):
    event_time: datetime
    endpoint_name: str
    severity: str
    event_type: str | None
    rule_description: str | None
    risk_score: int | None = None
    risk_reason: str | None = None


class DashboardResponse(BaseModel):
    stats: DashboardStats
    severity_7d: dict[str, int]
    timeline_7d: list[TimelinePoint]
    services: dict[str, ServiceStatus]
    recent_alerts: list[RecentAlert]
    anomalies: list[RecentAlert]  # latest behavioral anomalies (risk at/above the alert threshold)
