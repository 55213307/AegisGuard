from datetime import date, datetime

from pydantic import BaseModel


class DashboardSummary(BaseModel):
    total_customers: int
    active_customers: int
    monitoring_accounts: int
    locked_accounts: int
    pending_accounts: int
    platform_status: str


class GrowthPoint(BaseModel):
    date: date
    count: int


class CustomerGrowthResponse(BaseModel):
    points: list[GrowthPoint]


class ActivityOut(BaseModel):
    id: int
    description: str
    admin_name: str | None
    created_time: datetime

    model_config = {"from_attributes": True}


class ActivityListResponse(BaseModel):
    items: list[ActivityOut]
