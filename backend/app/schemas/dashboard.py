from pydantic import BaseModel


class DashboardSummary(BaseModel):
    total_customers: int
    active_customers: int
    monitoring_accounts: int
    locked_accounts: int
    pending_accounts: int
    platform_status: str
