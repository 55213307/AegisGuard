from datetime import datetime

from pydantic import BaseModel

from app.models.account import AccountStatus


class AccountOut(BaseModel):
    id: int
    customer_name: str
    customer_email: str
    customer_status: AccountStatus
    unique_id: int
    company_name: str
    contact_number: str | None
    remark: str | None
    operator_name: str | None
    submitted_time: datetime

    model_config = {"from_attributes": True}


class AccountListResponse(BaseModel):
    total: int
    items: list[AccountOut]


class AccountSummary(BaseModel):
    total: int
    active: int
    pending: int
    locked: int
