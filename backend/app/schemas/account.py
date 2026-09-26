from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.models.account import AccountRole, AccountStatus


class AccountOut(BaseModel):
    id: int
    name: str
    email: str
    role: AccountRole
    status: AccountStatus
    remarks: str | None
    company_id: int
    company_name: str
    operator_name: str | None
    submitted_at: datetime

    model_config = {"from_attributes": True}


class AccountListResponse(BaseModel):
    total: int
    items: list[AccountOut]


class AccountCreate(BaseModel):
    name: str
    email: EmailStr
    role: AccountRole
    company_id: int
    remarks: str | None = None


class AccountSummary(BaseModel):
    total: int
    active: int
    pending: int
    locked: int
