from datetime import datetime

from pydantic import BaseModel, EmailStr


class CustomerCreate(BaseModel):
    company_name: str
    contact_name: str | None = None
    contact_email: EmailStr
    contact_number: str | None = None
    remark: str | None = None


class CustomerOut(BaseModel):
    id: int
    customer_code: str
    company_name: str
    contact_name: str | None
    contact_email: str
    contact_number: str | None
    remark: str | None
    created_at: datetime
    activated_time: datetime | None

    model_config = {"from_attributes": True}


class PortalCredentials(BaseModel):
    """Company portal login details. initial_password is only ever returned
    at the moment it's generated — only its hash is stored."""

    login_url: str
    login_username: str
    initial_password: str


class CustomerCreatedOut(CustomerOut):
    credentials: PortalCredentials


class QueueResponse(BaseModel):
    """Full FIFO queue — the frontend decides how many of these to render."""

    total: int
    items: list[CustomerOut]
