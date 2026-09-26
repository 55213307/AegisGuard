from datetime import datetime

from pydantic import BaseModel, EmailStr


class CustomerCreate(BaseModel):
    company_name: str
    contact_person: str | None = None
    contact_email: EmailStr
    state: str | None = None
    area_code: str | None = None
    contact_number: str | None = None
    remark: str | None = None


class CustomerOut(BaseModel):
    id: int
    customer_code: str
    company_name: str
    contact_person: str | None
    contact_email: str
    state: str | None
    area_code: str | None
    contact_number: str | None
    remark: str | None
    is_activated: bool
    created_at: datetime
    activated_at: datetime | None

    model_config = {"from_attributes": True}


class QueueResponse(BaseModel):
    """Full FIFO queue — the frontend decides how many of these to render."""

    total: int
    items: list[CustomerOut]
