from datetime import datetime

from pydantic import BaseModel


class SecurityLogItem(BaseModel):
    timestamp: datetime
    endpoint_name: str
    user: str | None
    event_type: str | None
    severity: str  # lowercase: critical / warning / info
    description: str | None


class SecurityLogListResponse(BaseModel):
    items: list[SecurityLogItem]
    total: int
