import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator

from app.models.employee import EmployeeStatus

_USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,50}$")


class EmployeeCreate(BaseModel):
    employee_username: str
    employee_email: EmailStr

    @field_validator("employee_username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.strip().lower()
        if not _USERNAME_PATTERN.match(value):
            raise ValueError(
                "Username must be 3-50 characters: letters, numbers, dots, underscores or hyphens."
            )
        return value


class EmployeeOut(BaseModel):
    """An employee plus their computer's live state from Wazuh.

    endpoint_status is one of: "Not installed" (no installer run yet),
    "Connecting", "Online", "Offline", or "Unknown" (Wazuh unreachable).
    The ip/os/version/last-seen fields are None until the computer has
    reported in at least once.
    """

    id: int
    employee_username: str
    employee_email: str
    employee_status: EmployeeStatus
    created_time: datetime
    endpoint_name: str | None
    endpoint_status: str
    ip_address: str | None
    os_name: str | None
    agent_version: str | None
    last_seen_time: datetime | None


class EmployeeListResponse(BaseModel):
    total: int
    items: list[EmployeeOut]


class SecurityEventOut(BaseModel):
    id: int
    event_time: datetime
    severity: str
    event_type: str | None
    rule_description: str | None
    event_user: str | None
    windows_event_id: str | None

    model_config = {"from_attributes": True}


class SecurityEventListResponse(BaseModel):
    items: list[SecurityEventOut]
