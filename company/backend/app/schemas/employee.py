import re
from datetime import datetime

from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.models.employee import EmployeeStatus

_USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,50}$")


_CLOCK = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def _clock_time(value: str) -> str:
    match = _CLOCK.match(value.strip())
    if not match:
        raise ValueError("Use a 24-hour time such as 09:00.")
    return f"{int(match.group(1)):02d}:{match.group(2)}"


class EmployeeCreate(BaseModel):
    employee_username: str
    employee_email: EmailStr
    # What the behavior model treats as ordinary: "auto" (the default) learns it from the
    # computer's own activity; IT and security staff use command prompts and admin tools
    # every day, clerks never do, and these can be declared up front.
    department: Literal["auto", "office", "it", "security"] = "auto"
    # Optional: the working hours, when the company already knows them. Left out,
    # the behavior model learns them from the computer's activity.
    work_start: str | None = None
    work_end: str | None = None

    @field_validator("work_start", "work_end")
    @classmethod
    def optional_clock_time(cls, value: str | None) -> str | None:
        return _clock_time(value) if value not in (None, "") else None

    @model_validator(mode="after")
    def both_or_neither(self) -> "EmployeeCreate":
        if (self.work_start is None) != (self.work_end is None):
            raise ValueError("Give both the start and the end of the working day, or neither.")
        if self.work_start is not None and self.work_start == self.work_end:
            raise ValueError("The end of the working day must differ from the start.")
        return self

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
    # Set while the account is Locked: why, and since when (the computer is locked too).
    lock_reason: str | None = None
    locked_at: datetime | None = None
    # Set while overtime is approved: until when.
    overtime_until: datetime | None = None
    # Working hours the company declared ("HH:MM"); None: learned from the activity.
    work_start: str | None = None
    work_end: str | None = None
    department: str = "auto"
    # The computer's last setup window: while an installer is at work its events
    # aren't checked (they would look like admin tooling). Both ends, or None.
    maintenance_from: datetime | None = None
    maintenance_until: datetime | None = None
    # How far the behavior model has got in learning this computer: "learning" or
    # "learned" (None: not trained yet), with the real actions seen and needed.
    learning_state: str | None = None
    learning_actions: int | None = None
    learning_needed: int | None = None
    # Highest behavioral risk score (0-100) of this computer's events in the
    # last 24 hours; None when it has none scored.
    risk_24h: int | None = None
    # Highest risk score of the last 15 minutes if it reached the alert
    # threshold, else None: the computer has an active anomaly right now.
    risk_active: int | None = None


class OvertimeRequest(BaseModel):
    minutes: int = Field(ge=1, le=720)


class DepartmentRequest(BaseModel):
    department: Literal["auto", "office", "it", "security"]


class WorkHoursRequest(BaseModel):
    start: str
    end: str

    @field_validator("start", "end")
    @classmethod
    def clock_time(cls, value: str) -> str:
        return _clock_time(value)

    @field_validator("end")
    @classmethod
    def not_the_same(cls, value: str, info) -> str:
        if info.data.get("start") == value:
            raise ValueError("The end of the working day must differ from the start.")
        return value


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
    risk_score: int | None
    risk_reason: str | None

    model_config = {"from_attributes": True}


class SecurityEventListResponse(BaseModel):
    items: list[SecurityEventOut]
