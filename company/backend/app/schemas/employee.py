import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator

from app.models.employee import EmployeeRole, EmployeeStatus
from app.schemas.auth import check_password_strength

_USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,50}$")


class EmployeeCreate(BaseModel):
    employee_username: str
    employee_email: EmailStr
    employee_role: EmployeeRole = EmployeeRole.EMPLOYEE
    # Optional: left empty, a random one is generated. Either way the
    # employee must replace it on first login.
    temporary_password: str | None = None

    @field_validator("employee_username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.strip().lower()
        if not _USERNAME_PATTERN.match(value):
            raise ValueError(
                "Username must be 3-50 characters: letters, numbers, dots, underscores or hyphens."
            )
        return value

    @field_validator("temporary_password")
    @classmethod
    def check_temporary_password(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        return check_password_strength(value)


class EmployeeOut(BaseModel):
    id: int
    employee_username: str
    employee_email: str
    employee_role: EmployeeRole
    employee_status: EmployeeStatus
    must_change_password: bool
    last_login_time: datetime | None
    created_time: datetime

    model_config = {"from_attributes": True}


class EmployeeListResponse(BaseModel):
    total: int
    items: list[EmployeeOut]


class EmployeeCredentials(BaseModel):
    """initial_password is only returned when it's set — only its hash is stored."""

    employee_username: str
    initial_password: str


class EmployeeCreatedOut(EmployeeOut):
    credentials: EmployeeCredentials
