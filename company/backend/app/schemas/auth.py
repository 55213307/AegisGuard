import re

from pydantic import BaseModel, field_validator


def check_password_strength(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ValueError("Password must contain both letters and numbers.")
    return value


class PortalInfo(BaseModel):
    company_name: str


class LoginRequest(BaseModel):
    login_token: str
    username: str
    password: str


class LoginUser(BaseModel):
    username: str
    display_name: str
    company_name: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_change_password: bool
    user: LoginUser


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_strength(cls, value: str) -> str:
        return check_password_strength(value)


class MeResponse(LoginUser):
    must_change_password: bool
