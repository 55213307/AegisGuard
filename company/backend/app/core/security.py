import secrets
import string
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

TOKEN_SCOPE = "company"
KIND_COMPANY = "company"
KIND_EMPLOYEE = "employee"

# Look-alike characters (0/O, 1/l/I) are left out because these passwords
# are handed to people who type them in by hand.
_PASSWORD_ALPHABET = "".join(c for c in string.ascii_letters + string.digits if c not in "0O1lI")


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def generate_initial_password(length: int = 12) -> str:
    while True:
        password = "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))
        if any(c.isalpha() for c in password) and any(c.isdigit() for c in password):
            return password


def create_access_token(kind: str, subject_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": str(subject_id), "kind": kind, "scope": TOKEN_SCOPE, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> tuple[str, int] | None:
    """Returns (kind, id), where kind says whether id is an accounts.id
    (the company itself) or an employees.id."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None
    if payload.get("scope") != TOKEN_SCOPE or payload.get("kind") not in (KIND_COMPANY, KIND_EMPLOYEE):
        return None
    try:
        return payload["kind"], int(payload.get("sub"))
    except (TypeError, ValueError):
        return None
