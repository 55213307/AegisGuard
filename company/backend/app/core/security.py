from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

TOKEN_SCOPE = "company"
TOKEN_KIND = "company"


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(account_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": str(account_id), "kind": TOKEN_KIND, "scope": TOKEN_SCOPE, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> int | None:
    """Returns the company's accounts.id the token was issued for."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None
    # Tokens from the old employee logins carried kind "employee" with an
    # employees.id as sub; they must never be read as a company account id.
    if payload.get("scope") != TOKEN_SCOPE or payload.get("kind") != TOKEN_KIND:
        return None
    try:
        return int(payload.get("sub"))
    except (TypeError, ValueError):
        return None
