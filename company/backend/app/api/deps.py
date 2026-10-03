from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.account import Account, AccountStatus

bearer_scheme = HTTPBearer(auto_error=False)

PASSWORD_CHANGE_REQUIRED = "Password change required"


@dataclass
class Principal:
    """The signed-in company account (username = company name). It's the
    only identity that logs into the portal; employees don't sign in."""

    account: Account

    @property
    def company_id(self) -> int:
        return self.account.unique_id

    @property
    def company_name(self) -> str:
        return self.account.company.company_name

    @property
    def must_change_password(self) -> bool:
        return self.account.must_change_password

    @property
    def password_hash(self) -> str | None:
        return self.account.password_hash

    def set_password_hash(self, password_hash: str) -> None:
        self.account.password_hash = password_hash
        self.account.must_change_password = False


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Principal:
    """Any signed-in company, including one that still has to replace its
    issued password. Only the change-password flow should use this directly."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized
    account_id = decode_access_token(credentials.credentials)
    if account_id is None:
        raise unauthorized

    # Checked on every request, not just at login, so locking the company in
    # the admin panel cuts off sessions that are already open.
    account = db.query(Account).options(joinedload(Account.company)).filter(Account.id == account_id).first()
    if account is None or account.customer_status != AccountStatus.ACTIVE:
        raise unauthorized
    return Principal(account=account)


def require_password_changed(principal: Principal = Depends(get_current_principal)) -> Principal:
    """Every company portal route except the password-change flow depends on
    this, so the issued password can't be used for anything but replacing it."""
    if principal.must_change_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=PASSWORD_CHANGE_REQUIRED)
    return principal
