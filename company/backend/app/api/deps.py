from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, joinedload

from app.core.security import KIND_COMPANY, KIND_EMPLOYEE, decode_access_token
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.employee import Employee, EmployeeRole, EmployeeStatus

bearer_scheme = HTTPBearer(auto_error=False)

PASSWORD_CHANGE_REQUIRED = "Password change required"


@dataclass
class Principal:
    """Whoever is signed in to a company's portal: the company account itself
    (username = company name) or one of that company's employees."""

    account: Account
    employee: Employee | None = None

    @property
    def company_id(self) -> int:
        return self.account.unique_id

    @property
    def company_name(self) -> str:
        return self.account.company.company_name

    @property
    def username(self) -> str:
        return self.employee.employee_username if self.employee else self.company_name

    @property
    def role(self) -> EmployeeRole:
        # The company account itself always has full control of its portal.
        return self.employee.employee_role if self.employee else EmployeeRole.ADMINISTRATOR

    @property
    def is_administrator(self) -> bool:
        return self.role == EmployeeRole.ADMINISTRATOR

    @property
    def must_change_password(self) -> bool:
        return (self.employee or self.account).must_change_password

    @property
    def password_hash(self) -> str | None:
        return (self.employee or self.account).password_hash

    def set_password_hash(self, password_hash: str) -> None:
        target = self.employee or self.account
        target.password_hash = password_hash
        target.must_change_password = False


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Principal:
    """Any signed-in user, including one who still has to replace an issued
    password. Only the change-password flow should use this directly."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized
    decoded = decode_access_token(credentials.credentials)
    if decoded is None:
        raise unauthorized
    kind, subject_id = decoded

    # Status is checked on every request, not just at login, so locking an
    # account (company in the admin panel, or employee here) cuts off
    # sessions that are already open. A locked company locks all its employees.
    if kind == KIND_COMPANY:
        account = db.query(Account).options(joinedload(Account.company)).filter(Account.id == subject_id).first()
        if account is None or account.customer_status != AccountStatus.ACTIVE:
            raise unauthorized
        return Principal(account=account)

    if kind == KIND_EMPLOYEE:
        employee = db.get(Employee, subject_id)
        if employee is None or employee.employee_status != EmployeeStatus.ACTIVE:
            raise unauthorized
        account = (
            db.query(Account)
            .options(joinedload(Account.company))
            .filter(Account.unique_id == employee.unique_id)
            .first()
        )
        if account is None or account.customer_status != AccountStatus.ACTIVE:
            raise unauthorized
        return Principal(account=account, employee=employee)

    raise unauthorized


def require_password_changed(principal: Principal = Depends(get_current_principal)) -> Principal:
    """Every company portal route except the password-change flow depends on
    this, so an issued password can't be used for anything but replacing it."""
    if principal.must_change_password:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=PASSWORD_CHANGE_REQUIRED)
    return principal


def require_administrator(principal: Principal = Depends(require_password_changed)) -> Principal:
    if not principal.is_administrator:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can manage accounts.",
        )
    return principal
