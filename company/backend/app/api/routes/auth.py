from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import Principal, get_current_principal
from app.core.security import (
    KIND_COMPANY,
    KIND_EMPLOYEE,
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.employee import Employee, EmployeeStatus
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    LoginUser,
    MeResponse,
    PortalInfo,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

INVALID_CREDENTIALS = "Username or password wrong, please try again."
CONTACT_ADMIN = "Please contact your AegisGuard administrator."

# Checked against when the username doesn't exist, so an unknown user takes
# as long to reject as a wrong password (no timing hint about valid usernames).
_DUMMY_HASH = hash_password("not-a-real-password-0")


def _account_by_token(login_token: str, db: Session) -> Account | None:
    return (
        db.query(Account)
        .options(joinedload(Account.company))
        .filter(Account.login_token == login_token)
        .first()
    )


def _user_out(principal: Principal) -> LoginUser:
    return LoginUser(
        username=principal.username,
        display_name=principal.username,
        company_name=principal.company_name,
        role=principal.role,
        can_manage_accounts=principal.is_administrator,
    )


@router.get("/portal/{login_token}", response_model=PortalInfo)
def portal_info(login_token: str, db: Session = Depends(get_db)) -> PortalInfo:
    """Lets the login page show which company this login link belongs to."""
    account = _account_by_token(login_token, db)
    if account is None:
        raise HTTPException(status_code=404, detail="This login link is not valid.")
    return PortalInfo(company_name=account.company.company_name)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    account = _account_by_token(payload.login_token, db)
    if account is None:
        verify_password(payload.password, _DUMMY_HASH)
        raise invalid

    # The company name signs in as the company account itself; any other
    # username is looked up among that company's employees.
    username = payload.username.strip()
    employee = None
    if username.casefold() == account.company.company_name.strip().casefold():
        password_hash = account.password_hash
    else:
        employee = (
            db.query(Employee)
            .filter(Employee.unique_id == account.unique_id, Employee.employee_username == username.lower())
            .first()
        )
        password_hash = employee.password_hash if employee else None

    # Wrong link, unknown user, wrong password and "no password issued yet"
    # all get the same message, so a failed attempt reveals nothing about
    # which part was wrong.
    password_ok = verify_password(payload.password, password_hash or _DUMMY_HASH)
    if password_hash is None or not password_ok:
        raise invalid

    # Status is only revealed once the credentials are proven correct. A
    # company that isn't Active blocks its employees too.
    if account.customer_status == AccountStatus.PENDING:
        raise HTTPException(status_code=403, detail=f"This company account has not been activated yet. {CONTACT_ADMIN}")
    if account.customer_status == AccountStatus.LOCKED:
        raise HTTPException(status_code=403, detail=f"This company account is locked. {CONTACT_ADMIN}")
    if employee is not None and employee.employee_status == EmployeeStatus.LOCKED:
        raise HTTPException(
            status_code=403, detail="Your account is locked. Please contact your company administrator."
        )

    if employee is not None:
        employee.last_login_time = datetime.now(timezone.utc)
        db.commit()
        token = create_access_token(KIND_EMPLOYEE, employee.id)
    else:
        token = create_access_token(KIND_COMPANY, account.id)

    principal = Principal(account=account, employee=employee)
    return LoginResponse(
        access_token=token,
        must_change_password=principal.must_change_password,
        user=_user_out(principal),
    )


@router.post("/change-password", status_code=204)
def change_password(
    payload: ChangePasswordRequest,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> None:
    if not verify_password(payload.current_password, principal.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="New password must be different from the current one.")

    principal.set_password_hash(hash_password(payload.new_password))
    db.commit()


@router.get("/me", response_model=MeResponse)
def me(principal: Principal = Depends(get_current_principal)) -> MeResponse:
    return MeResponse(**_user_out(principal).model_dump(), must_change_password=principal.must_change_password)
