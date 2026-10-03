from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import Principal, get_current_principal
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.account import Account, AccountStatus
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

# Checked against when the account can't be found or has no password yet, so
# those cases take as long to reject as a wrong password (no timing hint).
_DUMMY_HASH = hash_password("not-a-real-password-0")


def _account_by_token(login_token: str, db: Session) -> Account | None:
    return (
        db.query(Account)
        .options(joinedload(Account.company))
        .filter(Account.login_token == login_token)
        .first()
    )


def _user_out(principal: Principal) -> LoginUser:
    name = principal.company_name
    return LoginUser(username=name, display_name=name, company_name=name)


@router.get("/portal/{login_token}", response_model=PortalInfo)
def portal_info(login_token: str, db: Session = Depends(get_db)) -> PortalInfo:
    """Lets the login page show which company this login link belongs to."""
    account = _account_by_token(login_token, db)
    if account is None:
        raise HTTPException(status_code=404, detail="This login link is not valid.")
    return PortalInfo(company_name=account.company.company_name)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    account = _account_by_token(payload.login_token, db)
    username_ok = (
        account is not None
        and payload.username.strip().casefold() == account.company.company_name.strip().casefold()
    )
    password_hash = account.password_hash if username_ok else None

    # Wrong link, wrong username, wrong password and "no password issued yet"
    # all get the same message, so a failed attempt reveals nothing about
    # which part was wrong.
    password_ok = verify_password(payload.password, password_hash or _DUMMY_HASH)
    if password_hash is None or not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    # Status is only revealed once the credentials are proven correct.
    if account.customer_status == AccountStatus.PENDING:
        raise HTTPException(status_code=403, detail=f"This company account has not been activated yet. {CONTACT_ADMIN}")
    if account.customer_status == AccountStatus.LOCKED:
        raise HTTPException(status_code=403, detail=f"This company account is locked. {CONTACT_ADMIN}")

    principal = Principal(account=account)
    return LoginResponse(
        access_token=create_access_token(account.id),
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
