from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.customer import Customer
from app.models.user import AdminUser
from app.schemas.account import AccountListResponse, AccountOut, AccountSummary

router = APIRouter(prefix="/api/accounts", tags=["accounts"], dependencies=[Depends(get_current_admin)])


def _to_out(account: Account) -> AccountOut:
    return AccountOut(
        id=account.id,
        name=account.name,
        email=account.email,
        role=account.role,
        status=account.status,
        remarks=account.remarks,
        company_id=account.company_id,
        company_name=account.company.company_name,
        operator_name=account.operator.display_name if account.operator else None,
        submitted_at=account.submitted_at,
    )


@router.get("", response_model=AccountListResponse)
def list_accounts(
    status_filter: AccountStatus | None = Query(default=None, alias="status"),
    company: str | None = None,
    role: str | None = None,
    search: str | None = None,
    sort: str = Query(default="newest", pattern="^(newest|oldest|name)$"),
    db: Session = Depends(get_db),
) -> AccountListResponse:
    query = db.query(Account).options(joinedload(Account.company), joinedload(Account.operator))

    if status_filter is not None:
        query = query.filter(Account.status == status_filter)
    if company:
        query = query.join(Customer).filter(Customer.company_name == company)
    if role:
        query = query.filter(Account.role == role)
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Account.name.ilike(like), Account.email.ilike(like)))

    if sort == "name":
        query = query.order_by(Account.name.asc())
    elif sort == "oldest":
        query = query.order_by(Account.submitted_at.asc())
    else:
        query = query.order_by(Account.submitted_at.desc())

    accounts = query.all()
    return AccountListResponse(total=len(accounts), items=[_to_out(a) for a in accounts])


@router.get("/summary", response_model=AccountSummary)
def account_summary(db: Session = Depends(get_db)) -> AccountSummary:
    all_accounts = db.query(Account).all()
    return AccountSummary(
        total=len(all_accounts),
        active=sum(1 for a in all_accounts if a.status == AccountStatus.ACTIVE),
        pending=sum(1 for a in all_accounts if a.status == AccountStatus.PENDING),
        locked=sum(1 for a in all_accounts if a.status == AccountStatus.LOCKED),
    )


def _get_account_or_404(account_id: int, db: Session) -> Account:
    account = (
        db.query(Account)
        .options(joinedload(Account.company), joinedload(Account.operator))
        .filter(Account.id == account_id)
        .first()
    )
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return account


@router.get("/{account_id}", response_model=AccountOut)
def get_account(account_id: int, db: Session = Depends(get_db)) -> AccountOut:
    return _to_out(_get_account_or_404(account_id, db))


@router.post("/{account_id}/approve", response_model=AccountOut)
def approve_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> AccountOut:
    account = _get_account_or_404(account_id, db)
    account.status = AccountStatus.ACTIVE
    account.operator_id = admin.id

    # This is what actually clears the customer out of the Activation Queue.
    account.company.is_activated = True
    account.company.activated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(account)
    return _to_out(account)


@router.post("/{account_id}/reject", status_code=204)
def reject_account(account_id: int, db: Session = Depends(get_db)) -> None:
    # A rejected Pending account has no place in the UI (only Pending/Active/
    # Locked are ever shown), so rejecting removes the request outright.
    # The customer itself goes too: it has no account left after this, which
    # would otherwise strand it in the Activation Queue forever with no way
    # to leave (there's no "re-request" action — creating a customer is what
    # created this account in the first place).
    account = _get_account_or_404(account_id, db)
    customer = account.company
    db.delete(account)
    db.delete(customer)
    db.commit()


@router.post("/{account_id}/lock", response_model=AccountOut)
def lock_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> AccountOut:
    account = _get_account_or_404(account_id, db)
    account.status = AccountStatus.LOCKED
    account.operator_id = admin.id
    db.commit()
    db.refresh(account)
    return _to_out(account)


@router.post("/{account_id}/unlock", response_model=AccountOut)
def unlock_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> AccountOut:
    account = _get_account_or_404(account_id, db)
    account.status = AccountStatus.ACTIVE
    account.operator_id = admin.id
    db.commit()
    db.refresh(account)
    return _to_out(account)


@router.delete("/{account_id}", status_code=204)
def delete_account(account_id: int, db: Session = Depends(get_db)) -> None:
    account = _get_account_or_404(account_id, db)
    db.delete(account)
    db.commit()
