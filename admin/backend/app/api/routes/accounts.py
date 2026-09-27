from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.activity_log import ActivityLog
from app.models.customer import Customer
from app.models.user import AdminUser
from app.schemas.account import AccountListResponse, AccountOut, AccountSummary

router = APIRouter(prefix="/api/accounts", tags=["accounts"], dependencies=[Depends(get_current_admin)])


def _to_out(account: Account) -> AccountOut:
    return AccountOut(
        id=account.id,
        customer_name=account.customer_name,
        customer_email=account.customer_email,
        customer_status=account.customer_status,
        unique_id=account.unique_id,
        company_name=account.company.company_name,
        contact_number=account.company.contact_number,
        remark=account.company.remark,
        operator_name=account.operator.display_name if account.operator else None,
        submitted_time=account.submitted_time,
    )


@router.get("", response_model=AccountListResponse)
def list_accounts(
    status_filter: AccountStatus | None = Query(default=None, alias="status"),
    company: str | None = None,
    search: str | None = None,
    sort: str = Query(default="newest", pattern="^(newest|oldest|name)$"),
    db: Session = Depends(get_db),
) -> AccountListResponse:
    query = db.query(Account).options(joinedload(Account.company), joinedload(Account.operator))

    if status_filter is not None:
        query = query.filter(Account.customer_status == status_filter)
    if company:
        query = query.join(Customer).filter(Customer.company_name == company)
    if search:
        like = f"%{search}%"
        query = query.filter(or_(Account.customer_name.ilike(like), Account.customer_email.ilike(like)))

    if sort == "name":
        query = query.order_by(Account.customer_name.asc())
    elif sort == "oldest":
        query = query.order_by(Account.submitted_time.asc())
    else:
        query = query.order_by(Account.submitted_time.desc())

    accounts = query.all()
    return AccountListResponse(total=len(accounts), items=[_to_out(a) for a in accounts])


@router.get("/summary", response_model=AccountSummary)
def account_summary(db: Session = Depends(get_db)) -> AccountSummary:
    all_accounts = db.query(Account).all()
    return AccountSummary(
        total=len(all_accounts),
        active=sum(1 for a in all_accounts if a.customer_status == AccountStatus.ACTIVE),
        pending=sum(1 for a in all_accounts if a.customer_status == AccountStatus.PENDING),
        locked=sum(1 for a in all_accounts if a.customer_status == AccountStatus.LOCKED),
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
    account.customer_status = AccountStatus.ACTIVE
    account.admin_id = admin.id

    # This is what actually clears the customer out of the Activation Queue.
    account.company.activated_time = datetime.now(timezone.utc)

    db.add(ActivityLog(admin_id=admin.id, description=f"Approved account for \"{account.company.company_name}\""))

    db.commit()
    db.refresh(account)
    return _to_out(account)


@router.post("/{account_id}/reject", status_code=204)
def reject_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> None:
    # A rejected Pending account has no place in the UI (only Pending/Active/
    # Locked are ever shown), so rejecting removes the request outright.
    # The customer itself goes too: it has no account left after this, which
    # would otherwise strand it in the Activation Queue forever with no way
    # to leave (there's no "re-request" action — creating a customer is what
    # created this account in the first place).
    account = _get_account_or_404(account_id, db)
    customer = account.company
    db.add(ActivityLog(admin_id=admin.id, description=f"Rejected account request for \"{customer.company_name}\""))
    db.delete(account)
    db.delete(customer)
    db.commit()


@router.post("/{account_id}/lock", response_model=AccountOut)
def lock_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> AccountOut:
    account = _get_account_or_404(account_id, db)
    account.customer_status = AccountStatus.LOCKED
    account.admin_id = admin.id
    db.add(ActivityLog(admin_id=admin.id, description=f"Locked account for \"{account.company.company_name}\""))
    db.commit()
    db.refresh(account)
    return _to_out(account)


@router.post("/{account_id}/unlock", response_model=AccountOut)
def unlock_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> AccountOut:
    account = _get_account_or_404(account_id, db)
    account.customer_status = AccountStatus.ACTIVE
    account.admin_id = admin.id
    db.add(ActivityLog(admin_id=admin.id, description=f"Unlocked account for \"{account.company.company_name}\""))
    db.commit()
    db.refresh(account)
    return _to_out(account)


@router.delete("/{account_id}", status_code=204)
def delete_account(
    account_id: int, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> None:
    # Same reasoning as reject_account: an account never exists without its
    # customer, so deleting only the account would leave that customer with
    # zero accounts — indistinguishable from "not yet activated" — and it
    # would be stuck in the Activation Queue forever with no way out.
    account = _get_account_or_404(account_id, db)
    customer = account.company
    db.add(ActivityLog(admin_id=admin.id, description=f"Deleted account for \"{customer.company_name}\""))
    db.delete(account)
    db.delete(customer)
    db.commit()
