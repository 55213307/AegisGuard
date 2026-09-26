from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.customer import Customer
from app.schemas.dashboard import DashboardSummary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_admin)])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    total_customers = db.query(Customer).count()
    active_customers = db.query(Customer).filter(Customer.is_activated.is_(True)).count()

    # The dashboard's stat cards ("Monitoring Accounts", "Pending Accounts",
    # "Locked Accounts") mirror the account statuses shown on the Account
    # Management page.
    pending_accounts = db.query(Account).filter(Account.status == AccountStatus.PENDING).count()
    locked_accounts = db.query(Account).filter(Account.status == AccountStatus.LOCKED).count()
    monitoring_accounts = db.query(Account).filter(Account.status == AccountStatus.ACTIVE).count()

    # TODO: wire this up to a real health check (Wazuh / worker liveness)
    # once that integration exists — for now it just reports the API is up.
    platform_status = "Operational"

    return DashboardSummary(
        total_customers=total_customers,
        active_customers=active_customers,
        monitoring_accounts=monitoring_accounts,
        locked_accounts=locked_accounts,
        pending_accounts=pending_accounts,
        platform_status=platform_status,
    )
