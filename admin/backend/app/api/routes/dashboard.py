from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.activity_log import ActivityLog
from app.models.customer import Customer
from app.schemas.dashboard import (
    ActivityListResponse,
    ActivityOut,
    CustomerGrowthResponse,
    DashboardSummary,
    GrowthPoint,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"], dependencies=[Depends(get_current_admin)])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    total_customers = db.query(Customer).count()
    active_customers = (
        db.query(Customer).join(Account).filter(Account.customer_status == AccountStatus.ACTIVE).count()
    )

    # The dashboard's stat cards ("Monitoring Accounts", "Pending Accounts",
    # "Locked Accounts") mirror the account statuses shown on the Account
    # Management page.
    pending_accounts = db.query(Account).filter(Account.customer_status == AccountStatus.PENDING).count()
    locked_accounts = db.query(Account).filter(Account.customer_status == AccountStatus.LOCKED).count()
    monitoring_accounts = db.query(Account).filter(Account.customer_status == AccountStatus.ACTIVE).count()

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


@router.get("/customer-growth", response_model=CustomerGrowthResponse)
def customer_growth(
    days: int = Query(default=14, ge=1, le=90), db: Session = Depends(get_db)
) -> CustomerGrowthResponse:
    """Daily count of new customers over the trailing `days` window.

    Feeds the "Customers Overview" chart. Days with no signups are filled
    in with 0 so the chart gets a continuous x-axis rather than gaps.
    """
    since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date()

    day_col = func.date(Customer.created_at)
    rows = (
        db.query(day_col.label("day"), func.count(Customer.id))
        .filter(day_col >= since)
        .group_by("day")
        .all()
    )
    counts = {row[0]: row[1] for row in rows}

    points = [
        GrowthPoint(date=since + timedelta(days=offset), count=counts.get(since + timedelta(days=offset), 0))
        for offset in range(days)
    ]
    return CustomerGrowthResponse(points=points)


@router.get("/activities", response_model=ActivityListResponse)
def recent_activities(
    limit: int = Query(default=10, ge=1, le=50), db: Session = Depends(get_db)
) -> ActivityListResponse:
    logs = (
        db.query(ActivityLog)
        .options(joinedload(ActivityLog.admin))
        .order_by(ActivityLog.created_time.desc())
        .limit(limit)
        .all()
    )
    return ActivityListResponse(
        items=[
            ActivityOut(
                id=log.id,
                description=log.description,
                admin_name=log.admin.display_name if log.admin else None,
                created_time=log.created_time,
            )
            for log in logs
        ]
    )
