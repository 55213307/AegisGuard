from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.core.security import (
    build_company_login_url,
    generate_initial_password,
    generate_login_token,
    hash_password,
)
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.activity_log import ActivityLog
from app.models.customer import Customer
from app.models.user import AdminUser
from app.schemas.customer import (
    CustomerCreate,
    CustomerCreatedOut,
    CustomerOut,
    PortalCredentials,
    QueueResponse,
)

router = APIRouter(prefix="/api/customers", tags=["customers"], dependencies=[Depends(get_current_admin)])


@router.get("", response_model=list[CustomerOut])
def list_customers(db: Session = Depends(get_db)) -> list[Customer]:
    return db.query(Customer).order_by(Customer.company_name).all()


@router.get("/queue", response_model=QueueResponse)
def get_activation_queue(db: Session = Depends(get_db)) -> QueueResponse:
    """Read-only FIFO view of customers whose account isn't Active yet.

    A customer enters this queue the moment it's created (its account starts
    life as Pending) and only drops out once that account is approved
    (status Active) in Account Management — there's no action to take here.

    The frontend (customer-management.js) only ever renders the first 4 of
    this list and shows a "+N more waiting" note for the rest — that display
    cap is a UI decision, not something enforced here.
    """
    items = (
        db.query(Customer)
        .outerjoin(
            Account,
            (Account.unique_id == Customer.id) & (Account.customer_status == AccountStatus.ACTIVE),
        )
        .filter(Account.id.is_(None))
        .order_by(Customer.created_at.asc())
        .all()
    )
    return QueueResponse(total=len(items), items=items)


@router.post("", response_model=CustomerCreatedOut, status_code=201)
def create_customer(
    payload: CustomerCreate, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> CustomerCreatedOut:
    customer = Customer(**payload.model_dump())
    db.add(customer)
    db.flush()  # assigns customer.id for the account's FK below

    # Registering a customer immediately registers its one account, Pending
    # until approved in Account Management. Its portal credentials are issued
    # now, but login is refused until the account is Active.
    initial_password = generate_initial_password()
    login_token = generate_login_token()
    db.add(
        Account(
            customer_name=customer.contact_name or customer.company_name,
            customer_email=customer.contact_email,
            customer_status=AccountStatus.PENDING,
            unique_id=customer.id,
            login_token=login_token,
            password_hash=hash_password(initial_password),
            must_change_password=True,
        )
    )
    db.add(
        ActivityLog(
            admin_id=admin.id,
            description=f"Registered new customer \"{customer.company_name}\"",
        )
    )

    db.commit()
    db.refresh(customer)
    return CustomerCreatedOut(
        **CustomerOut.model_validate(customer).model_dump(),
        credentials=PortalCredentials(
            login_url=build_company_login_url(login_token),
            login_username=customer.company_name,
            initial_password=initial_password,
        ),
    )
