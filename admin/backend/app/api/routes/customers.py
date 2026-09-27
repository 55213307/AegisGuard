from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.account import Account, AccountStatus
from app.models.activity_log import ActivityLog
from app.models.customer import Customer
from app.models.user import AdminUser
from app.schemas.customer import CustomerCreate, CustomerOut, QueueResponse

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


@router.post("", response_model=CustomerOut, status_code=201)
def create_customer(
    payload: CustomerCreate, db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)
) -> Customer:
    customer = Customer(**payload.model_dump())
    db.add(customer)
    db.flush()  # assigns customer.id for the account's FK below

    # Registering a customer immediately registers its one account, Pending
    # until approved in Account Management.
    db.add(
        Account(
            customer_name=customer.contact_name or customer.company_name,
            customer_email=customer.contact_email,
            customer_status=AccountStatus.PENDING,
            unique_id=customer.id,
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
    return customer
