from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.account import Account, AccountRole, AccountStatus
from app.models.customer import Customer
from app.schemas.customer import CustomerCreate, CustomerOut, QueueResponse

router = APIRouter(prefix="/api/customers", tags=["customers"], dependencies=[Depends(get_current_admin)])


@router.get("", response_model=list[CustomerOut])
def list_customers(db: Session = Depends(get_db)) -> list[Customer]:
    return db.query(Customer).order_by(Customer.company_name).all()


@router.get("/queue", response_model=QueueResponse)
def get_activation_queue(db: Session = Depends(get_db)) -> QueueResponse:
    """Read-only FIFO view of customers whose admin account isn't Active yet.

    A customer enters this queue the moment it's created (its admin account
    starts life as Pending) and only drops out once that account is approved
    (status Active) in Account Management — there's no action to take here.

    The frontend (customer-management.js) only ever renders the first 4 of
    this list and shows a "+N more waiting" note for the rest — that display
    cap is a UI decision, not something enforced here.
    """
    items = (
        db.query(Customer)
        .outerjoin(
            Account,
            (Account.company_id == Customer.id) & (Account.status == AccountStatus.ACTIVE),
        )
        .filter(Account.id.is_(None))
        .order_by(Customer.created_at.asc())
        .all()
    )
    return QueueResponse(total=len(items), items=items)


@router.post("", response_model=CustomerOut, status_code=201)
def create_customer(payload: CustomerCreate, db: Session = Depends(get_db)) -> Customer:
    customer = Customer(**payload.model_dump())
    db.add(customer)
    db.flush()  # assigns customer.id for the account's FK below

    # Registering a customer immediately registers its first administrator
    # account too, Pending until approved in Account Management.
    db.add(
        Account(
            name=customer.contact_person or customer.company_name,
            email=customer.contact_email,
            role=AccountRole.COMPANY_ADMIN,
            status=AccountStatus.PENDING,
            company_id=customer.id,
        )
    )

    db.commit()
    db.refresh(customer)
    return customer
