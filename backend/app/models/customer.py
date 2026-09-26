from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Customer(Base):
    """A customer company, registered from the Customer Management page.

    Creating a customer immediately creates its first admin Account too
    (Pending), and the customer enters the activation queue (is_activated=
    False) right away — the queue is a read-only, FIFO view; the frontend
    only caps the visible window to 4 at a time.

    is_activated flips to True (see accounts.approve_account) once that
    account is approved (Active) in Account Management — that's the only
    thing that clears a customer out of the queue.
    """

    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_name: Mapped[str] = mapped_column(String(200))
    contact_person: Mapped[str | None] = mapped_column(String(120), nullable=True)
    contact_email: Mapped[str] = mapped_column(String(255))
    state: Mapped[str | None] = mapped_column(String(120), nullable=True)
    area_code: Mapped[str | None] = mapped_column(String(10), nullable=True)
    contact_number: Mapped[str | None] = mapped_column(String(30), nullable=True)
    remark: Mapped[str | None] = mapped_column(String(500), nullable=True)

    is_activated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    accounts: Mapped[list["Account"]] = relationship(back_populates="company")  # noqa: F821

    @property
    def customer_code(self) -> str:
        return f"AG-CUS-{self.id:03d}"
