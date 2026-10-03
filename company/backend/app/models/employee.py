import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class EmployeeStatus(str, enum.Enum):
    ACTIVE = "Active"
    LOCKED = "Locked"


class Employee(Base):
    """An employee whose computer the company monitors, managed by the company
    account on the portal's Account Management page. Employees don't sign in
    anywhere; each one has a single monitored computer (see Endpoint).

    Owned by this backend (migrations in company/backend/alembic). Deleting
    the company in the admin panel removes its employees via ON DELETE CASCADE.
    """

    __tablename__ = "employees"
    __table_args__ = (UniqueConstraint("unique_id", "employee_username", name="uq_employees_company_username"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    # Stored lowercased, so uniqueness within a company is case-insensitive.
    employee_username: Mapped[str] = mapped_column(String(50))
    employee_email: Mapped[str] = mapped_column(String(255))
    employee_status: Mapped[EmployeeStatus] = mapped_column(
        Enum(EmployeeStatus, native_enum=False), default=EmployeeStatus.ACTIVE
    )
    created_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    company: Mapped["Customer"] = relationship()  # noqa: F821
    endpoint: Mapped["Endpoint | None"] = relationship(back_populates="employee", uselist=False)  # noqa: F821
