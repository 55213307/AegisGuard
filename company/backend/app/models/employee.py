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
    # Why and since when the account (and so the employee's computer) is locked.
    lock_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Which department they work in (features.DEPARTMENTS): "auto" learns from their own
    # activity; the others declare whether command-line and admin tools are ordinary.
    department: Mapped[str] = mapped_column(String(20), default="auto", server_default="auto")
    # While an administrator has approved overtime (see services/overtime.py).
    overtime_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Working hours the company declared ("HH:MM", local time); both None = learn them.
    work_start: Mapped[str | None] = mapped_column(String(5), nullable=True)
    work_end: Mapped[str | None] = mapped_column(String(5), nullable=True)

    company: Mapped["Customer"] = relationship()  # noqa: F821
    # cascade + passive_deletes so deleting an employee deletes its endpoint
    # (and, via the DB's ON DELETE CASCADE, that endpoint's security_events)
    # instead of trying to null the endpoint's NOT NULL employee_id FK.
    endpoint: Mapped["Endpoint | None"] = relationship(  # noqa: F821
        back_populates="employee",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
