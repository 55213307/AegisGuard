import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint, func, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class EmployeeRole(str, enum.Enum):
    EMPLOYEE = "Employee"
    ADMINISTRATOR = "Administrator"


class EmployeeStatus(str, enum.Enum):
    ACTIVE = "Active"
    LOCKED = "Locked"


class Employee(Base):
    """A staff member's own login to their company's portal, managed from the
    portal's Account Management page. Signs in through the company's login
    link like the company account does.

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
    employee_role: Mapped[EmployeeRole] = mapped_column(Enum(EmployeeRole, native_enum=False))
    employee_status: Mapped[EmployeeStatus] = mapped_column(
        Enum(EmployeeStatus, native_enum=False), default=EmployeeStatus.ACTIVE
    )
    password_hash: Mapped[str] = mapped_column(String(255))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    last_login_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    company: Mapped["Customer"] = relationship()  # noqa: F821
