import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AccountRole(str, enum.Enum):
    COMPANY_ADMIN = "Company Administrator"
    SECURITY_ANALYST = "Security Analyst"
    VIEWER = "Viewer"


class AccountStatus(str, enum.Enum):
    PENDING = "Pending"
    ACTIVE = "Active"
    LOCKED = "Locked"


class Account(Base):
    """A customer-portal user account, managed from the Account Management page."""

    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    role: Mapped[AccountRole] = mapped_column(Enum(AccountRole, native_enum=False))
    status: Mapped[AccountStatus] = mapped_column(Enum(AccountStatus, native_enum=False), default=AccountStatus.PENDING)
    remarks: Mapped[str | None] = mapped_column(String(500), nullable=True)

    company_id: Mapped[int] = mapped_column(ForeignKey("customers.id"))
    company: Mapped["Customer"] = relationship(back_populates="accounts")  # noqa: F821

    operator_id: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id"), nullable=True)
    operator: Mapped["AdminUser | None"] = relationship()  # noqa: F821

    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
