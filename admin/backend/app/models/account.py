import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, func, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AccountStatus(str, enum.Enum):
    PENDING = "Pending"
    ACTIVE = "Active"
    LOCKED = "Locked"


class Account(Base):
    """A customer's single admin account, managed from the Account Management page.

    unique_id is unique: a customer has exactly one account (see Customer's
    docstring) — that's the 1:1 relationship the ERD calls out.
    """

    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_name: Mapped[str] = mapped_column(String(120))
    customer_email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    customer_status: Mapped[AccountStatus] = mapped_column(
        Enum(AccountStatus, native_enum=False), default=AccountStatus.PENDING
    )

    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), unique=True)
    company: Mapped["Customer"] = relationship(back_populates="account")  # noqa: F821

    # Company portal login. The username is the company's name; login_token
    # is the unguessable part of this company's own login URL. password_hash
    # is NULL until an admin issues credentials (see reset-password), and the
    # company must replace the issued password on first login.
    login_token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    admin_id: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id"), nullable=True)
    operator: Mapped["AdminUser | None"] = relationship()  # noqa: F821

    submitted_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    update_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
