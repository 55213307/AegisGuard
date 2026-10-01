import enum

from sqlalchemy import Boolean, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class AccountStatus(str, enum.Enum):
    PENDING = "Pending"
    ACTIVE = "Active"
    LOCKED = "Locked"


class Account(Base):
    """The admin-owned `accounts` table (schema and migrations live in
    admin/backend), mapped here only for the columns portal login needs.
    The admin side issues login_token and the initial password; this portal
    only verifies them and lets the company replace the password."""

    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_status: Mapped[AccountStatus] = mapped_column(Enum(AccountStatus, native_enum=False))
    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id"), unique=True)
    login_token: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean)

    company: Mapped["Customer"] = relationship(back_populates="account")  # noqa: F821
