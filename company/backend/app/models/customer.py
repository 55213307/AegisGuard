from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Customer(Base):
    """Read-only view of the admin-owned `customers` table (schema and
    migrations live in admin/backend). Only the columns this portal needs."""

    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True)
    company_name: Mapped[str] = mapped_column(String(200))

    account: Mapped["Account | None"] = relationship(back_populates="company", uselist=False)  # noqa: F821
