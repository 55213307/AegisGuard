from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class ActivityLog(Base):
    """One entry in the Dashboard's "Recent Administrative Activities" feed.

    Written alongside the action it records (same DB transaction, see
    customers.create_customer and the accounts.py approve/reject/lock/
    unlock/delete routes) rather than reconstructed after the fact.
    """

    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    admin_id: Mapped[int | None] = mapped_column(ForeignKey("admin_users.id"), nullable=True)
    description: Mapped[str] = mapped_column(String(255))
    created_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    admin: Mapped["AdminUser | None"] = relationship()  # noqa: F821
