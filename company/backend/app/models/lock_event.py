from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class LockEvent(Base):
    """One lock or unlock of an employee's computer: who did it and why.

    Locking an employee account locks their monitored computer (the screen
    agent shows a full-screen lock until the company unlocks it in the portal),
    so this is the audit trail for that. Owned by this backend (migrations in
    company/backend/alembic); removed with the employee or the company.
    """

    __tablename__ = "lock_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(10))  # "lock" / "unlock"
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    actor: Mapped[str] = mapped_column(String(120))  # company username, or AegisGuard for automatic locks
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
