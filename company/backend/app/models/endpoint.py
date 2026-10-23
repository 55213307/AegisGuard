from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Endpoint(Base):
    """An employee's monitored computer, backed by a Wazuh agent that is
    pre-registered when the company first downloads that employee's
    installer. Only endpoints registered here can connect to the manager.

    endpoint_name is what the portal shows (the employee's username);
    wazuh_agent_name is the same name prefixed with the company code, since
    Wazuh agent names must be unique across every company on the manager.
    """

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), unique=True)
    endpoint_name: Mapped[str] = mapped_column(String(50))
    wazuh_agent_id: Mapped[str] = mapped_column(String(10), unique=True)
    wazuh_agent_name: Mapped[str] = mapped_column(String(128), unique=True)
    created_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # While an installer is working on the computer (it tells the portal when it
    # starts), events up to this time aren't scored and can't lock the computer.
    maintenance_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When that window started (the portal shows both ends).
    maintenance_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    employee: Mapped["Employee"] = relationship(back_populates="endpoint")  # noqa: F821
