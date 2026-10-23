from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RemovedEndpoint(Base):
    """A computer whose employee account was deleted in the portal, kept so the
    software still installed on it can be told to uninstall itself.

    Deleting an employee deletes their endpoint, so its upload token stops
    being accepted. The computer would otherwise just get 401s forever, which
    can't be told apart from a mistake. This record keeps the endpoint id and
    Wazuh agent id the token was derived from (see services/screens.py), so a
    token that is genuinely this computer's can be answered with an explicit
    "uninstall" instead. Owned by this backend (migrations in
    company/backend/alembic); removed with the company.
    """

    __tablename__ = "removed_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)  # the endpoint's id
    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    wazuh_agent_id: Mapped[str] = mapped_column(String(10))
    endpoint_name: Mapped[str] = mapped_column(String(50))
    removed_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
