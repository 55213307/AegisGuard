from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class SecurityEvent(Base):
    """One Wazuh alert, ingested from the manager's alerts.json into
    PostgreSQL by the background ingester (app/services/ingest.py).

    Owned by this backend (migrations in company/backend/alembic). Only
    alerts from endpoints registered through the portal are stored; the row
    carries the company (unique_id) so per-company queries need no join.
    wazuh_alert_id is unique so re-reading the file never duplicates rows.
    """

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    unique_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    wazuh_alert_id: Mapped[str] = mapped_column(String(64), unique=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    rule_level: Mapped[int] = mapped_column(Integer, default=0)
    rule_description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    severity: Mapped[str] = mapped_column(String(10))  # Info / Warning / Critical
    event_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_user: Mapped[str | None] = mapped_column(String(120), nullable=True)
    windows_event_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB)
    # Behavioral anomaly score (app/services/ml): 0-100 for events that are the
    # user's own actions, with a plain-language reason when it is elevated.
    # NULL when the event isn't a user action or the endpoint has no model yet.
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
