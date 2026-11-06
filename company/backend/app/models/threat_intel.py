from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ThreatIndicator(Base):
    """One thing that is publicly known to be bad: a file hash, a URL or a domain.

    The table behind services/threat_intel.py. A file, a URL or a command is looked up here
    by its exact value (no model, no guessing): a hit is a finding that is confirmed, a miss
    says nothing. Filled from public lists (MalwareBazaar, URLhaus, OpenPhish...) by
    `python -m app.services.threat_intel import`, plus a few built-in test entries.
    Shared by every company, owned by this backend (migrations in company/backend/alembic).
    """

    __tablename__ = "threat_intel"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_threat_intel_kind_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))  # sha256 / md5 / url / domain
    value: Mapped[str] = mapped_column(String(1000))  # normalised: see threat_intel.normalize
    source: Mapped[str] = mapped_column(String(40))  # where the entry comes from: malwarebazaar, urlhaus, openphish, eicar...
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)  # the malware family, "phishing", "test"...
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # as the source reports it
    added_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
