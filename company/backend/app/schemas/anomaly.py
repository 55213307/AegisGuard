from datetime import datetime

from pydantic import BaseModel


class AnomalyAlert(BaseModel):
    id: int
    event_time: datetime
    account_id: int | None  # the employee account that owns the computer
    endpoint_name: str
    severity: str
    risk_score: int
    risk_reason: str | None
    description: str | None


class AnomalyFeed(BaseModel):
    # Cursor: pass it back as after_id to get only anomalies newer than this
    # poll. With no after_id the feed is empty and only sets the cursor, so a
    # page that has just opened doesn't replay old anomalies as alerts.
    latest_id: int
    items: list[AnomalyAlert]
