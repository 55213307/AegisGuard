from datetime import datetime

from pydantic import BaseModel, Field


class SecurityLogItem(BaseModel):
    timestamp: datetime
    endpoint_name: str
    user: str | None
    event_type: str | None
    severity: str  # lowercase: critical / warning / info
    description: str | None
    risk_score: int | None  # behavioral anomaly score 0-100; None if not scored
    risk_reason: str | None


class SecurityLogListResponse(BaseModel):
    items: list[SecurityLogItem]
    total: int


class SecurityReportRequest(BaseModel):
    """The rows for the PDF report: exactly the ones the Security Logs page's
    own filters were showing when the button was clicked (the server renders
    them, it doesn't re-select them), plus a plain-text note of which filters
    were active, shown on the report so it's clear what it does and doesn't cover."""

    items: list[SecurityLogItem] = Field(max_length=5000)
    filters_summary: str | None = None
