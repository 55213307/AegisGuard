"""The real checks behind the dashboard's Platform Service Status.

Each service is checked when the dashboard asks, not assumed:

  - API Server: up, and no unhandled server errors lately (services/health.py);
  - Database: a query is run and timed;
  - Wazuh Manager: its API answers and the daemons agents and alerts depend on
    are running (the API can answer while wazuh-remoted is stuck);
  - Event Ingestion: the ingester thread is alive, the alerts file exists and
    can be read, and it hasn't been failing. Quiet computers don't count against
    it: no events is normal;
  - Behavior Model: the trainer thread is alive, hasn't been failing, and every
    computer has a model.

A problem is described in `detail`, so the dashboard shows what is wrong and not
just that something is.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.core.config import settings
from app.schemas.dashboard import ServiceStatus
from app.services import health, ingest, wazuh
from app.services.ml import registry

_STARTED = datetime.now(timezone.utc)

# Daemons of the Wazuh manager that the platform depends on, with whether their
# absence stops the platform working (down) or only part of it (warn). The
# others (cluster, mail, syslog, integrator...) are off by design here.
_WAZUH_DAEMONS = {
    "wazuh-analysisd": True,  # analyses events into alerts
    "wazuh-remoted": True,  # what agents connect to
    "wazuh-db": True,
    "wazuh-modulesd": False,
    "wazuh-execd": False,
}
SLOW_DATABASE_MS = 500
# A computer should have a model within minutes of being enrolled.
MODEL_GRACE = timedelta(minutes=30)


def _duration(delta: timedelta) -> str:
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 90 * 60:
        return f"{round(seconds / 60)} min"
    if seconds < 36 * 3600:
        return f"{seconds / 3600:.1f} h".replace(".0 h", " h")
    return f"{round(seconds / 86400)} days"


def _ago(when: datetime, now: datetime) -> str:
    return f"{_duration(now - when)} ago"


def _short(error: Exception | str) -> str:
    return str(error).strip().splitlines()[0][:160] if str(error).strip() else "No details"


def api_server(now: datetime | None = None) -> ServiceStatus:
    now = now or datetime.now(timezone.utc)
    problem = health.recent_error("api", now)
    if problem:
        return ServiceStatus(status="warn", label="Errors", detail=problem)
    return ServiceStatus(status="ok", label="Operational", detail=f"Up {_duration(now - _STARTED)}")


def database(db) -> ServiceStatus:
    started = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        return ServiceStatus(status="down", label="Unreachable", detail=_short(exc))
    ms = round((time.perf_counter() - started) * 1000)
    if ms > SLOW_DATABASE_MS:
        return ServiceStatus(status="warn", label="Slow", detail=f"A query took {ms} ms")
    return ServiceStatus(status="ok", label="Operational", detail=f"Answers in {ms} ms")


def wazuh_manager() -> ServiceStatus:
    try:
        daemons = wazuh.manager_daemons()
    except (wazuh.WazuhError, KeyError, IndexError, TypeError) as exc:
        return ServiceStatus(status="down", label="Unreachable", detail=_short(exc))
    stopped = [name for name in _WAZUH_DAEMONS if daemons.get(name) != "running"]
    if stopped:
        critical = any(_WAZUH_DAEMONS[name] for name in stopped)
        return ServiceStatus(
            status="down" if critical else "warn",
            label="Degraded",
            detail=", ".join(f"{name} is {daemons.get(name, 'missing')}" for name in stopped),
        )
    return ServiceStatus(status="ok", label="Connected", detail=f"{len(_WAZUH_DAEMONS)} core daemons running")


def ingestion(last_event_time: datetime | None, now: datetime | None = None) -> ServiceStatus:
    now = now or datetime.now(timezone.utc)
    if not settings.ingest_enabled:
        return ServiceStatus(status="unknown", label="Disabled", detail="INGEST_ENABLED is off")
    if not ingest.is_running():
        return ServiceStatus(status="down", label="Stopped", detail="The alert ingester is not running")
    path = settings.alerts_file_path
    if not os.path.exists(path):
        return ServiceStatus(status="warn", label="Waiting", detail=f"Alerts file not found: {path}")
    if not os.access(path, os.R_OK):
        return ServiceStatus(status="down", label="Cannot read alerts", detail="The service has no permission to read the Wazuh alerts file")
    problem = health.recent_error("ingestion", now)
    if problem:
        return ServiceStatus(status="warn", label="Errors", detail=problem)
    detail = f"Last event {_ago(last_event_time, now)}" if last_event_time else "No events yet"
    return ServiceStatus(status="ok", label="Active", detail=detail)


def behavior_model(endpoints: list[tuple[int, datetime]], now: datetime | None = None) -> ServiceStatus:
    """`endpoints` are this company's (endpoint id, enrolled time)."""
    now = now or datetime.now(timezone.utc)
    if not settings.ml_enabled:
        return ServiceStatus(status="unknown", label="Disabled", detail="ML_ENABLED is off")
    if not registry.is_running():
        return ServiceStatus(status="down", label="Stopped", detail="The model trainer is not running")
    problem = health.recent_error("ml", now)
    if problem:
        return ServiceStatus(status="warn", label="Errors", detail=problem)
    if not endpoints:
        return ServiceStatus(status="ok", label="Idle", detail="No computers enrolled yet")
    models = registry.status()
    # The models are in memory, so after a restart or deploy every computer has none
    # until the trainer gets to it: the grace period starts at the later of the
    # computer's enrolment and the trainer's start.
    started = registry.started_at()
    without = [
        eid for eid, enrolled in endpoints
        if eid not in models and now - (max(enrolled, started) if started else enrolled) > MODEL_GRACE
    ]  # fmt: skip
    if without:
        return ServiceStatus(
            status="warn",
            label="No model",
            detail=f"{len(without)} computer(s) have had no model for over {int(MODEL_GRACE.total_seconds() // 60)} minutes",
        )
    trained = [models[eid] for eid, _ in endpoints if eid in models]
    if len(trained) < len(endpoints):
        return ServiceStatus(status="ok", label="Training", detail=f"{len(trained)} of {len(endpoints)} computers have a model")
    return ServiceStatus(
        status="ok", label="Operational", detail=f"{len(trained)} model(s), last trained {_ago(max(e.trained_at for e in trained), now)}"
    )


def overall(services: dict[str, ServiceStatus]) -> str:
    """The one word for the Platform Status card."""
    statuses = {s.status for s in services.values()}
    if "down" in statuses:
        return "Down"
    if "warn" in statuses:
        return "Degraded"
    return "Operational"
