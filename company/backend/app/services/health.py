"""What went wrong recently in the platform's own parts, for the dashboard's
Platform Service Status.

The background workers (alert ingestion, model training) and the API catch
their own errors so one bad cycle never takes them down, which also means
nothing outside the logs ever saw those errors. They report here instead, and
the dashboard shows an error for a while after it happened, even if the next
cycle succeeded: a problem that comes and goes is still a problem.

In memory only: it describes this process, and starts clean when it restarts.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# How long an error keeps showing after it happened.
RECENT = timedelta(minutes=15)


@dataclass
class _Component:
    ok_at: datetime | None = None
    error_at: datetime | None = None
    error: str | None = None
    errors_in_a_row: int = 0


_lock = threading.Lock()
_components: dict[str, _Component] = {}


def _component(name: str) -> _Component:
    return _components.setdefault(name, _Component())


def ok(name: str) -> None:
    """The component just did its job successfully."""
    with _lock:
        component = _component(name)
        component.ok_at = datetime.now(timezone.utc)
        component.errors_in_a_row = 0


def fail(name: str, message: str) -> None:
    """The component just hit an error it handled (and logged)."""
    with _lock:
        component = _component(name)
        component.error_at = datetime.now(timezone.utc)
        component.error = message.strip().splitlines()[0][:200] if message.strip() else "Unknown error"
        component.errors_in_a_row += 1


def recent_error(name: str, now: datetime | None = None) -> str | None:
    """The component's last error if it happened within RECENT, else None."""
    now = now or datetime.now(timezone.utc)
    with _lock:
        component = _components.get(name)
        if component is None or component.error_at is None or now - component.error_at > RECENT:
            return None
        return component.error


def errors_in_a_row(name: str) -> int:
    with _lock:
        component = _components.get(name)
        return component.errors_in_a_row if component else 0


def last_ok(name: str) -> datetime | None:
    with _lock:
        component = _components.get(name)
        return component.ok_at if component else None


def reset() -> None:
    """For tests."""
    with _lock:
        _components.clear()
