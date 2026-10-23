"""Approved overtime.

Someone working late or at a weekend is not an attack, but to the behavioral
model an unusual hour is exactly what stands out. So an administrator can
approve overtime for an employee for a few hours: while the window is open the
time of day and day of the week of that computer's events aren't held against
them (see ml/model.py typical_time), while what they run is still judged as
usual, so an admin tool during overtime still raises an alert.

Every approval and early end is recorded in lock_events.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.employee import Employee
from app.models.endpoint import Endpoint
from app.models.lock_event import LockEvent

log = logging.getLogger("aegisguard.overtime")

MAX_HOURS = 12


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)  # a database that doesn't keep time zones


def is_active(employee: Employee, now: datetime | None = None) -> bool:
    until = employee.overtime_until
    return until is not None and _aware(until) > (now or datetime.now(timezone.utc))


def allow(db: Session, employee: Employee, minutes: int, actor: str) -> datetime:
    """Approves overtime from now for `minutes` minutes (replacing any open window)."""
    minutes = max(1, min(int(minutes), MAX_HOURS * 60))
    employee.overtime_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    label = f"{minutes // 60} h {minutes % 60:02d} min" if minutes >= 60 else f"{minutes} min"
    db.add(
        LockEvent(unique_id=employee.unique_id, employee_id=employee.id, action="overtime", reason=f"Approved for {label}", actor=actor)
    )
    db.commit()
    log.info("Overtime approved for %s (employee %s): %s [%s]", employee.employee_username, employee.id, label, actor)
    return _aware(employee.overtime_until)


def end(db: Session, employee: Employee, actor: str) -> bool:
    """Ends the overtime window early. False if there was none open."""
    if not is_active(employee):
        employee.overtime_until = None
        db.commit()
        return False
    employee.overtime_until = None
    db.add(LockEvent(unique_id=employee.unique_id, employee_id=employee.id, action="ot_end", reason=None, actor=actor))
    db.commit()
    return True


def windows(db: Session, endpoint_ids: set[int]) -> dict[int, datetime]:
    """endpoint id -> end of its employee's overtime window, for the open ones."""
    if not endpoint_ids:
        return {}
    now = datetime.now(timezone.utc)
    rows = (
        db.query(Endpoint.id, Employee.overtime_until)
        .join(Employee, Employee.id == Endpoint.employee_id)
        .filter(Endpoint.id.in_(endpoint_ids), Employee.overtime_until.is_not(None))
    )
    return {endpoint_id: _aware(until) for endpoint_id, until in rows if _aware(until) > now}
