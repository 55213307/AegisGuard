"""Locking and unlocking an employee's computer.

An employee account's status is the lock: while it is Locked, the screen agent
on their computer (which polls /api/agent/status) shows a full-screen lock and
blocks input, until someone unlocks the account in the company portal. The
state lives on the server, so the computer can't unlock itself.

Locks come from the portal's Lock button, and automatically from Critical
security events (see auto_lock). Every lock and unlock is recorded in
lock_events.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.employee import Employee, EmployeeStatus
from app.models.endpoint import Endpoint
from app.models.lock_event import LockEvent

log = logging.getLogger("aegisguard.lock")

AUTO_ACTOR = "AegisGuard (automatic)"
# A Critical event only locks the computer if it just happened: the ingester can
# re-read old alerts (after a restart or a log rotation), and those must not
# lock anyone.
RECENT_EVENT_WINDOW = timedelta(minutes=15)


# How long after the installer says it is at work the computer's events are left
# unjudged. The installer says so again before it configures the computer, so a
# slow download doesn't use the window up before the work that needs it.
MAINTENANCE_MINUTES = 10


def _aware(t: datetime) -> datetime:
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)  # a database that doesn't keep time zones


def begin_maintenance(db: Session, endpoint: Endpoint) -> datetime:
    """The installer is at work: events up to the returned time aren't scored
    and can't lock the computer. Called again while a window is open it extends
    it (from the moment of the call) and keeps the original start."""
    now = datetime.now(timezone.utc)
    if endpoint.maintenance_until is None or _aware(endpoint.maintenance_until) <= now:
        endpoint.maintenance_from = now
    endpoint.maintenance_until = now + timedelta(minutes=MAINTENANCE_MINUTES)
    db.commit()
    return _aware(endpoint.maintenance_until)


def maintenance_windows(db: Session, endpoint_ids: set[int]) -> dict[int, datetime]:
    """endpoint id -> end of its maintenance window, for those that have one."""
    if not endpoint_ids:
        return {}
    rows = db.query(Endpoint.id, Endpoint.maintenance_until).filter(
        Endpoint.id.in_(endpoint_ids), Endpoint.maintenance_until.is_not(None)
    )
    windows = {}
    for endpoint_id, until in rows:
        if until.tzinfo is None:  # a database that doesn't keep time zones
            until = until.replace(tzinfo=timezone.utc)
        windows[endpoint_id] = until
    return windows


def last_unlocks(db: Session, endpoint_ids) -> dict[int, datetime]:
    """endpoint id -> when its employee was last unlocked, for those that were.
    Unlocking starts the computer's risk over: what it did before doesn't count
    towards its risk score any more (the events themselves stay in the log)."""
    endpoint_ids = list(endpoint_ids)
    if not endpoint_ids:
        return {}
    rows = (
        db.query(Endpoint.id, func.max(LockEvent.event_time))
        .join(LockEvent, LockEvent.employee_id == Endpoint.employee_id)
        .filter(Endpoint.id.in_(endpoint_ids), LockEvent.action == "unlock")
        .group_by(Endpoint.id)
    )
    return {endpoint_id: _aware(t) for endpoint_id, t in rows}


def is_locked(employee: Employee) -> bool:
    return employee.employee_status == EmployeeStatus.LOCKED


def lock(db: Session, employee: Employee, reason: str, actor: str) -> bool:
    """Locks the employee's computer. False if it was already locked."""
    if is_locked(employee):
        return False
    employee.employee_status = EmployeeStatus.LOCKED
    employee.lock_reason = reason[:200]
    employee.locked_at = datetime.now(timezone.utc)
    db.add(LockEvent(unique_id=employee.unique_id, employee_id=employee.id, action="lock", reason=reason[:200], actor=actor))
    db.commit()
    log.warning("Locked %s (employee %s): %s [%s]", employee.employee_username, employee.id, reason, actor)
    return True


def unlock(db: Session, employee: Employee, actor: str) -> bool:
    """Unlocks the employee's computer. False if it wasn't locked."""
    if not is_locked(employee):
        return False
    employee.employee_status = EmployeeStatus.ACTIVE
    employee.lock_reason = None
    employee.locked_at = None
    db.add(LockEvent(unique_id=employee.unique_id, employee_id=employee.id, action="unlock", reason=None, actor=actor))
    db.commit()
    log.info("Unlocked %s (employee %s) [%s]", employee.employee_username, employee.id, actor)
    return True


def auto_lock(db: Session, events: list[dict]) -> int:
    """Locks the computers that just reported a Critical event. `events` are
    freshly stored security events (dicts with endpoint_id, severity,
    event_time and the reason fields). Returns how many computers were locked."""
    now = datetime.now(timezone.utc)
    first_critical: dict[int, dict] = {}
    for event in events:
        if event.get("severity") != "Critical" or now - event["event_time"] > RECENT_EVENT_WINDOW:
            continue
        first_critical.setdefault(event["endpoint_id"], event)
    if not first_critical:
        return 0

    locked = 0
    for endpoint_id, event in first_critical.items():
        employee = (
            db.query(Employee).join(Endpoint, Endpoint.employee_id == Employee.id).filter(Endpoint.id == endpoint_id).first()
        )
        if employee is None or is_locked(employee):
            continue
        # An event from before the last unlock must not lock the computer again.
        last_unlock = (
            db.query(func.max(LockEvent.event_time))
            .filter(LockEvent.employee_id == employee.id, LockEvent.action == "unlock")
            .scalar()
        )
        if last_unlock is not None:
            if last_unlock.tzinfo is None:  # a database that doesn't keep time zones
                last_unlock = last_unlock.replace(tzinfo=timezone.utc)
            if event["event_time"] <= last_unlock:
                continue
        why = event.get("risk_reason") or event.get("rule_description") or event.get("event_type") or "Critical security event"
        if lock(db, employee, f"Critical event: {why}", AUTO_ACTOR):
            locked += 1
    return locked
