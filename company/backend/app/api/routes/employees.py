import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session, joinedload

from app.api.deps import Principal, require_password_changed
from app.db.session import get_db
from app.models.employee import Employee, EmployeeStatus
from app.models.endpoint import Endpoint
from app.models.removed_endpoint import RemovedEndpoint
from app.models.security_event import SecurityEvent
from app.schemas.employee import (
    EmployeeCreate,
    EmployeeListResponse,
    EmployeeOut,
    OvertimeRequest,
    WorkHoursRequest,
    SecurityEventListResponse,
)
from app.services import endpoint_lock, overtime, screens, wazuh
from app.services.ml import registry
from app.services.ml.model import ANOMALY_RISK_THRESHOLD, EXPLAIN_RISK_FROM
from app.services.installer import build_installer

# Served as "accounts" because that's what the portal's Account Management
# page calls them: the employees whose computers the company monitors.
router = APIRouter(prefix="/api/accounts", tags=["employee accounts"])

logger = logging.getLogger(__name__)

ENDPOINT_SERVICE_DOWN = "The endpoint monitoring service is unavailable. Please try again later."

_STATUS_LABELS = {
    "active": "Online",
    "disconnected": "Offline",
    "pending": "Connecting",
    "never_connected": "Not installed",
}


def _get_employee_or_404(employee_id: int, principal: Principal, db: Session) -> Employee:
    # Always scoped to the signed-in company, so one company can never read
    # or change another company's employees by guessing ids.
    employee = (
        db.query(Employee)
        .options(joinedload(Employee.endpoint))
        .filter(Employee.id == employee_id, Employee.unique_id == principal.company_id)
        .first()
    )
    if employee is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return employee


def _agents_info(employees: list[Employee]) -> dict[str, dict] | None:
    """Live Wazuh state for these employees' computers, or None if Wazuh
    can't be reached (the page still loads, showing "Unknown")."""
    agent_ids = [e.endpoint.wazuh_agent_id for e in employees if e.endpoint is not None]
    try:
        return wazuh.get_agents_info(agent_ids)
    except wazuh.WazuhError:
        return None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Wazuh reports a far-future placeholder for agents that never connected.
    return None if parsed.year >= 9999 else parsed


# How long an anomaly keeps its computer marked as "active" on Live Monitoring.
ANOMALY_ACTIVE_MINUTES = 15


def _risk_24h(db: Session, employees: list[Employee]) -> dict[int, tuple[int | None, int | None]]:
    """Per endpoint id: (highest risk score in the last 24 hours, highest in the
    last ANOMALY_ACTIVE_MINUTES minutes)."""
    endpoint_ids = [e.endpoint.id for e in employees if e.endpoint is not None]
    if not endpoint_ids:
        return {}
    now = datetime.now(timezone.utc)
    recent_since = now - timedelta(minutes=ANOMALY_ACTIVE_MINUTES)
    rows = (
        db.query(
            SecurityEvent.endpoint_id,
            func.max(SecurityEvent.risk_score),
            func.max(case((SecurityEvent.event_time >= recent_since, SecurityEvent.risk_score), else_=None)),
        )
        .filter(SecurityEvent.endpoint_id.in_(endpoint_ids), SecurityEvent.event_time >= now - timedelta(hours=24))
        .group_by(SecurityEvent.endpoint_id)
        .all()
    )
    return {endpoint_id: (day, recent) for endpoint_id, day, recent in rows}


def _learning(endpoint) -> dict:
    progress = registry.learning_progress(endpoint.id) if endpoint else None
    if progress is None:
        return {}
    return {"learning_state": progress["state"], "learning_actions": progress["actions"], "learning_needed": progress["needed"]}


def _to_out(
    employee: Employee,
    agents_info: dict[str, dict] | None,
    risk_by_endpoint: dict[int, tuple[int | None, int | None]] | None = None,
) -> EmployeeOut:
    endpoint = employee.endpoint
    info: dict = {}
    if endpoint is None:
        status = "Not installed"
    elif agents_info is None:
        status = "Unknown"
    else:
        info = agents_info.get(endpoint.wazuh_agent_id, {})
        status = _STATUS_LABELS.get(info.get("status"), "Unknown")

    os_info = info.get("os") or {}
    os_name = " ".join(part for part in (os_info.get("name"), os_info.get("version")) if part) or None
    ip_address = info.get("ip")
    day_risk, recent_risk = (risk_by_endpoint or {}).get(endpoint.id, (None, None)) if endpoint else (None, None)
    return EmployeeOut(
        id=employee.id,
        employee_username=employee.employee_username,
        employee_email=employee.employee_email,
        employee_status=employee.employee_status,
        created_time=employee.created_time,
        endpoint_name=endpoint.endpoint_name if endpoint else None,
        endpoint_status=status,
        ip_address=ip_address if ip_address and ip_address != "any" else None,
        os_name=os_name,
        agent_version=info.get("version"),
        last_seen_time=_parse_time(info.get("lastKeepAlive")),
        lock_reason=employee.lock_reason,
        locked_at=employee.locked_at,
        overtime_until=employee.overtime_until if overtime.is_active(employee) else None,
        work_start=employee.work_start,
        work_end=employee.work_end,
        maintenance_from=endpoint.maintenance_from if endpoint else None,
        maintenance_until=endpoint.maintenance_until if endpoint else None,
        **_learning(endpoint),
        risk_24h=day_risk,
        risk_active=recent_risk if recent_risk is not None and recent_risk >= ANOMALY_RISK_THRESHOLD else None,
    )


@router.get("", response_model=EmployeeListResponse)
def list_employees(
    search: str | None = None,
    status_filter: EmployeeStatus | None = Query(default=None, alias="status"),
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> EmployeeListResponse:
    query = (
        db.query(Employee)
        .options(joinedload(Employee.endpoint))
        .filter(Employee.unique_id == principal.company_id)
    )
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(or_(Employee.employee_username.ilike(like), Employee.employee_email.ilike(like)))
    if status_filter is not None:
        query = query.filter(Employee.employee_status == status_filter)
    employees = query.order_by(Employee.employee_username.asc()).all()
    agents_info = _agents_info(employees)
    risk = _risk_24h(db, employees)
    return EmployeeListResponse(total=len(employees), items=[_to_out(e, agents_info, risk) for e in employees])


@router.post("", response_model=EmployeeOut, status_code=201)
def create_employee(
    payload: EmployeeCreate,
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> EmployeeOut:
    exists = (
        db.query(Employee.id)
        .filter(Employee.unique_id == principal.company_id, Employee.employee_username == payload.employee_username)
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="This username is already taken in your company.")

    employee = Employee(
        unique_id=principal.company_id,
        employee_username=payload.employee_username,
        employee_email=payload.employee_email,
        employee_status=EmployeeStatus.ACTIVE,
        work_start=payload.work_start,
        work_end=payload.work_end,
    )
    db.add(employee)
    db.commit()
    db.refresh(employee)
    return _to_out(employee, {})


@router.get("/{employee_id}", response_model=EmployeeOut)
def get_employee(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> EmployeeOut:
    employee = _get_employee_or_404(employee_id, principal, db)
    return _to_out(employee, _agents_info([employee]), _risk_24h(db, [employee]))


@router.post("/{employee_id}/lock", response_model=EmployeeOut)
def lock_employee(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> EmployeeOut:
    employee = _get_employee_or_404(employee_id, principal, db)
    endpoint_lock.lock(db, employee, "Locked by administrator", principal.company_name)
    return _to_out(employee, _agents_info([employee]))


@router.post("/{employee_id}/overtime", response_model=EmployeeOut)
def allow_overtime(
    employee_id: int,
    payload: OvertimeRequest,
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> EmployeeOut:
    """Approve overtime for a while: the hour and weekday of this computer's
    activity aren't held against it while the window is open."""
    employee = _get_employee_or_404(employee_id, principal, db)
    overtime.allow(db, employee, payload.minutes, principal.company_name)
    return _to_out(employee, _agents_info([employee]))


@router.delete("/{employee_id}/overtime", response_model=EmployeeOut)
def end_overtime(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> EmployeeOut:
    employee = _get_employee_or_404(employee_id, principal, db)
    overtime.end(db, employee, principal.company_name)
    return _to_out(employee, _agents_info([employee]))


@router.put("/{employee_id}/work-hours", response_model=EmployeeOut)
def set_work_hours(
    employee_id: int,
    payload: WorkHoursRequest,
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> EmployeeOut:
    """Declare the employee's working hours. The behavioral model starts from
    them and is retrained at once, so it learns the new hours straight away."""
    employee = _get_employee_or_404(employee_id, principal, db)
    employee.work_start, employee.work_end = payload.start, payload.end
    db.commit()
    if employee.endpoint is not None:
        registry.retrain_soon(employee.endpoint.id)
    return _to_out(employee, _agents_info([employee]))


@router.delete("/{employee_id}/work-hours", response_model=EmployeeOut)
def clear_work_hours(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> EmployeeOut:
    """Go back to learning the working hours from the computer's own activity."""
    employee = _get_employee_or_404(employee_id, principal, db)
    employee.work_start = employee.work_end = None
    db.commit()
    if employee.endpoint is not None:
        registry.retrain_soon(employee.endpoint.id)
    return _to_out(employee, _agents_info([employee]))


@router.post("/{employee_id}/unlock", response_model=EmployeeOut)
def unlock_employee(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> EmployeeOut:
    employee = _get_employee_or_404(employee_id, principal, db)
    endpoint_lock.unlock(db, employee, principal.company_name)
    return _to_out(employee, _agents_info([employee]))


def _get_or_register_endpoint(employee: Employee, principal: Principal, db: Session) -> Endpoint:
    """Each employee has one computer. Its Wazuh agent is pre-registered the
    first time the installer is requested; later downloads reuse it."""
    if employee.endpoint is not None:
        return employee.endpoint

    agent_name = f"AG-CUS-{principal.company_id:03d}-{employee.employee_username}"
    try:
        agent_id = wazuh.add_agent(agent_name)
    except wazuh.WazuhError as exc:
        raise HTTPException(status_code=503, detail=ENDPOINT_SERVICE_DOWN) from exc

    endpoint = Endpoint(
        unique_id=principal.company_id,
        employee_id=employee.id,
        endpoint_name=employee.employee_username,
        wazuh_agent_id=agent_id,
        wazuh_agent_name=agent_name,
    )
    db.add(endpoint)
    try:
        db.commit()
    except Exception:
        # Don't leave a registered agent (with a valid key) that nothing in
        # our database points to.
        db.rollback()
        wazuh.delete_agent(agent_id)
        raise
    db.refresh(endpoint)
    return endpoint


@router.get("/{employee_id}/installer")
def download_installer(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> Response:
    employee = _get_employee_or_404(employee_id, principal, db)
    endpoint = _get_or_register_endpoint(employee, principal, db)
    try:
        key_line = wazuh.get_agent_key_line(endpoint.wazuh_agent_id)
    except wazuh.WazuhError as exc:
        raise HTTPException(status_code=503, detail=ENDPOINT_SERVICE_DOWN) from exc

    filename = f"AegisGuard-Installer-{employee.employee_username}.cmd"
    installer = build_installer(
        company=principal.company_name,
        employee=employee.employee_username,
        key_line=key_line,
        screen_token=screens.screen_token(endpoint.id, endpoint.wazuh_agent_id),
    )
    return Response(
        content=installer,
        media_type="application/octet-stream",
        # The file embeds a credential: never let a browser or proxy cache it.
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


@router.get("/{employee_id}/screen")
def latest_screen(
    employee_id: int,
    live: bool = False,
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> Response:
    """Newest frame from this employee's computer. live=true is sent by the
    full-size view and makes the agent switch to one frame per second."""
    employee = _get_employee_or_404(employee_id, principal, db)
    latest = screens.latest_frame(employee.endpoint.id, live) if employee.endpoint else None
    if latest is None:
        raise HTTPException(status_code=404, detail="No screen received from this computer yet.")
    frame, received_at = latest
    # Age rather than a timestamp, so the browser's clock doesn't need to
    # agree with the server's.
    age_seconds = max(0.0, time.time() - received_at)
    return Response(
        content=frame,
        media_type="image/jpeg",
        headers={"Cache-Control": "no-store", "X-Frame-Age": f"{age_seconds:.1f}"},
    )


@router.get("/{employee_id}/events", response_model=SecurityEventListResponse)
def list_events(
    employee_id: int,
    limit: int = Query(default=20, ge=1, le=100),
    principal: Principal = Depends(require_password_changed),
    db: Session = Depends(get_db),
) -> SecurityEventListResponse:
    """Recent problems on this employee's computer, newest first: events the
    behavioral model rates elevated or worse, and Warning/Critical events.
    Routine activity (process creations, logons) is left out, and so are the
    CIS benchmark results, which each configuration scan reports in bulk."""
    employee = _get_employee_or_404(employee_id, principal, db)
    if employee.endpoint is None:
        return SecurityEventListResponse(items=[])
    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.endpoint_id == employee.endpoint.id,
            or_(
                SecurityEvent.risk_score >= EXPLAIN_RISK_FROM,
                and_(
                    SecurityEvent.severity.in_(("Warning", "Critical")),
                    or_(SecurityEvent.event_type.is_(None), SecurityEvent.event_type != "Security Configuration"),
                ),
            ),
        )
        .order_by(SecurityEvent.event_time.desc())
        .limit(limit)
        .all()
    )
    return SecurityEventListResponse(items=events)


@router.delete("/{employee_id}", status_code=204)
def delete_employee(
    employee_id: int, principal: Principal = Depends(require_password_changed), db: Session = Depends(get_db)
) -> None:
    employee = _get_employee_or_404(employee_id, principal, db)
    # Revoke the computer's agent key first. If Wazuh can't be reached the
    # deletion is refused rather than leaving a key that still works.
    if employee.endpoint is not None:
        try:
            wazuh.delete_agent(employee.endpoint.wazuh_agent_id)
        except wazuh.WazuhError as exc:
            # The 503 below is a handled response, so the underlying Wazuh
            # reason never reaches the logs on its own — record it here.
            logger.warning(
                "delete_agent failed for endpoint %s (agent %s): %s",
                employee.endpoint.id,
                employee.endpoint.wazuh_agent_id,
                exc,
            )
            raise HTTPException(status_code=503, detail=ENDPOINT_SERVICE_DOWN) from exc
        screens.forget(employee.endpoint.id)
        # Remember the computer, so the software still on it can be told to
        # uninstall itself (see agent.py status); forgotten after a year.
        db.merge(
            RemovedEndpoint(
                id=employee.endpoint.id,
                unique_id=employee.unique_id,
                wazuh_agent_id=employee.endpoint.wazuh_agent_id,
                endpoint_name=employee.endpoint.endpoint_name,
            )
        )
        db.query(RemovedEndpoint).filter(
            RemovedEndpoint.removed_time < datetime.now(timezone.utc) - timedelta(days=365)
        ).delete(synchronize_session=False)
    db.delete(employee)
    db.commit()
