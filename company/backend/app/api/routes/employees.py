from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import Principal, require_administrator
from app.core.security import generate_initial_password, hash_password
from app.db.session import get_db
from app.models.employee import Employee, EmployeeStatus
from app.schemas.employee import (
    EmployeeCreate,
    EmployeeCreatedOut,
    EmployeeCredentials,
    EmployeeListResponse,
    EmployeeOut,
)

# Served as "accounts" because that's what the portal's Account Management
# page calls them; these are the company's employee logins.
router = APIRouter(prefix="/api/accounts", tags=["employee accounts"])


def _get_employee_or_404(employee_id: int, principal: Principal, db: Session) -> Employee:
    # Always scoped to the signed-in company, so one company can never read
    # or change another company's employees by guessing ids.
    employee = (
        db.query(Employee)
        .filter(Employee.id == employee_id, Employee.unique_id == principal.company_id)
        .first()
    )
    if employee is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return employee


def _forbid_self(employee: Employee, principal: Principal, action: str) -> None:
    if principal.employee is not None and principal.employee.id == employee.id:
        raise HTTPException(status_code=400, detail=f"You can't {action} your own account.")


@router.get("", response_model=EmployeeListResponse)
def list_employees(
    search: str | None = None,
    status_filter: EmployeeStatus | None = Query(default=None, alias="status"),
    principal: Principal = Depends(require_administrator),
    db: Session = Depends(get_db),
) -> EmployeeListResponse:
    query = db.query(Employee).filter(Employee.unique_id == principal.company_id)
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(or_(Employee.employee_username.ilike(like), Employee.employee_email.ilike(like)))
    if status_filter is not None:
        query = query.filter(Employee.employee_status == status_filter)
    employees = query.order_by(Employee.employee_username.asc()).all()
    return EmployeeListResponse(total=len(employees), items=employees)


@router.post("", response_model=EmployeeCreatedOut, status_code=201)
def create_employee(
    payload: EmployeeCreate,
    principal: Principal = Depends(require_administrator),
    db: Session = Depends(get_db),
) -> EmployeeCreatedOut:
    # The company name is the company account's own username at login.
    if payload.employee_username == principal.company_name.strip().casefold():
        raise HTTPException(status_code=400, detail="This username is reserved for the company account.")
    exists = (
        db.query(Employee.id)
        .filter(Employee.unique_id == principal.company_id, Employee.employee_username == payload.employee_username)
        .first()
    )
    if exists:
        raise HTTPException(status_code=409, detail="This username is already taken in your company.")

    initial_password = payload.temporary_password or generate_initial_password()
    employee = Employee(
        unique_id=principal.company_id,
        employee_username=payload.employee_username,
        employee_email=payload.employee_email,
        employee_role=payload.employee_role,
        employee_status=EmployeeStatus.ACTIVE,
        password_hash=hash_password(initial_password),
        must_change_password=True,
    )
    db.add(employee)
    db.commit()
    db.refresh(employee)
    return EmployeeCreatedOut(
        **EmployeeOut.model_validate(employee).model_dump(),
        credentials=EmployeeCredentials(
            employee_username=employee.employee_username, initial_password=initial_password
        ),
    )


@router.get("/{employee_id}", response_model=EmployeeOut)
def get_employee(
    employee_id: int, principal: Principal = Depends(require_administrator), db: Session = Depends(get_db)
) -> Employee:
    return _get_employee_or_404(employee_id, principal, db)


@router.post("/{employee_id}/lock", response_model=EmployeeOut)
def lock_employee(
    employee_id: int, principal: Principal = Depends(require_administrator), db: Session = Depends(get_db)
) -> Employee:
    employee = _get_employee_or_404(employee_id, principal, db)
    _forbid_self(employee, principal, "lock")
    employee.employee_status = EmployeeStatus.LOCKED
    db.commit()
    db.refresh(employee)
    return employee


@router.post("/{employee_id}/unlock", response_model=EmployeeOut)
def unlock_employee(
    employee_id: int, principal: Principal = Depends(require_administrator), db: Session = Depends(get_db)
) -> Employee:
    employee = _get_employee_or_404(employee_id, principal, db)
    employee.employee_status = EmployeeStatus.ACTIVE
    db.commit()
    db.refresh(employee)
    return employee


@router.post("/{employee_id}/reset-password", response_model=EmployeeCredentials)
def reset_employee_password(
    employee_id: int, principal: Principal = Depends(require_administrator), db: Session = Depends(get_db)
) -> EmployeeCredentials:
    employee = _get_employee_or_404(employee_id, principal, db)
    _forbid_self(employee, principal, "reset the password of")
    new_password = generate_initial_password()
    employee.password_hash = hash_password(new_password)
    employee.must_change_password = True
    db.commit()
    return EmployeeCredentials(employee_username=employee.employee_username, initial_password=new_password)


@router.delete("/{employee_id}", status_code=204)
def delete_employee(
    employee_id: int, principal: Principal = Depends(require_administrator), db: Session = Depends(get_db)
) -> None:
    employee = _get_employee_or_404(employee_id, principal, db)
    _forbid_self(employee, principal, "delete")
    db.delete(employee)
    db.commit()
