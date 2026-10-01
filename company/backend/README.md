# AegisGuard Company Portal Backend

FastAPI app for the company portal. Serves the JSON API under `/api/*` and the
static frontend (`../frontend`) at `/`, like the admin backend.

It shares the admin backend's PostgreSQL database (`aegisguard`): a company's
login lives on the admin-owned `accounts` table, so the schema and migrations
for those columns are in `admin/backend` (run its `alembic upgrade head` first).

## Setup

```bash
cd AegisGuard/company/backend
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

copy .env.example .env          # set JWT_SECRET_KEY to a value different from admin's
alembic upgrade head            # company-owned tables (employees); run admin's migrations first
uvicorn app.main:app --reload --port 8002
```

The port must match `COMPANY_PORTAL_URL` in the admin backend's settings
(default `http://localhost:8002`), since that's what the issued login links point to.

## Development and deployment workflow

The Windows checkout is the source of truth; the Ubuntu server
(`portal.aegisguard.internal`, see `../deploy/`) only receives copies. There is
one database, on the server: locally both admin and this backend reach it
through an SSH tunnel (`.env` → `localhost:5433`):

```bash
ssh -N -L 5433:127.0.0.1:5432 shuyang@192.168.241.87
```

1. Open the tunnel, edit code on Windows, test locally on port 8002.
2. New DB change? `alembic revision --autogenerate -m "..."` — commit the file;
   the deploy script applies it on the server.
3. Deploy: `powershell -ExecutionPolicy Bypass -File ..\deploy\deploy.ps1`
   (packs company + resources without `.venv`/`.env`, uploads, reinstalls
   dependencies, runs migrations, restarts `aegisguard-company`).

## Login flow

1. An admin creates a company in Customer Management. That issues the company's
   own login link (`/login.html?c=<login_token>`), username (the company name)
   and a random password, shown to the admin once.
2. The company can sign in once the admin approves its account (Active).
   Pending and Locked accounts are refused.
3. First login forces a password change; every other portal route is blocked
   until then (`require_password_changed` in `app/api/deps.py`).
4. Admin "Reset Password" issues a new random password and forces a change again.

## Employee accounts

Administrators (the company account itself, or employees with role
Administrator) manage the company's employee logins on the portal's Account
Management page. Employees sign in through the same company login link with
their own username and an issued temporary password (forced change on first
login). Role `Employee` can use the portal but not Account Management.
Locking an employee (or the whole company in the admin panel) ends their open
sessions immediately. An administrator can't lock/delete/reset their own account.

The `employees` table is owned by this backend: its migrations live in
`alembic/` and are tracked in a separate `alembic_version_company` table,
since the database is shared with admin/backend. Deleting a company in the
admin panel deletes its employees (ON DELETE CASCADE).

## Endpoints

- `GET  /api/auth/portal/{login_token}` — company name for a login link
- `POST /api/auth/login` — `{login_token, username, password}`; username is the company name or an employee username
- `POST /api/auth/change-password` — `{current_password, new_password}` (8+ chars, letters and numbers)
- `GET  /api/auth/me`
- `GET  /api/accounts` — the company's employees (`search`, `status`); administrators only
- `POST /api/accounts` — `{employee_username, employee_email, employee_role, temporary_password?}`;
  returns the one-time password (random if not given)
- `GET  /api/accounts/{id}`
- `POST /api/accounts/{id}/lock|unlock|reset-password`
- `DELETE /api/accounts/{id}`

## Structure

```
app/
  core/       settings (.env) and JWT/password helpers
  db/         SQLAlchemy engine/session
  models/     Employee (owned here); Customer, Account (subset of the admin-owned tables)
  schemas/    Pydantic request/response models
  api/        auth dependencies and routes
```
