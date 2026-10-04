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

The company account (the only portal login) manages its employees on the
Account Management page. Employees don't sign in anywhere: each one is a
monitored computer (see "Endpoint installers" below). The page's View dialog
follows the Figma endpoint-detail design and shows the computer's live state
from Wazuh (online/offline, IP, OS, agent version, last seen).

The `employees` and `endpoints` tables are owned by this backend: their
migrations live in `alembic/` and are tracked in a separate
`alembic_version_company` table, since the database is shared with
admin/backend. Deleting a company in the admin panel deletes its employees
and endpoints (ON DELETE CASCADE).

## Endpoints

- `GET  /api/auth/portal/{login_token}` — company name for a login link
- `POST /api/auth/login` — `{login_token, username, password}`; username is the company name
- `POST /api/auth/change-password` — `{current_password, new_password}` (8+ chars, letters and numbers)
- `GET  /api/auth/me`
- `GET  /api/accounts` — the company's employees with their computer's live status (`search`, `status`)
- `POST /api/accounts` — `{employee_username, employee_email}`
- `GET  /api/accounts/{id}`
- `POST /api/accounts/{id}/lock|unlock`
- `DELETE /api/accounts/{id}` — also deletes the employee's Wazuh agent, revoking its key
- `GET  /api/accounts/{id}/installer` — the employee's one-click endpoint installer (`.cmd`)

## Endpoint installers

Each employee has one computer (`endpoints` table). The first installer
download pre-registers a Wazuh agent through the manager's API
(`AG-CUS-<company id>-<username>`, unique across companies; the portal shows
just the username) and the installer embeds that agent's own key. Running it
on the computer installs the Wazuh agent, writes the key into `client.keys`
and starts the service, so the endpoint never uses open self-enrollment.
The file is a credential: only the signed-in company account can download it.

Wazuh settings (`WAZUH_API_URL/USER/PASSWORD`, `WAZUH_MANAGER_ADDRESS`,
`WAZUH_AGENT_MSI_URL`) default to the lab setup in `app/core/config.py`.
The API is only reachable on the server itself; for local development add
`-L 55000:127.0.0.1:55000` to the SSH tunnel.

The installer first shows a monitoring notice that must be accepted (Y/N),
then also installs the **screen agent** (`C:\Program Files\AegisGuard\screen-agent.ps1`)
as a hidden scheduled task that runs in every user's session at logon (a
Windows service can't capture the desktop). It uploads a JPEG of the screen
to `POST /api/agent/screen`, authenticated by a per-endpoint token derived
from the endpoint and its agent id (so it stops working when the endpoint is
deleted). The server keeps only the latest frame per endpoint, in memory.
Agents send a frame every 10 s, or every second while someone has the live
view open (`GET /api/accounts/{id}/screen?live=true`).

**Windows Defender and the screen agent.** A script that captures the screen
and uploads it is flagged by Defender's AMSI scanning and blocked on the
endpoint. In a lab/demo the endpoint admin allows it with a path exclusion,
run once on each endpoint **before** the installer:
`Add-MpPreference -ExclusionPath "C:\Program Files\AegisGuard"`.
This is a deliberate owner-authorized allow-list, not detection evasion. The
installer does **not** add the exclusion itself: Defender tamper protection
blocks exclusion changes from untrusted processes, and self-whitelisting is
bad practice. In a real deployment this is instead solved by code-signing the
agent and pushing it via MDM/group policy — manual AV exclusions don't scale.

Known gap: deleting a company in the admin panel removes its endpoint rows
(ON DELETE CASCADE) but not their Wazuh agents.

## Structure

```
app/
  core/       settings (.env) and JWT/password helpers
  db/         SQLAlchemy engine/session
  models/     Employee (owned here); Customer, Account (subset of the admin-owned tables)
  schemas/    Pydantic request/response models
  api/        auth dependencies and routes
```
