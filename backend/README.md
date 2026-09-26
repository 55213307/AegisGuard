# AegisGuard Backend

FastAPI + PostgreSQL, per the IR (Section 2.3.3 / 2.3.4). Serves the JSON API under `/api/*`
and also hosts the existing static frontend (`../frontend`) at `/`, so the whole
app runs as one process.

## Setup

```bash
cd AegisGuard/backend
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt

copy .env.example .env          # then fill in DATABASE_URL / JWT_SECRET_KEY

# create the database first (e.g. via psql: CREATE DATABASE aegisguard;)
alembic revision --autogenerate -m "init schema"
alembic upgrade head

python seed.py                  # creates tester1 / 1234 for local login
uvicorn app.main:app --reload --port 8000
```

Then open `http://localhost:8000/login.html`.

## Structure

```
app/
  core/       settings (.env) and JWT/password helpers
  db/         SQLAlchemy engine/session, Base metadata
  models/     AdminUser, Customer, Account
  schemas/    Pydantic request/response models
  api/routes/ auth, dashboard, customers, accounts
alembic/      migrations
seed.py       creates a local dev admin account
```

## Endpoints implemented so far

All except `/api/auth/login` require `Authorization: Bearer <token>`.

- `POST /api/auth/login` — matches login.html's form fields exactly
- `GET  /api/dashboard/summary` — feeds the dashboard's stat cards
- `GET  /api/customers` — full company list (for the account filter dropdown)
- `GET  /api/customers/queue` — FIFO activation queue (frontend caps display to 4)
- `POST /api/customers` — Add New Customer form
- `POST /api/customers/{id}/activate`
- `GET  /api/accounts` — supports `status`, `company`, `role`, `search`, `sort`
- `GET  /api/accounts/summary` — feeds Account Management's stat cards
- `GET  /api/accounts/{id}`
- `POST /api/accounts/{id}/approve|reject|lock|unlock`
- `DELETE /api/accounts/{id}`

## Known assumptions (flag if wrong)

- "Reject" on a Pending account deletes it outright — the UI only ever shows
  Pending/Active/Locked, there's no "Rejected" status anywhere in the design.
- Dashboard's "Monitoring Accounts" stat = count of Active accounts;
  "Platform Status" is currently hardcoded to "Operational" pending a real
  Wazuh/worker health check.
- The frontend (`login.js`, `dashboard.js`, `customer-management.js`,
  `account-management.js`) still uses local fake data / `fakeAuthenticate()`.
  Wiring those `fetch()` calls to these endpoints is the next step, not done
  in this pass.
