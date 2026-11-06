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
- `POST /api/agent/scan` — (the scan agent, endpoint token) a USB drive or new downloads: names, attributes, hashes
- `POST /api/agent/containment` — (the scan agent) the processes it ended after a Critical finding

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
endpoint, so the installer adds a path exclusion for its own folder
(`Add-MpPreference -ExclusionPath "C:\Program Files\AegisGuard"`) before it sets
the agent up. It is best effort: if Windows tamper protection refuses, the
installer prints the same command for an administrator to run by hand. This is
a deliberate, owner-authorized allow-list of AegisGuard's own folder, not
detection evasion. In a real deployment the agent would instead be
code-signed and pushed via MDM/group policy — AV exclusions don't scale.

Known gap: deleting a company in the admin panel removes its endpoint rows
(ON DELETE CASCADE) but not their Wazuh agents.

## Security event ingestion

A background thread (`app/services/ingest.py`, started with the app) tails the
Wazuh manager's `alerts.json` and stores new alerts in the `security_events`
table. It only keeps alerts from portal-registered endpoints (matched by Wazuh
agent id → `endpoints`), skips the manager's own alerts (agent 000), and
dedups on `wazuh_alert_id` so re-reading never doubles rows. It handles the
daily log rotation (resets when the file is rotated/truncated) and partial
lines written mid-flush. Wazuh rule level maps to severity: 0-6 Info, 7-11
Warning, 12-15 Critical. The raw alert detail (`data.win`, groups, full_log)
is kept in a JSONB `details` column; `app/services/alerts.py` does the parsing
(pure functions).

The service user must be able to read `/var/ossec/logs/alerts/alerts.json`
(owner `wazuh:wazuh`, mode 640) — the deploy script adds `aegisguard` to the
`wazuh` group. Settings in `app/core/config.py`: `INGEST_ENABLED`,
`ALERTS_FILE_PATH`, `INGEST_POLL_SECONDS`. On Windows/local dev the file is
absent, so the ingester just idles (set `ALERTS_FILE_PATH` to a local file to
exercise it).

## Behavioral model

Per-endpoint anomaly detection lives in `app/services/ml/`, five files that depend on each other in one
direction (`model` ← `data` ← `runtime` ← `tools` ← `retrain`):

| file | what it is |
|---|---|
| `model.py` | the model itself, no database: the departments an employee can be in, the features an event is turned into (time of day, rarity, recent activity, parent/child pairs), and `BehaviorModel` (Isolation Forest + rules + learned command-line profiles) |
| `data.py` | where the model's data comes from: loaders for the database and for dataset files, the automatic first baseline, the synthetic baseline (`seed`) |
| `runtime.py` | what runs inside the backend: the models, kept **in memory only** (a restart retrains them), the thread that (re)trains them, and the scoring of new events (`risk_score`, `risk_reason`) |
| `tools.py` | offline commands; the backend uses only `evaluate_split` (the 80/20 test), through `retrain.py` |
| `retrain.py` | retrain + test by hand with charts; also what the portal's Retrain Now button runs |

**Retrain and test, by hand: `retrain.py`.** One script that trains a model and tests it the standard way: split the
events by time (oldest 80% to learn from, newest 20% to test on), inject labelled anomalies into the 20%, score,
then print the confusion matrix, accuracy, precision, recall, F1, false-positive rate, AUC and recall per kind of
anomaly, and draw the charts (`ml_reports/`). The portal's **Retrain Now** button runs the same code
(`retrain.run`): it trains and tests, swaps the new model in, and shows the result (the dialog, and *Test results*
next to the button, from `GET /api/accounts/{id}/training-report`). The injected anomalies are synthetic, and the
test says little for a computer with a short history (the dialog says so).

```
python -m app.services.ml.retrain                         # the default dataset file
python -m app.services.ml.retrain --csv file.csv.gz       # another dataset file
python -m app.services.ml.retrain --endpoint-id 8         # an endpoint's events from the database, nothing changes
python -m app.services.ml.retrain --endpoint-id 8 --apply # ...and the new model goes live
add --show to open the charts in windows (needs matplotlib: pip install matplotlib)
```

Offline commands (from `company/backend`; on the server use `.venv/bin/python`):

```
python -m app.services.ml.tools train     --csv file.csv.gz | --endpoint-id N
python -m app.services.ml.tools evaluate  [--csv file]                 # held-out time + injected anomalies
python -m app.services.ml.tools ablation  [--csv file] [--out r.md]    # rules vs forest vs both
python -m app.services.ml.tools export    --endpoint-id N --out f.csv.gz   # real events as a dataset
python -m app.services.ml.tools seed      --endpoint-id N --out f.csv.gz   # synthetic baseline
python -m app.services.ml.tools demo-history --endpoint-id N [--write|--delete]   # demo: ~2,200 typical actions over 3 weeks, stored like collected ones
```

Dataset files are kept outside the repository, in `Final Year Project/datasets/` (see the README there);
`tools` reads `datasets/dataset.csv.gz` when no `--csv` is given. Thresholds and schedules are settings
(`ML_*` in `app/core/config.py`).

## Scoring and detections

What is flagged is scored with **CVSS v3.1** (`app/services/cvss.py`): each kind of detection has one fixed
vector with its reason and MITRE ATT&CK technique written down in `CATALOG`, the standard formulas give the
score, the department sets the environmental requirements, and the confidence of the finding sets the
temporal Report Confidence. `risk_score` is that score x 10; from `CVSS_LOCK_FROM` (7.0, the start of High)
an event is Critical and locks the computer. `python -m app.services.cvss` checks the calculator against the
specification's examples. The full vector of every detection is kept in the event's `details["cvss"]`.

Three sources of detections, in `app/services/ml/runtime.py`:

| source | what | file |
|---|---|---|
| behaviour model | a program or time that is new for this computer (Isolation Forest) | `ml/model.py` |
| command model | LOLBAS rules + a classifier (TF-IDF + logistic regression) trained on LOLBAS and Atomic Red Team; a rule match counts alone, the classifier together with the behaviour model | `ml/commands.py` |
| BadUSB | a shell or PowerShell command within `BADUSB_WINDOW_SECONDS` (10) after a USB keyboard was plugged in | `services/badusb.py` |

The command model is trained by hand (`python -m app.services.ml.commands`, see its docstring; the public data
goes in `Final Year Project/datasets/public/`) and saved to `ml_models/command_model.joblib`, which the backend
loads if it exists. BadUSB reads event 6416 ("a new external device was recognized", audit subcategory
Plug and Play Events, turned on by the installer; rule 100110 in `deploy/wazuh/aegisguard_rules.xml` makes the
manager write it to alerts.json). Endpoints installed before this need the installer run again, or
`auditpol /set /subcategory:"{0CCE9248-69AE-11D9-BED3-505054503030}" /success:enable` in an administrator prompt.

### USB drives and downloads

The installer also puts a **scan agent** on the computer (`scan-agent.ps1`, a hidden SYSTEM task started at
boot; its text is `_SCAN_AGENT` in `app/services/installer.py`). It looks for a USB drive that was just plugged
in and for new files in the users' Downloads folders, and reports them to `POST /api/agent/scan` with the
endpoint's token. It only **reads**: it sends names, attributes and SHA256 hashes, never file content. For a
drive it sends the part of the file list that the rules look at (programs, scripts, shortcuts, hidden files,
autorun.inf), for Downloads the hashes of the new files. Its own log is `C:\ProgramData\AegisGuard\scan.log`.

On the server (`app/services/scan_results.py`): the hash of every file is looked up in the `threat_intel` table
(`app/services/threat_intel.py`; a hit is a confirmed finding), and a drive is checked against the USB rules
(`app/services/usb_scan.py`: autorun.inf whose programs are not signed, double extension, hidden program,
shortcut that starts a command or stands in for a hidden folder). Each finding is scored with CVSS and stored
as a security event (type "USB Drive Scan" / "Downloaded File"), a scanned drive also leaves one "scanned"
event, and a Critical finding (a known-bad hash) locks the computer and tells the agent to contain it: the
agent ends the processes that run from that drive (or from the flagged download) and the processes they
started, because a lock stops a person at the keyboard, not a script that is already running. What the agent
ended (and what it could not end) is reported back to `POST /api/agent/containment` and stored as a
"Containment" event, so it shows in Security Logs and the PDF report. A drive can also be read by hand:
`python -m app.services.usb_scan --scan E:\ --list`.

## Structure

```
app/
  core/       settings (.env) and JWT/password helpers
  db/         SQLAlchemy engine/session
  models/     Employee, Endpoint, SecurityEvent, LockEvent, RemovedEndpoint (owned here);
              Customer, Account (subset of the admin-owned tables)
  schemas/    Pydantic request/response models
  api/        auth dependencies and routes
  services/   Wazuh client, alert ingestion and parsing, installer builder, screen frames, endpoint
              lock, overtime, PDF report, platform status
    ml/       the behavioral model (above)
deploy/       deploy script, systemd unit, nginx config, Wazuh rules (company/deploy)
```
