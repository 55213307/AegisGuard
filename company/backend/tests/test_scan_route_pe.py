"""POST /api/agent/scan end to end (token, schema, rules, threat intel, events, lock), on an in-memory SQLite database."""
import json, sys, os, warnings
from pathlib import Path

warnings.filterwarnings("ignore")
from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@compiles(JSONB, "sqlite")
def _jsonb(type_, compiler, **kw):
    return "JSON"


from fastapi.testclient import TestClient

from app.db.session import Base, get_db
from fastapi import FastAPI
from app.api.routes import agent
app = FastAPI()
app.include_router(agent.router)
from app.models.customer import Customer
from app.models.employee import Employee
from app.models.endpoint import Endpoint
from app.models.lock_event import LockEvent
from app.models.security_event import SecurityEvent
from app.models.threat_intel import ThreatIndicator
from app.services import screens, threat_intel

S = Path(DATA)
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(engine, tables=[t.__table__ for t in (Customer, Employee, Endpoint, SecurityEvent, LockEvent, ThreatIndicator)])
Session = sessionmaker(bind=engine)
db = Session()
db.add(Customer(id=32, company_name="Acme"))
db.add(Employee(id=1, unique_id=32, employee_username="alice", employee_email="a@x.com", department="finance"))
db.flush()
db.add(Endpoint(id=8, unique_id=32, employee_id=1, endpoint_name="alice", wazuh_agent_id="008", wazuh_agent_name="AG-32-alice"))
db.commit()
usb = json.loads((S / "payload_usb.json").read_text(encoding="utf-8"))
bad = next(f["sha256"] for f in usb["files"] if f["path"] == "invoice_2026.pdf.exe")


def override():
    s = Session()
    try:
        yield s
    finally:
        s.close()


app.dependency_overrides[get_db] = override
client = TestClient(app)  # no `with`: the background threads of the real app are not started
token = screens.screen_token(8, "008")
H = {"X-AegisGuard-Token": token}

# ---------------- today's changes: PE header + weak signals through the real route ----------------
import json
import numpy as np
from app.services.ml import files as F, runtime
cols, X, y, yrs = F.load_dataset()
mal = [list(map(int, X[i])) for i in range(len(y)) if y[i] == 1 and X[i][cols.index("Machine")] == 332]
ben = [list(map(int, X[i])) for i in range(len(y)) if y[i] == 0 and X[i][cols.index("Machine")] == 332]
pe64 = list(mal[0]); pe64[cols.index("Machine")] = 34404; pe64[cols.index("Magic")] = 523
model = runtime.file_model()
probs = [model.check_row([float(v) for v in r])["probability"] for r in mal[:200]]
confident = next(r for r, p in zip(mal, probs) if p >= 0.995)
def post(files, kind="download"):
    return client.post("/api/agent/scan", headers=H, json={"scan_id": os.urandom(8).hex(), "kind": kind, "source": "Downloads", "total": len(files), "files": files})
def events():
    s = Session(); rows = s.query(SecurityEvent).order_by(SecurityEvent.id.desc()).all(); s.close(); return rows

print("A. a 32-bit program the header model is sure about (weak signal)")
before = len(events()); r = post([{"path": r"C:\Users\alice\Downloads\sure.exe", "size": 1000, "pe": confident}])
ev = events()[0]
print("  ", r.status_code, r.json(), "| severity:", ev.severity, "| weak_signal:", ev.details["cvss"].get("weak_signal"), "| reason:", ev.risk_reason[:110])
print("   not locked:", r.json()["locked"] is False, "| events added:", len(events()) - before)

print("B. a benign program, a 64-bit program, a malformed header")
before = len(events())
r = post([{"path": r"C:\d\ok.exe", "size": 1, "pe": ben[0]}, {"path": r"C:\d\x64.exe", "size": 1, "pe": pe64}, {"path": r"C:\d\bad.exe", "size": 1, "pe": [1, 2, 3]}, {"path": r"C:\d\neg.exe", "size": 1, "pe": [-5] * 55}])
print("  ", r.status_code, r.json(), "| events added:", len(events()) - before)

print("C. a header model finding and a known-bad hash on the same file: the confirmed one wins")
bad_hash = next(f["sha256"] for f in usb["files"] if f["path"] == "invoice_2026.pdf.exe")
threat_intel.add_many(db, [("sha256", bad_hash, "demo-test", "Mirai", None)])
r = post([{"path": r"C:\d\both.exe", "size": 1, "sha256": bad_hash, "pe": confident}])
ev = events()[0]; print("  ", r.status_code, r.json()["findings"], "finding(s) |", ev.severity, "|", ev.risk_reason[:90])

print("D. the same upload twice (the agent retries): stored once")
body = {"scan_id": "rep" + "0" * 13, "kind": "download", "source": "Downloads", "total": 1, "files": [{"path": r"C:\d\again.exe", "size": 1, "pe": confident}]}
a = client.post("/api/agent/scan", headers=H, json=body); n1 = len(events()); b = client.post("/api/agent/scan", headers=H, json=body); n2 = len(events())
print("  ", a.status_code, b.status_code, "| rows after 1st:", n1, "after 2nd:", n2, "| stored once:", n1 == n2)

print("E. a USB scan with pe numbers works too, and 5000 files with pe stay accepted")
r = post([{"path": f"E:/p{i}.exe", "size": 1, "pe": ben[i % len(ben)]} for i in range(300)], kind="usb")
print("  ", r.status_code, r.json())
