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


def post(payload, headers=H):
    return client.post("/api/agent/scan", json=payload, headers=headers)


r = post(usb)
print("1. drive with only the USB tricks ->", r.status_code, r.json())
check = Session()
print("   events stored:", check.query(SecurityEvent).count(), "| employee locked:", check.get(Employee, 1).employee_status.value)
for e in check.query(SecurityEvent).order_by(SecurityEvent.risk_score.desc().nullslast()).all():
    print(f"   {e.event_type:15} risk={e.risk_score!s:>4} {e.severity:9} {(e.risk_reason or e.rule_description)[:110]}")

r = post(usb)
print("\n2. the same scan again (new scan_id in the file is the same, so a retry) ->", r.status_code, r.json(), "| events now:", check.query(SecurityEvent).count(), "(unchanged: no duplicates)")

threat_intel.add_many(db, [("sha256", bad, "demo-test", "Mirai", None)])
usb2 = {**usb, "scan_id": "b" * 32}
r = post(usb2)
check.expire_all()
print("\n3. the drive again, now with a file whose hash is known bad ->", r.status_code, r.json())
print("   employee:", check.get(Employee, 1).employee_status.value, "|", check.get(Employee, 1).lock_reason)
print("   lock events:", [(l.action, l.actor) for l in check.query(LockEvent).all()])

print("\n4. wrong or missing token ->", post(usb, {"X-AegisGuard-Token": "8.abc"}).status_code, client.post("/api/agent/scan", json=usb).status_code)
print("5. broken body ->", post({"scan_id": "short", "kind": "usb", "source": "x", "files": []}).status_code)
dl = json.loads((S / "payload_download.json").read_text(encoding="utf-8"))
dl["scan_id"] = "c" * 32
r = post(dl)
print("6. a download whose hash is known bad ->", r.status_code, r.json())

# --- containment report from the agent
cont = json.loads((S / "payload_containment.json").read_text(encoding="utf-8"))
r = client.post("/api/agent/containment", json=cont, headers=H)
print("\n7. containment report (3 ended) ->", r.status_code, r.json())
r2 = client.post("/api/agent/containment", json=cont, headers=H)
check.expire_all()
rows = check.query(SecurityEvent).filter(SecurityEvent.event_type == "Containment").all()
print("8. the same report again -> stored once:", len(rows) == 1)
print("   event:", rows[0].severity, "|", rows[0].rule_description)
print("   details keys:", sorted(rows[0].details["containment"]), "| ended:", [(p["name"], p["pid"]) for p in rows[0].details["containment"]["ended"]])
empty = {"scan_id": "ffeeddccbbaa9988", "source": "E: (MYUSB)", "ended": [], "failed": []}
print("9. empty report ->", client.post("/api/agent/containment", json=empty, headers=H).json(), "|", check.query(SecurityEvent).filter(SecurityEvent.wazuh_alert_id.like("ag-%"), SecurityEvent.event_type == "Containment").count(), "containment events")
print("10. wrong token ->", client.post("/api/agent/containment", json=cont, headers={"X-AegisGuard-Token": "8.abc"}).status_code)
