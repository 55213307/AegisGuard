"""Containment is listed; a weak signal does not pop up or raise the 'alerting' flag."""
import sys, os, warnings
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
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
def _jsonb(type_, compiler, **kw): return "JSON"

from app.db.session import Base
from app.models.customer import Customer
from app.models.employee import Employee
from app.models.endpoint import Endpoint
from app.models.lock_event import LockEvent
from app.models.security_event import SecurityEvent
from app.api.routes import anomalies, employees, security_logs

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(engine, tables=[t.__table__ for t in (Customer, Employee, Endpoint, SecurityEvent, LockEvent)])
db = sessionmaker(bind=engine)()
db.add(Customer(id=32, company_name="Acme")); db.add(Employee(id=1, unique_id=32, employee_username="alice", employee_email="a@x.com", department="finance")); db.flush()
db.add(Endpoint(id=8, unique_id=32, employee_id=1, endpoint_name="alice", wazuh_agent_id="008", wazuh_agent_name="AG-32-alice")); db.commit()
now = datetime.now(timezone.utc)
def ev(n, severity, etype, risk, desc):
    return SecurityEvent(unique_id=32, endpoint_id=8, wazuh_alert_id=f"t{n}", event_time=now - timedelta(minutes=n), rule_id="r", rule_level=3, rule_description=desc,
                         severity=severity, event_type=etype, details={}, risk_score=risk, risk_reason=desc)
db.add_all([ev(1, "Critical", "Downloaded File", 78, "known malware"), ev(2, "Warning", "Downloaded File", 75, "WEAK signal (cvss 7.5, capped)"),
            ev(3, "Info", "Containment", None, "Containment on Downloads: 2 process(es) ended (run-test.exe, PING.EXE)"),
            ev(4, "Info", "Logon", None, "routine logon"), ev(5, "Warning", "Process", 51, "admin tool")]); db.commit()

print("1. Security Logs lists (before: Warning and Critical only):")
rows = security_logs._query(db, 32, 7).all()
for e, name in rows: print("   ", e.severity, "|", e.event_type, "|", e.rule_description[:60])
types = [e.event_type for e, _ in rows]
print("   Containment listed:", "Containment" in types, "| routine logon NOT listed:", "Logon" not in types)

print("2. the endpoint page 'Recent Problems' (employees.list_events):")
res = employees.list_events(1, 20, SimpleNamespace(company_id=32, account=SimpleNamespace(unique_id=32)), db)
print("   ", [(e.severity, e.event_type) for e in res.items])
print("   Containment listed:", any(e.event_type == "Containment" for e in res.items), "| routine logon NOT listed:", not any(e.event_type == "Logon" for e in res.items))

print("3. the pop-up feed (anomalies.feed), everything after id 0:")
p = SimpleNamespace(company_id=32, account=SimpleNamespace(unique_id=32))
feed = anomalies.feed(0, p, db)
for a in feed.items: print("   pops up:", a.severity, a.risk_score, a.description[:50])
print("   only the Critical one pops up:", [a.risk_score for a in feed.items] == [78])

print("4. the 'alerting' flag of the computer (risk_active) from the last 15 minutes:")
emp = db.query(Employee).get(1)
day, recent = employees._risk_24h(db, [emp])[8]
print("    24h peak:", day, "| recent (counts toward the flag):", recent, "| flag raised:", recent is not None and recent >= employees.CRITICAL_RISK)
# remove the Critical and ask again: only the weak signal is left
db.query(SecurityEvent).filter(SecurityEvent.severity == "Critical").delete(); db.commit()
day, recent = employees._risk_24h(db, [emp])[8]
print("    with only the weak signal left: 24h peak", day, "(still shown) | recent", recent, "| flag raised:", recent is not None and recent >= employees.CRITICAL_RISK)
