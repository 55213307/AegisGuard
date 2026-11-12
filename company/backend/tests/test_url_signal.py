"""Downloads with a source address -> blocklist (confirmed) or the address model (weak signal, never locks)."""
import sys, os, warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore")
from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models.threat_intel import ThreatIndicator
from app.schemas.scan import ScanUpload
from app.services import cvss, scan_results, threat_intel
from app.services.ml import runtime
from app.services.usb_scan import scan_listing

engine = create_engine("sqlite://")
Base.metadata.create_all(engine, tables=[ThreatIndicator.__table__])
db = sessionmaker(bind=engine)()
print("url model loaded:", runtime.url_model() is not None)
threat_intel.add_many(db, [("domain", "evil-listed.example", "demo-test", "phishing", None)])

files = [
    {"path": r"C:\Users\x\Downloads\setup.exe", "size": 10, "source_url": "https://download.microsoft.com/setup.exe"},
    {"path": r"C:\Users\x\Downloads\report.pdf", "size": 10, "source_url": "https://www.google.com/report.pdf"},
    {"path": r"C:\Users\x\Downloads\invoice.zip", "size": 10, "source_url": "https://login-update-account.web.app/invoice.zip"},
    {"path": r"C:\Users\x\Downloads\tool.exe", "size": 10, "source_url": "http://evil-listed.example/tool.exe"},
    {"path": r"C:\Users\x\Downloads\local.txt", "size": 10},
]
scan = ScanUpload(scan_id="a" * 16, kind="download", source="Downloads", total=len(files), files=files)
for dep in (None, "finance", "it"):
    req = cvss.requirements_for(dep) if dep else None
    findings = scan_results._worst_per_file(scan_results.address_findings(db, scan), req)
    rows = scan_results.build_events(8, 32, scan, findings, req, datetime.now(timezone.utc))
    print(f"\ndepartment={dep}: {len(rows)} finding(s)")
    for r in rows:
        print(f"  risk={r['risk_score']:>3} {r['severity']:9} weak={r['details']['cvss'].get('weak_signal', False)!s:5} {r['risk_reason']}")
