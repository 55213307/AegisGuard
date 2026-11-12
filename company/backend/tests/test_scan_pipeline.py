"""The payloads the PowerShell agent produces -> the backend's schema, rules, threat-intel lookup and events."""
import json, sys, os, warnings
from datetime import datetime, timezone
from pathlib import Path

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
from app.services.usb_scan import FileEntry, scan_listing

S = Path(DATA)
engine = create_engine("sqlite://")
Base.metadata.create_all(engine, tables=[ThreatIndicator.__table__])
db = sessionmaker(bind=engine)()


def judge(file, known_hash=None):
    scan = ScanUpload(**json.loads((S / file).read_text(encoding="utf-8")))
    entries = [FileEntry(path=f.path, is_dir=f.is_dir, size=f.size, hidden=f.hidden, sha256=f.sha256, target=f.target, target_signed=f.target_signed) for f in scan.files]
    if known_hash:
        threat_intel.add_many(db, [("sha256", known_hash, "demo-test", "Mirai", None)])
    req = cvss.requirements_for("finance")
    findings = scan_results._worst_per_file(scan_listing(entries, lambda h: threat_intel.lookup_many(db, "sha256", h), usb=scan.kind == "usb"), req)
    rows = scan_results.build_events(8, 32, scan, findings, req, datetime.now(timezone.utc))
    print(f"\n{file}: kind={scan.kind} source={scan.source!r} {len(scan.files)} entries reported, {len(findings)} finding(s), {len(rows)} event row(s)")
    for r in rows:
        print(f"  {r['event_type']:15} risk={r['risk_score']!s:>4} {r['severity']:9} {r['risk_reason'] or r['rule_description']}")
    return rows


judge("payload_usb.json")
print("\n-- the same drive, once a file of it is on a known-bad list (finance department: higher requirements)")
usb = json.loads((S / "payload_usb.json").read_text(encoding="utf-8"))
bad = next(f["sha256"] for f in usb["files"] if f["path"] == "invoice_2026.pdf.exe")
rows = judge("payload_usb.json", known_hash=bad)
print("\nalert ids unique:", len({r['wazuh_alert_id'] for r in rows}) == len(rows), "| e.g.", rows[0]["wazuh_alert_id"])
judge("payload_download.json")
# bad input is refused by the schema
for broken in ({"scan_id": "short", "kind": "usb", "source": "x", "files": []}, {"scan_id": "x" * 16, "kind": "other", "source": "x", "files": []},
               {"scan_id": "x" * 16, "kind": "usb", "source": "x", "files": [{"path": "a", "sha256": "zz"}]}):
    try:
        ScanUpload(**broken); print("accepted (BAD):", broken)
    except Exception as exc:
        print("refused:", str(exc).splitlines()[0][:70])
