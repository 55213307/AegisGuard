"""What happens to a scan the endpoint's scan agent reports (a USB drive, new downloads).

The agent only reads: it lists the files worth a look and the SHA256 of programs, and sends names,
attributes and hashes. This module runs the rules over that list (services/usb_scan.py: the hash is looked
up in the threat-intelligence table, the USB tricks are checked), scores each finding with CVSS like every
other detection, stores them as security events (so they show up in Security Logs, the dashboard and the PDF
report) and locks the computer when a finding is Critical (a hash on a known-bad list).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.schemas.scan import ContainmentReport, ScanUpload
from app.services import cvss, endpoint_lock, threat_intel
from app.services.ml import runtime
from app.services.usb_scan import FileEntry, Finding, scan_listing
from urllib.parse import urlsplit

log = logging.getLogger("aegisguard.scan")

EVENT_TYPES = {"usb": "USB Drive Scan", "download": "Downloaded File"}


def _worst_per_file(findings: list[Finding], requirements: dict | None) -> list[Finding]:
    """A file can be caught by several rules (a known-bad hash on a double-extension file); the one
    with the highest CVSS score is the one that is reported."""
    best: dict[str, tuple[tuple[int, float], Finding]] = {}
    for f in findings:
        score = cvss.score_detection(f.kind, "confirmed" if f.confirmed else "reasonable", requirements).score
        # A model's guess (weak) never hides a rule or a list hit on the same file, whatever its score: the guess is capped
        # at Warning, so a weak 7.5 in front of a confirmed 7.1 would have kept the computer from being locked.
        rank = (0 if f.weak else 1, score)
        if f.path.lower() not in best or rank > best[f.path.lower()][0]:
            best[f.path.lower()] = (rank, f)
    return [f for _, f in sorted(best.values(), key=lambda pair: (-pair[0][0], -pair[0][1]))]


def build_events(endpoint_id: int, company_id: int, scan: ScanUpload, findings: list[Finding], requirements: dict | None, now: datetime) -> list[dict]:
    """security_events rows for the findings, each scored with CVSS, and for a USB drive one more row that
    says it was scanned (so the portal shows that the drive was checked, also when nothing was found)."""
    event_type = EVENT_TYPES[scan.kind]
    rows: list[dict] = []

    def row(alert_key: str, description: str, details: dict) -> dict:
        return {
            "unique_id": company_id, "endpoint_id": endpoint_id,
            "wazuh_alert_id": "ag-" + hashlib.sha1(f"{scan.scan_id}|{alert_key}".encode()).hexdigest()[:40],
            "event_time": now, "rule_id": "ag-scan", "rule_level": 3, "rule_description": description[:500],
            "severity": "Info", "event_type": event_type, "event_user": None, "windows_event_id": None,
            "details": details, "risk_score": None, "risk_reason": None,
        }  # fmt: skip

    for f in findings:
        event = row(f"{f.kind}|{f.path}", f"{cvss.CATALOG[f.kind].title}: {f.path}", {"scan": {"kind": scan.kind, "source": scan.source, "path": f.path, **f.extra}})
        runtime.set_detection(event, f.kind, f.detail, requirements, command=f.path, confidence="confirmed" if f.confirmed else "reasonable", locks=not f.weak)
        rows.append(event)

    if scan.kind == "usb":  # the record that this drive was checked
        hashed = sum(1 for f in scan.files if f.sha256)
        outcome = f"{len(findings)} finding(s)" if findings else "nothing found"
        rows.append(row("summary", f"USB drive {scan.source} scanned: {outcome}", {
            "scan": {"kind": "usb", "source": scan.source, "files_total": scan.total, "files_reported": len(scan.files),
                     "hashed": hashed, "findings": len(findings)},
        }))  # fmt: skip
    return rows


def address_findings(db, scan: ScanUpload) -> list[Finding]:
    """The address each downloaded file came from (the browser writes it into the file's Zone.Identifier): a match in the
    threat-intelligence lists is confirmed; otherwise the phishing-address model gives its guess, which is a weak signal
    (an alert, never a lock). Only the host is shown in the reason; the full address stays in the event's details."""
    found: list[Finding] = []
    model = runtime.url_model()
    for f in scan.files:
        if not f.source_url:
            continue
        host = urlsplit(f.source_url).hostname or f.source_url[:60]
        hit = threat_intel.check_url(db, f.source_url)
        if hit is not None:
            category = f" ({hit.category})" if getattr(hit, "category", None) else ""
            found.append(Finding("phishing_url", f.path, f"{host} is on the {hit.source} list{category}", confirmed=True, extra={"url": f.source_url, "list": hit.source}))
        elif model is not None:
            verdict = model.check(f.source_url)
            if verdict["phishing"]:
                found.append(Finding("phishing_url", f.path, f"{host}: address model {verdict['probability']:.0%} phishing (weak signal, no lock)",
                                     weak=True, extra={"url": f.source_url, "probability": round(verdict["probability"], 4)}))
    return found


def header_findings(scan: ScanUpload) -> list[Finding]:
    """The malware model on the PE header numbers of 32-bit programs (the agent sends them; nothing else of the file leaves the computer).
    A weak signal: an alert from a probability of 99%, never a lock. A known-bad hash is judged by the lists, not by this."""
    model = runtime.file_model()
    if model is None:
        return []
    found: list[Finding] = []
    for f in scan.files:
        if not f.pe:
            continue
        verdict = model.check_row([float(v) for v in f.pe])
        if verdict and verdict["malicious"]:
            found.append(Finding("malicious_file", f.path, f"header model {verdict['probability']:.0%} malware (weak signal, no lock)",
                                 weak=True, extra={"probability": round(verdict["probability"], 4), "sha256": f.sha256}))
    return found


def _insert_events(db, rows: list[dict]) -> None:
    if not rows:  # a download scan with nothing found: values([]) would insert a row of defaults (and fail), and the agent would retry for ever
        return
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:  # the tests use SQLite
        from sqlalchemy.dialects.sqlite import insert
    db.execute(insert(SecurityEvent.__table__).values(rows).on_conflict_do_nothing(index_elements=["wazuh_alert_id"]))
    db.commit()


def build_containment_event(endpoint_id: int, company_id: int, report: ContainmentReport, now: datetime) -> dict:
    """The record of what the agent did about a Critical finding, as a security event (Security Logs, PDF
    report), so the portal shows that the processes were ended, which ones, and which could not be."""
    names = ", ".join(sorted({p.name for p in report.ended})) or "none"
    description = f"Containment on {report.source}: {len(report.ended)} process(es) ended ({names})"
    if report.failed:
        description += f", {len(report.failed)} could not be ended"
    return {
        "unique_id": company_id, "endpoint_id": endpoint_id,
        "wazuh_alert_id": "ag-" + hashlib.sha1(f"{report.scan_id}|containment".encode()).hexdigest()[:40],
        "event_time": now, "rule_id": "ag-contain", "rule_level": 3, "rule_description": description[:500],
        "severity": "Info", "event_type": "Containment", "event_user": None, "windows_event_id": None,
        "details": {"containment": {
            "scan_id": report.scan_id, "source": report.source,
            "ended": [p.model_dump(exclude_none=True) for p in report.ended],
            "failed": [p.model_dump(exclude_none=True) for p in report.failed],
        }},
        "risk_score": None, "risk_reason": None,
    }  # fmt: skip


def store_containment(db, endpoint: Endpoint, report: ContainmentReport) -> dict:
    row = build_containment_event(endpoint.id, endpoint.unique_id, report, datetime.now(timezone.utc))
    _insert_events(db, [row])
    log.info("Containment on endpoint %s (%s): %d ended, %d failed", endpoint.id, report.source, len(report.ended), len(report.failed))
    return {"stored": True}


def store_scan(db, endpoint: Endpoint, scan: ScanUpload) -> dict:
    """Judge a reported scan, store the findings as events and lock the computer if one is Critical."""
    entries = [FileEntry(path=f.path, is_dir=f.is_dir, size=f.size, hidden=f.hidden, sha256=f.sha256, target=f.target, target_signed=f.target_signed) for f in scan.files]
    requirements = cvss.requirements_for(endpoint.employee.department if endpoint.employee is not None else None)
    findings = scan_listing(entries, lambda hashes: threat_intel.lookup_many(db, "sha256", hashes), usb=scan.kind == "usb")
    findings += header_findings(scan)
    if scan.kind == "download":
        findings += address_findings(db, scan)
    findings = _worst_per_file(findings, requirements)[:50]
    rows = build_events(endpoint.id, endpoint.unique_id, scan, findings, requirements, datetime.now(timezone.utc))

    _insert_events(db, rows)

    locked = 0
    try:  # a failure here must not undo the storing
        locked = endpoint_lock.auto_lock(db, [r for r in rows if r["severity"] == "Critical"])
    except Exception:
        db.rollback()
        log.exception("Automatic locking after a scan failed")
    critical_paths = [r["details"]["scan"]["path"] for r in rows if r["severity"] == "Critical"]
    log.info("Scan %s of endpoint %s (%s): %d finding(s), %d locked, %d to contain", scan.scan_id, endpoint.id, scan.source, len(findings), locked, len(critical_paths))
    return {"findings": len(findings), "locked": bool(locked), "contain": bool(critical_paths), "contain_paths": critical_paths[:50]}
