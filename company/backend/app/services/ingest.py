"""Background ingester: tails the Wazuh manager's alerts.json and stores new
alerts (for portal-registered endpoints) in PostgreSQL.

Runs as a daemon thread started with the app (see app/main.py). Single uvicorn
worker, so one ingester. Safe when the file is absent (local dev): it just
waits. Robust to the daily log rotation and to partial lines mid-write, and
deduplicates on wazuh_alert_id so re-reading never doubles rows.
"""

import json
import logging
import os
import threading

from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.services.alerts import agent_id_of, parse_alert

log = logging.getLogger("aegisguard.ingest")

_stop = threading.Event()
_thread: threading.Thread | None = None


def _agent_map(db) -> dict[str, tuple[int, int]]:
    """wazuh_agent_id -> (endpoint_id, company unique_id) for every endpoint
    registered through the portal. Rebuilt each cycle so newly onboarded
    computers start getting ingested without a restart."""
    rows = db.query(Endpoint.wazuh_agent_id, Endpoint.id, Endpoint.unique_id).all()
    return {agent_id: (endpoint_id, unique_id) for agent_id, endpoint_id, unique_id in rows}


def _read_new_lines(path: str, state: dict) -> list[bytes]:
    """Complete lines appended since last call. Advances state only past whole
    lines; resets to the start when the file was rotated or truncated."""
    stat = os.stat(path)
    if stat.st_ino != state.get("inode") or stat.st_size < state["offset"]:
        state["offset"] = 0
        state["inode"] = stat.st_ino
    if stat.st_size == state["offset"]:
        return []

    with open(path, "rb") as handle:
        handle.seek(state["offset"])
        chunk = handle.read(stat.st_size - state["offset"])

    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return []  # only a partial line so far; wait for the rest
    state["offset"] += last_newline + 1
    return [line for line in chunk[:last_newline].split(b"\n") if line.strip()]


def _store(db, lines: list[bytes], agents: dict[str, tuple[int, int]]) -> int:
    rows = []
    for raw in lines:
        try:
            alert = json.loads(raw)
        except json.JSONDecodeError:
            continue
        agent_id = agent_id_of(alert)
        if agent_id is None or agent_id not in agents:
            continue  # manager's own alert, or an endpoint we don't manage
        parsed = parse_alert(alert)
        if parsed is None:
            continue
        endpoint_id, unique_id = agents[agent_id]
        rows.append({**parsed, "endpoint_id": endpoint_id, "unique_id": unique_id})

    if not rows:
        return 0
    # ON CONFLICT DO NOTHING makes rowcount unreliable, so count what RETURNING
    # actually yields — conflicting (already-seen) rows return nothing.
    stmt = (
        pg_insert(SecurityEvent.__table__)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["wazuh_alert_id"])
        .returning(SecurityEvent.id)
    )
    inserted = len(db.execute(stmt).fetchall())
    db.commit()
    return inserted


def _run() -> None:
    path = settings.alerts_file_path
    state = {"offset": 0, "inode": None}
    missing_logged = False

    while not _stop.is_set():
        try:
            if not os.path.exists(path):
                if not missing_logged:
                    log.warning("Alerts file not found at %s — waiting for it.", path)
                    missing_logged = True
            else:
                missing_logged = False
                lines = _read_new_lines(path, state)
                if lines:
                    db = SessionLocal()
                    try:
                        inserted = _store(db, lines, _agent_map(db))
                        if inserted:
                            log.info("Ingested %d new security event(s).", inserted)
                    finally:
                        db.close()
        except Exception:  # never let one bad cycle kill the thread
            log.exception("Alert ingestion cycle failed")
        _stop.wait(settings.ingest_poll_seconds)


def start() -> None:
    global _thread
    if not settings.ingest_enabled:
        log.info("Alert ingestion disabled (INGEST_ENABLED=false).")
        return
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_run, name="alert-ingester", daemon=True)
    _thread.start()
    log.info("Alert ingester started (reading %s).", settings.alerts_file_path)


def stop() -> None:
    _stop.set()
    if _thread:
        _thread.join(timeout=5)
