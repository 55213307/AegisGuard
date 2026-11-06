"""What runs inside the backend: the per-endpoint models kept in memory and the thread that (re)trains them
(registry), and the scoring of events as they arrive (scoring). Models live in memory only.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.employee import Employee
from app.models.endpoint import Endpoint
from app.services import badusb, cvss, health
from app.services.ml.data import (
    DAY,
    SEED_PREFIX,
    SHIFTS,
    build_baseline,
    load_csv,
    load_db,
    row_from_event,
    shift_from_hours,
)
from app.services.ml.model import (
    ANOMALY_RISK_THRESHOLD,
    BehaviorModel,
    HIGH_RISK_TOOLS,
    LOCAL_TZ,
    VARIETY_WINDOW,
    _ROUTINE_EVENT_TYPES,
    _USER_EVENT_TYPES,
    action_key,
    add_context,
    admin_ok_for,
    adopts_habits,
    is_admin_tool,
    is_user_action,
)

# ============================================================================
# scoring: put risk scores on security_events
# ============================================================================
#
# Put the behavioral model's risk scores on security_events.
#
#   - apply(): scores freshly parsed alerts as the ingester stores them.
#   - backfill(): scores events that arrived before the endpoint had a model
#     (or before this feature existed); run after an endpoint's model is trained.
#
# Only events that are the user's own actions get a score; everything else
# (machine activity, maintenance helpers, scans) keeps risk_score NULL.
# Functions take the model, or a lookup for it, so this module doesn't depend on
# the registry that trains the models.

_SEVERITY_ORDER = {"Info": 0, "Warning": 1, "Critical": 2}
# What the model flags is scored with CVSS v3.1 (services/cvss.py), and the event's risk_score
# is that score x 10 (7.5 -> 75), so the 0-100 scale the portal shows keeps its meaning:
# 40 and up is a CVSS Medium (a Warning), CRITICAL_RISK (70, a CVSS High) and up is Critical,
# which locks the computer. Events the model does not flag keep the model's own score.
CRITICAL_RISK = int(round(settings.cvss_lock_from * 10))


_command_model = None
_command_model_tried = False


def command_model():
    """The malicious-command model (rules + classifier, ml/commands.py), loaded once; None when
    it is switched off or its file is missing, in which case scoring works without it."""
    global _command_model, _command_model_tried
    if _command_model_tried or not settings.command_model_enabled:
        return _command_model
    _command_model_tried = True
    path = Path(settings.command_model_path) if settings.command_model_path else Path(__file__).resolve().parents[3] / "ml_models" / "command_model.joblib"
    try:
        if path.exists():
            from app.services.ml import commands

            _command_model = commands.load(path)
            log.info("Malicious-command model loaded from %s (%d rules).", path, _command_model.rules.entries if _command_model.rules else 0)
        else:
            log.info("No malicious-command model at %s: commands are not judged by it.", path)
    except Exception:
        log.exception("Loading the malicious-command model failed; commands are not judged by it")
    return _command_model


def _command_text(row: dict) -> str:
    return (row.get("command") or row.get("command_line") or "").strip()


def _command_verdicts(rows: list[dict]) -> dict[int, dict]:
    """index -> verdict of the command model, for the rows that are a user action with a command."""
    model = command_model()
    if model is None:
        return {}
    at = [i for i, r in enumerate(rows) if is_user_action(r) and len(_command_text(r)) >= 3]
    if not at:
        return {}
    try:
        return dict(zip(at, model.check_many([_command_text(rows[i]) for i in at])))
    except Exception:  # a failure here must never stop events from being scored
        log.exception("Judging commands failed")
        return {}


def detection_for(model: BehaviorModel, row: dict, score, verdict: dict | None = None) -> str:
    """Which kind of detection (a key of cvss.CATALOG) a flagged event is. The kind is what
    the event IS: a command the command model calls malicious, an encoded command line, a risky
    tool, a program never run here, or the user's usual doing at an unusual time. `verdict` is
    the command model's judgement of the command (None when there is no model or no command)."""
    if verdict and verdict["malicious"]:
        return "malicious_command"
    if score.command >= 0.3 and "encoded" in (model._command_novelty(row)[1] or ""):
        return "encoded_command"
    if (row.get("process_name") or "") in HIGH_RISK_TOOLS and verdict is None:
        return "high_risk_tool"  # no command model: judged by the program alone
    if score.novelty > 0:  # never seen on this computer
        if row["event_type"] in _ROUTINE_EVENT_TYPES:
            return "new_privileged_logon"
        if row["windows_event_id"] in ("4688", "4104"):
            return "admin_tool" if is_admin_tool(row, model.admin_ok) else "new_program"
    return "unusual_activity"


def severity_for_cvss(score: float, current: str | None) -> str:
    """The portal's severity for a CVSS score; never lowers what Wazuh's rule level gave."""
    target = cvss.severity_for_score(score, settings.cvss_lock_from)
    if current and _SEVERITY_ORDER.get(current, 0) >= _SEVERITY_ORDER[target]:
        return current
    return target


# Failed logons are a rule, not something the model judges: one wrong password
# is normal, so an alert needs FAILED_LOGON_LIMIT failures on the same computer
# within FAILED_LOGON_WINDOW (password guessing).
FAILED_LOGON_LIMIT = 3
FAILED_LOGON_WINDOW = timedelta(minutes=10)
_FAILED_LOGON = "Login Failed"


def failed_logon_risk(count: int) -> tuple[int, str | None]:
    """(risk, reason) for a failed logon that is number `count` within the
    window. Every FAILED_LOGON_LIMIT-th failure raises the alarm; the ones in
    between are shown as part of the burst but don't alert again."""
    if count < FAILED_LOGON_LIMIT:
        return 15, None
    minutes = int(FAILED_LOGON_WINDOW.total_seconds() // 60)
    if count % FAILED_LOGON_LIMIT == 0:
        return 95, f"{count} failed logons within {minutes} minutes (possible password guessing)"
    return 60, f"{count} failed logons within {minutes} minutes (still going)"


def failed_logon_counter(db, batch: list[dict] | None = None):
    """Returns count(event): how many failed logons the event's computer had in
    the window up to and including this one. Counts those already stored and,
    when scoring a batch that isn't stored yet, the earlier ones in the batch."""
    from sqlalchemy import func

    from app.models.security_event import SecurityEvent as SE

    from app.services import endpoint_lock

    in_batch = [e for e in batch or [] if e.get("event_type") == _FAILED_LOGON]
    unlocked_at: dict[int, object] = {}

    def count(event: dict) -> int:
        t = event["event_time"]
        start = t - FAILED_LOGON_WINDOW
        # Failures from before the last unlock are forgiven: the count starts over.
        if event["endpoint_id"] not in unlocked_at:
            unlocked_at[event["endpoint_id"]] = endpoint_lock.last_unlocks(db, [event["endpoint_id"]]).get(event["endpoint_id"])
        if unlocked_at[event["endpoint_id"]] is not None:
            start = max(start, unlocked_at[event["endpoint_id"]])
        stored = (
            db.query(func.count(SE.id))
            .filter(
                SE.endpoint_id == event["endpoint_id"],
                SE.event_type == _FAILED_LOGON,
                SE.event_time > start,
                SE.event_time < t,
            )
            .scalar()
        )
        earlier = sum(1 for o in in_batch if o is not event and o["endpoint_id"] == event["endpoint_id"] and start < o["event_time"] < t)
        return (stored or 0) + earlier + 1

    return count


def _set(event: dict, risk: int, reason: str | None) -> None:
    """An event that is not a detection: it keeps the model's own score and its severity."""
    event["risk_score"] = risk
    event["risk_reason"] = reason


COMMAND_SHOWN = 90  # characters of the command shown in the reason


def _shown(command: str | None) -> str:
    text = " ".join((command or "").split())
    return text if len(text) <= COMMAND_SHOWN else text[: COMMAND_SHOWN - 1] + "…"


def _set_detection(
    event: dict,
    kind: str,
    reason: str | None,
    requirements: dict | None = None,
    command: str | None = None,
    confidence: str = "reasonable",
    verdict: dict | None = None,
) -> None:
    """An event that is a detection: scored with CVSS v3.1 (the kind's fixed vector, the
    confidence of the finding, the computer's department). risk_score is the CVSS score x 10.
    The reason says how bad (the score and the ATT&CK technique), what kind of thing it is, and
    the command that was run, then why it was flagged. The severity follows the score, and
    the full vector is kept in details["cvss"] so the score can be checked by anyone."""
    result = cvss.score_detection(kind, confidence, requirements)
    event["risk_score"] = int(round(result.score * 10))
    technique = (verdict or {}).get("technique") or result.attack.split()[0]  # a LOLBAS match names its own
    head = f"CVSS {result.score:.1f} {result.rating} ({technique}) {cvss.SHORT[kind]}"
    if command:
        head += f": {_shown(command)}"
    text = head
    if verdict and verdict["malicious"]:  # what the command model found, before the behaviour model's reasons
        found = (
            f"Rule: LOLBAS {verdict['technique']} {verdict['category']}".strip()
            if verdict["confirmed"]
            else f"Classifier: {verdict['probability']:.0%} chance this command is malicious"
        )
        reason = f"{found} | {reason}" if reason else found
    for part in (reason or "").split(" | "):  # the column holds 200 characters: keep whole parts
        if part and len(text) + 3 + len(part) <= 200:
            text += f" | {part}"
    event["risk_reason"] = text[:200]
    if "severity" in event:
        event["severity"] = severity_for_cvss(result.score, event["severity"])
    details = event.get("details")
    if isinstance(details, dict):
        details["cvss"] = {
            "detection": kind, "vector": result.vector, "base": result.base, "score": result.score,
            "rating": result.rating, "attack": result.attack, "confidence": confidence,
        }  # fmt: skip
        if verdict:
            details["cvss"]["command_model"] = {
                "malicious": verdict["malicious"], "probability": round(verdict["probability"], 4),
                "confirmed": verdict["confirmed"], "technique": verdict["technique"], "category": verdict["category"],
            }  # fmt: skip


set_detection = _set_detection  # for the detections that do not come from the model (services/scan_results.py)


def _score_failed_logons(events: list[dict], failed_count, requirements: dict | None = None) -> None:
    for event in events:
        if event.get("event_type") == _FAILED_LOGON:
            risk, reason = failed_logon_risk(failed_count(event) if failed_count else 1)
            if risk >= ANOMALY_RISK_THRESHOLD:  # the alarm: failures piling up
                _set_detection(event, "password_guessing", reason, requirements)
            else:
                _set(event, risk, reason)


def keyboard_lookup(db):
    """devices(endpoint_id, start, end) -> [(time, description)] of the USB keyboards that were
    recognised on the computer in that period, from the stored events."""
    from app.models.security_event import SecurityEvent as SE

    def lookup(endpoint_id: int, start: datetime, end: datetime) -> list[tuple[datetime, str]]:
        rows = db.query(SE.event_time, SE.details).filter(
            SE.endpoint_id == endpoint_id, SE.windows_event_id == badusb.DEVICE_EVENT,
            SE.event_time >= start, SE.event_time <= end,
        )  # fmt: skip
        return [(t, d) for t, details in rows if (d := badusb.keyboard_description(details))]

    return lookup


def _score_badusb(events: list[dict], devices, requirements_of) -> None:
    """A shell or PowerShell command that starts within a few seconds after a USB keyboard was
    plugged in is what a device that types commands looks like (services/badusb.py). It is a
    detection of its own kind, and replaces the event's other detection only if it scores higher."""
    window = timedelta(seconds=settings.badusb_window_seconds)
    plugged: dict[int, list[tuple[datetime, str]]] = defaultdict(list)  # recognised in this same batch
    for e in events:
        if e.get("windows_event_id") == badusb.DEVICE_EVENT and (d := badusb.keyboard_description(e.get("details"))):
            plugged[e["endpoint_id"]].append((e["event_time"], d))
    for e in events:
        if e.get("windows_event_id") not in ("4688", "4104"):
            continue
        row = e.get("_row") or row_from_event(e)
        if not (badusb.is_shell(row) and is_user_action(row)):
            continue
        endpoint_id, when = e["endpoint_id"], e["event_time"]
        known = list(plugged.get(endpoint_id, []))
        if devices is not None:
            known += devices(endpoint_id, when - window, when)
        hit = badusb.keyboard_before(known, when, window)
        if hit is None:
            continue
        requirements = requirements_of(endpoint_id)
        result = cvss.score_detection("badusb", "reasonable", requirements)
        gap, description = hit
        note = f"USB keyboard plugged in {gap:.0f}s before: {description}"
        if result.score <= (((e.get("details") or {}).get("cvss")) or {}).get("score", 0):
            # the event already is something worse: keep that, but say that a keyboard had just been plugged in
            if e.get("risk_reason"):
                head, *rest = e["risk_reason"].split(" | ")
                text = f"{head} | {note}"
                for part in rest:  # the note goes first, then as many of the other reasons as fit
                    if len(text) + 3 + len(part) <= 200:
                        text += f" | {part}"
                e["risk_reason"] = text[:200]
            continue
        _set_detection(e, "badusb", note, requirements, command=_command_text(row) or row.get("process_name"))


def history_loader(db):
    """load(endpoint_id, since) -> model rows of the computer's stored user actions
    since then (newest 500). The model judges an event by what came just before
    it, and the events being scored may be the first of a batch."""
    from sqlalchemy import or_

    from app.models.security_event import SecurityEvent as SE

    def load(endpoint_id: int, since: datetime) -> list[dict]:
        query = (
            db.query(SE.event_time, SE.rule_level, SE.event_type, SE.event_user, SE.windows_event_id, SE.details, SE.wazuh_alert_id)
            .filter(
                SE.endpoint_id == endpoint_id,
                SE.event_time >= since,
                ~SE.wazuh_alert_id.like(SEED_PREFIX + "%"),
                or_(SE.windows_event_id.in_(("4688", "4104")), SE.event_type.in_(_USER_EVENT_TYPES)),
            )
            .order_by(SE.event_time.desc())
            .limit(500)
        )  # fmt: skip
        return [
            row_from_event(
                {
                    "event_time": t, "rule_level": level, "event_type": etype, "event_user": user,
                    "windows_event_id": win_id, "details": details, "wazuh_alert_id": alert_id,
                }
            )
            for t, level, etype, user, win_id, details, alert_id in query
        ]  # fmt: skip

    return load


def _score_into(
    model: BehaviorModel,
    events: list[dict],
    failed_count=None,
    overtime: dict | None = None,
    neutral_time: set | None = None,
    history: list[dict] | None = None,
    context: bool = True,
) -> None:
    """Sets risk_score / risk_reason on each event dict that is a user action:
    the model's judgement, except failed logons, which follow the rule above.
    `overtime` is endpoint id -> end of its approved overtime window; events
    inside one are judged as if at a usual time (what was done still counts), and
    so are all events of the endpoints in `neutral_time`: those whose working
    hours the model doesn't know yet. `history` is what the computer did just before
    these events (rows); `context=False` when the caller has worked the recent-activity
    features out already (backfill does, over the whole timeline at once)."""
    rows = [e.get("_row") or row_from_event(e) for e in events]
    if context:
        add_context((history or []) + rows)  # before any time override below: it is about what really happened
    for event, row in zip(events, rows):
        until = (overtime or {}).get(event["endpoint_id"])
        if (until is not None and event["event_time"] <= until) or event["endpoint_id"] in (neutral_time or ()):
            row["event_time"] = model.typical_time(row["event_time"])
    verdicts = _command_verdicts(rows)
    for i, (event, row, score) in enumerate(zip(events, rows, model.score_many(rows))):
        if not is_user_action(row) or event.get("event_type") == _FAILED_LOGON:
            continue
        verdict = verdicts.get(i)
        confirmed = bool(verdict and verdict["confirmed"])
        # Flagged by the behaviour model, or a command that is a known attack technique (a LOLBAS match
        # is precise enough to count on its own). The classifier's opinion alone is not: it counts
        # together with the behaviour model, because on its own it is wrong for about 1 benign command in 14.
        if score.is_anomaly or confirmed:
            _set_detection(
                event, detection_for(model, row, score, verdict), model.explain(row, score), model.requirements,
                command=_command_text(row), confidence="confirmed" if confirmed else "reasonable", verdict=verdict,
            )
        else:
            _set(event, score.risk, model.explain(row, score))
    _score_failed_logons(events, failed_count, model.requirements)


def apply(
    events: list[dict],
    get_model,
    failed_count=None,
    overtime: dict | None = None,
    neutral_time: set | None = None,
    history=None,
    devices=None,
) -> None:
    """Adds risk_score and risk_reason to parsed alerts (each carrying its
    endpoint_id). `get_model(endpoint_id)` returns the endpoint's model or
    None; `failed_count` is failed_logon_counter's function; `overtime` the open
    overtime windows (see _score_into); `history` is history_loader's function;
    `devices` is keyboard_lookup's function (USB keyboards plugged in just before).
    Every event gets both keys, so the rows can be inserted together."""
    by_endpoint: dict[int, list[dict]] = defaultdict(list)
    for event in events:
        event["risk_score"] = None
        event["risk_reason"] = None
        by_endpoint[event["endpoint_id"]].append(event)
    for endpoint_id, group in by_endpoint.items():
        model = get_model(endpoint_id)
        if model is not None:
            earlier = history(endpoint_id, min(e["event_time"] for e in group) - VARIETY_WINDOW) if history else []
            _score_into(model, group, failed_count, overtime, neutral_time, history=earlier)
        else:
            _score_failed_logons(group, failed_count)  # the rule needs no model
    # BadUSB is a rule too, and needs no model; it runs last so that it can replace a weaker detection.
    _score_badusb(events, devices, lambda endpoint_id: getattr(get_model(endpoint_id), "requirements", None))


def backfill(db, endpoint_id: int, model: BehaviorModel, days: int, batch: int = 2000, neutral_time: bool = False) -> int:
    """Scores the endpoint's unscored real events from the last `days` days.
    Returns how many events got a score."""
    from sqlalchemy import or_, update

    from app.models.security_event import SecurityEvent as SE

    since = datetime.now(timezone.utc) - timedelta(days=days)
    query = (
        db.query(
            SE.id, SE.event_time, SE.rule_level, SE.event_type, SE.event_user, SE.windows_event_id, SE.details,
            SE.severity,
        )  # fmt: skip
        .filter(
            SE.endpoint_id == endpoint_id,
            SE.risk_score.is_(None),
            SE.event_time >= since,
            ~SE.wazuh_alert_id.like(SEED_PREFIX + "%"),
            or_(SE.windows_event_id.in_(("4688", "4104")), SE.event_type.in_(_USER_EVENT_TYPES)),
        )
        .order_by(SE.event_time)
    )
    failed_count = failed_logon_counter(db)
    scored = 0
    updates: list[dict] = []
    for event_id, t, level, etype, user, win_id, details, severity in query.yield_per(2000):
        updates.append(
            {
                "id": event_id, "event_time": t, "rule_level": level, "event_type": etype,
                "event_user": user, "windows_event_id": win_id, "details": details, "severity": severity,
                "endpoint_id": endpoint_id,
            }
        )  # fmt: skip
    for e in updates:
        e["_row"] = row_from_event(e)
    add_context([e["_row"] for e in updates])  # over the whole timeline, so chunk edges don't lose context
    for i in range(0, len(updates), batch):
        chunk = updates[i : i + batch]
        _score_into(model, chunk, failed_count, neutral_time={endpoint_id} if neutral_time else None, context=False)
        db.execute(
            update(SE),
            [
                {
                    "id": e["id"], "risk_score": e.get("risk_score"), "risk_reason": e.get("risk_reason"),
                    "severity": e["severity"],
                }
                for e in chunk
            ],  # fmt: skip
        )
        scored += sum(1 for e in chunk if e.get("risk_score") is not None)
    db.commit()
    return scored


# ============================================================================
# registry: the models, and the job that trains them
# ============================================================================
#
# Per-endpoint behavioral models, kept in memory, and the background job that
# (re)trains them.
#
# Runs as a daemon thread started with the app (see app/main.py), like the alert
# ingester. Isolation Forest trains in seconds, so rather than learning
# continuously (it has no incremental update, and a model that keeps absorbing
# new events would also absorb an attack into "normal"), every endpoint's model
# is retrained from scratch on a schedule, weekly by default, and swapped in as
# a whole. A failed retrain keeps the previous model.
#
# What an endpoint is trained on:
#   - its real user actions from the last `ml_window_days` days, cleaned of admin
#     tooling and of events the current model already flags as anomalous;
#   - while it has less real history than `ml_min_real_actions` actions over
#     `ml_min_real_days` days, the baseline dataset file (ML_BASELINE_CSV, made
#     by seed_baseline.py --out) is trained on as well. Once it has enough, real
#     data only.
# An endpoint with neither enough real history nor a baseline file for it gets
# no model, and no risk score.

log = logging.getLogger("aegisguard.ml")


class NoBaseline(Exception):
    """Nothing to train an endpoint's model on yet."""


@dataclass
class Entry:
    model: BehaviorModel
    trained_at: datetime
    mode: str  # "real" or "baseline+real"
    real_actions: int  # clean real user actions that were available
    trained_on: int  # actions the model was fitted on
    excluded: int  # real actions left out because the previous model flagged them
    seconds: float
    # Where the first baseline came from: "declared" (working hours the company
    # entered), "file" (a dataset someone chose for this endpoint), "auto" (an
    # assumed working pattern) or "none".
    baseline_source: str = "none"
    # Admin tools this computer made a habit of and the model learned (action keys).
    adopted: frozenset = frozenset()
    # The result of the 80/20 test (see retrain.py), for a training that was asked to test itself.
    report: dict | None = None

    @property
    def time_trusted(self) -> bool:
        """Whether the hours and weekdays this model knows are the endpoint's
        own. An assumed (auto) baseline's are not, until enough real activity
        has been seen; a dataset file is an explicit choice, and a model trained
        on real data only is its own."""
        return (
            self.mode == "real"
            or self.baseline_source in ("file", "declared")
            or self.real_actions >= settings.ml_time_trust_actions
        )


_lock = threading.Lock()
_models: dict[int, Entry] = {}
_stop = threading.Event()
_thread: threading.Thread | None = None
_started_at: datetime | None = None


def get_model(endpoint_id: int) -> BehaviorModel | None:
    with _lock:
        entry = _models.get(endpoint_id)
    return entry.model if entry else None


def status() -> dict[int, Entry]:
    with _lock:
        return dict(_models)


def time_trusted(endpoint_id: int) -> bool | None:
    """Whether the endpoint's model knows its own working hours (None: no model)."""
    with _lock:
        entry = _models.get(endpoint_id)
    return entry.time_trusted if entry else None


def learning_progress(endpoint_id: int) -> dict | None:
    """For the portal: how far the endpoint's model has got in learning from the
    computer's own activity."""
    with _lock:
        entry = _models.get(endpoint_id)
    if entry is None:
        return None
    return {
        "state": "learned" if entry.mode == "real" else "learning",
        "actions": entry.real_actions,
        "needed": settings.ml_min_real_actions,
        "trained_at": entry.trained_at,
        "tested": entry.report is not None and "error" not in entry.report,
    }


def training_report(endpoint_id: int) -> dict | None:
    """The last 80/20 test of the endpoint's model (None if it never ran one)."""
    with _lock:
        entry = _models.get(endpoint_id)
    return entry.report if entry else None


def adopted_actions(real_rows: list[dict], admin_ok: bool, adopt_days: int) -> frozenset:
    """Admin tools this computer has made a habit of: used on at least `adopt_days`
    different days. The model learns those as ordinary (autonomously, nobody has to
    declare a department) instead of flagging them forever. Tools that are mostly
    used to attack or tamper (HIGH_RISK_TOOLS) are never adopted, and one burst of
    use on a single day is not a habit."""
    if adopt_days <= 0:
        return frozenset()
    days: dict[str, set] = {}
    for r in real_rows:
        if not is_user_action(r) or not is_admin_tool(r, admin_ok):
            continue
        if (r.get("process_name") or "") in HIGH_RISK_TOOLS:
            continue
        days.setdefault(action_key(r), set()).add(r["event_time"].astimezone(LOCAL_TZ).date())
    return frozenset(key for key, seen in days.items() if len(seen) >= adopt_days)


def peer_programs(db, employee: Employee | None, admin_ok: bool, since: datetime) -> Counter:
    """What the other computers of the same company and department run: program ->
    count. A new computer starts out expecting what its colleagues really use (the
    company's own ERP, say), not just a generic list. Empty for "auto" (no group)
    and when nobody else is in the department yet. Never raises: a failure here
    must not stop a model from being trained."""
    from sqlalchemy import func

    from app.models.security_event import SecurityEvent as SE

    if employee is None or employee.department in (None, "auto"):
        return Counter()
    try:
        peer_ids = [
            i
            for (i,) in db.query(Endpoint.id)
            .join(Employee, Employee.id == Endpoint.employee_id)
            .filter(
                Employee.unique_id == employee.unique_id,
                Employee.department == employee.department,
                Employee.id != employee.id,
            )
            .limit(PEER_LIMIT)
        ]
        if not peer_ids:
            return Counter()
        eventdata = SE.details["data"]["win"]["eventdata"]
        path, subject = eventdata["newProcessName"].astext, eventdata["subjectUserName"].astext
        rows = (
            db.query(path, func.count())
            .filter(
                SE.endpoint_id.in_(peer_ids),
                SE.windows_event_id == "4688",
                SE.event_time >= since,
                ~SE.wazuh_alert_id.like(SEED_PREFIX + "%"),
                subject.not_in(("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-")),
                ~subject.like("%$"),
            )
            .group_by(path)
            .all()
        )
    except Exception:
        db.rollback()
        log.exception("Looking up the department's programs failed; going without them")
        return Counter()
    counts: Counter = Counter()
    for process_path, n in rows:
        name = (process_path or "").rsplit("\\", 1)[-1].lower()
        probe = {"windows_event_id": "4688", "process_name": name, "creator": "x"}
        if name and is_user_action(probe) and not is_admin_tool(probe, admin_ok):
            counts[name] += n
    return counts


# How many colleagues' histories the prior draws on.
PEER_LIMIT = 10


def select_training_rows(
    real_rows: list[dict],
    previous: BehaviorModel | None,
    load_baseline,
    min_actions: int | None = None,
    min_days: int | None = None,
    exclude_flagged: bool | None = None,
    previous_trusted: bool = True,
    admin_ok: bool = False,
    adopted: frozenset = frozenset(),
) -> tuple[list[dict], str, int, int]:
    """(rows to train on, mode, number of real actions excluded as flagged,
    number of clean real actions). `load_baseline(n_real)` (the baseline rows,
    given how many clean real actions there are) is only called when the real
    history is too short. Flagged events are only left out when the previous
    model is trustworthy: a model still learning an endpoint's hours would flag
    its normal working hours, and excluding them would keep it from ever learning them."""
    min_actions = settings.ml_min_real_actions if min_actions is None else min_actions
    min_days = settings.ml_min_real_days if min_days is None else min_days
    exclude_flagged = settings.ml_exclude_flagged if exclude_flagged is None else exclude_flagged

    clean = [r for r in real_rows if is_user_action(r) and (not is_admin_tool(r, admin_ok) or action_key(r) in adopted)]
    excluded = 0
    if exclude_flagged and previous is not None and previous_trusted and clean:
        kept = [r for r, s in zip(clean, previous.score_many(clean)) if not s.is_anomaly or action_key(r) in adopted]
        excluded, clean = len(clean) - len(kept), kept

    span_days = (max(r["event_time"] for r in clean) - min(r["event_time"] for r in clean)).days if clean else 0
    if len(clean) >= min_actions and span_days >= min_days:
        return clean, "real", excluded, len(clean)
    baseline = load_baseline(len(clean))
    if not baseline and not clean:
        raise NoBaseline("no baseline file for this endpoint and no real history yet")
    extra: list[dict] = []
    if adopted and baseline:
        # The assumed baseline outweighs the little real history there is, which would
        # still make a habit look rare. Count the adopted habits as often as the real
        # history deserves next to it, so they come out ordinary straight away.
        factor = max(1, round(len(baseline) / max(len(clean), 1)))
        extra = [{**r, "_source": r} for r in clean if action_key(r) in adopted for _ in range(factor - 1)]
    return baseline + clean + extra, "baseline+real", excluded, len(clean)


def train_endpoint(db, endpoint_id: int, evaluate=None, apply: bool = True) -> Entry | None:
    """Train one endpoint's model and swap it in. Returns None (leaving any
    existing model alone) when there isn't enough data to train.

    `evaluate(rows, make_model)`, when given, first tests the training rows the standard
    way (train on 80%, test on 20%; see retrain.py) and the result goes to Entry.report.
    With apply=False nothing is swapped in and no earlier events are scored: the
    caller only wants the entry (and its report)."""
    started = time.time()
    since = datetime.now(timezone.utc) - timedelta(days=settings.ml_window_days)
    real = load_db(db, endpoint_id, include_seed=False, since=since, user_actions_only=True)
    previous = get_model(endpoint_id)
    previous_entry = status().get(endpoint_id)
    source = {"name": "none"}
    employee = (
        db.query(Employee).join(Endpoint, Endpoint.employee_id == Employee.id).filter(Endpoint.id == endpoint_id).first()
    )
    # Whether command-line/admin tooling is everyday work for this person (IT, security).
    admin_ok = admin_ok_for(employee.department if employee is not None else None)
    department = employee.department if employee is not None else None
    adopted = adopted_actions(real, admin_ok, settings.ml_adopt_days) if adopts_habits(department) else frozenset()
    peers = peer_programs(db, employee, admin_ok, since)
    # Working hours the company entered win over everything: they are explicit.
    declared = (
        shift_from_hours(employee.work_start, employee.work_end)
        if employee is not None and employee.work_start and employee.work_end
        else None
    )

    def baseline(n_real: int) -> list[dict]:
        if declared is not None:
            rows = build_baseline(real, declared, department=department, peers=peers)
            keep = int(settings.ml_prior_rows * max(0.0, 1.0 - n_real / settings.ml_min_real_actions))
            source["name"] = "declared"
            return random.Random(endpoint_id).sample(rows, min(keep, len(rows)))
        # The endpoint's own file first, then the shared one (which holds
        # rows for the endpoint ids it was made for).
        candidates = []
        if settings.ml_baseline_dir:
            candidates.append(Path(settings.ml_baseline_dir) / f"endpoint-{endpoint_id}.csv.gz")
        if settings.ml_baseline_csv:
            candidates.append(Path(settings.ml_baseline_csv))
        for path in candidates:
            if path.exists():
                rows = load_csv(str(path), endpoint_id=endpoint_id, user_actions_only=True)
                if rows:
                    source["name"] = "file"
                    return rows
        if settings.ml_auto_baseline:
            shift = SHIFTS.get(settings.ml_default_shift, DAY)
            log.info("Endpoint %s: no baseline file, using an assumed %s-shift prior until it has its own history", endpoint_id, shift.name)
            rows = build_baseline(real, shift, department=department, peers=peers)
            # The prior fades out as the endpoint's own activity accumulates.
            keep = int(settings.ml_prior_rows * max(0.0, 1.0 - n_real / settings.ml_min_real_actions))
            source["name"] = "auto"
            return random.Random(endpoint_id).sample(rows, min(keep, len(rows)))
        return []

    try:
        rows, mode, excluded, real_actions = select_training_rows(
            real, previous, baseline, previous_trusted=previous_entry.time_trusted if previous_entry else True,
            admin_ok=admin_ok,
            adopted=adopted,
        )
    except NoBaseline as exc:
        log.info("Endpoint %s: no model yet (%s)", endpoint_id, exc)
        return None

    def make_model() -> BehaviorModel:
        return BehaviorModel(
            admin_ok=admin_ok,
            adopted=adopted,
            min_command_evidence=settings.ml_min_command_evidence,
            min_program_commands=settings.ml_min_program_commands,
            requirements=cvss.requirements_for(department),
        )

    report = None
    if evaluate is not None:
        try:
            report = evaluate(rows, make_model)
        except Exception as exc:  # a failed test must never cost the endpoint its model
            log.exception("Endpoint %s: testing the model failed", endpoint_id)
            report = {"error": f"The test failed: {exc}"}
        if "error" not in report:
            report["data"] = {"mode": mode, "baseline": source["name"], "real_actions": real_actions, "department": department}

    model = make_model().fit(rows)
    entry = Entry(
        model=model,
        trained_at=datetime.now(timezone.utc),
        mode=mode,
        real_actions=real_actions,
        trained_on=model.trained_on,
        excluded=excluded,
        seconds=time.time() - started,
        baseline_source=source["name"],
        adopted=adopted,
        report=report,
    )
    if not apply:
        return entry
    with _lock:
        _models[endpoint_id] = entry  # swapped in whole; readers never see a half-trained model
    health.ok("ml")
    log.info(
        "Endpoint %s: trained on %d actions (%s, %s baseline; %d real, %d flagged and left out; %s) in %.1fs",
        endpoint_id, entry.trained_on, mode, entry.baseline_source, real_actions, excluded,
        "knows its working hours" if entry.time_trusted else "still learning its working hours", entry.seconds,
    )  # fmt: skip
    try:
        scored = backfill(db, endpoint_id, model, days=settings.ml_window_days, neutral_time=not entry.time_trusted)
        if scored:
            log.info("Endpoint %s: scored %d earlier events", endpoint_id, scored)
    except Exception:  # the model is in place either way; the next retrain tries again
        db.rollback()
        log.exception("Endpoint %s: scoring earlier events failed", endpoint_id)
    return entry


def _due(endpoint_id: int) -> bool:
    """Needs training outside the weekly round: it has no model yet, or it is
    still learning and its model is a few hours old."""
    entry = status().get(endpoint_id)
    if entry is None:
        return True
    age = datetime.now(timezone.utc) - entry.trained_at
    return entry.mode != "real" and age > timedelta(hours=settings.ml_learning_retrain_hours)


def retrain_soon(endpoint_id: int) -> None:
    """Trains one endpoint's model right away, in the background (after the
    company changed its working hours), instead of waiting for the next round."""

    def work() -> None:
        db = SessionLocal()
        try:
            train_endpoint(db, endpoint_id)
        except Exception as exc:
            log.exception("Training the model for endpoint %s failed", endpoint_id)
            health.fail("ml", f"Training the model for endpoint {endpoint_id} failed: {exc}")
        finally:
            db.close()

    threading.Thread(target=work, name=f"ml-retrain-{endpoint_id}", daemon=True).start()


def retrain_all(only_due: bool = False) -> None:
    """Trains every endpoint's model; with only_due, just the new ones and the
    ones still learning (see _due)."""
    db = SessionLocal()
    try:
        ids = [i for (i,) in db.query(Endpoint.id).all()]
        for endpoint_id in ids:
            if only_due and not _due(endpoint_id):
                continue
            try:
                train_endpoint(db, endpoint_id)
            except Exception as exc:  # one endpoint failing must not stop the rest; its old model stays
                log.exception("Training the model for endpoint %s failed; keeping the previous one", endpoint_id)
                health.fail("ml", f"Training the model for endpoint {endpoint_id} failed: {exc}")
        with _lock:
            for gone in set(_models) - set(ids):
                del _models[gone]  # endpoint was deleted
    finally:
        db.close()


def _run() -> None:
    _stop.wait(settings.ml_start_delay_seconds)  # let the app finish starting
    next_full = 0.0
    while not _stop.is_set():
        try:
            if time.time() >= next_full:
                retrain_all()
                next_full = time.time() + settings.ml_retrain_days * 86400
            else:
                retrain_all(only_due=True)  # new endpoints, and those still learning
        except Exception as exc:  # never let one bad cycle kill the thread
            log.exception("Model retraining cycle failed")
            health.fail("ml", f"Model retraining cycle failed: {exc}")
        _stop.wait(settings.ml_check_minutes * 60)


def is_running() -> bool:
    return _thread is not None and _thread.is_alive()


def started_at() -> datetime | None:
    """When the trainer thread started. Models live in memory, so a restart
    empties them and every endpoint is without one until it has been retrained."""
    return _started_at


def start() -> None:
    global _thread
    if not settings.ml_enabled:
        log.info("Behavioral model training disabled (ML_ENABLED=false).")
        return
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    global _started_at
    _started_at = datetime.now(timezone.utc)
    _thread = threading.Thread(target=_run, name="ml-trainer", daemon=True)
    _thread.start()
    log.info("Model trainer started (retraining every %g days).", settings.ml_retrain_days)


def stop() -> None:
    _stop.set()
    if _thread:
        _thread.join(timeout=5)
