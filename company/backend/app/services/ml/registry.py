"""Per-endpoint behavioral models, kept in memory, and the background job that
(re)trains them.

Runs as a daemon thread started with the app (see app/main.py), like the alert
ingester. Isolation Forest trains in seconds, so rather than learning
continuously (it has no incremental update, and a model that keeps absorbing
new events would also absorb an attack into "normal"), every endpoint's model
is retrained from scratch on a schedule, weekly by default, and swapped in as
a whole. A failed retrain keeps the previous model.

What an endpoint is trained on:
  - its real user actions from the last `ml_window_days` days, cleaned of admin
    tooling and of events the current model already flags as anomalous;
  - while it has less real history than `ml_min_real_actions` actions over
    `ml_min_real_days` days, the baseline dataset file (ML_BASELINE_CSV, made
    by seed_baseline.py --out) is trained on as well. Once it has enough, real
    data only.
An endpoint with neither enough real history nor a baseline file for it gets
no model, and no risk score.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.employee import Employee
from app.models.endpoint import Endpoint
from app.services import health
from app.services.ml import baseline as auto_baseline
from app.services.ml import dataset, scoring, seed_baseline
from app.services.ml.features import (
    HIGH_RISK_TOOLS, LOCAL_TZ, action_key, admin_ok_for, adopts_habits, is_admin_tool, is_user_action,
)
from app.services.ml.model import BehaviorModel

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
    }


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
        extra = [r for r in clean if action_key(r) in adopted] * (factor - 1)
    return baseline + clean + extra, "baseline+real", excluded, len(clean)


def train_endpoint(db, endpoint_id: int) -> Entry | None:
    """Train one endpoint's model and swap it in. Returns None (leaving any
    existing model alone) when there isn't enough data to train."""
    started = time.time()
    since = datetime.now(timezone.utc) - timedelta(days=settings.ml_window_days)
    real = dataset.load_db(db, endpoint_id, include_seed=False, since=since, user_actions_only=True)
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
    # Working hours the company entered win over everything: they are explicit.
    declared = (
        seed_baseline.shift_from_hours(employee.work_start, employee.work_end)
        if employee is not None and employee.work_start and employee.work_end
        else None
    )

    def baseline(n_real: int) -> list[dict]:
        if declared is not None:
            rows = auto_baseline.build(real, declared, department=department)
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
                rows = dataset.load_csv(str(path), endpoint_id=endpoint_id, user_actions_only=True)
                if rows:
                    source["name"] = "file"
                    return rows
        if settings.ml_auto_baseline:
            shift = seed_baseline.SHIFTS.get(settings.ml_default_shift, seed_baseline.DAY)
            log.info("Endpoint %s: no baseline file, using an assumed %s-shift prior until it has its own history", endpoint_id, shift.name)
            rows = auto_baseline.build(real, shift, department=department)
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

    model = BehaviorModel(admin_ok=admin_ok, adopted=adopted).fit(rows)
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
    )
    with _lock:
        _models[endpoint_id] = entry  # swapped in whole; readers never see a half-trained model
    health.ok("ml")
    log.info(
        "Endpoint %s: trained on %d actions (%s, %s baseline; %d real, %d flagged and left out; %s) in %.1fs",
        endpoint_id, entry.trained_on, mode, entry.baseline_source, real_actions, excluded,
        "knows its working hours" if entry.time_trusted else "still learning its working hours", entry.seconds,
    )  # fmt: skip
    try:
        scored = scoring.backfill(db, endpoint_id, model, days=settings.ml_window_days, neutral_time=not entry.time_trusted)
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
        except Exception:
            log.exception("Training the model for endpoint %s failed", endpoint_id)
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
