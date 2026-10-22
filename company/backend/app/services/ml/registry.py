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
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.endpoint import Endpoint
from app.services.ml import baseline as auto_baseline
from app.services.ml import dataset, scoring, seed_baseline
from app.services.ml.features import is_admin_tool, is_user_action
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


_lock = threading.Lock()
_models: dict[int, Entry] = {}
_stop = threading.Event()
_thread: threading.Thread | None = None


def get_model(endpoint_id: int) -> BehaviorModel | None:
    with _lock:
        entry = _models.get(endpoint_id)
    return entry.model if entry else None


def status() -> dict[int, Entry]:
    with _lock:
        return dict(_models)


def select_training_rows(
    real_rows: list[dict],
    previous: BehaviorModel | None,
    load_baseline,
    min_actions: int | None = None,
    min_days: int | None = None,
    exclude_flagged: bool | None = None,
) -> tuple[list[dict], str, int, int]:
    """(rows to train on, mode, number of real actions excluded as flagged,
    number of clean real actions). `load_baseline` (returns the baseline file's
    rows for the endpoint) is only called when the real history is too short."""
    min_actions = settings.ml_min_real_actions if min_actions is None else min_actions
    min_days = settings.ml_min_real_days if min_days is None else min_days
    exclude_flagged = settings.ml_exclude_flagged if exclude_flagged is None else exclude_flagged

    clean = [r for r in real_rows if is_user_action(r) and not is_admin_tool(r)]
    excluded = 0
    if exclude_flagged and previous is not None and clean:
        kept = [r for r, s in zip(clean, previous.score_many(clean)) if not s.is_anomaly]
        excluded, clean = len(clean) - len(kept), kept

    span_days = (max(r["event_time"] for r in clean) - min(r["event_time"] for r in clean)).days if clean else 0
    if len(clean) >= min_actions and span_days >= min_days:
        return clean, "real", excluded, len(clean)
    baseline = load_baseline()
    if not baseline and not clean:
        raise NoBaseline("no baseline file for this endpoint and no real history yet")
    return baseline + clean, "baseline+real", excluded, len(clean)


def train_endpoint(db, endpoint_id: int) -> Entry | None:
    """Train one endpoint's model and swap it in. Returns None (leaving any
    existing model alone) when there isn't enough data to train."""
    started = time.time()
    since = datetime.now(timezone.utc) - timedelta(days=settings.ml_window_days)
    real = dataset.load_db(db, endpoint_id, include_seed=False, since=since, user_actions_only=True)
    previous = get_model(endpoint_id)

    def baseline() -> list[dict]:
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
                    return rows
        if settings.ml_auto_baseline:
            shift = seed_baseline.SHIFTS.get(settings.ml_default_shift, seed_baseline.DAY)
            log.info("Endpoint %s: no baseline file, building a %s-shift baseline from its own history", endpoint_id, shift.name)
            return auto_baseline.build(real, shift)
        return []

    try:
        rows, mode, excluded, real_actions = select_training_rows(real, previous, baseline)
    except NoBaseline as exc:
        log.info("Endpoint %s: no model yet (%s)", endpoint_id, exc)
        return None

    model = BehaviorModel().fit(rows)
    entry = Entry(
        model=model,
        trained_at=datetime.now(timezone.utc),
        mode=mode,
        real_actions=real_actions,
        trained_on=model.trained_on,
        excluded=excluded,
        seconds=time.time() - started,
    )
    with _lock:
        _models[endpoint_id] = entry  # swapped in whole; readers never see a half-trained model
    log.info(
        "Endpoint %s: trained on %d actions (%s; %d real, %d flagged and left out) in %.1fs",
        endpoint_id, entry.trained_on, mode, real_actions, excluded, entry.seconds,
    )  # fmt: skip
    try:
        scored = scoring.backfill(db, endpoint_id, model, days=settings.ml_window_days)
        if scored:
            log.info("Endpoint %s: scored %d earlier events", endpoint_id, scored)
    except Exception:  # the model is in place either way; the next retrain tries again
        db.rollback()
        log.exception("Endpoint %s: scoring earlier events failed", endpoint_id)
    return entry


def retrain_all(only_missing: bool = False) -> None:
    """Trains every endpoint's model; with only_missing, just the endpoints
    that don't have one yet (the new ones)."""
    db = SessionLocal()
    try:
        ids = [i for (i,) in db.query(Endpoint.id).all()]
        for endpoint_id in ids:
            if only_missing and get_model(endpoint_id) is not None:
                continue
            try:
                train_endpoint(db, endpoint_id)
            except Exception:  # one endpoint failing must not stop the rest; its old model stays
                log.exception("Training the model for endpoint %s failed; keeping the previous one", endpoint_id)
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
                retrain_all(only_missing=True)  # picks up endpoints enrolled since the last look
        except Exception:  # never let one bad cycle kill the thread
            log.exception("Model retraining cycle failed")
        _stop.wait(settings.ml_check_minutes * 60)


def start() -> None:
    global _thread
    if not settings.ml_enabled:
        log.info("Behavioral model training disabled (ML_ENABLED=false).")
        return
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_run, name="ml-trainer", daemon=True)
    _thread.start()
    log.info("Model trainer started (retraining every %g days).", settings.ml_retrain_days)


def stop() -> None:
    _stop.set()
    if _thread:
        _thread.join(timeout=5)
