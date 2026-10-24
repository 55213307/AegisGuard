"""Put the behavioral model's risk scores on security_events.

  - apply(): scores freshly parsed alerts as the ingester stores them.
  - backfill(): scores events that arrived before the endpoint had a model
    (or before this feature existed); run after an endpoint's model is trained.

Only events that are the user's own actions get a score; everything else
(machine activity, maintenance helpers, scans) keeps risk_score NULL.
Functions take the model, or a lookup for it, so this module doesn't depend on
the registry that trains the models.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from app.services.ml import dataset
from app.services.ml.features import is_user_action
from app.services.ml.model import ANOMALY_RISK_THRESHOLD, BehaviorModel

_SEVERITY_ORDER = {"Info": 0, "Warning": 1, "Critical": 2}
# A risk this high is Critical; from the alert threshold up it is a Warning.
CRITICAL_RISK = 90


def severity_for_risk(risk: int, current: str | None) -> str | None:
    """The event's severity once its behavioral risk is taken into account: an
    anomaly is at least a Warning, a strong one Critical. Never lowers the
    severity Wazuh's rule level already gave it."""
    if risk >= CRITICAL_RISK:
        target = "Critical"
    elif risk >= ANOMALY_RISK_THRESHOLD:
        target = "Warning"
    else:
        return current
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
    event["risk_score"] = risk
    event["risk_reason"] = reason
    if "severity" in event:
        event["severity"] = severity_for_risk(risk, event["severity"])


def _score_failed_logons(events: list[dict], failed_count) -> None:
    for event in events:
        if event.get("event_type") == _FAILED_LOGON:
            _set(event, *failed_logon_risk(failed_count(event) if failed_count else 1))


def _score_into(
    model: BehaviorModel, events: list[dict], failed_count=None, overtime: dict | None = None, neutral_time: set | None = None
) -> None:
    """Sets risk_score / risk_reason on each event dict that is a user action:
    the model's judgement, except failed logons, which follow the rule above.
    `overtime` is endpoint id -> end of its approved overtime window; events
    inside one are judged as if at a usual time (what was done still counts), and
    so are all events of the endpoints in `neutral_time`: those whose working
    hours the model doesn't know yet."""
    rows = [dataset.row_from_event(e) for e in events]
    for event, row in zip(events, rows):
        until = (overtime or {}).get(event["endpoint_id"])
        if (until is not None and event["event_time"] <= until) or event["endpoint_id"] in (neutral_time or ()):
            row["event_time"] = model.typical_time(row["event_time"])
    for event, row, score in zip(events, rows, model.score_many(rows)):
        if not is_user_action(row) or event.get("event_type") == _FAILED_LOGON:
            continue
        _set(event, score.risk, model.explain(row, score))
    _score_failed_logons(events, failed_count)


def apply(
    events: list[dict], get_model, failed_count=None, overtime: dict | None = None, neutral_time: set | None = None
) -> None:
    """Adds risk_score and risk_reason to parsed alerts (each carrying its
    endpoint_id). `get_model(endpoint_id)` returns the endpoint's model or
    None; `failed_count` is failed_logon_counter's function; `overtime` the open
    overtime windows (see _score_into). Every event gets
    both keys, so the rows can be inserted together."""
    by_endpoint: dict[int, list[dict]] = defaultdict(list)
    for event in events:
        event["risk_score"] = None
        event["risk_reason"] = None
        by_endpoint[event["endpoint_id"]].append(event)
    for endpoint_id, group in by_endpoint.items():
        model = get_model(endpoint_id)
        if model is not None:
            _score_into(model, group, failed_count, overtime, neutral_time)
        else:
            _score_failed_logons(group, failed_count)  # the rule needs no model


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
            ~SE.wazuh_alert_id.like(dataset.SEED_PREFIX + "%"),
            or_(SE.windows_event_id == "4688", SE.event_type.in_(dataset._USER_EVENT_TYPES)),
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
    for i in range(0, len(updates), batch):
        chunk = updates[i : i + batch]
        _score_into(model, chunk, failed_count, neutral_time={endpoint_id} if neutral_time else None)
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
