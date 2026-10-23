"""Per-endpoint behavioral anomaly model.

Isolation Forest (scikit-learn, the model and framework the IR selected),
fitted on one endpoint's baseline of normal behavior, plus two things that
turn its raw score into something usable:

  - Calibration against the baseline. The forest's raw score is mapped to a
    0-1 "behaviour" score so that the median baseline event is ~5 and only the
    most anomalous 0.5% of the baseline itself reaches the alert threshold
    (70). That bounds the false-alarm rate on normal behaviour by construction.
  - A novelty factor. An Isolation Forest never extrapolates: something it has
    never seen (a program this user has never run) looks no stranger to it
    than the rarest thing it has seen. So an action absent from the baseline
    gets its own high novelty score, combined with the behaviour score by
    noisy-OR:  risk = 1 - (1 - behaviour) * (1 - novelty).

No feature scaling is applied, as Isolation Forest doesn't need it (IR 2.3.8).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from app.services.ml.features import (
    FEATURE_NAMES, LOCAL_TZ, action_key, event_features, is_admin_tool, is_user_action, is_weekend, local_hour,
)  # fmt: skip

# Risk at/above this counts as an anomaly worth surfacing.
ANOMALY_RISK_THRESHOLD = 70
# Share of the baseline allowed to reach the threshold.
BASELINE_TAIL = 0.5  # percent
# Risk of a baseline-median event / of the baseline tail, which fix the
# logistic curve in _behaviour().
_MEDIAN_RISK, _TAIL_RISK = 0.05, 0.70
# What never having seen an action before is worth. Admin tooling, or an event
# type that has never occurred, is a strong signal. An ordinary program the
# user simply hasn't opened yet is only worth a look: on its own it stays well
# below the alert threshold, and it takes an unusual time of day as well to
# reach one (a computer is locked on Critical events, so a new calculator
# must not be one).
_NOVELTY_UNSEEN = 0.9
_NOVELTY_UNSEEN_PROGRAM = 0.4
# Scores from here up get a written reason.
EXPLAIN_RISK_FROM = 50


def _hour_ranges(hours: set[int]) -> str:
    """{22,23,0,1,2} -> "22:00-03:00", wrapping past midnight."""
    if not hours:
        return "never"
    if len(hours) == 24:
        return "around the clock"
    runs = []
    for h in sorted(hours):
        if (h - 1) % 24 not in hours:  # start of a run
            end = h
            while (end + 1) % 24 in hours:
                end = (end + 1) % 24
            runs.append(f"{h:02d}:00-{(end + 1) % 24:02d}:00")
    return ", ".join(runs)


@dataclass
class Score:
    risk: int  # 0-100
    behaviour: float  # 0-1, from the Isolation Forest (when / how often)
    novelty: float  # 0-1, never seen this action before
    is_anomaly: bool


class BehaviorModel:
    def __init__(self, n_estimators: int = 200, max_samples: int = 2048, random_state: int = 42) -> None:
        self._n_estimators = n_estimators
        self._max_samples = max_samples
        self._random_state = random_state
        self._forest: IsolationForest | None = None
        self._counts: Counter = Counter()
        self._hours: Counter = Counter()
        self._weekend = 0
        self._total = 0
        self._median = 0.0
        self._tail = 0.0
        self.trained_on = 0

    @property
    def fitted(self) -> bool:
        return self._forest is not None

    def _rarity(self, key: str) -> float:
        # Laplace-smoothed so unseen actions get a finite, maximal rarity.
        return -math.log((self._counts.get(key, 0) + 1) / (self._total + len(self._counts) + 1))

    def _hour_rarity(self, hour: int) -> float:
        # Same smoothing over the 24 hours of the day.
        return -math.log((self._hours.get(hour, 0) + 1) / (self._total + 24 + 1))

    def _vector(self, row: dict) -> list[float]:
        return event_features(
            row["event_time"],
            self._hour_rarity(local_hour(row["event_time"])),
            self._rarity(action_key(row)),
            row["rule_level"],
            row["event_type"] == "Login Failed",
        )

    def fit(self, rows) -> "BehaviorModel":
        """Fit on the baseline rows: user actions are picked out, the rest
        ignored, and admin/maintenance tooling is left out of what counts as
        this user's normal behaviour."""
        actions = [r for r in rows if is_user_action(r) and not is_admin_tool(r)]
        if not actions:
            raise ValueError("no user actions in the baseline to learn from")
        self._counts = Counter(action_key(r) for r in actions)
        self._hours = Counter(local_hour(r["event_time"]) for r in actions)
        self._weekend = sum(1 for r in actions if is_weekend(r["event_time"]))
        self._total = len(actions)
        x = np.asarray([self._vector(r) for r in actions], dtype=float)
        if x.shape[1] != len(FEATURE_NAMES):
            raise ValueError("feature vector does not match FEATURE_NAMES")
        self._forest = IsolationForest(
            n_estimators=self._n_estimators,
            max_samples=min(self._max_samples, len(actions)),
            random_state=self._random_state,
        ).fit(x)
        base = self._forest.decision_function(x)
        self._median = float(np.median(base))
        self._tail = float(np.percentile(base, BASELINE_TAIL))
        self.trained_on = len(actions)
        return self

    def _behaviour(self, raw: float) -> float:
        # 0 at the baseline median, 1 at the baseline tail, beyond for stranger.
        span = (self._median - self._tail) or 1e-9
        d = (self._median - raw) / span
        # Logistic through (d=0 -> _MEDIAN_RISK) and (d=1 -> _TAIL_RISK).
        k = math.log(_TAIL_RISK / (1 - _TAIL_RISK)) - math.log(_MEDIAN_RISK / (1 - _MEDIAN_RISK))
        d0 = -math.log(_MEDIAN_RISK / (1 - _MEDIAN_RISK)) / k
        return 1.0 / (1.0 + math.exp(-k * (d - d0)))

    def score_many(self, rows) -> list[Score]:
        """Score events. Rows that aren't user actions get risk 0."""
        if not self.fitted:
            raise RuntimeError("BehaviorModel is not fitted")
        rows = list(rows)
        idx = [i for i, r in enumerate(rows) if is_user_action(r)]
        out = [Score(0, 0.0, 0.0, False) for _ in rows]
        if not idx:
            return out
        x = np.asarray([self._vector(rows[i]) for i in idx], dtype=float)
        raws = self._forest.decision_function(x)
        for i, raw in zip(idx, raws):
            behaviour = self._behaviour(float(raw))
            novelty = 0.0
            if self._counts.get(action_key(rows[i]), 0) == 0:
                ordinary_program = rows[i]["windows_event_id"] == "4688" and not is_admin_tool(rows[i])
                novelty = _NOVELTY_UNSEEN_PROGRAM if ordinary_program else _NOVELTY_UNSEEN
            risk = int(round(100 * (1 - (1 - behaviour) * (1 - novelty))))
            out[i] = Score(risk, behaviour, novelty, risk >= ANOMALY_RISK_THRESHOLD)
        return out

    def typical_time(self, like: datetime) -> datetime:
        """A usual moment for this endpoint: the busiest hour of its baseline,
        on a weekday of the week `like` falls in. Scoring an event as if it
        happened then judges what was done without holding its time of day or
        weekday against it (approved overtime)."""
        hour = self._hours.most_common(1)[0][0] if self._hours else 12
        local = like.astimezone(LOCAL_TZ)
        wednesday = local - timedelta(days=local.weekday()) + timedelta(days=2)
        return wednesday.replace(hour=hour, minute=30, second=0, microsecond=0)

    def score_one(self, row: dict) -> Score:
        return self.score_many([row])[0]

    def explain(self, row: dict, score: Score) -> str | None:
        """Why an elevated score is elevated, in words an administrator can
        act on (the IR asks for interpretable results). None for ordinary
        events."""
        if score.risk < EXPLAIN_RISK_FROM:
            return None
        what = row.get("process_name") or row.get("event_type") or "this activity"
        if score.novelty:
            return f"Never seen on this endpoint before: {what}"
        hour = local_hour(row["event_time"])
        if self._hours.get(hour, 0) / self._total < 0.01:
            usual = {h for h, n in self._hours.items() if n / self._total >= 0.02}
            return f"Unusual time of day ({hour:02d}:00); normally active {_hour_ranges(usual)}"
        if is_weekend(row["event_time"]) and self._weekend / self._total < 0.02:
            return "Unusual day: this endpoint is almost never active at weekends"
        return f"Rare activity for this endpoint: {what}"
