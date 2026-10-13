"""Per-endpoint behavioral anomaly model.

Wraps scikit-learn's Isolation Forest (the model the IR selected) with:
  - feature scaling (StandardScaler) so each feature contributes evenly;
  - a calibrated mapping from the raw anomaly score to a 0–100 risk score,
    anchored on the training baseline so the number is interpretable:
    behaviour typical of the baseline scores low, behaviour far outside it
    scores high.

Isolation Forest is unsupervised: it is fitted only on *normal* behaviour
(the synthetic baseline, see profiles.py) and flags whatever is isolated from
it. `decision_function` is positive for inliers and negative for outliers.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.services.ml.features import FEATURE_NAMES

# Risk at/above this counts as an anomaly worth surfacing.
ANOMALY_RISK_THRESHOLD = 70


@dataclass
class ScoredEvent:
    risk: int           # 0–100
    is_anomaly: bool
    raw_score: float    # Isolation Forest decision_function (>0 inlier)


class RiskModel:
    def __init__(self) -> None:
        self._scaler = StandardScaler()
        self._forest = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
        )
        # Baseline decision_function statistics, used to calibrate risk.
        self._base_mean = 0.0
        self._base_std = 1.0
        self.fitted = False

    def fit(self, matrix: list[list[float]]) -> "RiskModel":
        if not matrix:
            raise ValueError("cannot fit RiskModel on empty baseline")
        x = np.asarray(matrix, dtype=float)
        if x.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {x.shape[1]}")
        xs = self._scaler.fit_transform(x)
        self._forest.fit(xs)
        base = self._forest.decision_function(xs)
        self._base_mean = float(base.mean())
        self._base_std = float(base.std()) or 1.0
        self.fitted = True
        return self

    def _risk_from_score(self, score: float) -> int:
        # How many "baseline std-devs" more anomalous than a typical normal
        # point this is. z>0 means more anomalous (lower decision score).
        z = (self._base_mean - score) / self._base_std
        # Logistic squashing to 0–100, centred so a point as anomalous as the
        # baseline mean sits near 50 and clearly-outside points approach 100.
        risk = 100.0 / (1.0 + np.exp(-1.4 * (z - 1.0)))
        return int(round(max(0.0, min(100.0, risk))))

    def score_one(self, features: list[float]) -> ScoredEvent:
        if not self.fitted:
            raise RuntimeError("RiskModel is not fitted")
        xs = self._scaler.transform(np.asarray([features], dtype=float))
        raw = float(self._forest.decision_function(xs)[0])
        risk = self._risk_from_score(raw)
        return ScoredEvent(risk=risk, is_anomaly=risk >= ANOMALY_RISK_THRESHOLD, raw_score=raw)

    def score_many(self, matrix: list[list[float]]) -> list[ScoredEvent]:
        if not self.fitted:
            raise RuntimeError("RiskModel is not fitted")
        if not matrix:
            return []
        xs = self._scaler.transform(np.asarray(matrix, dtype=float))
        raws = self._forest.decision_function(xs)
        return [
            ScoredEvent(risk=r, is_anomaly=r >= ANOMALY_RISK_THRESHOLD, raw_score=float(s))
            for s, r in ((s, self._risk_from_score(float(s))) for s in raws)
        ]
