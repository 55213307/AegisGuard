"""Turn security events into numeric feature vectors for the behavioral
anomaly model (Isolation Forest, per the IR).

The model learns a per-endpoint *baseline* of normal behavior; the features
describe WHEN and HOW an event happened so that activity which deviates from
the baseline (e.g. a night-shift user suddenly active at midday) stands out.

Kept deliberately small and interpretable:
  - hour_sin / hour_cos: cyclic encoding of the hour of day. This is the main
    UEBA signal — "is this user active at their usual hours?" Encoding the
    hour on a circle means 23:00 and 00:00 sit next to each other, so the
    model sees time-of-day as continuous rather than a jump at midnight.
  - is_weekend: weekday vs weekend activity.
  - rule_level_norm: Wazuh rule level 0–15 scaled to 0–1 (how severe the
    triggering event was).
"""

from __future__ import annotations

import math
from datetime import datetime

FEATURE_NAMES = ["hour_sin", "hour_cos", "is_weekend", "rule_level_norm"]


def event_features(event_time: datetime, rule_level: int = 0) -> list[float]:
    """Feature vector for one event. `event_time` is used for its local hour
    and weekday; `rule_level` is the Wazuh rule level (0–15)."""
    hour = event_time.hour + event_time.minute / 60.0
    angle = 2 * math.pi * hour / 24.0
    is_weekend = 1.0 if event_time.weekday() >= 5 else 0.0
    rule_level_norm = max(0.0, min(1.0, (rule_level or 0) / 15.0))
    return [math.sin(angle), math.cos(angle), is_weekend, rule_level_norm]


def features_matrix(events: list[tuple[datetime, int]]) -> list[list[float]]:
    """Feature matrix for many (event_time, rule_level) pairs."""
    return [event_features(t, lvl) for t, lvl in events]
