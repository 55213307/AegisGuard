"""Synthetic normal-behavior baselines for training the anomaly model.

Genuinely learning a user's behavior baseline takes weeks of real telemetry,
which we don't have for the FYP demo. Instead each endpoint is given a
*behavior profile* describing its normal working pattern, and we generate a
realistic "normal" dataset from it to train the per-endpoint Isolation Forest.

The headline demo profile is NIGHT_SHIFT: the user normally works nights, so
the model learns that activity belongs to the small hours. During a daytime
presentation the endpoint's real daytime activity falls far outside that
baseline and is flagged as anomalous — a clean, deterministic UEBA demo.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class BehaviorProfile:
    key: str
    label: str
    # Hours of day (0–23) the user is normally active. Wrap-around is fine,
    # e.g. a night shift is [22, 23, 0, 1, 2, 3, 4, 5].
    active_hours: tuple[int, ...]
    # Normal events skew to low Wazuh rule levels (routine activity).
    typical_level_range: tuple[int, int] = (2, 6)
    works_weekends: bool = False


DAY_SHIFT = BehaviorProfile(
    key="day_shift",
    label="Day shift (09:00–18:00)",
    active_hours=tuple(range(9, 19)),
)

NIGHT_SHIFT = BehaviorProfile(
    key="night_shift",
    label="Night shift (22:00–06:00)",
    active_hours=(22, 23, 0, 1, 2, 3, 4, 5),
)

PROFILES: dict[str, BehaviorProfile] = {p.key: p for p in (DAY_SHIFT, NIGHT_SHIFT)}
DEFAULT_PROFILE = DAY_SHIFT


def generate_baseline(
    profile: BehaviorProfile,
    days: int = 42,
    per_active_hour_mean: float = 1.6,
    seed: int = 0,
) -> list[tuple[datetime, int]]:
    """Generate ~`days` weeks of normal (event_time, rule_level) samples for a
    profile: events concentrated in the profile's active hours, with the
    occasional low-rate event at other times (people aren't perfectly
    predictable). Deterministic for a given seed so training is reproducible."""
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(days=days)
    samples: list[tuple[datetime, int]] = []
    active = set(profile.active_hours)
    lo, hi = profile.typical_level_range

    for day in range(days):
        date = start + timedelta(days=day)
        is_weekend = date.weekday() >= 5
        if is_weekend and not profile.works_weekends:
            # A little activity may still happen, but much less.
            day_scale = 0.1
        else:
            day_scale = 1.0
        for hour in range(24):
            if hour in active:
                lam = per_active_hour_mean * day_scale
            else:
                lam = 0.04 * day_scale  # rare off-hours noise
            n = _poisson(rng, lam)
            for _ in range(n):
                minute = rng.randint(0, 59)
                t = date.replace(hour=hour, minute=minute, second=0, microsecond=0)
                level = rng.randint(lo, hi)
                samples.append((t, level))
    return samples


def _poisson(rng: random.Random, lam: float) -> int:
    """Knuth's Poisson sampler — small lambda, no numpy dependency here."""
    if lam <= 0:
        return 0
    el = math.exp(-lam)
    k = 0
    p = 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= el:
            return k - 1
