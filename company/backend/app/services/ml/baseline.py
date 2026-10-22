"""Automatic first baseline for an endpoint that has no dataset file.

A computer that was just enrolled has no history to learn from, so its first
model is trained on a year of the persona's working pattern (see seed_baseline
for the shifts), built here in memory from what the endpoint has actually done
so far:

  - the user's name and the programs they have run come from the endpoint's own
    real events; a short list of typical office programs is mixed in while that
    history is thin, so ordinary software the user simply hasn't opened yet
    isn't mistaken for something never seen;
  - how busy a signed-in hour is also comes from the real events (a default
    until there are enough).

This is the same kind of baseline as the dataset files made by
seed_baseline.py --out, without the extra steps: the trainer builds it by
itself the first time it sees the endpoint, and real data replaces it as it
accumulates (see registry.py). Rows are model rows (ml/dataset.py).
"""

from __future__ import annotations

import random
from collections import Counter
from datetime import datetime, timedelta

from app.services.ml import dataset, seed_baseline
from app.services.ml.features import LOCAL_TZ, ADMIN_TOOLS, MAINTENANCE_TOOLS, is_user_action

# Programs a person typically launches in an office day. Only a fallback.
TYPICAL_PROGRAMS = {
    "explorer.exe": 3, "msedge.exe": 10, "notepad.exe": 3, "excel.exe": 6, "winword.exe": 5,
    "outlook.exe": 4, "acrobat.exe": 3, "ms-teams.exe": 3, "calc.exe": 1, "mspaint.exe": 1,
}  # fmt: skip
# With this many distinct programs of its own, an endpoint is trusted on its own history.
ENOUGH_PROGRAMS = 8
DEFAULT_PER_HOUR = 30.0
SEED_ALERT_ID = dataset.SEED_PREFIX + "auto"


def _profile(real_rows: list[dict]) -> tuple[str, dict[str, float], float]:
    """(user name, program weights, user process events per signed-in hour)."""
    users: Counter = Counter()
    programs: Counter = Counter()
    hours: Counter = Counter()
    for r in real_rows:
        if r["windows_event_id"] != "4688" or not is_user_action(r):
            continue
        if r["process_name"] in ADMIN_TOOLS or r["process_name"] in MAINTENANCE_TOOLS:
            continue
        users[r["creator"]] += 1
        programs[r["process_name"]] += 1
        hours[r["event_time"].astimezone(LOCAL_TZ).replace(minute=0, second=0, microsecond=0)] += 1

    user = users.most_common(1)[0][0] if users else "user"
    weights: dict[str, float] = {}
    total = sum(programs.values())
    if programs:
        weights.update({name: 0.7 * n / total for name, n in programs.items()})
    if len(programs) < ENOUGH_PROGRAMS:
        typical_total = sum(TYPICAL_PROGRAMS.values())
        for name, n in TYPICAL_PROGRAMS.items():
            weights[name] = weights.get(name, 0.0) + (0.3 if programs else 1.0) * n / typical_total
    counts = sorted(hours.values())
    per_hour = float(counts[len(counts) // 2]) if len(counts) >= 5 else DEFAULT_PER_HOUR
    return user, weights, min(max(per_hour, 10.0), 80.0)


def build(
    real_rows: list[dict],
    shift: seed_baseline.Shift,
    days: int = 365,
    seed: int = 2026,
    now: datetime | None = None,
) -> list[dict]:
    """A year of the shift's working pattern as model rows."""
    rng = random.Random(seed)
    now = now or datetime.now(LOCAL_TZ)
    user, weights, per_hour = _profile(real_rows)
    names, probabilities = list(weights), list(weights.values())
    rows: list[dict] = []

    def add(when: datetime, event_type: str, win_id: str, process: str = "") -> None:
        rows.append(dataset.model_row(when, 3, event_type, user, win_id, process, user if win_id == "4688" else None, SEED_ALERT_ID))

    for day in seed_baseline._shift_nights(days, rng, now.date()):
        signin = seed_baseline._at(day, shift.signin, 8, rng, shift.overnight)
        pause = seed_baseline._at(day, shift.break_at, 6, rng, shift.overnight)
        resume = pause + timedelta(minutes=rng.uniform(*shift.break_minutes))
        signout = seed_baseline._at(day, shift.signout, 6, rng, shift.overnight)

        add(signin, "Login Success", "4624")
        add(resume, "Login Success", "4624")  # unlocking after the break
        add(resume + timedelta(milliseconds=rng.randint(2, 30)), "Logoff", "4634")
        add(signout, "Logoff", "4634")
        busy = rng.lognormvariate(0, 0.25)  # busier and quieter days
        for begin, end in ((signin, pause), (resume, signout)):
            hours = (end - begin).total_seconds() / 3600
            for _ in range(seed_baseline._poisson(rng, per_hour * busy * hours)):
                add(begin + (end - begin) * rng.random(), "Process", "4688", rng.choices(names, probabilities)[0])
    return [r for r in rows if r["event_time"] < now]
