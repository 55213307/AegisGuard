"""Train the behavioral anomaly model on a dataset and show how it scores.

Usage: open this file in VS Code and press Run (reads DEFAULT_CSV), or from company/backend:
  python -m app.services.ml.train --csv /tmp/dataset.csv.gz        # the synthetic first baseline
  python -m app.services.ml.train --endpoint-id 6                  # security_events (seed + real)
  python -m app.services.ml.train --endpoint-id 6 --real-only      # real events only, once there are enough

Prints the baseline's own risk distribution (its false-alarm rate) and the
risk of a few demo scenarios: the usual night work, the same programs in
the daytime, and programs this user has never run.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

if __package__ in (None, ""):  # run as a plain file (e.g. VS Code's Run button): make `app` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import numpy as np  # noqa: E402

from app.services.ml import dataset  # noqa: E402
from app.services.ml.features import LOCAL_TZ, action_key, is_user_action  # noqa: E402
from app.services.ml.model import ANOMALY_RISK_THRESHOLD, BehaviorModel  # noqa: E402

# Where seed_baseline.py's example command writes the dataset.
DEFAULT_CSV = Path(__file__).resolve().parents[7] / "dataset.csv.gz"


def _next(weekday: int, hhmm: str) -> datetime:
    """The next given weekday (0=Mon) at hh:mm local time."""
    hour, minute = map(int, hhmm.split(":"))
    day = datetime.now(LOCAL_TZ).replace(hour=hour, minute=minute, second=0, microsecond=0)
    return day + timedelta(days=(weekday - day.weekday()) % 7 or 7)


def _scenario(when: datetime, etype: str, process: str = "", level: int = 3) -> dict:
    return {
        "event_time": when, "rule_level": level, "event_type": etype, "event_user": "user",
        "windows_event_id": "4688" if process else "4624", "process_name": process, "creator": "user" if process else None,
    }  # fmt: skip


def report(model: BehaviorModel, rows: list[dict]) -> None:
    actions = [r for r in rows if is_user_action(r)]
    risks = np.array([s.risk for s in model.score_many(actions)])
    print(f"baseline  : {len(rows):,} events, {len(actions):,} user actions the model learns from")
    print(f"baseline risk: median={np.median(risks):.0f}  p95={np.percentile(risks, 95):.0f}  p99={np.percentile(risks, 99):.0f}  "
          f"share >= {ANOMALY_RISK_THRESHOLD}: {np.mean(risks >= ANOMALY_RISK_THRESHOLD) * 100:.2f}%")  # fmt: skip

    # The programs this endpoint's user actually runs, most common first.
    counts = Counter(action_key(r) for r in actions)
    print("most common user actions: " + ", ".join(f"{k.split(':', 1)[1]}={v:,}" for k, v in counts.most_common(8)))
    programs = [k.split(":", 1)[1] for k, _ in counts.most_common() if k.startswith("proc:")]
    usual, other = (programs + ["msedge.exe", "explorer.exe"])[:2]
    never = next(p for p in ("powershell.exe", "cmd.exe", "regedit.exe") if f"proc:{p}" not in counts)

    mon_night, tue_night, mon_day, sat_day = _next(0, "23:30"), _next(1, "03:10"), _next(0, "14:05"), _next(5, "15:00")
    cases = [
        (f"Mon 23:30  {usual:<18}(usual)", _scenario(mon_night, "Process", usual)),
        (f"Tue 03:10  {other:<18}(usual)", _scenario(tue_night, "Process", other)),
        ("Mon 23:30  Login             (usual)", _scenario(mon_night, "Login Success")),
        (f"Mon 14:05  {usual:<18}(daytime)", _scenario(mon_day, "Process", usual)),
        ("Mon 14:05  Login             (daytime)", _scenario(mon_day, "Login Success")),
        ("Sat 15:00  Login             (weekend day)", _scenario(sat_day, "Login Success")),
        (f"Mon 23:30  {never:<18}(never run)", _scenario(mon_night, "Process", never)),
        (f"Mon 14:05  {never:<18}(daytime + never run)", _scenario(mon_day, "Process", never)),
        ("Tue 03:10  Login Failed      (night)", _scenario(tue_night, "Login Failed", level=5)),
    ]
    scores = model.score_many([c[1] for c in cases])
    print(f"\n{'scenario':<50} {'behaviour':>9} {'novelty':>7} {'RISK':>5}")
    for (name, _), s in zip(cases, scores):
        flag = "  <-- anomaly" if s.is_anomaly else ""
        print(f"{name:<50} {s.behaviour * 100:>9.0f} {s.novelty * 100:>7.0f} {s.risk:>5}{flag}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the behavioral anomaly model and report how it scores.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--csv", help=f"dataset file exported by seed_baseline.py (default: {DEFAULT_CSV})")
    source.add_argument("--endpoint-id", type=int, help="read this endpoint's events from security_events")
    parser.add_argument("--real-only", action="store_true", help="with --endpoint-id: leave out the synthetic seed rows")
    args = parser.parse_args()

    started = time.time()
    if args.endpoint_id is None:
        path = args.csv or str(DEFAULT_CSV)
        if not Path(path).exists():
            raise SystemExit(f"Dataset not found: {path}\nGenerate it with seed_baseline.py --out, or pass --csv.")
        print(f"dataset: {path}")
        rows = dataset.load_csv(path)
    else:
        from app.db.session import SessionLocal

        rows = dataset.load_db(SessionLocal(), args.endpoint_id, include_seed=not args.real_only)
    print(f"loaded {len(rows):,} rows in {time.time() - started:.1f}s")

    started = time.time()
    model = BehaviorModel().fit(rows)
    print(f"trained in {time.time() - started:.1f}s\n")
    report(model, rows)


if __name__ == "__main__":
    main()
