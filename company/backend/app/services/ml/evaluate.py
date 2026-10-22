"""Evaluate the behavioral anomaly model: train on the past, test on the
future, with known anomalies injected.

The model is unsupervised (IR 2.1.4: security logs rarely have attack labels),
so it can't be scored against labelled attacks the way a classifier is. The
standard way to evaluate an unsupervised detector without labels is:

  1. Split the baseline by time: train on the first part (the past), keep the
     last part (the future) aside. Held-out normal behaviour is label 0.
  2. Inject anomalies of known kinds into the held-out period, label 1 (these
     are synthetic, and are described as such in the report).
  3. Score everything and compare the model's alerts with the labels:
     confusion matrix, accuracy, precision, recall, F1, false-positive rate,
     ROC-AUC, plus how much of each kind of anomaly was caught.

Usage: open this file in VS Code and press Run (reads train.py's DEFAULT_CSV),
or, from company/backend:
  python -m app.services.ml.evaluate [--csv path] [--train-share 0.8]
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

if __package__ in (None, ""):  # run as a plain file (e.g. VS Code's Run button): make `app` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import numpy as np  # noqa: E402
from sklearn.metrics import confusion_matrix, roc_auc_score  # noqa: E402

from app.services.ml import dataset  # noqa: E402
from app.services.ml.features import LOCAL_TZ, action_key, is_user_action  # noqa: E402
from app.services.ml.model import ANOMALY_RISK_THRESHOLD, BehaviorModel  # noqa: E402
from app.services.ml.train import DEFAULT_CSV  # noqa: E402

# Tools an intruder or a careless insider might run, which this user never has.
_UNSEEN_TOOLS = ["powershell.exe", "cmd.exe", "regedit.exe", "net.exe", "whoami.exe", "certutil.exe", "bitsadmin.exe", "mimikatz.exe"]  # fmt: skip


def _event(when: datetime, etype: str, process: str = "", level: int = 3) -> dict:
    return {
        "event_time": when, "rule_level": level, "event_type": etype, "event_user": "user",
        "windows_event_id": "4688" if process else {"Login Failed": "4625", "Special Privileges": "4672"}.get(etype, "4624"),
        "process_name": process, "creator": "user" if process else None,
    }  # fmt: skip


def inject_anomalies(train: list[dict], test_start: datetime, test_end: datetime, per_kind: int, seed: int = 7):
    """Labelled anomalies spread over the test period: (kind, row) pairs."""
    rng = random.Random(seed)
    usual = [k.split(":", 1)[1] for k, _ in Counter(action_key(r) for r in train).most_common() if k.startswith("proc:")][:8]
    seen = {action_key(r) for r in train}
    unseen = [t for t in _UNSEEN_TOOLS if f"proc:{t}" not in seen]
    span = (test_end - test_start).total_seconds()

    def moment(weekday_only=False, weekend_only=False, hours=range(24)) -> datetime:
        while True:
            t = test_start + timedelta(seconds=rng.uniform(0, span))
            local = t.astimezone(LOCAL_TZ)
            if local.hour not in hours or (weekday_only and local.weekday() >= 5) or (weekend_only and local.weekday() < 5):
                continue
            return t

    day, night = range(8, 19), (22, 23, 0, 1, 2, 3, 4, 5)
    kinds: list[tuple[str, callable]] = [
        ("daytime activity (usual programs, 08-19h weekday)", lambda: _event(moment(True, hours=day), "Process", rng.choice(usual))),
        ("weekend daytime logon", lambda: _event(moment(weekend_only=True, hours=range(9, 21)), "Login Success")),
        ("privileged logon off-hours", lambda: _event(moment(hours=range(8, 19)), "Special Privileges")),
    ]
    if unseen:
        kinds.append(("never-seen admin tool at night", lambda: _event(moment(hours=night), "Process", rng.choice(unseen))))
    return [(name, make()) for name, make in kinds for _ in range(per_kind)]


def _score(model: BehaviorModel, rows: list[dict], desc: str, chunk: int = 500) -> np.ndarray:
    out = []
    for i in dataset.progress(range(0, len(rows), chunk), desc=desc, unit=" chunk"):
        out.extend(s.risk for s in model.score_many(rows[i : i + chunk]))
    return np.asarray(out)


def _metrics(y: np.ndarray, risk: np.ndarray, threshold: int) -> dict:
    pred = risk >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[False, True]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "accuracy": (tp + tn) / len(y), "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
    }  # fmt: skip


def evaluate(rows: list[dict], train_share: float = 0.8) -> None:
    actions = sorted((r for r in rows if is_user_action(r)), key=lambda r: r["event_time"])
    cut = int(len(actions) * train_share)
    train, test_normal = actions[:cut], actions[cut:]
    t0, t1 = train[0]["event_time"], test_normal[-1]["event_time"]
    split = test_normal[0]["event_time"]
    print(f"user actions : {len(actions):,}   ({t0:%Y-%m-%d} .. {t1:%Y-%m-%d})")
    print(f"train (past) : {len(train):,}   up to {split:%Y-%m-%d}")
    print(f"test normal  : {len(test_normal):,}   {split:%Y-%m-%d} .. {t1:%Y-%m-%d}")

    started = time.time()
    model = BehaviorModel().fit(train)
    print(f"model        : Isolation Forest, 200 trees, trained in {time.time() - started:.1f}s\n")

    per_kind = max(100, len(test_normal) // 100)
    injected = inject_anomalies(train, split, t1, per_kind)
    rows_all = test_normal + [r for _, r in injected]
    y = np.array([0] * len(test_normal) + [1] * len(injected))
    kind = ["normal"] * len(test_normal) + [k for k, _ in injected]
    print(f"test set     : {len(test_normal):,} normal + {len(injected):,} injected anomalies "
          f"({len(injected) / len(rows_all) * 100:.1f}%, {len({k for k, _ in injected})} kinds)\n")  # fmt: skip

    risk = _score(model, rows_all, "Scoring test set")
    m = _metrics(y, risk, ANOMALY_RISK_THRESHOLD)

    print(f"\n=== Results at alert threshold risk >= {ANOMALY_RISK_THRESHOLD} ===")
    print("confusion matrix            predicted normal   predicted anomaly")
    print(f"  actual normal             {m['tn']:>16,} {m['fp']:>19,}")
    print(f"  actual anomaly            {m['fn']:>16,} {m['tp']:>19,}")
    print(f"accuracy  {m['accuracy'] * 100:6.2f}%   precision {m['precision'] * 100:6.2f}%   recall {m['recall'] * 100:6.2f}%   "
          f"F1 {m['f1'] * 100:6.2f}%")  # fmt: skip
    print(f"false-positive rate {m['fpr'] * 100:.2f}%   ROC-AUC {roc_auc_score(y, risk):.4f}")

    print("\ndetection by kind of anomaly (recall at the threshold, median risk):")
    for name in dict.fromkeys(k for k, _ in injected):
        mask = np.array([k == name for k in kind])
        print(f"  {name:<52} caught {np.mean(risk[mask] >= ANOMALY_RISK_THRESHOLD) * 100:5.1f}%   median risk {np.median(risk[mask]):.0f}")

    print("\nthreshold sweep:")
    print(f"  {'risk >=':<8} {'precision':>9} {'recall':>8} {'F1':>7} {'false-pos rate':>15}")
    for th in (40, 50, 60, 70, 80, 90):
        s = _metrics(y, risk, th)
        print(f"  {th:<8} {s['precision'] * 100:>8.1f}% {s['recall'] * 100:>7.1f}% {s['f1'] * 100:>6.1f}% {s['fpr'] * 100:>14.2f}%")
    print("\nNote: anomalies are synthetic, injected into held-out time; normal rows are the real (replayed) logs' future.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the behavioral anomaly model on held-out time with injected anomalies.")
    parser.add_argument("--csv", default=str(DEFAULT_CSV), help=f"dataset file (default: {DEFAULT_CSV})")
    parser.add_argument("--train-share", type=float, default=0.8, help="fraction of time (oldest) used for training")
    args = parser.parse_args()
    if not Path(args.csv).exists():
        raise SystemExit(f"Dataset not found: {args.csv}\nGenerate it with seed_baseline.py --out, or pass --csv.")
    print(f"dataset: {args.csv}")
    rows = dataset.load_csv(args.csv, show_progress=True)
    evaluate(rows, args.train_share)


if __name__ == "__main__":
    main()
