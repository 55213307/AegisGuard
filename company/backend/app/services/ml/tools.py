"""Offline tools for the model. The backend runs none of the commands; it uses only evaluate_split (the 80/20
test), through retrain.py, which is what the portal's Retrain Now button runs.

  python -m app.services.ml.tools train      --csv file.csv.gz | --endpoint-id N [--real-only]
  python -m app.services.ml.tools evaluate   [--csv file] [--train-share 0.8]
  python -m app.services.ml.tools ablation   [--csv file] [--instances 40] [--out results.md]
  python -m app.services.ml.tools export     --endpoint-id N --out file.csv.gz
  python -m app.services.ml.tools seed       --endpoint-id N [--shift day] (--out file | --write | --delete)
  python -m app.services.ml.tools demo-history --endpoint-id N [--actions 2200] [--days 21] [--write | --delete]

Run from company/backend (on the server: with .venv/bin/python). With no command, 'evaluate' runs.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
from sklearn.decomposition import PCA
from sklearn.metrics import confusion_matrix, precision_recall_curve, roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler

if __package__ in (None, ""):  # run as a plain file (e.g. VS Code's Run button): make `app` importable
    _backend = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)  # the settings read .env from the current folder

from app.services.ml.data import (
    NotEnoughEvents,
    SEED_PREFIX,
    SHIFTS,
    Templates,
    _is_person,
    _process_name,
    build_rows,
    delete_demo,
    delete_seed,
    demo_plan,
    load_csv,
    load_db,
    load_templates,
    model_row,
    progress,
    schedule,
    write_dataset,
    write_seed,
)
from app.services.ml.model import (
    ANOMALY_RISK_THRESHOLD,
    BehaviorModel,
    LOCAL_TZ,
    MIN_PROGRAM_COMMANDS,
    VARIETY_WINDOW,
    action_key,
    add_context,
    is_admin_tool,
    is_user_action,
    local_hour,
)

# ============================================================================
# train: train a model on a dataset and show how it scores
# ============================================================================
#
# Train the behavioral anomaly model on a dataset and show how it scores.
#
# Usage: open this file in VS Code and press Run (reads DEFAULT_CSV), or from company/backend:
#   python -m app.services.ml.tools train --csv /tmp/dataset.csv.gz        # the synthetic first baseline
#   python -m app.services.ml.tools train --endpoint-id 6                  # security_events (seed + real)
#   python -m app.services.ml.tools train --endpoint-id 6 --real-only      # real events only, once there are enough
#
# Prints the baseline's own risk distribution (its false-alarm rate) and the
# risk of a few demo scenarios: the usual night work, the same programs in
# the daytime, and programs this user has never run.

# The dataset the tools read when none is given: Final Year Project/datasets/dataset.csv.gz (outside the repository).
DEFAULT_CSV = Path(__file__).resolve().parents[7] / "datasets" / "dataset.csv.gz"


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


def _train_main() -> None:
    parser = argparse.ArgumentParser(description="Train the behavioral anomaly model and report how it scores.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--csv", help=f"dataset file exported by py (default: {DEFAULT_CSV})")
    source.add_argument("--endpoint-id", type=int, help="read this endpoint's events from security_events")
    parser.add_argument("--real-only", action="store_true", help="with --endpoint-id: leave out the synthetic seed rows")
    args = parser.parse_args()

    started = time.time()
    if args.endpoint_id is None:
        path = args.csv or str(DEFAULT_CSV)
        if not Path(path).exists():
            raise SystemExit(f"Dataset not found: {path}\nGenerate it with py --out, or pass --csv.")
        print(f"dataset: {path}")
        rows = load_csv(path)
    else:
        from app.db.session import SessionLocal

        rows = load_db(SessionLocal(), args.endpoint_id, include_seed=not args.real_only)
    print(f"loaded {len(rows):,} rows in {time.time() - started:.1f}s")

    started = time.time()
    model = BehaviorModel().fit(rows)
    print(f"trained in {time.time() - started:.1f}s\n")
    report(model, rows)


# ============================================================================
# evaluate: train on the past, test on the future, with known anomalies injected
# ============================================================================
#
# Evaluate the behavioral anomaly model: train on the past, test on the
# future, with known anomalies injected.
#
# The model is unsupervised (IR 2.1.4: security logs rarely have attack labels),
# so it can't be scored against labelled attacks the way a classifier is. The
# standard way to evaluate an unsupervised detector without labels is:
#
#   1. Split the baseline by time: train on the first part (the past), keep the
#      last part (the future) aside. Held-out normal behaviour is label 0.
#   2. Inject anomalies of known kinds into the held-out period, label 1 (these
#      are synthetic, and are described as such in the report).
#   3. Score everything and compare the model's alerts with the labels:
#      confusion matrix, accuracy, precision, recall, F1, false-positive rate,
#      ROC-AUC, plus how much of each kind of anomaly was caught.
#
# Usage: open this file in VS Code and press Run (reads train.py's DEFAULT_CSV),
# or, from company/backend:
#   python -m app.services.ml.tools evaluate [--csv path] [--train-share 0.8]

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

    class NoMoment(Exception):
        """The test period has no moment of that kind (no weekend in a few days of test data)."""

    def moment(weekday_only=False, weekend_only=False, hours=range(24)) -> datetime:
        for _ in range(5000):
            t = test_start + timedelta(seconds=rng.uniform(0, span))
            local = t.astimezone(LOCAL_TZ)
            if local.hour not in hours or (weekday_only and local.weekday() >= 5) or (weekend_only and local.weekday() < 5):
                continue
            return t
        raise NoMoment

    # "Off-hours" is whatever hours this computer is hardly ever active in (under 1% of its
    # actions each), so the scenarios fit a day-shift computer as well as a night-shift one.
    by_hour = Counter(local_hour(r["event_time"]) for r in train)
    quiet = [h for h in range(24) if by_hour[h] / max(len(train), 1) < 0.01]
    quiet = quiet or sorted(range(24), key=lambda h: by_hour[h])[:6]
    kinds: list[tuple[str, callable]] = [
        ("usual programs in the quiet hours", lambda: _event(moment(hours=quiet), "Process", rng.choice(usual))),
        ("weekend logon in the quiet hours", lambda: _event(moment(weekend_only=True, hours=quiet), "Login Success")),
        ("privileged logon in the quiet hours", lambda: _event(moment(hours=quiet), "Special Privileges")),
    ]
    if unseen:
        kinds.append(("never-seen admin tool in the quiet hours", lambda: _event(moment(hours=quiet), "Process", rng.choice(unseen))))
    injected = []
    for name, make in kinds:
        try:
            injected += [(name, make()) for _ in range(per_kind)]
        except NoMoment:  # this kind cannot happen in the test period: leave it out
            continue
    return injected


def _score(model: BehaviorModel, rows: list[dict], desc: str, chunk: int = 500, show: bool = True) -> np.ndarray:
    out = []
    steps = range(0, len(rows), chunk)
    for i in progress(steps, desc=desc, unit=" chunk") if show else steps:
        out.extend(s.risk for s in model.score_many(rows[i : i + chunk]))
    return np.asarray(out)


def _score_all(model: BehaviorModel, rows: list[dict], chunk: int = 500) -> list:
    out = []
    for i in range(0, len(rows), chunk):
        out.extend(model.score_many(rows[i : i + chunk]))
    return out


def _decide(model: BehaviorModel, rows: list[dict], scores: list) -> np.ndarray:
    """What the portal does with each event: the CVSS score of the detection it would raise (the kind of
    detection and the command model's verdict decide it, exactly as in runtime._score_into), 0 when
    nothing is raised. This is what an alert is, so it is what the test counts."""
    from app.services import cvss
    from app.services.ml import runtime

    verdicts = runtime._command_verdicts(rows)  # noqa: SLF001
    out = np.zeros(len(rows))
    for i, (row, s) in enumerate(zip(rows, scores)):
        verdict = verdicts.get(i)
        confirmed = bool(verdict and verdict["confirmed"])
        if s.is_anomaly or confirmed:
            kind = runtime.detection_for(model, row, s, verdict)
            out[i] = cvss.score_detection(kind, "confirmed" if confirmed else "reasonable", model.requirements).score
    return out


def _evaluate_metrics(y: np.ndarray, risk: np.ndarray, threshold: float) -> dict:
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


MAX_EVALUATION_ROWS = 40_000  # the newest ones: keeps a manual retrain quick on a big history
MIN_EVALUATION_ROWS = 100  # fewer training events than this and a test means nothing
SCATTER_NORMALS = 2000  # normal events drawn in the scatter plot (all the anomalies are)


def _thin(values, n: int = 60) -> list[float]:
    """At most n evenly spaced values of a curve (the reports only need its shape)."""
    values = np.asarray(values, dtype=float)
    if len(values) <= n:
        return [round(float(v), 4) for v in values]
    return [round(float(v), 4) for v in values[np.linspace(0, len(values) - 1, n).astype(int)]]


def evaluate_split(rows: list[dict], make_model=BehaviorModel, train_share: float = 0.8) -> dict:
    """The standard test, on any set of events: train on the oldest `train_share` (80%) of the
    user actions, hold the newest rest back as the test set, add injected anomalies (label 1)
    to it, and compare the model's alerts with the labels. `make_model()` returns an unfitted
    BehaviorModel. Returns a JSON-friendly report (print_report writes it out), or
    {"error": ...} when there are too few events to hold any back."""
    actions = sorted((dict(r) for r in rows if is_user_action(r)), key=lambda r: r["event_time"])[-MAX_EVALUATION_ROWS:]
    cut = int(len(actions) * train_share)
    train, test_normal = actions[:cut], actions[cut:]
    if len(train) < MIN_EVALUATION_ROWS or len(test_normal) < 20:
        return {"error": f"Only {len(actions)} user actions: too few to hold 20% back as a test."}
    split, end = test_normal[0]["event_time"], test_normal[-1]["event_time"]

    from app.core.config import settings
    from app.services import cvss

    started = time.time()
    model = make_model().fit(train)
    seconds = time.time() - started

    # Admin tools are left out of the model's training and flagged on purpose (nobody in an ordinary role is
    # expected to run them), so a real event of that kind is not "normal" for this test: it would be
    # counted as a false alarm for doing what the policy asks. They stay in the timeline the model looks at.
    admin_ok, adopted = getattr(model, "admin_ok", False), getattr(model, "adopted", frozenset())
    all_normal = test_normal
    test_normal = [r for r in all_normal if not (is_admin_tool(r, admin_ok) and action_key(r) not in adopted)]
    excluded_admin = len(all_normal) - len(test_normal)

    injected = inject_anomalies(train, split, end, max(10, len(test_normal) // 100))
    rows_all = test_normal + [r for _, r in injected]
    # The model judges an event by what came just before it, so the test rows need that too
    # (normal ones from the normal timeline, each injected one from the activity around it).
    _add_test_context(all_normal, [(k, i, [r]) for i, (k, r) in enumerate(injected)])
    y = np.array([0] * len(test_normal) + [1] * len(injected))
    kind = np.array(["normal"] * len(test_normal) + [k for k, _ in injected])
    scores = _score_all(model, rows_all)
    risk = np.array([s.risk for s in scores])  # the behaviour model's own score: for its ranking (AUC, curves)
    decision = _decide(model, rows_all, scores)  # what the portal does: the CVSS score of the detection
    warn_from, lock_from = cvss.MEDIUM_FROM, settings.cvss_lock_from

    m = _evaluate_metrics(y, decision, warn_from)
    mc = _evaluate_metrics(y, decision, lock_from)
    fpr, tpr, _ = roc_curve(y, risk)
    precision, recall, _ = precision_recall_curve(y, risk)
    edges = list(range(0, 105, 5))

    # The model's own features squeezed into two dimensions (PCA fitted on the training events).
    x_train = np.asarray([model._vector(r) for r in train], dtype=float)  # noqa: SLF001
    x_test = np.asarray([model._vector(r) for r in rows_all], dtype=float)  # noqa: SLF001
    scaler = StandardScaler().fit(x_train)
    pca = PCA(n_components=2, random_state=42).fit(scaler.transform(x_train))
    points = pca.transform(scaler.transform(x_test))
    rng = np.random.default_rng(42)
    normals = np.flatnonzero(y == 0)
    keep = np.concatenate([rng.permutation(normals)[:SCATTER_NORMALS], np.flatnonzero(y == 1)])

    return {
        "train_share": train_share,
        "actions": len(actions),
        "train": len(train),
        "test_normal": len(test_normal),
        "injected": len(injected),
        "from": train[0]["event_time"].isoformat(),
        "split": split.isoformat(),
        "to": end.isoformat(),
        "seconds": round(seconds, 1),
        # An alert is what the portal raises: a detection scored CVSS 4.0 (Warning) or more. The lock level
        # (CVSS 7.0 or more, a Critical event) is reported next to it. See _decide.
        "threshold": warn_from,
        "threshold_critical": lock_from,
        "ml_threshold": ANOMALY_RISK_THRESHOLD,  # the behaviour model's own score, on the histogram
        "excluded_admin": excluded_admin,
        "confusion": {k: int(m[k]) for k in ("tn", "fp", "fn", "tp")},
        "metrics": {k: float(m[k]) for k in ("accuracy", "precision", "recall", "f1", "fpr")}
        | {"auc": float(roc_auc_score(y, risk))},
        "critical": {
            "confusion": {k: int(mc[k]) for k in ("tn", "fp", "fn", "tp")},
            "metrics": {k: float(mc[k]) for k in ("accuracy", "precision", "recall", "f1", "fpr")},
        },
        "kinds": [
            {
                "name": name,
                "count": int((kind == name).sum()),
                "caught": float(np.mean(decision[kind == name] >= warn_from)),
                "caught_critical": float(np.mean(decision[kind == name] >= lock_from)),
                "median_risk": float(np.median(risk[kind == name])),
                "median_cvss": float(np.median(decision[kind == name])),
            }
            for name in dict.fromkeys(k for k, _ in injected)
        ],
        "sweep": [{"threshold": th} | {k: float(v) for k, v in _evaluate_metrics(y, decision, th).items() if k in ("precision", "recall", "f1", "fpr")} for th in (3.0, 4.0, 5.0, 6.0, 7.0, 8.0)],
        "roc": {"fpr": _thin(fpr), "tpr": _thin(tpr)},
        "pr": {"precision": _thin(precision), "recall": _thin(recall)},
        "histogram": {
            "edges": edges,
            "normal": np.histogram(risk[y == 0], bins=edges)[0].tolist(),
            "anomaly": np.histogram(risk[y == 1], bins=edges)[0].tolist(),
        },
        "scatter": {
            "x": [round(float(v), 3) for v in points[keep, 0]],
            "y": [round(float(v), 3) for v in points[keep, 1]],
            "anomaly": [int(v) for v in y[keep]],
            "alarm": [int(v >= warn_from) for v in decision[keep]],
            "kept": round(float(pca.explained_variance_ratio_.sum()), 3),
        },
        "note": "The anomalies are synthetic: written by the authors and injected into the held-out period. "
        "Every real event of the held-out days counts as normal, so a new program or an installation in those days "
        "shows up as a false alarm even when it is harmless.",
    }


def print_report(report: dict) -> None:
    if "error" in report:
        print(report["error"])
        return
    c, m = report["confusion"], report["metrics"]
    day = lambda iso: iso[:10]  # noqa: E731
    print(f"user actions : {report['actions']:,}   ({day(report['from'])} .. {day(report['to'])})")
    print(f"train ({report['train_share']:.0%})  : {report['train']:,}   up to {day(report['split'])}   (trained in {report['seconds']}s)")
    print(f"test normal  : {report['test_normal']:,}   {day(report['split'])} .. {day(report['to'])}")
    if report.get("excluded_admin"):
        print(f"               ({report['excluded_admin']:,} admin-tool events left out: the model flags them on purpose)")
    print(f"test anomalies: {report['injected']:,} injected ({len(report['kinds'])} kinds)\n")
    print(f"=== An alert is what the portal raises: a detection of CVSS >= {report['threshold']} (Warning or Critical) ===")
    print("confusion matrix            predicted normal   predicted anomaly")
    print(f"  actual normal             {c['tn']:>16,} {c['fp']:>19,}")
    print(f"  actual anomaly            {c['fn']:>16,} {c['tp']:>19,}")
    print(f"accuracy  {m['accuracy'] * 100:6.2f}%   precision {m['precision'] * 100:6.2f}%   recall {m['recall'] * 100:6.2f}%   F1 {m['f1'] * 100:6.2f}%")
    print(f"false-positive rate {m['fpr'] * 100:.2f}%   ROC-AUC of the behaviour model's score {m['auc']:.4f}")
    if "critical" in report:
        cc, mc = report["critical"]["confusion"], report["critical"]["metrics"]
        print(f"\n=== The lock level: CVSS >= {report['threshold_critical']} (a Critical event, the computer is locked) ===")
        print(f"  anomalies that would lock the computer: {cc['tp']:,} of {cc['tp'] + cc['fn']:,}    false locks: {cc['fp']:,} of {cc['tn'] + cc['fp']:,} normal events")
        print(f"  precision {mc['precision'] * 100:6.2f}%   recall {mc['recall'] * 100:6.2f}%   F1 {mc['f1'] * 100:6.2f}%")
    print("\ndetection by kind of anomaly (recall at the alert level / at the lock level, median CVSS):")
    for k in report["kinds"]:
        print(f"  {k['name']:<52} {k['caught'] * 100:5.1f}% / {k.get('caught_critical', 0) * 100:5.1f}%   median CVSS {k.get('median_cvss', 0):.1f}")
    print("\nthreshold sweep (alert if CVSS >=):")
    print(f"  {'CVSS >=':<8} {'precision':>9} {'recall':>8} {'F1':>7} {'false-pos rate':>15}")
    for s in report["sweep"]:
        print(f"  {s['threshold']:<8} {s['precision'] * 100:>8.1f}% {s['recall'] * 100:>7.1f}% {s['f1'] * 100:>6.1f}% {s['fpr'] * 100:>14.2f}%")
    print(f"\nNote: {report['note']} Normal rows are the real (or replayed) events of the held-out period.")


def evaluate(rows: list[dict], train_share: float = 0.8) -> None:
    print_report(evaluate_split(rows, BehaviorModel, train_share))


def _evaluate_main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the behavioral anomaly model on held-out time with injected anomalies.")
    parser.add_argument("--csv", default=str(DEFAULT_CSV), help=f"dataset file (default: {DEFAULT_CSV})")
    parser.add_argument("--train-share", type=float, default=0.8, help="fraction of time (oldest) used for training")
    args = parser.parse_args()
    if not Path(args.csv).exists():
        raise SystemExit(f"Dataset not found: {args.csv}\nGenerate it with py --out, or pass --csv.")
    print(f"dataset: {args.csv}")
    rows = load_csv(args.csv, show_progress=True)
    evaluate(rows, args.train_share)


# ============================================================================
# ablation: which part of the detector does the work
# ============================================================================
#
# Which part of the detector does the work? An ablation study.
#
# The alerts a person sees come from two things working together: hand-written
# rules (an admin tool that was never seen scores 90, a program never seen 40) and the
# Isolation Forest (when, how often, and in what company an action happens). This
# measures each alone and together, on the same held-out data, so it is on the table
# how much the model adds:
#
#   A  rules only
#   B  Isolation Forest only, judging single events (the model as it was)
#   C  Isolation Forest only, with recent-activity context (bursts, variety, pairs)
#   D  C plus the command-line profile (how each program is usually run on this computer)
#   E  rules + forest without context (the detector as it was)
#   F  rules + forest with context
#   G  rules + forest + context + command line (the detector now)
#
# D and G exist only when the data has command lines: events collected before command-line
# auditing was on do not (export a computer's real events with export_events.py to get some).
#
# Held-out normal behaviour is label 0. Injected scenarios of known kinds are label 1.
# The scenarios are SYNTHETIC and written by the author of the detector: they show
# what each part can and cannot see, not how it fares against real intrusions. For
# that, replace them with attacks recorded in a lab (labelled by time window).
#
# Usage, from company/backend:
#   python -m app.services.ml.tools ablation --csv path/to/dataset.csv.gz [--out results.md]

DETECTORS = {
    "A": "rules only",
    "B": "forest only, single events",
    "C": "forest only, with context",
    "D": "forest + context + command line",
    "E": "rules + forest, single events (before)",
    "F": "rules + forest, with context",
    "G": "rules + forest + context + command line (now)",
}

_RECON = ["whoami.exe", "ipconfig.exe", "net.exe", "systeminfo.exe", "tasklist.exe", "netstat.exe"]


def _row(when: datetime, etype: str, process: str = "", parent: str = "") -> dict:
    win_id = "4688" if process else {"Login Failed": "4625"}.get(etype, "4624")
    return model_row(when, 3, etype, "user", win_id, process, "user" if process else None, "inj", parent)


def inject(train: list[dict], start: datetime, end: datetime, instances: int, seed: int = 7) -> list[tuple[str, int, list[dict]]]:
    """(scenario, instance number, rows): every row of an instance is label 1."""
    rng = random.Random(seed)
    usual = [k.split(":", 1)[1] for k, _ in Counter(action_key(r) for r in train).most_common() if k.startswith("proc:")][:9]
    span = (end - start).total_seconds()
    # The scenarios must differ from normal in one way each, so the hours are taken from the
    # data: "usual" hours are where this computer is normally active (whatever shift its
    # user works), "rare" hours where it almost never is.
    by_hour = Counter(local_hour(r["event_time"]) for r in train)
    share = {h: by_hour.get(h, 0) / len(train) for h in range(24)}
    usual_hours = [h for h in range(24) if share[h] >= 0.02] or list(range(24))
    rare_hours = [h for h in range(24) if share[h] < 0.003] or [h for h in range(24) if share[h] < 0.01] or [3]

    def moment(hours, weekday=True) -> datetime:
        while True:
            t = start + timedelta(seconds=rng.uniform(0, span))
            local = t.astimezone(LOCAL_TZ)
            if local.hour in hours and (local.weekday() < 5) == weekday:
                return t

    day, night = usual_hours, rare_hours
    out: list[tuple[str, int, list[dict]]] = []
    for i in range(instances):
        t = moment(night)
        out.append(("after-hours session (usual programs, rarely active hours)", i, [_row(t + timedelta(seconds=50 * k), "Process", rng.choice(usual)) for k in range(6)]))
        t = moment(day)
        out.append(("recon: 6 admin tools in 90 s (usual hours)", i, [_row(t + timedelta(seconds=15 * k), "Process", name, "cmd.exe") for k, name in enumerate(_RECON)]))
        t = moment(day)
        out.append(("scripted burst: 15 usual programs in 45 s (usual hours)", i, [_row(t + timedelta(seconds=3 * k), "Process", usual[k % len(usual)]) for k in range(15)]))
        t = moment(day)
        out.append(("single admin tool (usual hours)", i, [_row(t, "Process", "cmd.exe")]))
        t = moment(usual_hours, weekday=False)
        out.append(("weekend logon (usual hours)", i, [_row(t, "Login Success")]))
    return out


def inject_command_lines(train: list[dict], start: datetime, end: datetime, instances: int, seed: int = 11):
    """Programs this computer runs often, run in an unusual way, in its usual hours: a
    real command line of the program with a long encoded-looking string added, and with
    three options it has never been given. Single events, label 1."""
    import base64

    rng = random.Random(seed)
    by_program: dict[str, list[str]] = {}
    for r in train:
        if r.get("command_line"):
            by_program.setdefault((r.get("process_name") or "").lower(), []).append(r["command_line"])
    programs = [name for name, lines in by_program.items() if len(lines) >= MIN_PROGRAM_COMMANDS and name]
    if not programs:
        return []
    by_hour = Counter(local_hour(r["event_time"]) for r in train)
    usual = [h for h in range(24) if by_hour.get(h, 0) / len(train) >= 0.02] or list(range(24))
    span = (end - start).total_seconds()

    def moment() -> datetime:
        while True:
            t = start + timedelta(seconds=rng.uniform(0, span))
            if t.astimezone(LOCAL_TZ).hour in usual and t.astimezone(LOCAL_TZ).weekday() < 5:
                return t

    out = []
    for i in range(instances):
        program = rng.choice(programs)
        line = rng.choice(by_program[program])
        blob = base64.b64encode(bytes(rng.randrange(256) for _ in range(90))).decode()
        for name, extra in (
            ("usual program, long encoded-looking string added", f" {blob}"),
            ("usual program, three options it never had", " --zq-one --zq-two=3 --zq-three"),
        ):
            row = _row(moment(), "Process", program)
            row["command_line"] = line + extra
            out.append((name, i, [row]))
    return out


def _add_test_context(normal: list[dict], injected: list[tuple[str, int, list[dict]]]) -> None:
    """Recent-activity features for the test set. The normal rows get theirs from the normal
    timeline alone, so an injected burst does not turn the normal events after it into false
    alarms. Each injected instance gets its own from the normal activity around it plus itself
    (an intruder works among everyone else's events)."""
    import bisect

    add_context(normal)
    times = [r["event_time"] for r in normal]
    for _, _, group in injected:
        first = min(r["event_time"] for r in group)
        last = max(r["event_time"] for r in group)
        lo = bisect.bisect_left(times, first - VARIETY_WINDOW)
        hi = bisect.bisect_right(times, last)
        background = [dict(r) for r in normal[lo:hi]]  # copies: the normal rows keep their own context
        add_context(background + group)


def rule_risk(rows: list[dict], seen: set[str]) -> np.ndarray:
    """What the hand-written rules alone would say: an admin tool, or an event of a
    kind never seen, 90; a program never seen, 40; anything else nothing."""
    risk = []
    for r in rows:
        if is_admin_tool(r):
            risk.append(90)
        elif action_key(r) in seen:
            risk.append(0)
        else:
            risk.append(40 if r["windows_event_id"] == "4688" else 90)
    return np.asarray(risk)


def _ablation_metrics(y: np.ndarray, risk: np.ndarray, threshold: int) -> dict:
    pred = risk >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[False, True]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision, "recall": recall, "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "auc": roc_auc_score(y, risk) if len(set(y)) > 1 else float("nan"),
    }  # fmt: skip


def run(rows: list[dict], train_share: float = 0.8, instances: int = 40) -> str:
    actions = sorted((r for r in rows if is_user_action(r)), key=lambda r: r["event_time"])
    cut = int(len(actions) * train_share)
    train, normal = actions[:cut], actions[cut:]
    start, end = normal[0]["event_time"], normal[-1]["event_time"]
    seen = {action_key(r) for r in train if not is_admin_tool(r)}

    forest_plain = BehaviorModel(use_context=False, use_command=False).fit(train)
    forest_ctx = BehaviorModel(use_context=True, use_command=False).fit(train)
    forest_cmd = BehaviorModel(use_context=True, use_command=True).fit(train)
    has_command = forest_cmd._command_ready

    injected = inject(train, start, end, instances)
    if has_command:
        injected += inject_command_lines(train, start, end, instances)
    test = list(normal) + [r for _, _, group in injected for r in group]
    y = np.array([0] * len(normal) + [1] * sum(len(g) for _, _, g in injected))
    _add_test_context(normal, injected)

    plain, ctx, cmd = forest_plain.score_many(test), forest_ctx.score_many(test), forest_cmd.score_many(test)
    rules = rule_risk(test, seen)
    risk = {
        "A": rules,
        "B": np.asarray([round(100 * s.behaviour) for s in plain]),
        "C": np.asarray([round(100 * s.behaviour) for s in ctx]),
        "D": np.asarray([round(100 * (1 - (1 - s.behaviour) * (1 - s.command))) for s in cmd]),
        "E": np.asarray([s.risk for s in plain]),
        "F": np.asarray([s.risk for s in ctx]),
        "G": np.asarray([s.risk for s in cmd]),
    }
    detectors = {k: v for k, v in DETECTORS.items() if has_command or k not in ("D", "G")}

    lines = [
        f"# Ablation: which part of the detector does the work",
        "",
        f"- trained on {len(train):,} actions ({train[0]['event_time']:%Y-%m-%d} .. {train[-1]['event_time']:%Y-%m-%d}), "
        f"tested on {len(normal):,} held-out normal actions ({start:%Y-%m-%d} .. {end:%Y-%m-%d})",
        f"- {instances} instances of each of {len({k for k, _, _ in injected})} synthetic scenarios injected "
        f"({int(y.sum()):,} labelled events); alert threshold: risk >= {ANOMALY_RISK_THRESHOLD}",
        "- the scenarios are synthetic: they show what each part can and cannot see, not performance against real intrusions",
        f"- command lines: {'used (the data has them)' if has_command else 'NOT evaluated: this data has no command lines (events from before command-line auditing was on); export real events with export_events.py'}",
        "",
        "## Overall (event level)",
        "",
        "| detector | precision | recall | F1 | false-positive rate | ROC-AUC |",
        "|---|---|---|---|---|---|",
    ]
    for key, name in detectors.items():
        m = _ablation_metrics(y, risk[key], ANOMALY_RISK_THRESHOLD)
        lines.append(f"| {key}  {name} | {m['precision'] * 100:.1f}% | {m['recall'] * 100:.1f}% | {m['f1'] * 100:.1f}% | {m['fpr'] * 100:.2f}% | {m['auc']:.3f} |")

    lines += ["", "## Scenarios caught (an instance counts as caught when any of its events alerts)", "", "| scenario | " + " | ".join(detectors) + " |", "|---|" + "---|" * len(detectors)]
    offset = len(normal)
    spans: dict[str, list[tuple[int, int]]] = {}
    for name, _, group in injected:
        spans.setdefault(name, []).append((offset, offset + len(group)))
        offset += len(group)
    for name, ranges in spans.items():
        cells = []
        for key in detectors:
            caught = sum(1 for a, b in ranges if (risk[key][a:b] >= ANOMALY_RISK_THRESHOLD).any())
            cells.append(f"{caught * 100 / len(ranges):.0f}%")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _ablation_main() -> None:
    parser = argparse.ArgumentParser(description="Ablation: rules vs Isolation Forest vs both, with and without context.")
    parser.add_argument("--csv", default=str(DEFAULT_CSV))
    parser.add_argument("--train-share", type=float, default=0.8)
    parser.add_argument("--instances", type=int, default=40, help="instances of each synthetic scenario")
    parser.add_argument("--out", help="also write the result (Markdown) to this file")
    args = parser.parse_args()
    if not Path(args.csv).exists():
        raise SystemExit(f"Dataset not found: {args.csv}")
    rows = load_csv(args.csv, show_progress=True, user_actions_only=True)
    report = run(rows, args.train_share, args.instances)
    print("\n" + report)
    if args.out:
        Path(args.out).write_text(report + "\n", encoding="utf-8")


# ============================================================================
# export: an endpoint's real events as a dataset file
# ============================================================================
#
# Export an endpoint's REAL events from security_events to a dataset file (CSV, .csv.gz to
# compress), in the format dataset.load_csv reads, so the evaluations (ablation.py,
# evaluate.py, train.py) can run on what a computer really did, command lines included.
#
# Run on the server, from company/backend:
#   .venv/bin/python -m app.services.ml.tools export --endpoint-id 8 --out /tmp/endpoint-8.csv.gz
# then copy the file to the PC (scp) and run, for example:
#   python -m app.services.ml.tools ablation --csv endpoint-8.csv.gz
#
# Real events only: the synthetic baseline rows (wazuh_alert_id starting "seed-") are left out.

COLUMNS = (
    "wazuh_alert_id", "endpoint_id", "unique_id", "event_time", "rule_id", "rule_level", "rule_description", "severity",
    "event_type", "event_user", "windows_event_id", "process_name", "parent_process", "details",
)  # fmt: skip


def export(endpoint_id: int, out: str) -> int:
    from app.db.session import SessionLocal
    from app.models.security_event import SecurityEvent as SE

    db = SessionLocal()
    opener = gzip.open if out.endswith(".gz") else open
    written = 0
    try:
        query = (
            db.query(SE)
            .filter(SE.endpoint_id == endpoint_id, ~SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
            .order_by(SE.event_time)
        )
        with opener(out, "wt", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(COLUMNS)
            for e in query.yield_per(2000):
                eventdata = (((e.details or {}).get("data") or {}).get("win") or {}).get("eventdata") or {}
                writer.writerow(
                    [
                        e.wazuh_alert_id, e.endpoint_id, e.unique_id, e.event_time.isoformat(), e.rule_id, e.rule_level,
                        e.rule_description, e.severity, e.event_type, e.event_user, e.windows_event_id,
                        (eventdata.get("newProcessName") or "").rsplit("\\", 1)[-1],
                        (eventdata.get("parentProcessName") or "").rsplit("\\", 1)[-1],
                        json.dumps(e.details),
                    ]
                )  # fmt: skip
                written += 1
    finally:
        db.close()
    return written


def _export_main() -> None:
    parser = argparse.ArgumentParser(description="Export an endpoint's real security events as a dataset file.")
    parser.add_argument("--endpoint-id", type=int, required=True)
    parser.add_argument("--out", required=True, help="output file (.csv or .csv.gz)")
    args = parser.parse_args()
    print(f"wrote {export(args.endpoint_id, args.out):,} events to {args.out}")


# ============================================================================
# seed: the synthetic baseline's command line
# ============================================================================
#
# A year of synthetic logs, as the training dataset for the anomaly model.
#
# The demo endpoint has only a couple of weeks of real history, so a year of it
# is generated from the endpoint's *own* real events, in exactly the format the
# ingester stores them:
#
#   - Every generated row is a copy of a real security_events row from this
#     endpoint (same rule, description, event type, user, Windows event and
#     details JSON), given a new time, alert id and event record id.
#   - How many events happen per hour is measured from the real data too, so the
#     year has the same volume and mix as the real machine.
#   - Three kinds of events are replayed differently:
#       machine events (no person behind them: SYSTEM processes, application
#       logs, agent start/stop) happen around the clock, as on a workstation
#       that stays on, at the real machine's *median* hourly rate (the real
#       history is mostly start-up bursts, which the mean would inflate);
#       CIS configuration scans (SCA) run every 12 hours like Wazuh's own
#       schedule: the first reports every check, later ones a summary plus the
#       occasional status change, each with the burst of check commands
#       (auditpol, secedit...) the agent runs as SYSTEM;
#       session events (the user's logons, logoffs and the processes in their
#       session) happen only during the user's working hours: by default night
#       shifts, 22:00-06:00 local time (--shift day: 09:00-18:00), on shifts
#       starting Monday to Friday, minus leave.
#   - The night-shift user is a clerk, not an administrator, so admin tooling
#     seen in the real data (powershell, cmd, reg, net... mostly our own
#     installer at work) is left out of their sessions, as are admin-only
#     events such as special-privilege logons.
#
# Generated rows are marked so they can always be told apart and removed:
# wazuh_alert_id starts with "seed-" and details["seed"] is true.
#
# Usage, from company/backend on the server:
#   .venv/bin/python -m app.services.ml.tools seed --endpoint-id 6            # preview, writes nothing
#   .venv/bin/python -m app.services.ml.tools seed --endpoint-id 6 --write    # (re)write the year
#   .venv/bin/python -m app.services.ml.tools seed --endpoint-id 6 --delete   # remove it

# Programs the clerk's sessions never contain (see features.py).

# Commands Wazuh's configuration scan runs as SYSTEM to read settings.

# Columns copied from the real row; time and ids are set per copy.


# --- what the real machine does ---------------------------------------------


# --- the working calendar -----------------------------------------------------


# --- the year -----------------------------------------------------------------


# --- writing ------------------------------------------------------------------


# --- dataset file -------------------------------------------------------------

# security_events' columns, plus two pulled out of details for convenience.


# --- CLI ----------------------------------------------------------------------


def _print_preview(t: Templates, plan: list[tuple[datetime, dict]]) -> None:
    print(f"learned from {t.real_rows:,} real events over {t.real_hours} hours the machine was on:")
    print(f"  machine events : {len(t.machine):,} templates, median {t.machine_per_hour:.1f} per hour")
    print(f"  config scans   : {len(t.scan_summaries)} seen; {len(t.scan_checks)} checks reported on the first scan, "
          f"then ~{t.changes_per_scan:.1f} status changes and ~{t.processes_per_scan:.0f} check commands per scan")  # fmt: skip
    print(f"  session events : {len(t.session):,} process templates, median {t.session_per_hour:.1f} per signed-in hour; "
          f"{len(t.logons)} logons, {len(t.logoffs)} logoffs")  # fmt: skip
    if t.left_out:
        print("  left out (admin/maintenance): " + ", ".join(f"{k}={v}" for k, v in t.left_out.most_common()))
    programs = Counter(_process_name(r["details"]) for r in t.session)
    print("  user programs kept: " + ", ".join(f"{k}={v}" for k, v in programs.most_common(15)))

    first, last = plan[0][0], plan[-1][0]
    size_mb = sum(len(json.dumps(tpl["details"])) for _, tpl in plan) / 1e6
    print(f"\nyear: {first:%Y-%m-%d} .. {last:%Y-%m-%d}   rows={len(plan):,}   ~{size_mb:,.0f} MB of details JSON")
    print("types : " + ", ".join(f"{k}={v:,}" for k, v in Counter(tpl["event_type"] for _, tpl in plan).most_common()))
    users = Counter(tpl["event_user"] if _is_person(tpl["event_user"]) else "(machine)" for _, tpl in plan)
    print("users : " + ", ".join(f"{k}={v:,}" for k, v in users.most_common()))
    person = Counter(t_.astimezone(LOCAL_TZ).hour for t_, tpl in plan if _is_person(tpl["event_user"]))
    print("user events by hour: " + "  ".join(f"{h:02d}:{person[h]:,}" for h in range(24) if person[h]))

    # A slice of one mid-year shift start, everything that happened.
    mid = plan[len(plan) // 2][0].date()
    while mid.weekday() != 2:  # a Wednesday
        mid += timedelta(days=1)
    lo = datetime.combine(mid, time(21, 50), tzinfo=LOCAL_TZ)
    sample = [p for p in plan if lo <= p[0] < lo + timedelta(minutes=25)][:20]
    print(f"\nsample: {mid:%a %Y-%m-%d} from 21:50 (first {len(sample)} events)")
    for t_, tpl in sample:
        proc = _process_name(tpl["details"])
        print(f"  {t_.astimezone(LOCAL_TZ):%H:%M:%S}  {tpl['event_type'] or '-':<22} {tpl['windows_event_id'] or '-':<5} "
              f"{tpl['rule_id'] or '-':<6} {tpl['event_user'] or '-':<24} {proc or (tpl['rule_description'] or '')[:40]}")  # fmt: skip


def _seed_main() -> None:
    parser = argparse.ArgumentParser(description="Generate a year of an endpoint's logs as the anomaly model's dataset.")
    parser.add_argument("--endpoint-id", type=int, required=True)
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--seed", type=int, default=2026, help="random seed, for a reproducible year")
    parser.add_argument("--scale", type=float, default=1.0, help="multiply the hourly rates (bigger dataset)")
    parser.add_argument("--shift", choices=sorted(SHIFTS), default="night", help="the persona's working hours (default: night, 22:00-06:00; day is 09:00-18:00)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--out", help="write the dataset to this CSV file (.csv.gz to compress); no database writes")
    action.add_argument("--write", action="store_true", help="replace this endpoint's seed rows in the database")
    action.add_argument("--delete", action="store_true", help="remove this endpoint's seed rows")
    args = parser.parse_args()

    from app.db.session import SessionLocal
    from app.models.endpoint import Endpoint

    db = SessionLocal()
    endpoint = db.get(Endpoint, args.endpoint_id)
    if endpoint is None:
        raise SystemExit(f"No endpoint with id {args.endpoint_id}.")
    if args.delete:
        print(f"Deleted {delete_seed(db, endpoint.id):,} seed rows for endpoint {endpoint.id}.")
        return

    try:
        templates = load_templates(db, endpoint.id)
    except NotEnoughEvents as exc:
        raise SystemExit(str(exc))
    plan = schedule(templates, days=args.days, seed=args.seed, scale=args.scale, shift=SHIFTS[args.shift])
    _print_preview(templates, plan)

    if args.out:
        rows = build_rows(plan, endpoint.id, seed=args.seed)
        written = write_dataset(args.out, rows, endpoint.id, endpoint.unique_id, total=len(plan))
        print(f"\nWrote {written:,} rows to {args.out}.")
    elif args.write:
        rows = build_rows(plan, endpoint.id, seed=args.seed)
        inserted = write_seed(db, endpoint.id, endpoint.unique_id, rows, total=len(plan))
        print(f"\nWrote {inserted:,} seed rows for endpoint {endpoint.id}.")
    else:
        print("\nPreview only — nothing written. Add --write to store these rows.")


# ======================================================================================
# the command line
# ======================================================================================

def _demo_history_main() -> None:
    """For a demo: store about 2,000 of the user's own actions, spread over the last weeks, as if
    the computer had been monitored all that time (so it counts as learned straight away).

    The actions are the programs, logons and logoffs this computer really produced (the real events
    are the templates), put on the working days inside the working hours. They are stored like
    collected events; only details["demo"] marks them, so --delete can take them out again."""
    parser = argparse.ArgumentParser(description="Store a few weeks of this computer's typical activity (for a demo).")
    parser.add_argument("--endpoint-id", type=int, required=True)
    parser.add_argument("--actions", type=int, default=2200, help="user actions to create (default 2200: a margin over the 2000 needed)")
    parser.add_argument("--days", type=int, default=21, help="how many days back (default 21: more than the 14 needed)")
    parser.add_argument("--hours", help="working hours HH:MM-HH:MM (default: the employee's declared hours, else 09:00-18:00)")
    parser.add_argument("--seed", type=int, default=2026)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="store the rows")
    action.add_argument("--delete", action="store_true", help="remove the rows this command stored")
    args = parser.parse_args()

    from app.db.session import SessionLocal
    from app.models.employee import Employee
    from app.models.endpoint import Endpoint

    db = SessionLocal()
    endpoint = db.get(Endpoint, args.endpoint_id)
    if endpoint is None:
        raise SystemExit(f"No endpoint with id {args.endpoint_id}.")
    if args.delete:
        print(f"Deleted {delete_demo(db, endpoint.id):,} demo rows of endpoint {endpoint.id}.")
        return

    employee = db.get(Employee, endpoint.employee_id)
    span = args.hours or (
        f"{employee.work_start}-{employee.work_end}" if employee is not None and employee.work_start and employee.work_end else "09:00-18:00"
    )
    try:
        start, end = (datetime.strptime(p.strip(), "%H:%M").time() for p in span.split("-"))
    except ValueError:
        raise SystemExit(f"--hours must look like 09:00-18:00, not {span!r}.")
    try:
        templates = load_templates(db, endpoint.id)
    except NotEnoughEvents as exc:
        raise SystemExit(str(exc))

    plan = demo_plan(templates, args.actions, args.days, (start, end), seed=args.seed)
    kinds = Counter("logon/logoff" if tpl["event_type"] in ("Login Success", "Logoff") else _process_name(tpl["details"]) for _, tpl in plan)
    print(f"templates : {len(templates.session)} session processes, {len(templates.logons)} logons, {len(templates.logoffs)} logoffs "
          f"(from {templates.real_rows:,} real events)")  # fmt: skip
    print(f"plan      : {len(plan):,} actions, {plan[0][0]:%Y-%m-%d} .. {plan[-1][0]:%Y-%m-%d}, working hours {span}")
    print("programs  : " + ", ".join(f"{k}={v}" for k, v in kinds.most_common(12)))
    if not args.write:
        print("\nPreview only, nothing written. Add --write to store these rows (--delete removes them again).")
        return
    inserted = write_seed(db, endpoint.id, endpoint.unique_id, build_rows(plan, endpoint.id, seed=args.seed, demo=True),
                          total=len(plan), replace=False)  # fmt: skip
    print(f"\nStored {inserted:,} actions for endpoint {endpoint.id}. Retrain Now (or wait for the next round) to learn from them.")


COMMANDS = {
    "demo-history": (_demo_history_main, "store a few weeks of typical activity so a demo computer counts as learned"),
    "train": (_train_main, "train a model on a dataset and show how it scores"),
    "evaluate": (_evaluate_main, "train on the past, test on the future with injected anomalies"),
    "ablation": (_ablation_main, "rules vs Isolation Forest vs both, with and without context"),
    "export": (_export_main, "export an endpoint's real events as a dataset file"),
    "seed": (_seed_main, "make the synthetic baseline from an endpoint's real events"),
}


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "evaluate"
    if command in ("-h", "--help") or command not in COMMANDS:
        print("usage: python -m app.services.ml.tools <command> [options]\n\ncommands:")
        for name, (_, help_text) in COMMANDS.items():
            print(f"  {name:<9} {help_text}")
        print("\nrun a command with --help for its options; with no command, 'evaluate' runs on the default dataset")
        raise SystemExit(0 if command in ("-h", "--help") else 2)
    sys.argv = [f"tools.py {command}"] + sys.argv[2:]
    COMMANDS[command][0]()


if __name__ == "__main__":
    main()
