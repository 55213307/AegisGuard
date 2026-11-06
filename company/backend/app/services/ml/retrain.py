"""Retrain a model by hand and test it the standard way. One script, two ways to run it:

  - the portal's "Retrain Now" button calls run(): the endpoint's model is retrained and swapped in,
    and the result of the test is kept for the portal to show (GET /api/accounts/{id}/training-report);
  - the command line, for the same test with charts (from company/backend):

      python -m app.services.ml.retrain                        # the default dataset file
      python -m app.services.ml.retrain --csv file.csv.gz      # another dataset file
      python -m app.services.ml.retrain --endpoint-id 8        # an endpoint's events from the database
      python -m app.services.ml.retrain --endpoint-id 8 --apply   # ...and make the new model the live one
      add --show to open the charts in windows; they are always saved in ml_reports/

What it does, in order (the numbers come out of tools.evaluate_split):
  1. take the endpoint's training events (its real actions, plus the baseline while it has little history);
  2. split by time: the oldest 80% to learn from, the newest 20% to test on;
  3. train an Isolation Forest on the 80%;
  4. add injected anomalies (label 1) to the 20%, score everything, compare the alerts with the labels:
     confusion matrix, accuracy, precision, recall, F1, false-positive rate, AUC, recall per kind of anomaly;
  5. train the live model on all of the events (the 80/20 model is only for the test).
Without --apply the command line changes nothing: the live model and the stored risk scores stay as they are.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a plain file (e.g. VS Code's Run button): make `app` importable
    _backend = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)  # the settings read .env from the current folder

from app.services import health
from app.services.ml import runtime
from app.services.ml.data import load_csv
from app.services.ml.model import BehaviorModel
from app.services.ml.tools import DEFAULT_CSV, evaluate_split, print_report

log = logging.getLogger("aegisguard.ml")
REPORTS = Path(__file__).resolve().parents[3] / "ml_reports"

# What the portal gets: the numbers, not the points of the charts.
_CHART_DATA = ("roc", "pr", "histogram", "scatter")


def public(report: dict) -> dict:
    return {k: v for k, v in report.items() if k not in _CHART_DATA}


def run(endpoint_id: int, apply: bool = True) -> dict | None:
    """Train the endpoint's model from the database and test it (see the top of this file).
    With apply the new model becomes the live one and earlier events are scored again.
    Returns the report, or None when there was nothing to train on."""
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        entry = runtime.train_endpoint(db, endpoint_id, evaluate=evaluate_split, apply=apply)
    except Exception as exc:
        log.exception("Retraining the model for endpoint %s failed", endpoint_id)
        health.fail("ml", f"Retraining the model for endpoint {endpoint_id} failed: {exc}")
        raise
    finally:
        db.close()
    return entry.report if entry else None


def run_in_background(endpoint_id: int) -> None:
    """What the portal's button starts: run() on its own thread."""
    import threading

    def work() -> None:
        try:
            run(endpoint_id, apply=True)
        except Exception:  # run() has logged it and told the health page
            pass

    threading.Thread(target=work, name=f"ml-retrain-{endpoint_id}", daemon=True).start()


# ---------------------------------------------------------------------------------------------------------
# charts (command line only; they need matplotlib: pip install matplotlib)
# ---------------------------------------------------------------------------------------------------------
BLUE, RED, GREY = "#2f6fb0", "#c0392b", "#888888"


def save_charts(report: dict, folder: Path, show: bool = False) -> list[Path]:
    try:
        import matplotlib

        if not show:
            matplotlib.use("Agg")  # draw to files, no window
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nCharts skipped: matplotlib is not installed (pip install matplotlib).")
        return []

    folder.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    c, m = report["confusion"], report["metrics"]
    threshold = report.get("ml_threshold", report["threshold"])  # the histogram is of the behaviour model's own 0-100 score

    def finish(fig, name: str) -> None:
        fig.tight_layout()
        path = folder / name
        fig.savefig(path, dpi=150)
        saved.append(path)
        if not show:
            plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.5, 4))
    grid = [[c["tn"], c["fp"]], [c["fn"], c["tp"]]]
    ax.imshow(grid, cmap="Blues")
    for i, row in enumerate(grid):
        for j, value in enumerate(row):
            ax.text(j, i, f"{value:,}", ha="center", va="center", fontsize=14, color="white" if value > c["tn"] / 2 else "black")
    ax.set_xticks([0, 1], ["normal", "anomaly"])
    ax.set_yticks([0, 1], ["normal", "anomaly"])
    ax.set_xlabel("predicted")
    ax.set_ylabel("actual")
    ax.set_title("Confusion matrix (test set)")
    finish(fig, "confusion_matrix.png")

    fig, ax = plt.subplots(figsize=(4.5, 4))
    ax.plot(report["roc"]["fpr"], report["roc"]["tpr"], color=BLUE, label=f"Isolation Forest (AUC {m['auc']:.3f})")
    ax.plot([0, 1], [0, 1], "--", color=GREY, label="guessing")
    ax.set_xlabel("false alarm rate")
    ax.set_ylabel("recall")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")
    finish(fig, "roc_curve.png")

    fig, ax = plt.subplots(figsize=(4.5, 4))
    ax.plot(report["pr"]["recall"], report["pr"]["precision"], color=BLUE)
    ax.axhline(report["injected"] / (report["injected"] + report["test_normal"]), ls="--", color=GREY, label="guessing")
    ax.set_xlabel("recall")
    ax.set_ylabel("precision")
    ax.set_title("Precision-recall curve")
    ax.legend()
    finish(fig, "precision_recall_curve.png")

    h = report["histogram"]
    centres = [(a + b) / 2 for a, b in zip(h["edges"], h["edges"][1:])]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(centres, h["normal"], width=4, color=BLUE, alpha=0.7, label="normal events")
    ax.bar(centres, h["anomaly"], width=4, color=RED, alpha=0.7, label="injected anomalies")
    ax.axvline(threshold, color="black", ls="--", label=f"alert threshold ({threshold})")
    ax.set_yscale("log")
    ax.set_xlabel("risk score")
    ax.set_ylabel("events (log scale)")
    ax.set_title("Risk scores on the test set")
    ax.legend()
    finish(fig, "score_distribution.png")

    kinds = report["kinds"]
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.barh([k["name"] for k in kinds], [k["caught"] for k in kinds], color=BLUE)
    for y, k in enumerate(kinds):
        ax.text(k["caught"] + 0.01, y, f"{k['caught']:.2f}", va="center")
    ax.set_xlim(0, 1.1)
    ax.set_xlabel("recall")
    ax.set_title("Recall by kind of anomaly")
    finish(fig, "recall_by_kind.png")

    s = report["scatter"]
    fig, ax = plt.subplots(figsize=(6.5, 5))
    normal = [i for i, a in enumerate(s["anomaly"]) if not a]
    anomaly = [i for i, a in enumerate(s["anomaly"]) if a]
    alarm = [i for i, a in enumerate(s["alarm"]) if a]
    ax.scatter([s["x"][i] for i in normal], [s["y"][i] for i in normal], s=6, color=BLUE, alpha=0.35, label="normal events")
    ax.scatter([s["x"][i] for i in anomaly], [s["y"][i] for i in anomaly], s=14, color=RED, alpha=0.8, label="injected anomalies")
    ax.scatter([s["x"][i] for i in alarm], [s["y"][i] for i in alarm], s=60, facecolors="none", edgecolors="black", linewidths=0.8, label="alert raised")
    ax.set_xlabel("PCA 1")
    ax.set_ylabel("PCA 2")
    ax.set_title(f"Test events in 2 dimensions ({s['kept']:.0%} of the variation kept)")
    ax.legend(loc="best")
    finish(fig, "scatter_pca.png")

    if show:
        plt.show()
    return saved


# ---------------------------------------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Retrain the behavioral model by hand and test it 80/20, with charts.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--csv", help=f"dataset file (default: {DEFAULT_CSV})")
    source.add_argument("--endpoint-id", type=int, help="an endpoint's events, read from the database")
    parser.add_argument("--apply", action="store_true", help="with --endpoint-id: make the new model the live one and score earlier events again")
    parser.add_argument("--charts", help=f"folder for the charts (default: {REPORTS}/<source>)")
    parser.add_argument("--no-charts", action="store_true")
    parser.add_argument("--show", action="store_true", help="open the charts in windows as well")
    args = parser.parse_args()

    if args.endpoint_id is not None:
        name = f"endpoint-{args.endpoint_id}"
        print(f"endpoint {args.endpoint_id}: reading its events from the database{' (the new model goes live)' if args.apply else ''}")
        report = run(args.endpoint_id, apply=args.apply)
        if report is None:
            raise SystemExit("Nothing to train on yet: no baseline for this endpoint and no real history.")
    else:
        path = Path(args.csv or DEFAULT_CSV)
        if not path.exists():
            raise SystemExit(f"Dataset not found: {path}\nPass --csv, or --endpoint-id.")
        name = path.name.split(".")[0]
        print(f"dataset: {path}")
        report = evaluate_split(load_csv(str(path), show_progress=True), BehaviorModel)

    print()
    print_report(report)
    if "error" not in report and not args.no_charts:
        saved = save_charts(report, Path(args.charts) if args.charts else REPORTS / name, show=args.show)
        if saved:
            print(f"\n{len(saved)} charts saved in {saved[0].parent}")


if __name__ == "__main__":
    main()
