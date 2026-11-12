"""Is this Windows program malware? A supervised classifier on the numbers in the program's PE header.

The exact check (is the file's SHA-256 in MalwareBazaar: threat_intel.lookup) only knows files someone has already
reported. This model answers for a file nobody has seen, from the header of the file alone (nothing is run).

  dataset   ClaMP, "Classification of Malware with PE headers" (Kumar et al., 2016; Kaggle: saurabhshahane/classification-of-malwares),
            file ClaMP_Raw-5184.csv: 5,184 Windows programs, 2,683 malware (class 1) and 2,501 benign (class 0), each
            as 55 numbers read from its PE header (DOS header, file header, optional header). We use the Raw file; the
            Integrated file is the same samples with added columns (packer detection...) that the endpoint could not
            compute without extra tools. 624 rows of the Raw file are exact duplicates and are removed first: a copy on
            both sides of the split would only measure memory.
  features  the 55 header fields, log-scaled and standardised. Nothing is read from the program's code.
  model     gradient boosting (scikit-learn HistGradientBoostingClassifier) trained round by round, 5 trees per epoch, with the accuracy and
            loss of every epoch printed and drawn like a Keras run. A small neural network is trained on the same split for
            comparison: it matches the trees on a random split but falls to 74% on newer programs, which is why it is not the one used.

Run it from company/backend (or press Run in VS Code):

    python -m app.services.ml.files                     # train, test two ways, draw charts, save the model
    python -m app.services.ml.files --epochs 80
    python -m app.services.ml.files --no-charts
    python -m app.services.ml.files --show              # also open the charts in windows

The test is reported two ways, and both belong in the report:
  - random split   the usual way papers report. Programs from the same family are on both sides.
  - split by time  learn on programs compiled up to a cut year, test on the newer ones (at least 25% of the programs). This is closer
                   to use: a new program is newer than what the model learned from.
What the test does not show: the benign programs of ClaMP are mostly older Windows files, so it says little about
how modern signed installers look; and it is not a measurement of detection on the malware a company will meet.
That is why the exact hash lookup stays as the first line and this model is meant as a weak signal.
"""

from __future__ import annotations

import argparse
import copy
import csv
import math
import os
import sys
import time
import warnings
from pathlib import Path

if __name__ == "__main__":  # run as a plain file (VS Code Run): make `app` importable and find .env
    _backend = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)

import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, log_loss, precision_recall_curve, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from app.services.ml.urls import BLUE, GREEN, GREY, RED, _progress

warnings.filterwarnings("ignore", category=UserWarning)

_BACKEND = Path(__file__).resolve().parents[3]
DATASETS = Path(__file__).resolve().parents[7] / "datasets"
DATASET_CSV = DATASETS / "public" / "ClaMP_Raw-5184.csv"
MODEL_PATH = _BACKEND / "ml_models" / "file_model.joblib"
REPORTS = _BACKEND / "ml_reports" / "files"

THRESHOLD = 0.5  # the reports count a program with at least this chance as malware
ALERT_THRESHOLD = 0.99  # a portal alert starts here (the threshold table of the test: 81% of the newer malware caught, 0.3% of the benign programs flagged): the model is a weak signal
SEED = 42
NAMES = ("benign", "malware")
# The 55 header fields in the order of the dataset's columns. The scan agent on the endpoint sends them in this order
# (Get-PeHeader in services/installer.py), as plain numbers; e_res and e_res2 are empty in the dataset and are 0.
PE_COLUMNS = [
    "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc",
    "e_ovno", "e_res", "e_oemid", "e_oeminfo", "e_res2", "e_lfanew", "Machine", "NumberOfSections", "CreationYear", "PointerToSymbolTable",
    "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics", "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
    "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment",
    "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion",
    "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics",
    "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes",
]
MACHINE_I386, MAGIC_PE32 = 332, 267  # 99.8% of the dataset's programs are 32-bit; the model is only asked about these
YEAR_RANGE = (1995, 2021)  # compile years outside this are not believable (the file has 2066 and 2102) and only go to the learning part


# ============================================================================
# the data
# ============================================================================


def load_dataset(path: Path = DATASET_CSV) -> tuple[list[str], np.ndarray, np.ndarray, np.ndarray]:
    """(column names, the numbers as a matrix, labels with 1 = malware, compile years) with exact duplicates removed."""
    if not path.exists():
        raise SystemExit(f"Dataset not found: {path}\nDownload it from https://www.kaggle.com/datasets/saurabhshahane/classification-of-malwares")
    with open(path, encoding="utf-8", errors="replace", newline="") as handle:
        rows = [r for r in csv.reader(handle) if r]
    header, body = rows[0], rows[1:]
    unique = list(dict.fromkeys(tuple(r) for r in body))  # keeps the order
    print(f"{path.name}: {len(body):,} rows, {len(body) - len(unique):,} exact duplicates removed, {len(unique):,} left.")
    number = lambda c: float(c) if c.strip() else 0.0
    X = np.array([[number(c) for c in r[:-1]] for r in unique])
    y = np.array([int(float(r[-1])) for r in unique])
    columns = header[:-1]
    if columns != PE_COLUMNS:
        raise SystemExit("The dataset's columns are not the ones the endpoint agent sends (PE_COLUMNS in files.py).")
    return columns, X, y, X[:, columns.index("CreationYear")]


# ============================================================================
# the model
# ============================================================================


class FileModel:
    def __init__(self, columns: list[str]) -> None:
        self.columns = columns
        self.scaler = StandardScaler()  # used by the neural network we compare with and by the charts; trees do not need it
        self.net: HistGradientBoostingClassifier | None = None
        self.history: dict[str, list[float]] = {}
        self.best_epoch = 0

    @staticmethod
    def transform_raw(X: np.ndarray) -> np.ndarray:
        return np.log1p(np.clip(X, 0, None))

    def matrix(self, X: np.ndarray) -> np.ndarray:
        return self.scaler.transform(self.transform_raw(X))

    def fit(self, X: np.ndarray, y: np.ndarray, Xv: np.ndarray, yv: np.ndarray, epochs: int = 40, patience: int = 8, rounds: int = 5,
            verbose: bool = True) -> None:
        """Gradient boosting, trained round by round: one epoch = `rounds` more trees. After each epoch the validation part is scored; the trees of
        the best epoch (lowest validation loss) are kept, and training stops when it has not improved for `patience` epochs."""
        say = print if verbose else (lambda *a, **k: None)
        net = HistGradientBoostingClassifier(max_iter=rounds, learning_rate=0.1, max_leaf_nodes=15, l2_regularization=1.0,
                                             early_stopping=False, warm_start=True, random_state=1)
        self.history = {"accuracy": [], "loss": [], "val_accuracy": [], "val_loss": []}
        best, best_net, waited = math.inf, None, 0
        for epoch in range(1, epochs + 1):
            say(f"Epoch {epoch}/{epochs}")
            started = time.time()
            net.set_params(max_iter=epoch * rounds)
            net.fit(X, y)
            p, pv = net.predict_proba(X)[:, 1], net.predict_proba(Xv)[:, 1]
            acc, loss = float(accuracy_score(y, p >= THRESHOLD)), float(log_loss(y, p, labels=[0, 1]))
            val_acc, val_loss = float(accuracy_score(yv, pv >= THRESHOLD)), float(log_loss(yv, pv, labels=[0, 1]))
            if verbose:
                _progress(rounds, rounds, started, f"accuracy: {acc:.4f} - loss: {loss:.4f} - val_accuracy: {val_acc:.4f} - val_loss: {val_loss:.4f}", done=True)
            for key, value in zip(self.history, (acc, loss, val_acc, val_loss)):
                self.history[key].append(value)
            if val_loss < best - 1e-5:
                best, waited, self.best_epoch, best_net = val_loss, 0, epoch, copy.deepcopy(net)
            else:
                waited += 1
                if waited >= patience:
                    say(f"Early stopping: the validation loss has not improved for {patience} epochs (best epoch: {self.best_epoch}).")
                    break
        self.net = best_net
        say(f"Kept the trees of epoch {self.best_epoch} ({self.best_epoch * rounds} trees, val_loss {best:.4f}).")

    def refit(self, X: np.ndarray, y: np.ndarray, rounds: int = 5) -> None:
        """After the tests: the same number of trees as the best epoch, learned again from all the programs (the saved model).
        The numbers of the tests above are of the model that did not see the test programs."""
        self.net = HistGradientBoostingClassifier(max_iter=self.best_epoch * rounds, learning_rate=0.1, max_leaf_nodes=15,
                                                  l2_regularization=1.0, early_stopping=False, random_state=1).fit(self.matrix(X), y)

    def knows(self, values: list[float]) -> bool:
        """Is this a 32-bit program? The dataset has almost no others, so the model says nothing about them."""
        return len(values) == len(self.columns) and values[self.columns.index("Machine")] == MACHINE_I386 and values[self.columns.index("Magic")] == MAGIC_PE32

    def check_row(self, values: list[float]) -> dict | None:
        """`values` are the 55 header numbers in PE_COLUMNS order; None when the program is not one the model knows."""
        if not self.knows(values):
            return None
        p = float(self.probability(np.array([values], dtype=float))[0])
        return {"malicious": p >= ALERT_THRESHOLD, "probability": p}

    def probability(self, X: np.ndarray) -> np.ndarray:
        """Chance that each program (a row of the header numbers, in the order of `columns`) is malware."""
        return self.net.predict_proba(self.matrix(np.atleast_2d(X)))[:, 1]

    def check(self, header: dict[str, float]) -> dict:
        """`header` maps the column names to numbers; a missing field counts as 0."""
        p = float(self.probability(np.array([[float(header.get(c, 0)) for c in self.columns]]))[0])
        return {"malicious": p >= ALERT_THRESHOLD, "probability": p}


def save(model: FileModel, path: Path = MODEL_PATH) -> None:
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path: Path = MODEL_PATH) -> FileModel:
    import joblib

    return joblib.load(path)


# ============================================================================
# the test
# ============================================================================


def _scores(y: np.ndarray, p: np.ndarray) -> dict:
    hit = p >= THRESHOLD
    return {"accuracy": accuracy_score(y, hit), "auc": roc_auc_score(y, p), "recall": float(hit[y == 1].mean()), "false_alarm": float(hit[y == 0].mean()), "n": len(y)}


def split_random(y: np.ndarray, seed: int = SEED) -> tuple[np.ndarray, np.ndarray]:
    return train_test_split(np.arange(len(y)), test_size=0.2, random_state=seed, stratify=y)


def split_time(years: np.ndarray) -> tuple[np.ndarray, np.ndarray, int]:
    """Learn on the programs compiled up to a cut year (and those with an unbelievable year), test on the newer ones. The cut is the
    latest year that still leaves at least 25% of the believable programs for the test: most of the file is from 2005-2012, so
    a cut at a fixed percentile would leave a test of a few dozen programs (we saw 57)."""
    believable = (years >= YEAR_RANGE[0]) & (years <= YEAR_RANGE[1])
    cut = max(c for c in range(YEAR_RANGE[0], YEAR_RANGE[1]) if (years[believable] > c).mean() >= 0.25)
    return np.where(~believable | (years <= cut))[0], np.where(believable & (years > cut))[0], cut


def _fit_and_score(columns, X, y, learn, test, epochs, verbose=False, seed=SEED) -> tuple[FileModel, dict, dict, np.ndarray, np.ndarray]:
    a, b = train_test_split(np.arange(len(learn)), test_size=0.1, random_state=seed + 1, stratify=y[learn])
    train, val = learn[a], learn[b]
    model = FileModel(columns)
    model.scaler.fit(model.transform_raw(X[train]))
    X_train, X_val, X_test = model.matrix(X[train]), model.matrix(X[val]), model.matrix(X[test])
    model.fit(X_train, y[train], X_val, y[val], epochs=epochs, verbose=verbose)
    p = model.net.predict_proba(X_test)[:, 1]
    net = MLPClassifier(hidden_layer_sizes=(64, 32), alpha=1e-3, batch_size=64, early_stopping=True, validation_fraction=0.1,
                        n_iter_no_change=8, max_iter=200, random_state=SEED).fit(X_train, y[train])
    return model, _scores(y[test], p), _scores(y[test], net.predict_proba(X_test)[:, 1]), X_train, X_test


def run_tests(columns, X, y, years, epochs: int = 40, charts: bool = True, show_windows: bool = False) -> FileModel:
    from app.services.ml.commands import show

    print(f"Programs: {len(y):,}  (malware {int(y.sum()):,}, benign {int((1 - y).sum()):,})   features: {len(columns)}")
    learn, test, cut = split_time(years)
    print(f"Split by time: learn on {len(learn):,} programs (compiled up to {cut}, plus those with an unbelievable year), "
          f"test on {len(test):,} compiled after {cut}   (malware share {y[learn].mean():.1%} / {y[test].mean():.1%})\n")
    print(f"Model: gradient boosting on {len(columns)} header fields, 5 trees per epoch (a neural network is trained on the same split for comparison)\n")

    model, main, net_main, X_train, X_test = _fit_and_score(columns, X, y, learn, test, epochs, verbose=True)
    a, _ = train_test_split(np.arange(len(learn)), test_size=0.1, random_state=SEED + 1, stratify=y[learn])  # the same split _fit_and_score made
    y_train, y_test = y[learn][a], y[test]
    prob_test = model.net.predict_proba(X_test)[:, 1]
    show("TEST SET (programs compiled after the learning ones)", y_test, (prob_test >= THRESHOLD).astype(int), prob_test, NAMES)

    print("\nChoosing the alert threshold (the model is a weak signal, so alerts must be rare):")
    print(f"  {'threshold':>9} {'malware caught':>15} {'benign flagged':>15} {'precision':>10}")
    for t in (0.5, 0.7, 0.8, 0.9, 0.95, 0.99):
        hit = prob_test >= t
        caught, wrong = int((hit & (y_test == 1)).sum()), int((hit & (y_test == 0)).sum())
        print(f"  {t:>9.2f} {caught / max(int(y_test.sum()), 1):>15.1%} {wrong / max(int((y_test == 0).sum()), 1):>15.2%} {caught / max(caught + wrong, 1):>10.1%}")
    print(f"\nTrain accuracy {accuracy_score(y_train, model.net.predict(X_train)):.4f} vs test accuracy {main['accuracy']:.4f}"
          f"  (a large gap would mean the model memorised the training programs)")

    print("\nHow much of that is a shortcut? Decision trees on the same numbers, no neural network:")
    for depth in (1, 3):
        tree = DecisionTreeClassifier(max_depth=depth, random_state=SEED).fit(X_train, y_train)
        print(f"  tree of depth {depth}: test accuracy {accuracy_score(y_test, tree.predict(X_test)):.4f}")
    stump = DecisionTreeClassifier(max_depth=1, random_state=SEED).fit(X_train, y_train)
    print(f"  the single rule behind depth 1: '{columns[int(stump.tree_.feature[0])]}'")

    names = _permutation_importance(model, X_test, y_test, columns)
    print("\nWhich header fields matter most (accuracy lost when one is shuffled):")
    for name, drop in names[:8]:
        print(f"  {drop:+.4f}  {name}")

    print("\nExtra test for the summary below: the same method with a random split ...")
    r_learn, r_test = split_random(y)
    _, rand, net_rand, _, _ = _fit_and_score(columns, X, y, r_learn, r_test, epochs)
    rows = [("Random split (usual in papers; same families on both sides)", rand, net_rand),
            (f"Split by time (learn up to {cut}, test newer)", main, net_main)]
    print("\nSUMMARY: the same method, tested two ways (read both together)")
    print(f"  {'test':<58} {'model':<14} {'accuracy':>9} {'AUC':>7} {'malware caught':>15} {'benign flagged':>15}")
    for name, small, big in rows:
        for label, s in (("boosted trees", small), ("neural net", big)):
            print(f"  {name:<58} {label:<14} {s['accuracy']:>9.1%} {s['auc']:>7.4f} {s['recall']:>15.1%} {s['false_alarm']:>15.1%}")
            name = ""
    print("  The random split is higher because programs of one family are on both sides. The split by time is closer to a new file.")
    print("  Caution: the share of malware changes a lot from year to year in this file (10% in 2006, 78% in 2011, 19% in 2012): the compile year is partly a stand-in for where the benign files were taken from.")

    if charts:
        draw_charts(model, X_train, y_train, X_test, y_test, prob_test, names, columns, show_windows)
    return model


def _permutation_importance(model: FileModel, X: np.ndarray, y: np.ndarray, columns: list[str]) -> list[tuple[str, float]]:
    rng = np.random.default_rng(SEED)
    base = accuracy_score(y, model.net.predict(X))
    out = []
    for j, name in enumerate(columns):
        shuffled = X.copy()
        shuffled[:, j] = rng.permutation(shuffled[:, j])
        out.append((name, base - accuracy_score(y, model.net.predict(shuffled))))
    return sorted(out, key=lambda t: -t[1])


# ============================================================================
# charts
# ============================================================================


def draw_charts(model, X_train, y_train, X_test, y_test, prob_test, importance, columns, show_windows: bool = False) -> None:
    try:
        import matplotlib

        if not show_windows:
            matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.colors import ListedColormap
    except ImportError:
        print("\nCharts skipped: matplotlib is not installed (pip install matplotlib).")
        return
    REPORTS.mkdir(parents=True, exist_ok=True)
    saved = []

    def finish(fig, name: str) -> None:
        fig.tight_layout()
        fig.savefig(REPORTS / name, dpi=150)
        saved.append(name)
        if not show_windows:
            plt.close(fig)

    h, epochs = model.history, range(1, len(model.history["loss"]) + 1)
    fig, (a, b) = plt.subplots(1, 2, figsize=(10, 4))
    a.plot(epochs, h["accuracy"], color=BLUE, label="train")
    a.plot(epochs, h["val_accuracy"], color=RED, label="validation")
    a.axvline(model.best_epoch, ls="--", color=GREY, label=f"best epoch ({model.best_epoch})")
    a.set(title="Model accuracy", xlabel="epoch", ylabel="accuracy")
    a.legend()
    b.plot(epochs, h["loss"], color=BLUE, label="train")
    b.plot(epochs, h["val_loss"], color=RED, label="validation")
    b.axvline(model.best_epoch, ls="--", color=GREY)
    b.set(title="Model loss", xlabel="epoch", ylabel="loss (log loss)")
    b.legend()
    finish(fig, "training_curves.png")

    from sklearn.metrics import confusion_matrix

    cm = confusion_matrix(y_test, (prob_test >= THRESHOLD).astype(int), labels=[0, 1])
    fig, ax = plt.subplots(figsize=(5, 4.5))
    shown = ax.matshow(cm)
    fig.colorbar(shown)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", color="white" if cm[i, j] < cm.max() / 2 else "black", fontsize=13)
    ax.set_xticks([0, 1], NAMES)
    ax.set_yticks([0, 1], NAMES)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.xaxis.set_label_position("bottom")
    ax.xaxis.tick_bottom()
    ax.set_title("Confusion matrix (test set, newer programs)")
    finish(fig, "confusion_matrix.png")

    fpr, tpr, _ = roc_curve(y_test, prob_test)
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    ax.plot(fpr, tpr, color=BLUE, label=f"boosted trees (AUC {roc_auc_score(y_test, prob_test):.4f})")
    ax.plot([0, 1], [0, 1], "--", color=GREY, label="guessing")
    ax.set(title="ROC curve", xlabel="false positive rate", ylabel="true positive rate")
    ax.legend(loc="lower right")
    finish(fig, "roc_curve.png")

    precision, recall, _ = precision_recall_curve(y_test, prob_test)
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    ax.plot(recall, precision, color=BLUE)
    ax.axhline(y_test.mean(), ls="--", color=GREY, label="guessing")
    ax.set(title="Precision-recall curve", xlabel="recall", ylabel="precision")
    ax.legend()
    finish(fig, "precision_recall_curve.png")

    fig, ax = plt.subplots(figsize=(6.5, 4))
    bins = np.linspace(0, 1, 26)
    ax.hist(prob_test[y_test == 0], bins=bins, color=GREEN, alpha=0.7, label="benign")
    ax.hist(prob_test[y_test == 1], bins=bins, color=RED, alpha=0.7, label="malware")
    ax.axvline(THRESHOLD, color="black", ls="--", label=f"threshold ({THRESHOLD})")
    ax.set_yscale("log")
    ax.set(title="Predicted chance of malware (test set)", xlabel="probability", ylabel="programs (log scale)")
    ax.legend()
    finish(fig, "score_distribution.png")

    top = importance[:12][::-1]
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.barh([n for n, _ in top], [d for _, d in top], color=BLUE)
    ax.set(title="Feature importance (accuracy lost when shuffled)", xlabel="drop in accuracy")
    finish(fig, "feature_importance.png")

    # the two-feature picture of the tutorials: the real model has 55 features, so the programs are
    # projected to 2 dimensions (PCA) and a logistic regression is fitted on those 2 numbers, just to draw
    rng = np.random.default_rng(SEED)
    pca = PCA(n_components=2, random_state=SEED).fit(X_train)
    full = pca.transform(X_train)
    flat = LogisticRegression(max_iter=500).fit(full, y_train)
    x1, x2 = np.meshgrid(np.linspace(np.percentile(full[:, 0], 0.5), np.percentile(full[:, 0], 99.5), 300),
                         np.linspace(np.percentile(full[:, 1], 0.5), np.percentile(full[:, 1], 99.5), 300))
    region = flat.predict(np.c_[x1.ravel(), x2.ravel()]).reshape(x1.shape)
    for name, X, y, title in (("decision_boundary_train.png", X_train, y_train, "Training set"), ("decision_boundary_test.png", X_test, y_test, "Test set")):
        idx = rng.choice(len(y), min(400, len(y)), replace=False)
        P = pca.transform(X[idx])
        acc2 = accuracy_score(y, flat.predict(pca.transform(X)))
        fig, ax = plt.subplots(figsize=(6.5, 5))
        ax.contourf(x1, x2, region, alpha=0.75, cmap=ListedColormap((GREEN, RED)))
        for value, colour, label in ((0, GREEN, "benign"), (1, RED, "malware")):
            ax.scatter(P[y[idx] == value, 0], P[y[idx] == value, 1], color=colour, edgecolor="white", linewidths=0.4, s=22, label=label)
        ax.set_xlim(x1.min(), x1.max())
        ax.set_ylim(x2.min(), x2.max())
        ax.set(title=f"{title}: PCA projection, for illustration only\n(a 2-feature model on the projection scores {acc2:.1%}; the real model uses all {len(columns)} fields)",
               xlabel="PC 1", ylabel="PC 2")
        ax.title.set_fontsize(9)
        ax.legend(loc="upper right")
        finish(fig, name)

    print(f"\n{len(saved)} charts saved in {REPORTS}:")
    for name in saved:
        print(f"  {name}")
    if show_windows:
        plt.show()


# ============================================================================
# command line
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--epochs", type=int, default=40, help="the most epochs to train (default 40; stops earlier when the validation loss stops improving)")
    parser.add_argument("--no-charts", action="store_true")
    parser.add_argument("--show", action="store_true", help="also open the charts in windows (they are always saved to ml_reports/files/)")
    args = parser.parse_args()

    columns, X, y, years = load_dataset()
    model = run_tests(columns, X, y, years, epochs=args.epochs, charts=not args.no_charts, show_windows=args.show)
    model.refit(X, y)
    save(model)
    print(f"\nThe saved model is learned again from all {len(y):,} programs with the same {model.best_epoch * 5} trees (the numbers above are of the model that had not seen the test programs).")
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    # Run the module under its own name, not as __main__: the saved model remembers the module of its
    # classes, and the backend can only load it if that is app.services.ml.files.
    from app.services.ml.files import main as _main

    _main()
