"""Is this web address a phishing site? A supervised classifier trained on a public dataset.

The exact check (is the address in a blocklist: threat_intel.check_url) only knows addresses that
someone has already reported. This model answers for an address nobody has seen, from the address
itself, so it can be used on the endpoint without opening the page.

  dataset   PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024), UCI Machine Learning Repository,
            id 967: 235,795 pages, 134,850 legitimate and 100,945 phishing
            https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset   (CC BY 4.0)
  more legitimate hosts   Tranco top sites list (Le Pochat et al., NDSS 2019), https://tranco-list.eu, a research-oriented
            ranking of popular domains. PhiUSIIL's legitimate addresses are all `www.<site>` home pages, so they
            say nothing about ordinary hosts such as `download.microsoft.com` or a bare `github.com`. From the list
            we add bare domains (real) and the same domains with a common subdomain in front (made up by us: the
            prefix is picked at random from a list of everyday ones, it is not known to exist). The test reports
            the real part and the added part separately.
  features  only the host (the domain part) of the address: its length, characters, labels, TLD,
            suspicious words, free-hosting services. The scheme (http/https), a leading "www." and the
            path are ignored on purpose: in this dataset every legitimate address is a bare
            https://www.<site> home page, so those parts only tell which list the address came from
            (a first version that used them scored 99.8% and called a real GitHub link phishing).
            The dataset's page columns (title, forms, links) and its ratios computed against a list of
            legitimate sites are not used either: the endpoint agent only has the address.
  model     a small neural network (scikit-learn MLPClassifier, 2 hidden layers) trained epoch by epoch,
            with the accuracy and loss of every epoch printed and drawn like a Keras training run.

Run it from company/backend (or press Run in VS Code):

    python -m app.services.ml.urls                      # train, test, draw charts, save the model
    python -m app.services.ml.urls --epochs 40          # more epochs (it stops early when the validation loss stops improving)
    python -m app.services.ml.urls --no-charts
    python -m app.services.ml.urls --show               # also open the charts in windows
    python -m app.services.ml.urls --classify "http://paypal-secure-login.example.xyz/verify.php"

What the test does and does not show (also printed with the results):
  - The split is by registered domain: the same site never appears in both the learning and the test part.
  - Even on the host alone, the legitimate hosts are popular sites and many phishing hosts are throw-away
    names on free hosting. The test prints what a single rule scores, so the model's value is what it
    adds on top of that.
  - It is a test on this dataset. It is not a measurement of detection on the phishing a company will
    meet, which is why the exact blocklist check stays as the first line.
  - Published results on this and similar sets reach 96% and more, but with a random split, where the same
    site is on both sides. Tried on other data (a Kaggle full-address set, a pretrained model, the page columns) every
    variant fell back or flagged ordinary download pages, so this simple version is the one used (see urls_full.py,
    which holds the larger experiment and is not deployed).
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import sys
import time
import warnings
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

if __name__ == "__main__":  # run as a plain file (VS Code Run): make `app` importable and find .env
    _backend = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)

import numpy as np
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, log_loss, precision_recall_curve, roc_auc_score, roc_curve
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore", category=UserWarning)

_BACKEND = Path(__file__).resolve().parents[3]
DATASETS = Path(__file__).resolve().parents[7] / "datasets"
DATASET_CSV = DATASETS / "public" / "PhiUSIIL_Phishing_URL_Dataset.csv"
TRANCO_CSV = DATASETS / "public" / "tranco" / "top-1m.csv"
TRANCO_COUNT = 60000  # legitimate domains taken from the top 100,000 of the list
TRUSTED_RANK = 1000  # a domain in the top 1,000 of the list is not judged by the model (see UrlModel.check), unless it hosts other people's pages
_PREFIXES = ("mail", "docs", "support", "download", "cdn", "api", "login", "accounts", "shop", "blog", "help", "m", "app", "static",
             "images", "news", "portal", "secure", "my", "store", "dev", "status", "careers", "forum", "learn", "en", "id", "update")
MODEL_PATH = _BACKEND / "ml_models" / "url_model.joblib"
REPORTS = _BACKEND / "ml_reports" / "urls"

THRESHOLD = 0.5  # the reports count an address with at least this chance as phishing
ALERT_THRESHOLD = 0.8  # the portal raises an alert from here: the model is a weak signal (see the threshold table of the test), so alerts are kept rare
SEED = 42
NAMES = ("legitimate", "phishing")

# ============================================================================
# features: numbers read from the address string
# ============================================================================

_WORDS = ("login", "signin", "secure", "account", "update", "verify", "confirm", "banking", "bank", "paypal",
          "webscr", "password", "wallet", "support", "billing", "invoice", "free", "bonus", "gift", "alert")
_HOSTING = ("web.app", "firebaseapp.com", "weebly.com", "wixsite.com", "github.io", "blogspot.com", "pages.dev",
            "netlify.app", "000webhostapp.com", "herokuapp.com", "glitch.me", "godaddysites.com", "sites.google.com",
            "workers.dev", "vercel.app", "myportfolio.com", "square.site", "webflow.io", "ukit.com", "xsph.ru",
            "lima-city.de", "gq", "tk", "ml", "ga", "cf")
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at")
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

FEATURES = [
    "host_length", "tld_length", "is_ip_host", "subdomains", "label_count", "longest_label", "mean_label_length",
    "host_dots", "host_hyphens", "host_digits", "host_digit_ratio", "has_punycode", "longest_digit_run",
    "longest_consonant_run", "vowel_ratio", "host_entropy", "suspicious_words", "hosting_service", "shortener",
    "digit_letter_switches", "tld_phishing_rate",
]
_COLUMNS = {name: i for i, name in enumerate(FEATURES)}


def split_url(url: str) -> tuple[str, str, str, str, int]:
    """(host, path, query, scheme, has_port) of an address; a missing scheme is read as http."""
    text = url.strip()
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
        port = 1 if parts.port else 0
    except ValueError:
        host, port, parts = "", 0, urlsplit("http://invalid")
    return host, parts.path, parts.query, parts.scheme.lower(), port


def registered_domain(host: str) -> str:
    """'a.b.example.co.uk' -> 'example.co.uk'; an IP address is its own domain."""
    if _IP.match(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def _longest_run(text: str, pattern: str) -> int:
    runs = re.findall(pattern, text)
    return max((len(r) for r in runs), default=0)


def features(url: str) -> list[float]:
    """The numbers the model sees, read from the host only (the last one, tld_phishing_rate, is filled in by the model
    from its training data). The scheme, 'www.' and the path are left out on purpose (see the top of this file)."""
    host = split_url(url)[0]
    is_ip = 1 if _IP.match(host) else 0
    bare = host[4:] if host.startswith("www.") else host
    labels = bare.split(".") if bare else []
    letters = [ch for ch in bare if ch.isalpha()]
    digits = sum(ch.isdigit() for ch in bare)
    n = max(len(bare), 1)
    domain = registered_domain(bare)
    subdomains = 0 if is_ip else max(len(labels) - len(domain.split(".")), 0)
    switches = len(re.findall(r"(?<=[a-z])\d|(?<=\d)[a-z]", bare))
    return [
        len(bare), len(labels[-1]) if labels else 0, is_ip, subdomains, len(labels), max((len(x) for x in labels), default=0),
        sum(len(x) for x in labels) / max(len(labels), 1), bare.count("."), bare.count("-"), digits, digits / n,
        1 if "xn--" in bare else 0, _longest_run(bare, r"\d+"), _longest_run(bare, r"[bcdfghjklmnpqrstvwxyz]+"),
        sum(ch in "aeiou" for ch in letters) / max(len(letters), 1), _entropy(bare), sum(w in bare for w in _WORDS),
        1 if any(bare == h or bare.endswith("." + h) for h in _HOSTING) else 0, 1 if any(bare == t for t in _SHORTENERS) else 0,
        switches, 0.0,
    ]


# ============================================================================
# the dataset
# ============================================================================


def bar(iterable, desc: str, total: int | None = None):
    try:
        from tqdm import tqdm
    except ImportError:
        return iterable
    return tqdm(iterable, desc=desc, total=total, ncols=88)


def load_dataset(path: Path = DATASET_CSV, tranco: bool = True) -> tuple[list[str], np.ndarray, np.ndarray]:
    """The addresses, their labels (1 = phishing; the file has it the other way round) and where each came from
    (0 = PhiUSIIL, 1 = added from the Tranco list)."""
    if not path.exists():
        raise SystemExit(f"Dataset not found: {path}\nDownload it from https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset")
    urls, labels, seen = [], [], set()
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in bar(rows, "Reading the dataset"):
        url = (row.get("URL") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        labels.append(0 if row["label"] == "1" else 1)
    source = [0] * len(urls)
    if tranco:
        extra = tranco_legit([split_url(u)[0] for u, l in zip(urls, labels) if l == 1])
        urls += extra
        labels += [0] * len(extra)
        source += [1] * len(extra)
        print(f"Added {len(extra):,} legitimate hosts from the Tranco list ({TRANCO_CSV.name}).")
    return urls, np.array(labels, dtype=int), np.array(source, dtype=int)


def tranco_legit(phishing_hosts: list[str], path: Path = TRANCO_CSV) -> list[str]:
    """Legitimate hosts from the Tranco list: each chosen domain bare, and 40% of them again with an everyday subdomain in front.
    Domains that host many phishing pages (free hosting services) get no made-up subdomains, and a host that the dataset
    calls phishing is never added as legitimate."""
    if not path.exists():
        raise SystemExit(f"Tranco list not found: {path}\nDownload https://tranco-list.eu/top-1m.csv.zip and unzip it there (or run with --no-tranco).")
    hosting = {d for d, n in Counter(registered_domain(h) for h in phishing_hosts).items() if n >= 3}
    bad = set(phishing_hosts)
    domains = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            rank, _, domain = line.strip().partition(",")
            if domain and int(rank) <= 100000:
                domains.append(domain.lower())
    rng = np.random.default_rng(SEED)
    chosen = [domains[i] for i in rng.choice(len(domains), min(TRANCO_COUNT, len(domains)), replace=False)]
    out = []
    for domain in chosen:
        if domain in bad:
            continue
        out.append("https://" + domain)
        if domain not in hosting and rng.random() < 0.4:
            out.append(f"https://{_PREFIXES[rng.integers(len(_PREFIXES))]}.{domain}")
    return out


def trusted_domains(phishing_hosts: list[str], path: Path = TRANCO_CSV, rank: int = TRUSTED_RANK) -> frozenset[str]:
    """The registered domains of the `rank` most popular sites, without the ones that host pages of other people. The model sees only the host
    name, and a long or hyphenated sub-domain of a big site (release-assets.githubusercontent.com, 0.97 before this) looks like phishing to it,
    while the site is not. Free hosting and site builders (web.app, github.io, blogspot.com) are in that list too and are exactly where phishing
    lives, so they stay judged: the hosting list above, plus every domain with even one phishing host in the learning data (google.com is one: sites.google.com).
    The cost was measured on the test set: top 1,000 loses 73 of 5,790 phishing alerts (1.3%), top 10,000 would lose 224. The benefit cannot be measured
    on this data (its legitimate addresses are home pages, not download servers); it comes from a real case: a 7-Zip download from release-assets.githubusercontent.com."""
    if not path.exists():
        return frozenset()
    hosting = {registered_domain(h) for h in _HOSTING} | {d for d, n in Counter(registered_domain(h) for h in phishing_hosts).items() if n >= 1}
    popular = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            position, _, domain = line.strip().partition(",")
            if domain and int(position) <= rank:
                popular.add(domain.lower())
    return frozenset(popular - hosting)


# ============================================================================
# the model: features + scaler + a small neural network trained one epoch at a time
# ============================================================================


class UrlModel:
    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.net: MLPClassifier | None = None
        self.tld_rate: dict[str, float] = {}
        self.prior = 0.5
        self.history: dict[str, list[float]] = {}
        self.best_epoch = 0
        self.trusted: frozenset[str] = frozenset()  # popular domains that are not judged (trusted_domains)

    # -- features ---------------------------------------------------------------
    def fit_tlds(self, urls: list[str], y: np.ndarray, smoothing: float = 20.0) -> None:
        """How often addresses ending in each TLD are phishing, in the learning part only (smoothed towards the overall rate)."""
        self.prior = float(y.mean())
        total, bad = Counter(), Counter()
        for url, label in zip(urls, y):
            tld = split_url(url)[0].rsplit(".", 1)[-1]
            total[tld] += 1
            bad[tld] += int(label)
        self.tld_rate = {t: (bad[t] + smoothing * self.prior) / (n + smoothing) for t, n in total.items()}

    def raw_matrix(self, urls: list[str], desc: str | None = None) -> np.ndarray:
        rows = []
        for url in bar(urls, desc, total=len(urls)) if desc else urls:
            row = features(url)
            row[_COLUMNS["tld_phishing_rate"]] = self.tld_rate.get(split_url(url)[0].rsplit(".", 1)[-1], self.prior)
            rows.append(row)
        return np.log1p(np.clip(np.array(rows, dtype=float), 0, None))

    def matrix(self, urls: list[str], desc: str | None = None) -> np.ndarray:
        return self.scaler.transform(self.raw_matrix(urls, desc))

    # -- training ---------------------------------------------------------------
    def fit(self, X: np.ndarray, y: np.ndarray, Xv: np.ndarray, yv: np.ndarray, epochs: int = 30, patience: int = 5, batch: int = 512) -> None:
        """One epoch = one pass over the learning part in batches of 512. After each epoch the validation part is scored;
        the weights of the best epoch (lowest validation loss) are kept, and training stops when it has not improved for `patience` epochs."""
        rng = np.random.default_rng(SEED)
        self.net = MLPClassifier(hidden_layer_sizes=(64, 32), activation="relu", solver="adam", alpha=1e-4,
                                 batch_size=batch, learning_rate_init=1e-3, random_state=SEED)
        self.history = {"accuracy": [], "loss": [], "val_accuracy": [], "val_loss": []}
        best, best_weights, waited = math.inf, None, 0
        steps = math.ceil(len(y) / batch)
        for epoch in range(1, epochs + 1):
            print(f"Epoch {epoch}/{epochs}")
            order = rng.permutation(len(y))
            started, loss_sum, right, seen = time.time(), 0.0, 0, 0
            for step in range(steps):
                idx = order[step * batch:(step + 1) * batch]
                self.net.partial_fit(X[idx], y[idx], classes=[0, 1])
                loss_sum += self.net.loss_ * len(idx)
                right += int((self.net.predict(X[idx]) == y[idx]).sum())
                seen += len(idx)
                if step % 15 == 0 or step == steps - 1:
                    _progress(step + 1, steps, started, f"accuracy: {right / seen:.4f} - loss: {loss_sum / seen:.4f}")
            p = self.net.predict_proba(Xv)[:, 1]
            val_loss, val_acc = float(log_loss(yv, p, labels=[0, 1])), float(accuracy_score(yv, p >= THRESHOLD))
            acc, loss = right / seen, loss_sum / seen
            _progress(steps, steps, started, f"accuracy: {acc:.4f} - loss: {loss:.4f} - val_accuracy: {val_acc:.4f} - val_loss: {val_loss:.4f}", done=True)
            for key, value in zip(self.history, (acc, loss, val_acc, val_loss)):
                self.history[key].append(float(value))
            if val_loss < best - 1e-5:
                best, waited, self.best_epoch = val_loss, 0, epoch
                best_weights = ([w.copy() for w in self.net.coefs_], [b.copy() for b in self.net.intercepts_])
            else:
                waited += 1
                if waited >= patience:
                    print(f"Early stopping: the validation loss has not improved for {patience} epochs (best epoch: {self.best_epoch}).")
                    break
        if best_weights:
            self.net.coefs_, self.net.intercepts_ = best_weights
            print(f"Restored the weights of epoch {self.best_epoch} (val_loss {best:.4f}).")

    # -- using it ---------------------------------------------------------------
    def probability(self, urls: list[str]) -> np.ndarray:
        return self.net.predict_proba(self.matrix(urls))[:, 1]

    def is_trusted(self, url: str) -> bool:
        return registered_domain(split_url(url)[0]) in getattr(self, "trusted", frozenset())

    def check(self, url: str) -> dict:
        p = float(self.probability([url])[0])
        trusted = self.is_trusted(url)
        return {"phishing": p >= ALERT_THRESHOLD and not trusted, "probability": p, "trusted": trusted}


def _progress(step: int, total: int, started: float, text: str, done: bool = False) -> None:
    """A Keras-style line:  370/370 ━━━━━━━━━━━━━━━━━━━━ 1s 3ms/step - accuracy: 0.9505 - loss: 0.1141"""
    elapsed = time.time() - started
    fill = "━" if _can_print("━") else "="
    width = 20
    done_part = int(width * step / total)
    bar_text = fill * done_part + (" " * (width - done_part))
    per = elapsed / max(step, 1) * 1000
    line = f"{step:>{len(str(total))}}/{total} {bar_text} {elapsed:.0f}s {per:.0f}ms/step - {text}"
    sys.stdout.write("\r" + line + ("\n" if done else ""))
    sys.stdout.flush()


def _can_print(text: str) -> bool:
    try:
        text.encode(sys.stdout.encoding or "utf-8")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def save(model: UrlModel, path: Path = MODEL_PATH) -> None:
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path: Path = MODEL_PATH) -> UrlModel:
    import joblib

    return joblib.load(path)


# ============================================================================
# the test
# ============================================================================


def group_split(domains: list[str], test_size: float, seed: int = SEED) -> tuple[np.ndarray, np.ndarray]:
    """Learn / test split where all the addresses of one registered domain go to the same side."""
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    learn, test = next(splitter.split(np.zeros(len(domains)), groups=domains))
    return learn, test


def run_tests(urls: list[str], y: np.ndarray, source: np.ndarray, epochs: int = 30, charts: bool = True, show_windows: bool = False) -> UrlModel:
    from app.services.ml.commands import show

    domains = [registered_domain(split_url(u)[0]) for u in urls]
    learn, test = group_split(domains, 0.2)
    sub_train, sub_val = group_split([domains[i] for i in learn], 0.1, seed=SEED + 1)
    train, val = learn[sub_train], learn[sub_val]
    print(f"\nAddresses: {len(urls):,}  (phishing {int(y.sum()):,}, legitimate {int((1 - y).sum()):,}); registered domains: {len(set(domains)):,}")
    print(f"Split by registered domain: train {len(train):,} | validation {len(val):,} | test {len(test):,}"
          f"   (phishing share {y[train].mean():.1%} / {y[val].mean():.1%} / {y[test].mean():.1%})\n")

    model = UrlModel()
    model.fit_tlds([urls[i] for i in train], y[train])
    model.scaler.fit(model.raw_matrix([urls[i] for i in train], "Features (train)"))
    X_train = model.matrix([urls[i] for i in train])
    X_val = model.matrix([urls[i] for i in val], "Features (validation)")
    X_test = model.matrix([urls[i] for i in test], "Features (test)")
    y_train, y_val, y_test = y[train], y[val], y[test]

    print(f"\nModel: neural network {len(FEATURES)} -> 64 -> 32 -> 1 (ReLU, Adam, batches of 512)\n")
    model.fit(X_train, y_train, X_val, y_val, epochs=epochs)

    prob_test = model.net.predict_proba(X_test)[:, 1]
    flagged = (prob_test >= THRESHOLD).astype(int)
    show("TEST SET (domains the model has never seen)", y_test, flagged, prob_test, NAMES)
    src = source[test]
    if src.any():
        print("\nThe test set by where the legitimate addresses come from:")
        for name, mask in (("PhiUSIIL (real; legitimate = www home pages, plus all phishing)", src == 0), ("Tranco (added; legitimate only)", src == 1)):
            wrong_legit = int(((flagged == 1) & (y_test == 0) & mask).sum())
            n_legit = int(((y_test == 0) & mask).sum())
            print(f"  {name}: legitimate flagged as phishing {wrong_legit:,} of {n_legit:,} ({wrong_legit / max(n_legit, 1):.1%})")
    print(f"\nChoosing the alert threshold (the model is a weak signal, so alerts must be rare):")
    print(f"  {'threshold':>9} {'phishing caught':>16} {'legitimate flagged':>19} {'precision':>10}")
    for t in (0.5, 0.7, 0.8, 0.9, 0.95):
        hit = prob_test >= t
        caught, wrong = int((hit & (y_test == 1)).sum()), int((hit & (y_test == 0)).sum())
        print(f"  {t:>9.2f} {caught / max(int(y_test.sum()), 1):>15.1%} {wrong / max(int((y_test == 0).sum()), 1):>18.2%} {caught / max(caught + wrong, 1):>10.1%}")
    model.trusted = trusted_domains([split_url(urls[i])[0] for i in train if y[i] == 1])
    skip = np.array([model.is_trusted(urls[i]) for i in test])
    alert = prob_test >= ALERT_THRESHOLD
    print(f"\nPopular domains are not judged ({len(model.trusted):,} domains of the Tranco top {TRUSTED_RANK:,}, free hosting left out). Effect on the test set at the alert threshold {ALERT_THRESHOLD}:")
    print(f"  legitimate flagged: {alert[y_test == 0].sum():,} -> {(alert & ~skip)[y_test == 0].sum():,} of {int((y_test == 0).sum()):,}")
    print(f"  phishing caught:    {alert[y_test == 1].sum():,} -> {(alert & ~skip)[y_test == 1].sum():,} of {int(y_test.sum()):,}  (a phishing host on a popular domain would be lost here)")
    train_acc = accuracy_score(y_train, model.net.predict(X_train))
    print(f"\nTrain accuracy {train_acc:.4f} vs test accuracy {accuracy_score(y_test, flagged):.4f}"
          f"  (a large gap would mean the model memorised the training addresses)")

    print("\nHow much of that is the shortcut? Decision trees on the same features, no neural network:")
    for depth in (1, 3):
        tree = DecisionTreeClassifier(max_depth=depth, random_state=SEED).fit(X_train, y_train)
        print(f"  tree of depth {depth}: test accuracy {accuracy_score(y_test, tree.predict(X_test)):.4f}")
    stump = DecisionTreeClassifier(max_depth=1, random_state=SEED).fit(X_train, y_train)
    print(f"  the single rule behind depth 1: '{FEATURES[int(stump.tree_.feature[0])]}'")

    names = _permutation_importance(model, X_test, y_test)
    print("\nWhich features matter most (accuracy lost when one feature is shuffled, 5,000 test addresses):")
    for name, drop in names[:8]:
        print(f"  {drop:+.4f}  {name}")

    if charts:
        draw_charts(model, X_train, y_train, X_test, y_test, prob_test, names, show_windows)
    return model


def _permutation_importance(model: UrlModel, X: np.ndarray, y: np.ndarray, n: int = 5000) -> list[tuple[str, float]]:
    rng = np.random.default_rng(SEED)
    idx = rng.choice(len(y), min(n, len(y)), replace=False)
    Xs, ys = X[idx], y[idx]
    base = accuracy_score(ys, model.net.predict(Xs))
    out = []
    for j, name in enumerate(FEATURES):
        shuffled = Xs.copy()
        shuffled[:, j] = rng.permutation(shuffled[:, j])
        out.append((name, base - accuracy_score(ys, model.net.predict(shuffled))))
    return sorted(out, key=lambda t: -t[1])


# ============================================================================
# charts
# ============================================================================
GREEN, RED, BLUE, GREY = "#2e8b57", "#c0392b", "#2f6fb0", "#888888"


def draw_charts(model, X_train, y_train, X_test, y_test, prob_test, importance, show_windows: bool = False) -> None:
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
    ax.set_title("Confusion matrix (test set)")
    finish(fig, "confusion_matrix.png")

    fpr, tpr, _ = roc_curve(y_test, prob_test)
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    ax.plot(fpr, tpr, color=BLUE, label=f"neural network (AUC {roc_auc_score(y_test, prob_test):.4f})")
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
    ax.hist(prob_test[y_test == 0], bins=bins, color=GREEN, alpha=0.7, label="legitimate")
    ax.hist(prob_test[y_test == 1], bins=bins, color=RED, alpha=0.7, label="phishing")
    ax.axvline(THRESHOLD, color="black", ls="--", label=f"threshold ({THRESHOLD})")
    ax.set_yscale("log")
    ax.set(title="Predicted chance of phishing (test set)", xlabel="probability", ylabel="addresses (log scale)")
    ax.legend()
    finish(fig, "score_distribution.png")

    top = importance[:12][::-1]
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.barh([n for n, _ in top], [d for _, d in top], color=BLUE)
    ax.set(title="Feature importance (accuracy lost when shuffled)", xlabel="drop in accuracy")
    finish(fig, "feature_importance.png")

    # the two-feature picture of the tutorials: the real model has 21 features, so the addresses are
    # projected to 2 dimensions (PCA) and a logistic regression is fitted on those 2 numbers, just to draw
    rng = np.random.default_rng(SEED)
    pca = PCA(n_components=2, random_state=SEED).fit(X_train)
    flat = LogisticRegression(max_iter=500).fit(pca.transform(X_train), y_train)
    for name, X, y, title in (("decision_boundary_train.png", X_train, y_train, "Training set"), ("decision_boundary_test.png", X_test, y_test, "Test set")):
        idx = rng.choice(len(y), min(400, len(y)), replace=False)
        P = pca.transform(X[idx])
        full = pca.transform(X_train)
        x1, x2 = np.meshgrid(np.arange(full[:, 0].min() - 1, full[:, 0].max() + 1, 0.05), np.arange(full[:, 1].min() - 1, full[:, 1].max() + 1, 0.05))
        region = flat.predict(np.c_[x1.ravel(), x2.ravel()]).reshape(x1.shape)
        acc2 = accuracy_score(y, flat.predict(pca.transform(X)))
        fig, ax = plt.subplots(figsize=(6.5, 5))
        ax.contourf(x1, x2, region, alpha=0.75, cmap=ListedColormap((GREEN, RED)))
        for value, colour, label in ((0, GREEN, "legitimate"), (1, RED, "phishing")):
            ax.scatter(P[y[idx] == value, 0], P[y[idx] == value, 1], color=colour, edgecolor="white", linewidths=0.4, s=22, label=label)
        ax.set_xlim(np.percentile(full[:, 0], 0.5), np.percentile(full[:, 0], 99.5))
        ax.set_ylim(np.percentile(full[:, 1], 0.5), np.percentile(full[:, 1], 99.5))
        ax.set(title=f"{title}: PCA projection, for illustration only\n(a 2-feature model on the projection scores {acc2:.1%}; the real model uses all {len(FEATURES)} features)",
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
    parser.add_argument("--epochs", type=int, default=30, help="the most epochs to train (default 30; stops earlier when the validation loss stops improving)")
    parser.add_argument("--no-tranco", action="store_true", help="train on the PhiUSIIL addresses only (to see the bias)")
    parser.add_argument("--no-charts", action="store_true")
    parser.add_argument("--show", action="store_true", help="also open the charts in windows (they are always saved to ml_reports/urls/)")
    parser.add_argument("--classify", metavar="URL", help="check one address with the saved model")
    args = parser.parse_args()

    if args.classify:
        result = load().check(args.classify)
        print(f"Address:      {args.classify}")
        print(f"Prediction:   {'PHISHING' if result['phishing'] else 'legitimate'}")
        print(f"Probability:  {result['probability']:.4f}  (chance the address is phishing; an alert from {ALERT_THRESHOLD})")
        return

    urls, y, source = load_dataset(tranco=not args.no_tranco)
    model = run_tests(urls, y, source, epochs=args.epochs, charts=not args.no_charts, show_windows=args.show)
    save(model)
    print(f"\nModel saved to {MODEL_PATH}")
    print("\n--- Example predictions (the saved model) ---")
    print(f"{'prediction':<11} {'probability':>11}  address")
    for example in [
        "https://www.google.com",
        "https://github.com/anthropics/anthropic-sdk-python/releases",
        "https://download.microsoft.com/download/setup.exe",
        "https://docs.python.org/3/library/",
        "https://objects.githubusercontent.com/github-production-release-asset/1",
        "http://paypal-secure-login.verify-account.example.xyz/webscr.php?cmd=login",
        "http://192.0.2.15/bank/signin/confirm.html",
        "https://login-update-account.web.app/",
    ]:
        r = model.check(example)
        print(f"{'PHISHING' if r['phishing'] else 'legitimate':<11} {r['probability']:>11.4f}  {example}")


if __name__ == "__main__":
    # Run the module under its own name, not as __main__: the saved model remembers the module of its
    # classes, and the backend can only load it if that is app.services.ml.urls.
    from app.services.ml.urls import main as _main

    _main()
