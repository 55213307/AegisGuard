"""REPORT ONLY, NOT DEPLOYED. Is this web address a phishing or malware site? The fuller model: Kaggle + PhiUSIIL + Tranco, text model + boosted trees.

The exact check (is the address in a blocklist: threat_intel.check_url) only knows addresses that
someone has already reported. This model answers for an address nobody has seen, from the address
itself, so it can be used on the endpoint without opening the page.

  data      three public sets, merged (addresses are lower-cased, the scheme and a leading "www." are removed):
              Kaggle "Malicious URLs dataset" (malicious_phish.csv): benign, phishing and malware addresses with paths.
                       Its "defacement" class (hacked ordinary sites) is left out: it is not phishing or malware.
              PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024), UCI id 967, CC BY 4.0: 235,795 home-page addresses.
              Tranco top sites list (Le Pochat et al., NDSS 2019), https://tranco-list.eu: popular legitimate domains,
                       bare (real) and with an everyday subdomain in front (made up by us, disclosed in the test).
            A downloaded file's name (.exe, .zip, .pdf ...) is cut off the end of the address, because most malware addresses
            in Kaggle end in .exe and the model would learn the file type instead of the place it comes from.
            The scheme and "www." are removed because in these sets they only tell which list an address came from
            (in PhiUSIIL every legitimate address is https://www.<site>; a first version that used them scored 99.8%
            and called a real GitHub link phishing).
  model     two steps, then a boosted-tree learner trained round by round with an epoch log like a Keras run:
              1. a text model reads the address as a sequence of 1-4 characters (TF-IDF + logistic regression, SGD);
                 its chance for the learning addresses is made out-of-fold, so the second step cannot copy it;
              2. gradient boosting (scikit-learn HistGradientBoostingClassifier) takes that chance, the share of
                 phishing for the address's TLD and 50 numbers read from the address (lengths, characters, entropy,
                 path depth, file extension, suspicious words, free hosting, shorteners).
            The page itself (title, forms, links) is never used: the endpoint agent only has the address.

Run it from company/backend (or press Run in VS Code):

    python -m app.services.ml.urls_full                      # train, test three ways, draw charts, save the model
    python -m app.services.ml.urls_full --quick              # skip the extra tests (random split, cross-dataset)
    python -m app.services.ml.urls_full --epochs 40
    python -m app.services.ml.urls_full --no-charts
    python -m app.services.ml.urls_full --show               # also open the charts in windows
    python -m app.services.ml.urls_full --classify "http://paypal-secure-login.example.xyz/verify.php"

What the numbers mean (they are printed together at the end so none can be quoted alone):
  - random split        addresses of one site can be on both sides. This is the usual way papers report, and the
                        highest number, because the model has already seen the site. It is NOT how well a new site is recognised.
  - split by domain     all addresses of one registered domain go to the same side. This is the number to quote.
  - cross-dataset       learn on one source, test on the other. It shows how much of the score is the source's own style.
Even the split by domain is a test on these datasets, not a measurement of the phishing a company will meet, which is
why the exact blocklist check stays as the first line and this model only raises a weak signal.
"""

from __future__ import annotations

import argparse
import copy
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
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, log_loss, precision_recall_curve, roc_auc_score, roc_curve
from sklearn.model_selection import GroupKFold, GroupShuffleSplit, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore", category=UserWarning)

_BACKEND = Path(__file__).resolve().parents[3]
DATASETS = Path(__file__).resolve().parents[7] / "datasets"
PHIUSIIL_CSV = DATASETS / "public" / "PhiUSIIL_Phishing_URL_Dataset.csv"
KAGGLE_CSV = DATASETS / "public" / "malicious_phish.csv"
TRANCO_CSV = DATASETS / "public" / "tranco" / "top-1m.csv"
TRANCO_COUNT = 60000  # legitimate domains taken from the top 100,000 of the list
_PREFIXES = ("mail", "docs", "support", "download", "cdn", "api", "login", "accounts", "shop", "blog", "help", "m", "app", "static",
             "images", "news", "portal", "secure", "my", "store", "dev", "status", "careers", "forum", "learn", "en", "id", "update")
MODEL_PATH = _BACKEND / "ml_models" / "url_model_full.joblib"
REPORTS = _BACKEND / "ml_reports" / "urls_full"

THRESHOLD = 0.5  # the reports count an address with at least this chance as bad
ALERT_THRESHOLD = 0.8  # the portal raises an alert from here: the model is a weak signal (see the threshold table of the test), so alerts are kept rare
SEED = 42
NAMES = ("legitimate", "phishing/malware")
SOURCES = ("PhiUSIIL", "Tranco", "Kaggle")

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
_EXTENSIONS = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jpg", ".png", ".gif", ".css", ".js", ".exe", ".zip", ".pdf", ".txt")
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}
_FILE_NAME = re.compile(r"/[^/?#]*\.(?:exe|msi|zip|rar|7z|iso|dll|jar|apk|bin|dmg|pdf|docx?|xlsx?|pptx?|txt|csv)(?=[?#]|$)", re.I)
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

DENSE = [
    "length", "host_length", "path_length", "query_length", "dots", "host_dots", "host_hyphens", "hyphens", "underscores", "slashes",
    "equals", "ampersands", "percents", "at_signs", "tildes", "digit_ratio", "host_digits", "host_entropy", "path_entropy", "entropy",
    "tokens", "longest_token", "mean_token", "labels", "tld_length", "is_ip_host", "suspicious_words", "host_suspicious_words",
    "double_slash", "http_in_path", "longest_digit_run", "path_segments",
] + ["ext_" + e[1:] for e in _EXTENSIONS] + ["hosting_service", "shortener", "punycode"]
FEATURES = DENSE + ["text_model", "tld_phishing_rate"]  # what the boosted trees see


def normalise(url: str) -> str:
    """The form the model works on: no scheme, no leading 'www.', lower case. 'https://www.Example.com/a' -> 'example.com/a'."""
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", url.strip(), flags=re.I)
    text = re.sub(r"^www\.", "", text, flags=re.I).lower()
    # the name of a downloaded file says what the file is, not where it came from: in the Kaggle set most malware
    # addresses end in .exe, which would make every real installer look bad, so a file name like that is cut off
    return _FILE_NAME.sub("", text)


def _parts(text: str):
    try:
        return urlsplit("//" + text)
    except ValueError:
        return urlsplit("//invalid")


def host_of(text: str) -> str:
    """The host of a normalised address."""
    try:
        return _parts(text).hostname or ""
    except ValueError:
        return ""


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


def dense(text: str) -> list[float]:
    """The 50 numbers read from a normalised address."""
    parts = _parts(text)
    try:
        host = parts.hostname or ""
    except ValueError:
        host = ""
    path, query = parts.path, parts.query
    labels = host.split(".") if host else [""]
    tokens = re.findall(r"[a-z0-9]+", text)
    digit_runs = re.findall(r"\d+", text)
    n = max(len(text), 1)
    row = [
        len(text), len(host), len(path), len(query), text.count("."), host.count("."), host.count("-"), text.count("-"), text.count("_"),
        text.count("/"), text.count("="), text.count("&"), text.count("%"), text.count("@"), text.count("~"),
        sum(c.isdigit() for c in text) / n, sum(c.isdigit() for c in host), _entropy(host), _entropy(path), _entropy(text),
        len(tokens), max((len(t) for t in tokens), default=0), float(np.mean([len(t) for t in tokens])) if tokens else 0.0,
        len(labels), len(labels[-1]), 1 if _IP.match(host) else 0, sum(w in text for w in _WORDS), sum(w in host for w in _WORDS),
        1 if "//" in text else 0, 1 if "http" in path + query else 0, max((len(d) for d in digit_runs), default=0),
        len([p for p in path.split("/") if p]),
    ]
    row += [1 if path.endswith(e) else 0 for e in _EXTENSIONS]
    row += [1 if any(host == h or host.endswith("." + h) for h in _HOSTING) else 0, 1 if host in _SHORTENERS else 0, 1 if "xn--" in host else 0]
    return row


def dense_matrix(texts: list[str], desc: str | None = None) -> np.ndarray:
    return np.array([dense(t) for t in (bar(texts, desc, total=len(texts)) if desc else texts)], dtype=np.float32)


# ============================================================================
# the data
# ============================================================================


def bar(iterable, desc: str, total: int | None = None):
    try:
        from tqdm import tqdm
    except ImportError:
        return iterable
    return tqdm(iterable, desc=desc, total=total, ncols=88)


def load_dataset(tranco: bool = True, phiusiil: bool = True) -> tuple[list[str], np.ndarray, np.ndarray, np.ndarray]:
    """(addresses, labels with 1 = phishing or malware, source 0/1/2 = PhiUSIIL/Tranco/Kaggle, kind 'phishing'/'malware'/'' ).
    A string that would appear twice (also across the sets) is kept once, the first time."""
    for path, where in ((KAGGLE_CSV, "https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset"),
                        (PHIUSIIL_CSV, "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset")):
        if not path.exists():
            raise SystemExit(f"Dataset not found: {path}\nDownload it from {where}")
    texts, labels, source, kind, seen = [], [], [], [], set()

    def add(text: str, label: int, src: int, what: str = "") -> None:
        if text and text not in seen:
            seen.add(text)
            texts.append(text)
            labels.append(label)
            source.append(src)
            kind.append(what)

    with open(KAGGLE_CSV, encoding="utf-8", errors="replace", newline="") as handle:
        for row in bar(list(csv.DictReader(handle)), "Reading Kaggle"):
            if row["type"] != "defacement":
                add(normalise(row["url"]), 0 if row["type"] == "benign" else 1, 2, "" if row["type"] == "benign" else row["type"])
    if phiusiil:
        with open(PHIUSIIL_CSV, encoding="utf-8-sig", newline="") as handle:
            for row in bar(list(csv.DictReader(handle)), "Reading PhiUSIIL"):
                add(normalise((row.get("URL") or "")), 0 if row["label"] == "1" else 1, 0, "" if row["label"] == "1" else "phishing")
    if tranco:
        bad = [t for t, l in zip(texts, labels) if l == 1]
        extra = tranco_legit([host_of(t) for t in bad])
        before = len(texts)
        for t in extra:
            add(t, 0, 1)
        print(f"Added {len(texts) - before:,} legitimate hosts from the Tranco list ({TRANCO_CSV.name}).")
    return texts, np.array(labels, dtype=int), np.array(source, dtype=int), np.array(kind)


def tranco_legit(phishing_hosts: list[str], path: Path = TRANCO_CSV) -> list[str]:
    """Legitimate hosts from the Tranco list: each chosen domain bare, and 40% of them again with an everyday subdomain in front.
    Domains that host many phishing pages (free hosting services) get no made-up subdomains, and a host that a dataset
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
        out.append(domain)
        if domain not in hosting and rng.random() < 0.4:
            out.append(f"{_PREFIXES[rng.integers(len(_PREFIXES))]}.{domain}")
    return out


# ============================================================================
# the model
# ============================================================================


def _sgd() -> SGDClassifier:
    return SGDClassifier(loss="log_loss", alpha=2e-6, max_iter=15, tol=None, random_state=1)


def _vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(analyzer="char", ngram_range=(1, 4), min_df=5, max_features=300000, sublinear_tf=True, dtype=np.float32)


class UrlModel:
    def __init__(self) -> None:
        self.vec = _vectorizer()
        self.text: SGDClassifier | None = None
        self.net: HistGradientBoostingClassifier | None = None
        self.tld_rate: dict[str, float] = {}
        self.prior = 0.5
        self.history: dict[str, list[float]] = {}
        self.best_epoch = 0
        self.text_val_accuracy = 0.0

    # -- the two inputs that depend on the learning data ----------------------------
    def fit_tlds(self, texts: list[str], y: np.ndarray, smoothing: float = 20.0) -> None:
        """How often addresses ending in each TLD are bad, in the learning part only (smoothed towards the overall rate)."""
        self.prior = float(y.mean())
        total, bad = Counter(), Counter()
        for text, label in zip(texts, y):
            tld = host_of(text).rsplit(".", 1)[-1]
            total[tld] += 1
            bad[tld] += int(label)
        self.tld_rate = {t: (bad[t] + smoothing * self.prior) / (n + smoothing) for t, n in total.items()}

    def text_probability(self, texts: list[str]) -> np.ndarray:
        return self.text.predict_proba(self.vec.transform(texts))[:, 1]

    def stack(self, D: np.ndarray, text_p: np.ndarray, texts: list[str]) -> np.ndarray:
        """The matrix the trees see: the 50 numbers, the text model's chance and the TLD rate."""
        rate = np.array([self.tld_rate.get(host_of(t).rsplit(".", 1)[-1], self.prior) for t in texts], dtype=np.float32)
        return np.c_[D, text_p, rate].astype(np.float32)

    def matrix(self, texts: list[str], D: np.ndarray | None = None) -> np.ndarray:
        return self.stack(dense_matrix(texts) if D is None else D, self.text_probability(texts), texts)

    # -- training ---------------------------------------------------------------
    def fit(self, texts: list[str], D: np.ndarray, y: np.ndarray, val_texts: list[str], val_D: np.ndarray, val_y: np.ndarray,
            epochs: int = 30, patience: int = 5, rounds: int = 10, verbose: bool = True) -> tuple[np.ndarray, np.ndarray]:
        """Returns the stacked matrices (learning, validation). One epoch = `rounds` more boosting rounds; after each epoch the
        validation part is scored, the best epoch (lowest validation loss) is kept and training stops when it has not
        improved for `patience` epochs. The accuracy and loss of the learning part are measured on a fixed sample of 50,000."""
        say = print if verbose else (lambda *a, **k: None)
        say("Step 1/2  text model: the address as a sequence of 1-4 characters")
        T = self.vec.fit_transform(texts)
        self.text = _sgd().fit(T, y)
        groups = np.array([registered_domain(host_of(t)) for t in texts])
        oof = np.zeros(len(y))
        for a, b in GroupKFold(3).split(T, y, groups):  # out-of-fold, so the trees cannot copy a model that has seen the answer
            oof[b] = _sgd().fit(T[a], y[a]).predict_proba(T[b])[:, 1]
        val_text = self.text_probability(val_texts)
        self.text_val_accuracy = float(accuracy_score(val_y, val_text >= THRESHOLD))
        say(f"          the text model alone scores {self.text_val_accuracy:.4f} on the validation part")
        self.fit_tlds(texts, y)
        S, Sv = self.stack(D, oof, texts), self.stack(val_D, val_text, val_texts)

        say(f"Step 2/2  boosted trees on {S.shape[1]} features, {rounds} rounds per epoch\n")
        rng = np.random.default_rng(SEED)
        sample = rng.choice(len(y), min(50000, len(y)), replace=False)
        net = HistGradientBoostingClassifier(max_iter=rounds, learning_rate=0.08, max_leaf_nodes=63, early_stopping=False,
                                             warm_start=True, random_state=1)
        self.history = {"accuracy": [], "loss": [], "val_accuracy": [], "val_loss": []}
        best, best_net, waited = math.inf, None, 0
        for epoch in range(1, epochs + 1):
            say(f"Epoch {epoch}/{epochs}")
            started = time.time()
            net.set_params(max_iter=epoch * rounds)
            net.fit(S, y)
            p, pv = net.predict_proba(S[sample])[:, 1], net.predict_proba(Sv)[:, 1]
            acc, loss = float(accuracy_score(y[sample], p >= THRESHOLD)), float(log_loss(y[sample], p, labels=[0, 1]))
            val_acc, val_loss = float(accuracy_score(val_y, pv >= THRESHOLD)), float(log_loss(val_y, pv, labels=[0, 1]))
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
        say(f"Kept the trees of epoch {self.best_epoch} (val_loss {best:.4f}).")
        return S, Sv

    # -- using it ---------------------------------------------------------------
    def probability(self, urls: list[str]) -> np.ndarray:
        """Chance that each address (as written on the endpoint, with scheme and path if it has them) is phishing or malware."""
        texts = [normalise(u) for u in urls]
        return self.net.predict_proba(self.matrix(texts))[:, 1]

    def check(self, url: str) -> dict:
        p = float(self.probability([url])[0])
        return {"phishing": p >= ALERT_THRESHOLD, "probability": p}


def _progress(step: int, total: int, started: float, text: str, done: bool = False) -> None:
    """A Keras-style line:  10/10 ━━━━━━━━━━━━━━━━━━━━ 3s 300ms/step - accuracy: 0.9505 - loss: 0.1141"""
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
    joblib.dump(model, path, compress=3)


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


def _scores(y: np.ndarray, p: np.ndarray) -> dict:
    hit = p >= THRESHOLD
    return {"accuracy": accuracy_score(y, hit), "auc": roc_auc_score(y, p), "recall": float(hit[y == 1].mean()) if (y == 1).any() else float("nan"),
            "false_alarm": float(hit[y == 0].mean()) if (y == 0).any() else float("nan"), "n": len(y)}


def _extra_run(texts, D, y, groups, learn, test, by_group: bool) -> dict:
    """Train a model quietly on `learn`, score it on `test` (used for the random-split and cross-dataset columns)."""
    if by_group:
        a, b = group_split([groups[i] for i in learn], 0.1, seed=SEED + 1)
    else:
        a, b = train_test_split(np.arange(len(learn)), test_size=0.1, random_state=SEED + 1, stratify=y[learn])
    train, val = learn[a], learn[b]
    model = UrlModel()
    model.fit([texts[i] for i in train], D[train], y[train], [texts[i] for i in val], D[val], y[val], verbose=False)
    p = model.net.predict_proba(model.matrix([texts[i] for i in test], D[test]))[:, 1]
    out = _scores(y[test], p)
    out["epochs"] = model.best_epoch
    return out


def run_tests(texts: list[str], y: np.ndarray, source: np.ndarray, kind: np.ndarray, epochs: int = 30, charts: bool = True,
              show_windows: bool = False, extra: bool = True) -> UrlModel:
    from app.services.ml.commands import show

    D = dense_matrix(texts, "Features")
    groups = [registered_domain(host_of(t)) for t in texts]
    learn, test = group_split(groups, 0.2)
    sub_train, sub_val = group_split([groups[i] for i in learn], 0.1, seed=SEED + 1)
    train, val = learn[sub_train], learn[sub_val]
    print(f"\nAddresses: {len(texts):,}  (bad {int(y.sum()):,}, legitimate {int((1 - y).sum()):,}); registered domains: {len(set(groups)):,}")
    for code, name in enumerate(SOURCES):
        m = source == code
        if m.any():
            print(f"  {name:<9} {int(m.sum()):>8,} addresses, {y[m].mean():.0%} bad")
    print(f"Split by registered domain: train {len(train):,} | validation {len(val):,} | test {len(test):,}"
          f"   (bad share {y[train].mean():.1%} / {y[val].mean():.1%} / {y[test].mean():.1%})\n")

    model = UrlModel()
    S_train, _ = model.fit([texts[i] for i in train], D[train], y[train], [texts[i] for i in val], D[val], y[val], epochs=epochs)
    y_train, y_test = y[train], y[test]
    S_test = model.matrix([texts[i] for i in test], D[test])

    prob_test = model.net.predict_proba(S_test)[:, 1]
    flagged = (prob_test >= THRESHOLD).astype(int)
    main = _scores(y_test, prob_test)
    show("TEST SET (registered domains the model has never seen)", y_test, flagged, prob_test, NAMES)

    print("\nThe test set by where the addresses come from:")
    print(f"  {'source':<9} {'addresses':>10} {'accuracy':>9} {'bad caught':>11} {'legit flagged':>14}")
    for code, name in enumerate(SOURCES):
        m = source[test] == code
        if m.any():
            s = _scores(y_test[m], prob_test[m]) if len(set(y_test[m])) == 2 else {"accuracy": accuracy_score(y_test[m], flagged[m]), "recall": float("nan"), "false_alarm": float(flagged[m].mean()) if (y_test[m] == 0).all() else float("nan")}
            caught = "-" if math.isnan(s["recall"]) else f"{s['recall']:.1%}"
            wrong = "-" if math.isnan(s["false_alarm"]) else f"{s['false_alarm']:.1%}"
            print(f"  {name:<9} {int(m.sum()):>10,} {s['accuracy']:>9.1%} {caught:>11} {wrong:>14}")
    for what in ("phishing", "malware"):
        m = (kind[test] == what) & (source[test] == 2)
        if m.any():
            print(f"  Kaggle {what}: {(flagged[m] == 1).mean():.1%} caught ({int(m.sum()):,} addresses)")

    print("\nChoosing the alert threshold (the model is a weak signal, so alerts must be rare):")
    print(f"  {'threshold':>9} {'bad caught':>11} {'legitimate flagged':>19} {'precision':>10}")
    for t in (0.5, 0.7, 0.8, 0.9, 0.95):
        hit = prob_test >= t
        caught, wrong = int((hit & (y_test == 1)).sum()), int((hit & (y_test == 0)).sum())
        print(f"  {t:>9.2f} {caught / max(int(y_test.sum()), 1):>11.1%} {wrong / max(int((y_test == 0).sum()), 1):>18.2%} {caught / max(caught + wrong, 1):>10.1%}")
    print(f"\nTrain accuracy {accuracy_score(y_train, model.net.predict(S_train)):.4f} vs test accuracy {main['accuracy']:.4f}"
          f"  (a large gap would mean the model memorised the training addresses)")

    print("\nHow much do the trees add to the text model alone? (the text model's own chance used as the answer)")
    text_p = S_test[:, FEATURES.index("text_model")]
    print(f"  text model only: accuracy {accuracy_score(y_test, text_p >= THRESHOLD):.4f}, AUC {roc_auc_score(y_test, text_p):.4f}")
    print(f"  text + trees:    accuracy {main['accuracy']:.4f}, AUC {main['auc']:.4f}")
    for depth in (1, 3):
        tree = DecisionTreeClassifier(max_depth=depth, random_state=SEED).fit(S_train, y_train)
        print(f"  tree of depth {depth} on the same features: accuracy {accuracy_score(y_test, tree.predict(S_test)):.4f}")

    names = _permutation_importance(model, S_test, y_test)
    print("\nWhich features matter most (accuracy lost when one feature is shuffled, 5,000 test addresses):")
    for name, drop in names[:8]:
        print(f"  {drop:+.4f}  {name}")

    rows = [("Split by registered domain (the number to quote)", main)]
    if extra:
        print("\nExtra tests for the summary below (each trains a model quietly, this takes a few minutes) ...")
        everything = np.arange(len(texts))
        rng = np.random.default_rng(SEED)
        shuffled = rng.permutation(everything)
        cut = int(len(shuffled) * 0.8)
        rows.insert(0, ("Random split (usual in papers; same sites on both sides)", _extra_run(texts, D, y, groups, shuffled[:cut], shuffled[cut:], by_group=False)))
        kaggle, other = everything[source == 2], everything[source != 2]
        rows.append(("Learn on Kaggle, test on PhiUSIIL + Tranco", _extra_run(texts, D, y, groups, kaggle, other, by_group=True)))
        rows.append(("Learn on PhiUSIIL + Tranco, test on Kaggle", _extra_run(texts, D, y, groups, other, kaggle, by_group=True)))
    print("\nSUMMARY: the same method, tested four ways (read all of them together)")
    print(f"  {'test':<55} {'accuracy':>9} {'AUC':>7} {'bad caught':>11} {'legit flagged':>14}")
    for name, s in rows:
        print(f"  {name:<55} {s['accuracy']:>9.1%} {s['auc']:>7.4f} {s['recall']:>11.1%} {s['false_alarm']:>14.1%}")
    if extra:
        print("  The random split is higher only because a site seen while learning is seen again while testing.")
        print("  The cross-dataset rows are lower because each source has its own style (PhiUSIIL: home pages only; Kaggle: addresses with paths).")

    if charts:
        scaler = StandardScaler().fit(np.log1p(np.clip(S_train, 0, None)))
        chart = lambda S: scaler.transform(np.log1p(np.clip(S, 0, None)))
        draw_charts(model, chart(S_train), y_train, chart(S_test), y_test, prob_test, names, show_windows)
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
    fig, ax = plt.subplots(figsize=(5.4, 4.5))
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
    ax.plot(fpr, tpr, color=BLUE, label=f"model (AUC {roc_auc_score(y_test, prob_test):.4f})")
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
    ax.hist(prob_test[y_test == 1], bins=bins, color=RED, alpha=0.7, label="phishing/malware")
    ax.axvline(THRESHOLD, color="black", ls="--", label=f"threshold ({THRESHOLD})")
    ax.set_yscale("log")
    ax.set(title="Predicted chance of phishing/malware (test set)", xlabel="probability", ylabel="addresses (log scale)")
    ax.legend()
    finish(fig, "score_distribution.png")

    top = importance[:12][::-1]
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.barh([n for n, _ in top], [d for _, d in top], color=BLUE)
    ax.set(title="Feature importance (accuracy lost when shuffled)", xlabel="drop in accuracy")
    finish(fig, "feature_importance.png")

    # the two-feature picture of the tutorials: the real model has 52 features, so the addresses are
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
        for value, colour, label in ((0, GREEN, "legitimate"), (1, RED, "phishing/malware")):
            ax.scatter(P[y[idx] == value, 0], P[y[idx] == value, 1], color=colour, edgecolor="white", linewidths=0.4, s=22, label=label)
        ax.set_xlim(x1.min(), x1.max())
        ax.set_ylim(x2.min(), x2.max())
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
    parser.add_argument("--no-tranco", action="store_true", help="leave the Tranco hosts out")
    parser.add_argument("--no-phiusiil", action="store_true", help="leave PhiUSIIL out (its addresses are home pages without paths)")
    parser.add_argument("--quick", action="store_true", help="skip the extra tests (random split, cross-dataset)")
    parser.add_argument("--no-charts", action="store_true")
    parser.add_argument("--show", action="store_true", help="also open the charts in windows (they are always saved to ml_reports/urls_full/)")
    parser.add_argument("--classify", metavar="URL", help="check one address with the saved model")
    args = parser.parse_args()

    if args.classify:
        result = load().check(args.classify)
        print(f"Address:      {args.classify}")
        print(f"Prediction:   {'PHISHING/MALWARE' if result['phishing'] else 'legitimate'}")
        print(f"Probability:  {result['probability']:.4f}  (chance the address is bad; an alert from {ALERT_THRESHOLD})")
        return

    texts, y, source, kind = load_dataset(tranco=not args.no_tranco, phiusiil=not args.no_phiusiil)
    model = run_tests(texts, y, source, kind, epochs=args.epochs, charts=not args.no_charts, show_windows=args.show, extra=not args.quick)
    save(model)
    print(f"\nModel saved to {MODEL_PATH}")
    print("\n--- Example predictions (the saved model, addresses written as an endpoint would see them) ---")
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
    # classes, and the backend can only load it if that is app.services.ml.urls_full.
    from app.services.ml.urls_full import main as _main

    _main()
