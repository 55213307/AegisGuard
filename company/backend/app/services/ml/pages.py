"""PROTOTYPE: read a web page and turn it into the page-content numbers of the PhiUSIIL dataset.

The address alone tells little about phishing (see the README and ml/urls.py: on every public set we tried it stops
at about 85-90% when tested by site). The page itself says more, and the PhiUSIIL dataset has 28 columns
about the page (lines of code, forms, password field, links, images ...). This file answers the one question that
decides whether that can be used: can the same 28 numbers be computed from a real page, and do they look like the
dataset's? PhiUSIIL does not publish its crawler, so the definitions below are our reading of the column names and
of the values in the file; each one is marked when it is a guess.

  fetch_page(url)     a careful GET: http(s) only, the address must resolve to a public IP (checked on every redirect and
                      used for the connection), 10 s, 2 MB, no cookies, no scripts run, nothing but HTML is read.
  page_features(...)  the 28 numbers
  compare(...)        where each number lies among PhiUSIIL's legitimate and phishing pages

Run from company/backend:

    python -m app.services.ml.pages https://www.python.org https://example.com
    python -m app.services.ml.pages --html saved_page.html --url https://example.com     # a page saved earlier, nothing fetched

Not wired into the scan on purpose: it makes the server contact an address that may be malicious, which needs a
decision (where it runs, what it may reach) before it is switched on.
"""

from __future__ import annotations

import argparse
import csv
import http.client
import ipaddress
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import numpy as np

PHIUSIIL_CSV = Path(__file__).resolve().parents[7] / "datasets" / "public" / "PhiUSIIL_Phishing_URL_Dataset.csv"
FEATURES = [
    "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore", "URLTitleMatchScore", "HasFavicon", "Robots",
    "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame", "HasExternalFormSubmit",
    "HasSocialNet", "HasSubmitButton", "HasHiddenFields", "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]
MAX_BYTES, TIMEOUT, MAX_REDIRECTS = 2_000_000, 10, 5
USER_AGENT = "Mozilla/5.0 (compatible; AegisGuard-page-check/0.1)"


# ============================================================================
# fetching
# ============================================================================


class FetchError(Exception):
    pass


@dataclass
class Page:
    url: str  # the address that was asked for
    final_url: str  # where the redirects ended
    html: str
    redirects: int = 0  # how many redirects were followed
    self_redirects: int = 0  # of those, how many stayed on the same host
    status: int = 200
    truncated: bool = False
    chain: list[str] = field(default_factory=list)


def _public_address(host: str, port: int) -> str:
    """The IP address to connect to: the first one the name resolves to, which must be a public one."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise FetchError(f"cannot resolve {host}: {err}") from None
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            raise FetchError(f"{host} resolves to {ip}, which is not a public address (private, loopback and link-local are never contacted)")
    return infos[0][4][0]


def _connection(scheme: str, host: str, port: int, ip: str) -> http.client.HTTPConnection:
    """A connection that goes to the vetted IP, so the name cannot resolve to something else between the check and the connect."""
    if scheme == "https":
        context = ssl.create_default_context()

        class Secure(http.client.HTTPSConnection):
            def connect(self) -> None:
                raw = socket.create_connection((ip, port), TIMEOUT)
                self.sock = context.wrap_socket(raw, server_hostname=host)

        return Secure(host, port, timeout=TIMEOUT)

    class Plain(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = socket.create_connection((ip, port), TIMEOUT)

    return Plain(host, port, timeout=TIMEOUT)


def fetch_page(url: str) -> Page:
    """GET the page and follow up to 5 redirects. Raises FetchError for anything that is not a small HTML page on a public host."""
    current, redirects, same_host, chain = url, 0, 0, []
    while True:
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FetchError(f"only http and https addresses are fetched: {current}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip = _public_address(parts.hostname, port)
        chain.append(current)
        conn = _connection(parts.scheme, parts.hostname, port, ip)
        try:
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            conn.request("GET", path, headers={"Host": parts.netloc, "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml",
                                               "Accept-Encoding": "identity", "Connection": "close"})
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308) and response.getheader("Location"):
                if redirects >= MAX_REDIRECTS:
                    raise FetchError("too many redirects")
                nxt = urljoin(current, response.getheader("Location"))
                redirects += 1
                same_host += urlsplit(nxt).hostname == parts.hostname
                current = nxt
                continue
            kind = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
            if kind and kind not in ("text/html", "application/xhtml+xml", "text/plain"):
                raise FetchError(f"not a web page ({kind}); nothing was read")  # never pull a file down
            body = response.read(MAX_BYTES + 1)
            truncated = len(body) > MAX_BYTES
            charset = re.search(r"charset=([\w-]+)", response.getheader("Content-Type") or "")
            text = body[:MAX_BYTES].decode(charset.group(1) if charset else "utf-8", errors="replace")
            return Page(url, current, text, redirects, same_host, response.status, truncated, chain)
        except (OSError, http.client.HTTPException, LookupError) as err:
            raise FetchError(f"{type(err).__name__}: {err}") from None
        finally:
            conn.close()


# ============================================================================
# the 28 numbers
# ============================================================================

_SOCIAL = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com", "pinterest.com", "tiktok.com")


def _label(host: str) -> str:
    """'login.paypal.co.uk' -> 'paypal' (the part of the domain that is the name)."""
    labels = [x for x in host.lower().split(".") if x and x != "www"]
    if len(labels) >= 3 and len(labels[-2]) <= 3:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")


class _Reader(HTMLParser):
    """Counts what the dataset counts. Scripts are never run, only their text is looked at."""

    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base, self.host = base, (urlsplit(base).hostname or "").lower()
        self.title, self._in_title, self._in_script = "", False, False
        self.script_text, self.text = [], []
        self.n = dict.fromkeys(("img", "css", "js", "iframe", "self", "empty", "external"), 0)
        self.flag = dict.fromkeys(("favicon", "robots", "viewport", "description", "ext_form", "social", "submit", "hidden", "password"), 0)

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            self._in_script = True
            self.n["js"] += 1
        elif tag == "img":
            self.n["img"] += 1
        elif tag == "iframe":
            self.n["iframe"] += 1
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel:
                self.n["css"] += 1
            if "icon" in rel:
                self.flag["favicon"] = 1
        elif tag == "meta":
            name = a.get("name", "").lower()
            if name == "viewport":
                self.flag["viewport"] = 1
            elif name == "description" and a.get("content", "").strip():
                self.flag["description"] = 1
            elif name == "robots":
                self.flag["robots"] = 1
        elif tag == "form":
            action = a.get("action", "").strip()
            target = urlsplit(urljoin(self.base, action)).hostname if action else None
            if target and target.lower() != self.host:
                self.flag["ext_form"] = 1
        elif tag == "input":
            kind = a.get("type", "text").lower()
            if kind == "password":
                self.flag["password"] = 1
            elif kind == "hidden":
                self.flag["hidden"] = 1
            elif kind == "submit":
                self.flag["submit"] = 1
        elif tag == "button" and a.get("type", "submit").lower() == "submit":
            self.flag["submit"] = 1
        elif tag == "a":
            href = a.get("href", "").strip()
            if not href or href == "#" or href.lower().startswith(("javascript:", "#")):
                self.n["empty"] += 1
            else:
                host = (urlsplit(urljoin(self.base, href)).hostname or "").lower()
                if host and host != self.host and not href.lower().startswith(("mailto:", "tel:")):
                    self.n["external"] += 1
                    if any(host == s or host.endswith("." + s) for s in _SOCIAL):
                        self.flag["social"] = 1
                else:
                    self.n["self"] += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._in_script:
            self.script_text.append(data)
        else:
            self.text.append(data)


def page_features(page: Page) -> dict[str, float]:
    """The 28 numbers. Guesses are marked (g): they follow the column name and the values seen in the dataset."""
    reader = _Reader(page.final_url)
    try:
        reader.feed(page.html)
    except Exception:  # broken HTML is normal on phishing pages
        pass
    lines = page.html.split("\n")
    title = reader.title.strip()
    host = urlsplit(page.final_url).hostname or ""
    name = _label(host)
    squashed = re.sub(r"[^a-z0-9]", "", title.lower())
    visible = " ".join(reader.text).lower()
    script = " ".join(reader.script_text).lower()
    f = reader.flag
    n = reader.n
    return {
        "LineOfCode": len(lines),
        "LargestLineLength": max((len(x) for x in lines), default=0),
        "HasTitle": 1 if title else 0,
        "DomainTitleMatchScore": 100 if name and name in squashed else 0,  # (g) the dataset's values are mostly 0 or 100
        "URLTitleMatchScore": 100 if name and name in squashed else 0,  # (g) same rule on the address; the dataset's two columns differ in ~6%
        "HasFavicon": f["favicon"],
        "Robots": f["robots"],  # (g) a robots meta tag
        "IsResponsive": f["viewport"],  # (g) a viewport meta tag
        "NoOfURLRedirect": 1 if page.redirects else 0,  # (g) 0/1 in the dataset
        "NoOfSelfRedirect": 1 if page.self_redirects else 0,  # (g) 0/1 in the dataset
        "HasDescription": f["description"],
        "NoOfPopup": script.count("window.open("),  # (g)
        "NoOfiFrame": n["iframe"],
        "HasExternalFormSubmit": f["ext_form"],
        "HasSocialNet": f["social"],
        "HasSubmitButton": f["submit"],
        "HasHiddenFields": f["hidden"],
        "HasPasswordField": f["password"],
        "Bank": 1 if re.search(r"\bbank", visible) else 0,  # (g) a word search in the visible text
        "Pay": 1 if re.search(r"\bpay", visible) else 0,  # (g)
        "Crypto": 1 if re.search(r"crypto|bitcoin|ethereum", visible) else 0,  # (g)
        "HasCopyrightInfo": 1 if ("©" in page.html or "&copy;" in page.html.lower() or "copyright" in visible) else 0,  # (g)
        "NoOfImage": n["img"],
        "NoOfCSS": n["css"],
        "NoOfJS": n["js"],
        "NoOfSelfRef": n["self"],
        "NoOfEmptyRef": n["empty"],
        "NoOfExternalRef": n["external"],
    }


# ============================================================================
# comparing with the dataset
# ============================================================================


def dataset_columns() -> tuple[np.ndarray, np.ndarray]:
    """(the 28 columns of PhiUSIIL as a matrix, labels with 1 = phishing)."""
    with open(PHIUSIIL_CSV, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    X = np.array([[float(r[c] or 0) for c in FEATURES] for r in rows])
    y = np.array([0 if r["label"] == "1" else 1 for r in rows])
    return X, y


def compare(features: dict[str, float], X: np.ndarray, y: np.ndarray) -> list[str]:
    """For each number: its value and the share of PhiUSIIL's legitimate / phishing pages that have a value at most as large."""
    out = [f"  {'feature':<22} {'value':>8}   {'legit pages <=':>15} {'phishing pages <=':>18}"]
    for j, name in enumerate(FEATURES):
        v = features[name]
        out.append(f"  {name:<22} {v:>8.0f}   {(X[y == 0, j] <= v).mean():>14.0%} {(X[y == 1, j] <= v).mean():>17.0%}")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("urls", nargs="*")
    parser.add_argument("--html", type=Path, help="a page saved earlier (nothing is fetched)")
    parser.add_argument("--url", help="the address the saved page came from")
    parser.add_argument("--compare", action="store_true", help="show where each number lies among PhiUSIIL's pages")
    args = parser.parse_args()
    X = y = None
    if args.compare:
        X, y = dataset_columns()
    jobs = []
    if args.html:
        jobs.append(Page(args.url or "http://saved.invalid/", args.url or "http://saved.invalid/", args.html.read_text(encoding="utf-8", errors="replace")))
    for url in args.urls:
        try:
            jobs.append(fetch_page(url))
        except FetchError as err:
            print(f"{url}\n  not read: {err}\n")
    for page in jobs:
        feats = page_features(page)
        print(f"{page.url}  ->  {page.final_url}  (status {page.status}, {len(page.html):,} characters{', cut at 2 MB' if page.truncated else ''}, {page.redirects} redirect(s))")
        if X is not None:
            print("\n".join(compare(feats, X, y)))
        else:
            print("  " + ", ".join(f"{k}={v:.0f}" for k, v in feats.items()))
        print()


if __name__ == "__main__":
    main()
