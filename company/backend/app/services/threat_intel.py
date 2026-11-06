"""Threat intelligence: is this exact file, address or domain publicly known to be bad?

An exact lookup, not a model. A file hash, a URL or a domain is looked up in the `threat_intel` table (public
lists of malware hashes and of malicious and phishing addresses). A hit is a fact with a source ("this
hash is in MalwareBazaar as Emotet"), so a detection that rests on it is Confirmed (CVSS Report Confidence,
services/cvss.py). A miss says nothing: a new file or a new address is not in any list, and that is what
the classifiers are for.

Used wherever something can be looked up by its exact value:

    file scan (USB drive, downloads)    lookup(db, "sha256", hash)
    phishing / malware web addresses    check_url(db, url)       (the URL, then its domain)
    commands that fetch from the net    check_url(db, <the address in the command>)

Fill the table with public lists (they are downloaded by hand, some need a free key):

    python -m app.services.threat_intel seed                                 # the built-in test entries (EICAR)
    python -m app.services.threat_intel import --kind sha256 --source malwarebazaar --file recent.csv
    python -m app.services.threat_intel import --kind url --source openphish --file feed.txt
    python -m app.services.threat_intel lookup --kind sha256 <hash>
    python -m app.services.threat_intel stats

Run from company/backend. The lists' sources and terms are in the README.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

if __name__ == "__main__":  # run as a plain file (VS Code Run): make `app` importable and find .env
    _backend = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)

KINDS = ("sha256", "md5", "url", "domain")
MAX_VALUE = 1000  # the column's length; longer addresses are skipped
_HEX = {"sha256": re.compile(r"^[0-9a-f]{64}$"), "md5": re.compile(r"^[0-9a-f]{32}$")}

# The EICAR test file is a harmless 68-byte file that every antivirus is made to treat as a virus: the
# standard way to test a detection without a real one. Only its hashes are kept here (the file itself is
# not written into the source: antivirus would quarantine this file). The addresses are EICAR's own.
BUILTIN = [
    ("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "eicar", "test file"),
    ("md5", "44d88612fea8a8f36de82e1278abb02f", "eicar", "test file"),
    ("url", "https://secure.eicar.org/eicar.com", "eicar", "test file"),
    ("url", "https://secure.eicar.org/eicar.com.txt", "eicar", "test file"),
]


@dataclass(frozen=True)
class Hit:
    kind: str
    value: str
    source: str
    category: str | None
    first_seen: datetime | None


# ============================================================================
# values: one spelling for each thing, so that an exact lookup finds it
# ============================================================================


def normalize(kind: str, value: str | None) -> str | None:
    """The value as it is stored and looked up; None if it is not a valid `kind` (or is too long)."""
    text = (value or "").strip().strip("\"'").strip()
    if not text:
        return None
    if kind in _HEX:
        text = text.lower()
        return text if _HEX[kind].match(text) else None
    if kind == "domain":
        text = text.lower().rstrip(".")
        return text if "." in text and "/" not in text and len(text) <= MAX_VALUE else None
    if kind == "url":
        if "://" not in text:
            return None
        parts = urlsplit(text)
        if not parts.netloc:
            return None
        # scheme and host are not case sensitive, the path is; the #fragment never reaches the server
        text = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))
        return text if len(text) <= MAX_VALUE else None
    raise ValueError(f"unknown kind {kind!r} (use one of {KINDS})")


def domain_of(url: str) -> str | None:
    """'http://Evil.Example.com:8080/a' -> 'evil.example.com'"""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return normalize("domain", host) if host else None


# ============================================================================
# lookup
# ============================================================================


def _model():
    from app.models.threat_intel import ThreatIndicator

    return ThreatIndicator


def _hit(row) -> Hit:
    return Hit(row.kind, row.value, row.source, row.category, row.first_seen)


def lookup(db, kind: str, value: str | None) -> Hit | None:
    """The entry for this exact value, or None (which only means: not in any list we have)."""
    key = normalize(kind, value)
    if key is None:
        return None
    T = _model()
    row = db.query(T).filter(T.kind == kind, T.value == key).first()
    return _hit(row) if row else None


def lookup_many(db, kind: str, values: list[str]) -> dict[str, Hit]:
    """Many lookups in one query: normalised value -> entry, for the ones that are known."""
    keys = {k for v in values if (k := normalize(kind, v))}
    if not keys:
        return {}
    T = _model()
    rows = db.query(T).filter(T.kind == kind, T.value.in_(keys))
    return {r.value: _hit(r) for r in rows}


def check_url(db, url: str | None) -> Hit | None:
    """A web address is known if the address itself is in a list, or its domain is."""
    key = normalize("url", url)
    if key is None:
        return None
    hit = lookup(db, "url", key)
    if hit is None and (domain := domain_of(key)):
        hit = lookup(db, "domain", domain)
    return hit


# ============================================================================
# filling the table
# ============================================================================


def _insert(db, rows: list[dict]) -> None:
    """Insert rows, skipping the ones that are already there (the dialect's own ON CONFLICT DO NOTHING)."""
    T = _model()
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:  # the tests use SQLite
        from sqlalchemy.dialects.sqlite import insert
    db.execute(insert(T.__table__).values(rows).on_conflict_do_nothing(index_elements=["kind", "value"]))


def add_many(db, entries, batch: int = 5000) -> tuple[int, int]:
    """Add (kind, value, source, category, first_seen) entries. Returns (added or already known, skipped as invalid)."""
    pending, seen, skipped, total = [], set(), 0, 0

    def flush() -> None:
        nonlocal pending, total
        if pending:
            _insert(db, pending)
            db.commit()
            total += len(pending)
            pending = []

    for kind, value, source, category, first_seen in entries:
        key = normalize(kind, value)
        if key is None:
            skipped += 1
            continue
        if (kind, key) in seen:
            continue
        seen.add((kind, key))
        pending.append({"kind": kind, "value": key, "source": source, "category": category[:100] if category else None, "first_seen": first_seen})
        if len(pending) >= batch:
            flush()
    flush()
    return total, skipped


def seed_builtin(db) -> int:
    return add_many(db, [(k, v, s, c, None) for k, v, s, c in BUILTIN])[0]


_FIRST_SEEN = ("first_seen_utc", "first_seen", "dateadded", "date_added", "submission_time")
_CATEGORY = ("signature", "threat", "malware", "family", "tags", "category")
_FILE_TYPE = ("file_type_guess", "file_type")  # MalwareBazaar's column for what kind of file it is (exe, dll, elf...)


def _parse_time(text: str | None) -> datetime | None:
    text = (text or "").strip()
    for fmt, size in (("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            return datetime.strptime(text[:size], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def read_list(path: Path, kind: str, source: str, column: str | None = None, types: set[str] | None = None):
    """Entries from a downloaded list. Understands what the public lists look like: a plain file with one
    value per line, or a CSV whose header may be a '# "first_seen_utc", "sha256_hash", ...' comment line
    (MalwareBazaar, URLhaus). The value's column is found by name (`column`, or the first one whose name
    holds the kind); the category and the date by their usual names, when the list has them."""
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
        header: list[str] | None = None
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                names = [c.strip().strip("\"'#").strip().lower() for c in next(csv.reader([line.lstrip("#").strip()], skipinitialspace=True), [])]
                if any(kind in n for n in names):
                    header = names  # the comment line that names the columns
                continue
            if "," not in line and header is None:
                yield (kind, line, source, None, None)  # one value per line
                continue
            cells = next(csv.reader([line], skipinitialspace=True))
            if header is None:  # a CSV whose first line is the header
                if any(kind in c.lower() for c in cells):
                    header = [c.strip().lower() for c in cells]
                    continue
                yield (kind, cells[0], source, None, None)
                continue
            row = dict(zip(header, cells))
            name = (column or "").lower() or next((n for n in header if kind in n), None)
            if name is None or name not in row:
                continue
            if types and (file_type := next((row[n].strip().lower() for n in _FILE_TYPE if n in row), None)) is not None and file_type not in types:
                continue  # e.g. only exe and dll: the lists also hold Linux and Android malware
            category = next((row[n].strip() for n in _CATEGORY if row.get(n, "").strip() not in ("", "n/a", "None")), None)
            when = next((_parse_time(row[n]) for n in _FIRST_SEEN if row.get(n)), None)
            yield (kind, row[name], source, category, when)


def stats(db) -> list[tuple[str, str, int]]:
    from sqlalchemy import func

    T = _model()
    return db.query(T.kind, T.source, func.count()).group_by(T.kind, T.source).order_by(T.kind, T.source).all()


# ============================================================================
# command line
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("seed", help="add the built-in test entries (EICAR)")
    imp = sub.add_parser("import", help="add a public list")
    imp.add_argument("--kind", choices=KINDS, required=True)
    imp.add_argument("--source", required=True, help="where the list comes from, e.g. malwarebazaar")
    imp.add_argument("--file", required=True, type=Path, help="the downloaded list (.csv, .txt or .gz)")
    imp.add_argument("--column", help="the CSV column that holds the value (found by its name by default)")
    imp.add_argument("--types", help="only these file types, comma separated, e.g. exe,dll,msi (MalwareBazaar's file_type_guess column)")
    look = sub.add_parser("lookup", help="look one value up")
    look.add_argument("--kind", choices=KINDS, required=True)
    look.add_argument("value")
    sub.add_parser("stats", help="how many entries there are")
    args = parser.parse_args()

    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        if args.command == "seed":
            print(f"{seed_builtin(db)} built-in entries added or already there")
        elif args.command == "import":
            types = {t.strip().lower() for t in args.types.split(",") if t.strip()} if args.types else None
            total, skipped = add_many(db, read_list(args.file, args.kind, args.source, args.column, types))
            print(f"{total} {args.kind} entries from {args.source} added or already there, {skipped} skipped as not valid")
        elif args.command == "lookup":
            hit = check_url(db, args.value) if args.kind == "url" else lookup(db, args.kind, args.value)
            if hit:
                print(f"KNOWN BAD  {hit.kind} {hit.value}\n  source: {hit.source}   category: {hit.category}   first seen: {hit.first_seen}")
            else:
                print("not in the lists (which says nothing about whether it is safe)")
        else:
            rows = stats(db)
            print(f"{'kind':8} {'source':20} entries")
            for kind, source, n in rows:
                print(f"{kind:8} {source:20} {n:>8}")
            if not rows:
                print("(empty: run 'seed', then 'import')")
    finally:
        db.close()


if __name__ == "__main__":
    main()
