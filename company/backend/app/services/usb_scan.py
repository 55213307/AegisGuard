"""What is wrong with the files on a USB drive: the rules a removable drive is checked against.

When a USB drive is plugged in, the endpoint lists its files (name, size, whether it is hidden, the SHA256
of programs and scripts, where a shortcut leads) and the backend runs this module over that list. It is a
set of rules and one exact lookup, no model: what makes a USB worm recognisable is a handful of tricks that
are easy to write down, and the file ML model (a classifier of program headers) judges the programs
themselves, separately.

    1. a file whose hash is on a threat-intelligence list        -> confirmed malware (services/threat_intel.py)
    2. an autorun.inf in the root of the drive                   -> T1091 Replication Through Removable Media
    3. a double extension: report.pdf.exe, photo.jpg.scr         -> T1036.007 Masquerading
    4. a program or script that is hidden or marked "system"     -> hiding a program from the user
    5. a shortcut that starts a command or a program on the drive, or one that stands in for a folder that
       has been hidden (the "shortcut virus": the folders vanish, shortcuts with their names start the malware)

Each finding says which kind of detection it is (a key of cvss.CATALOG), where, and why. This module has no
database and no web code; the lookup in 1 is a function that is handed in. Run this file to see it work:

    python -m app.services.usb_scan
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

# Files that run when opened. (.dll is not here: a library does not start by itself.)
EXECUTABLE = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
    ".hta", ".cpl", ".msi", ".jar", ".lnk",
}  # fmt: skip
# What a document, picture or archive is called: a file that ends in one of these and then in a program
# extension is a program wearing a document's name.
DOCUMENT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".jpg", ".jpeg", ".png",
    ".gif", ".bmp", ".zip", ".rar", ".7z", ".mp3", ".mp4", ".avi", ".mov",
}  # fmt: skip
_PROGRAM = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".cpl", ".lnk"}
# A shortcut that starts one of these is not a shortcut to a file.
_LAUNCHERS = re.compile(r"\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b", re.I)
MAX_FINDINGS = 50


@dataclass
class FileEntry:
    path: str  # relative to the root of the drive, with \ or /
    is_dir: bool = False
    size: int = 0
    hidden: bool = False  # Hidden or System attribute
    sha256: str | None = None  # of programs and scripts (the endpoint computes it)
    target: str | None = None  # a .lnk's target and arguments; an autorun.inf's open= / shellexecute= line
    target_signed: bool | None = None  # autorun.inf only: True if every program it starts has a valid digital signature

    @property
    def name(self) -> str:
        return re.split(r"[\\/]", self.path.rstrip("\\/"))[-1]

    @property
    def parent(self) -> str:
        parts = re.split(r"[\\/]", self.path.rstrip("\\/"))
        return "/".join(parts[:-1]).lower()

    @property
    def extension(self) -> str:
        dot = self.name.rfind(".")
        return self.name[dot:].lower() if dot > 0 else ""


@dataclass
class Finding:
    kind: str  # a key of cvss.CATALOG
    path: str
    detail: str  # one line for the reason shown in the portal
    confirmed: bool = False  # from an exact lookup (threat intelligence), not from a rule
    category: str | None = None  # the malware family, when a list names one
    extra: dict = field(default_factory=dict)


def scan_listing(entries: list[FileEntry], known_bad: Callable[[list[str]], dict] | None = None, usb: bool = True) -> list[Finding]:
    """The findings in a file list. `known_bad(hashes)` returns {hash: Hit} for the hashes that are on a
    threat-intelligence list (threat_intel.lookup_many); without it the lookup is skipped. With usb=False
    (the list is a Downloads folder, not a drive) only that lookup is made: the other rules are about what
    is on a USB drive."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, entry: FileEntry, detail: str, **kw) -> None:
        if (kind, entry.path.lower()) not in seen and len(findings) < MAX_FINDINGS:
            seen.add((kind, entry.path.lower()))
            findings.append(Finding(kind, entry.path, detail, **kw))

    # 1. exact: a hash on a list
    if known_bad is not None:
        hashes: dict[str, list[FileEntry]] = {}  # several files can be the same program: all of them are reported
        for e in entries:
            if e.sha256:
                hashes.setdefault(e.sha256.lower(), []).append(e)
        for digest, hit in (known_bad(list(hashes)) if hashes else {}).items():
            for entry in hashes.get(digest, []):
                add("malicious_file", entry, f"on the {hit.source} list" + (f" as {hit.category}" if hit.category else ""),
                    confirmed=True, category=hit.category, extra={"sha256": digest, "source": hit.source})  # fmt: skip

    if not usb:
        return findings
    hidden_dirs = {(e.parent, e.name.lower()) for e in entries if e.is_dir and e.hidden}
    for e in entries:
        if e.is_dir:
            continue
        name, ext = e.name.lower(), e.extension
        # 2. autorun.inf in the root. A Windows installation drive has one too, pointing at Microsoft's
        #    signed setup.exe; a worm's points at the program it brought. A valid signature tells them apart.
        if name == "autorun.inf" and not e.parent and not e.target_signed:
            pointing = f", opens {e.target}" if e.target else ""
            unsigned = ", and what it opens is not signed (or is not on the drive)" if e.target_signed is False else ""
            add("usb_autorun", e, f"autorun.inf in the root of the drive{pointing}{unsigned}")
        # 3. report.pdf.exe
        if ext in _PROGRAM:
            stem_ext = e.name[: -len(ext)].rsplit(".", 1)
            if len(stem_ext) == 2 and ("." + stem_ext[1].lower()) in DOCUMENT:
                add("usb_disguised_file", e, f"a program named like a document: {e.name}")
        # 4. a hidden program
        if e.hidden and ext in EXECUTABLE and ext != ".lnk":
            add("usb_disguised_file", e, f"hidden program: {e.name}")
        # 5. shortcuts
        if ext == ".lnk":
            stem = e.name[:-4].lower()
            if (e.parent, stem) in hidden_dirs:
                add("usb_disguised_file", e, f"shortcut standing in for the hidden folder '{e.name[:-4]}'")
            elif e.target and _LAUNCHERS.search(e.target):
                add("usb_disguised_file", e, f"shortcut that starts a command: {e.target[:80]}")
    return findings


def describe(f: Finding) -> str:
    return f"{f.path}: {f.detail}"


# ---------------------------------------------------------------------------
# reading a real drive (or any folder): what the endpoint's scanner will also do
# ---------------------------------------------------------------------------

_HIDDEN, _SYSTEM = 0x2, 0x4  # Windows file attributes
_SKIP_DIRS = {"system volume information", "$recycle.bin"}  # Windows' own, hidden on every drive
_HASHED = EXECUTABLE | {".dll"}  # the files whose hash is taken: programs, scripts, shortcuts, libraries
_AUTORUN_LINE = re.compile(r"^\s*(open|shellexecute|shell\\[^=]*\\command|icon)\s*=\s*(.+)$", re.I)


def _sha256(path: str) -> str | None:
    import hashlib

    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _autorun_target(path: str) -> str | None:
    """The command lines an autorun.inf asks Windows to run (open=, shellexecute=...)."""
    lines: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle.readlines()[:100]:
                match = _AUTORUN_LINE.match(line)
                if match and match.group(1).lower() != "icon":  # icon= only names a picture
                    lines.append(line.strip())
    except OSError:
        return None
    return "; ".join(lines)[:200] or None


def _autorun_programs(command_lines: str, root: str) -> list[str]:
    """The files on the drive that an autorun.inf starts: 'open=sources\\SetupError.exe x64' -> that file.
    A command is its longest start that is a file on the drive (what follows is its arguments)."""
    import os

    found: list[str] = []
    for line in command_lines.split(";"):
        value = line.split("=", 1)[-1].strip().strip('"')
        words = value.split(" ")
        for n in range(len(words), 0, -1):
            candidate = os.path.join(root, " ".join(words[:n]).strip('"'))
            if os.path.isfile(candidate):
                found.append(candidate)
                break
    return found


def _signatures_valid(paths: list[str]) -> dict[str, bool]:
    """For each file: does it carry a valid digital signature (Windows' own check, Get-AuthenticodeSignature)?"""
    import json
    import os
    import subprocess
    import tempfile

    if not paths:
        return {}
    script = (
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $out = @(); "
        "foreach ($p in (Get-Content -LiteralPath $env:AG_FILES -Encoding UTF8)) { try { $s = Get-AuthenticodeSignature -LiteralPath $p; "
        "$out += [pscustomobject]@{p = [string]$p; ok = ([string]$s.Status -eq 'Valid')} } catch {} }; "
        "ConvertTo-Json -Compress -InputObject $out"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        handle.write("\n".join(paths))
        listing = handle.name
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", timeout=120, env={**os.environ, "AG_FILES": listing},
        )  # fmt: skip
        data = json.loads(done.stdout) if done.stdout.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    finally:
        os.unlink(listing)
    return {item["p"]: bool(item["ok"]) for item in (data if isinstance(data, list) else [data])}


def _shortcut_targets(paths: list[str]) -> dict[str, str]:
    """Where each .lnk leads ('target arguments'), asked of Windows itself (WScript.Shell), all in one call."""
    import json
    import os
    import subprocess
    import tempfile

    if not paths:
        return {}
    script = (
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $sh = New-Object -ComObject WScript.Shell; "
        "$out = @(); foreach ($p in (Get-Content -LiteralPath $env:AG_LNKS -Encoding UTF8)) { try { $l = $sh.CreateShortcut($p); "
        "$out += [pscustomobject]@{p = [string]$p; t = (($l.TargetPath + ' ' + $l.Arguments).Trim())} } catch {} }; "
        "ConvertTo-Json -Compress -InputObject $out"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        handle.write("\n".join(paths))
        listing = handle.name
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", timeout=120, env={**os.environ, "AG_LNKS": listing},
        )  # fmt: skip
        data = json.loads(done.stdout) if done.stdout.strip() else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    finally:
        os.unlink(listing)
    return {item["p"]: item["t"] for item in (data if isinstance(data, list) else [data]) if item.get("t")}


def read_drive(root: str, max_entries: int = 20000, max_hash_mb: int = 200) -> tuple[list[FileEntry], dict]:
    """The file list of a drive or folder: names, sizes, hidden or not, the SHA256 of programs and scripts,
    where shortcuts lead. Only reads; nothing is opened as a program. Returns (entries, notes)."""
    import os

    root = os.path.abspath(root)
    entries: list[FileEntry] = []
    notes = {"hashed": 0, "too_big": 0, "unreadable": 0, "truncated": False, "shortcuts": 0}
    lnk_paths: dict[str, FileEntry] = {}

    def attributes(path: str) -> tuple[int, int]:
        try:
            st = os.stat(path)
            return getattr(st, "st_file_attributes", 0), st.st_size
        except OSError:
            notes["unreadable"] += 1
            return 0, 0

    for folder, dirs, files in os.walk(root, onerror=lambda e: notes.__setitem__("unreadable", notes["unreadable"] + 1)):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        for name, is_dir in [(d, True) for d in dirs] + [(f, False) for f in files]:
            if len(entries) >= max_entries:
                notes["truncated"] = True
                return entries, notes
            full = os.path.join(folder, name)
            attrs, size = attributes(full)
            entry = FileEntry(os.path.relpath(full, root), is_dir=is_dir, size=size, hidden=bool(attrs & (_HIDDEN | _SYSTEM)))
            if not is_dir:
                ext = entry.extension
                if ext in _HASHED:
                    if size > max_hash_mb << 20:
                        notes["too_big"] += 1
                    else:
                        entry.sha256 = _sha256(full)
                        notes["hashed"] += entry.sha256 is not None
                if ext == ".lnk":
                    lnk_paths[full] = entry
                elif entry.name.lower() == "autorun.inf" and folder == root:
                    entry.target = _autorun_target(full)
            entries.append(entry)
    for full, target in _shortcut_targets(list(lnk_paths)).items():
        lnk_paths[full].target = target
        notes["shortcuts"] += 1
    # an autorun.inf is judged by what it starts: are those programs signed?
    for entry in entries:
        if entry.name.lower() == "autorun.inf" and not entry.parent and entry.target:
            programs = _autorun_programs(entry.target, root)
            checked = _signatures_valid(programs)
            entry.target_signed = bool(programs) and all(checked.get(p) for p in programs)
            notes["signed_autorun" if entry.target_signed else "unsigned_autorun"] = len(programs)
    return entries, notes


# ---------------------------------------------------------------------------
# run this file: a made-up drive, or a real one with --scan
# ---------------------------------------------------------------------------


def _demo() -> None:
    from app.services import cvss

    clean = [
        FileEntry("Documents", is_dir=True),
        FileEntry("Documents/report.docx", size=20_000),
        FileEntry("Photos/holiday.jpg", size=3_000_000),
        FileEntry("setup.exe", size=900_000, sha256="aa" * 32),  # an ordinary installer
        FileEntry("Shortcut to Documents.lnk", target=r"C:\Windows\explorer.exe Documents"),
    ]
    infected = [
        FileEntry("autorun.inf", size=60, hidden=True, target="open=RECYCLER\\svchost.exe"),
        FileEntry("RECYCLER", is_dir=True, hidden=True),
        FileEntry("RECYCLER/svchost.exe", size=120_000, hidden=True, sha256="bb" * 32),
        FileEntry("Documents", is_dir=True, hidden=True),
        FileEntry("Documents.lnk", target=r"C:\Windows\System32\cmd.exe /c start RECYCLER\svchost.exe && start Documents"),
        FileEntry("invoice_2026.pdf.exe", size=450_000, sha256="cc" * 32),
        FileEntry("holiday.jpg", size=3_000_000),
    ]

    class Hit:  # what threat_intel.lookup_many returns for a known-bad hash
        source, category = "malwarebazaar", "Mirai"

    lookup = lambda hashes: {h: Hit() for h in hashes if h == "cc" * 32}
    for title, listing, bad in (("A clean drive", clean, lookup), ("An infected drive", infected, lookup)):
        print(f"\n{title}: {len(listing)} entries")
        found = scan_listing(listing, bad)
        if not found:
            print("  nothing found")
        for f in found:
            result = cvss.score_detection(f.kind, "confirmed" if f.confirmed else "reasonable")
            print(f"  CVSS {result.score:>4} {result.rating:8} {f.kind:19} {describe(f)}")


def _scan_real(root: str, show_list: bool, use_db: bool) -> None:
    from app.services import cvss

    print(f"Reading {root} (only reading: nothing is opened as a program, changed or sent anywhere)...")
    entries, notes = read_drive(root)
    files = [e for e in entries if not e.is_dir]
    print(f"{len(entries)} entries: {len(files)} files, {len(entries) - len(files)} folders; "
          f"{notes['hashed']} programs/scripts hashed, {notes['shortcuts']} shortcuts read, "
          f"{sum(e.hidden for e in entries)} hidden")  # fmt: skip
    for key, text in (("too_big", "too big to hash (over 200 MB)"), ("unreadable", "could not be read")):
        if notes[key]:
            print(f"  {notes[key]} {text}")
    if notes["truncated"]:
        print("  stopped at 20,000 entries")
    if show_list:
        print("\nEverything that was read:  (H = hidden, # = hashed)")
        for e in entries:
            mark = ("H" if e.hidden else " ") + ("#" if e.sha256 else " ")
            extra = f"  -> {e.target}" if e.target else ""
            if e.target_signed is not None:
                extra += "   [what it opens is signed]" if e.target_signed else "   [what it opens is NOT signed or was not found]"
            print(f"  {mark} {'[dir] ' if e.is_dir else ''}{e.path}{extra}")

    known_bad = None
    if use_db:
        try:
            from app.db.session import SessionLocal
            from app.services import threat_intel

            db = SessionLocal()
            known_bad = lambda hashes: threat_intel.lookup_many(db, "sha256", hashes)
            known_bad(["0" * 64])  # fails here, not in the middle of the scan, if the database cannot be reached
        except Exception as exc:
            known_bad = None
            print(f"\nThe threat-intelligence database could not be reached ({type(exc).__name__}): the hash lookup is skipped.")
            print("  (is the SSH tunnel open? use --no-db to skip it on purpose)")
    findings = scan_listing(entries, known_bad)
    print(f"\n{len(findings)} finding(s):" if findings else "\nNothing found.")
    for f in sorted(findings, key=lambda f: -cvss.score_detection(f.kind, "confirmed" if f.confirmed else "reasonable").score):
        result = cvss.score_detection(f.kind, "confirmed" if f.confirmed else "reasonable")
        print(f"  CVSS {result.score:>4} {result.rating:8} {f.kind:19} {describe(f)}")


if __name__ == "__main__":
    import argparse
    import os
    import sys
    from pathlib import Path

    _backend = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)
    parser = argparse.ArgumentParser(description="Check the files of a USB drive (or any folder) against the USB rules.")
    parser.add_argument("--scan", metavar="DRIVE_OR_FOLDER", help=r"read a real drive or folder, e.g. E:\ (without it, a made-up drive is shown)")
    parser.add_argument("--list", action="store_true", help="also print every file that was read")
    parser.add_argument("--no-db", action="store_true", help="skip the hash lookup in the threat-intelligence database")
    args = parser.parse_args()
    if args.scan:
        _scan_real(args.scan, args.list, not args.no_db)
    else:
        _demo()
