"""CVSS v3.1 scoring for AegisGuard detections.

Why CVSS: the severity of a detection must come from an established, published
scoring system rather than numbers we picked. CVSS v3.1 (FIRST, 2019) is that
system: https://www.first.org/cvss/v3.1/specification-document

CVSS was written for vulnerabilities, not for events seen on a computer. The way
it is applied here follows the IDS literature (for instance Duraz et al., "Using
CVSS scores can make more informed and more adapted Intrusion Detection Systems",
Journal of Universal Computer Science 30(9), 2024, doi:10.3897/jucs.131659): every
kind of detection ("a BadUSB keyboard", "a phishing URL"...) is given ONE fixed
CVSS vector, written down with its reason in CATALOG below, and the score comes
out of the standard formulas. Nothing else is invented:

    Base score           from the detection kind's vector (what the attack can do)
    Temporal  (RC)       Report Confidence: how sure we are it is real (model or
                         rule only = Reasonable, confirmed by threat intelligence
                         = Confirmed)
    Environmental (CR/IR/AR)   how much the computer's role matters

This module has no database and no web code: it only calculates. Run this file to
check the calculator against the examples of the CVSS specification:

    python -m app.services.cvss
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# ============================================================================
# the CVSS v3.1 calculator (FIRST specification, sections 7 and 8)
# ============================================================================

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Temporal
_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
# Environmental requirements
_REQ = {"X": 1.0, "M": 1.0, "L": 0.5, "H": 1.5}

BASE_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest number with one decimal that is >= value
    (written with integers so floating point error cannot change the result)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """'CVSS:3.1/AV:N/AC:L/...' -> {'AV': 'N', 'AC': 'L', ...}."""
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError("not a CVSS:3.1 vector: " + vector)
    metrics = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        metrics[key] = value
    missing = [k for k in BASE_KEYS if k not in metrics]
    if missing:
        raise ValueError("vector lacks base metrics " + ",".join(missing))
    return metrics


def _impact_sub_score(c: str, i: str, a: str) -> float:
    return 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])


def base_score(m: dict[str, str]) -> float:
    changed = m["S"] == "C"
    iss = _impact_sub_score(m["C"], m["I"], m["A"])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def temporal_score(m: dict[str, str]) -> float:
    base = base_score(m)
    return roundup(base * _E[m.get("E", "X")] * _RL[m.get("RL", "X")] * _RC[m.get("RC", "X")])


def environmental_score(m: dict[str, str]) -> float:
    """The score with the temporal and environmental metrics applied (the 'modified'
    base metrics default to the base ones, as the specification says)."""

    def modified(key: str) -> str:
        value = m.get("M" + key, "X")
        return m[key] if value == "X" else value

    ms = modified("S")
    changed = ms == "C"
    miss = min(
        1
        - (1 - _REQ[m.get("CR", "X")] * _CIA[modified("C")])
        * (1 - _REQ[m.get("IR", "X")] * _CIA[modified("I")])
        * (1 - _REQ[m.get("AR", "X")] * _CIA[modified("A")]),
        0.915,
    )
    impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13 if changed else 6.42 * miss
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[modified("PR")]
    exploitability = 8.22 * _AV[modified("AV")] * _AC[modified("AC")] * pr * _UI[modified("UI")]
    if impact <= 0:
        return 0.0
    factor = _E[m.get("E", "X")] * _RL[m.get("RL", "X")] * _RC[m.get("RC", "X")]
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return roundup(roundup(min(total, 10)) * factor)


def rating(score: float) -> str:
    """The qualitative severity rating of the specification (section 5)."""
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ============================================================================
# what each kind of detection is worth: one fixed vector, with its reason
# ============================================================================
#
# Each entry: the CVSS base vector, the MITRE ATT&CK technique the behaviour is
# an instance of (https://attack.mitre.org), and why each metric has its value.
# These are judgements about the KIND of event, made once and written down here
# so that they can be read, questioned and changed in one place; they are not
# tuned to make any result come out higher or lower.
#
#   AV  attack vector      P physical, L local, N network
#   AC  complexity         L low, H high
#   PR  privileges needed  N none, L low (an ordinary user), H high
#   UI  user interaction   N none, R required (the user has to do something)
#   S   scope              U stays inside the user's session, C reaches beyond it
#   C/I/A  confidentiality / integrity / availability impact  N none, L low, H high


@dataclass(frozen=True)
class Detection:
    key: str
    title: str
    vector: str  # base metrics only
    attack: str  # MITRE ATT&CK technique
    why: str


CATALOG: dict[str, Detection] = {
    d.key: d
    for d in [
        Detection(
            "new_program",
            "A program this computer has never run",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
            "T1204 User Execution",
            "Local, run by the user who clicked it (UI:R), ordinary privileges (PR:L). On its own an unfamiliar "
            "program says little about harm, so only a low confidentiality impact is assumed.",
        ),
        Detection(
            "admin_tool",
            "A command-line or administration tool this computer has never run",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
            "T1059 Command and Scripting Interpreter",
            "The user's own session (AV:L, PR:L) with nobody needing to click (UI:N). Shells and system tools can "
            "read and change data and stop services, but nothing says how far they were used: low impact each.",
        ),
        Detection(
            "high_risk_tool",
            "A tool commonly abused to download or run payloads (certutil, bitsadmin, mshta, wscript...)",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
            "T1218 System Binary Proxy Execution / T1105 Ingress Tool Transfer",
            "Signed system programs that attackers use to fetch and execute code while looking legitimate. Code "
            "can run with the user's rights: high impact on data and integrity, low on availability.",
        ),
        Detection(
            "encoded_command",
            "A command line holding a long encoded string",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "T1027 Obfuscated Files or Information / T1059.001 PowerShell",
            "Encoding a command hides what it does and is rare in honest use. It runs as the user (PR:L) with "
            "whatever the user can do, so all three impacts are high.",
        ),
        Detection(
            "usb_autorun",
            "An autorun.inf on a USB drive",
            "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
            "T1091 Replication Through Removable Media",
            "Delivered on a drive someone plugs in (AV:P), needs no account (PR:N). Since Windows 7 AutoPlay no longer "
            "supports AutoRun for non-optical removable media such as USB drives (Microsoft Security Response Center, "
            "'AutoRun changes in Windows 7', 28 April 2009), so the user has to open what it points to (UI:R); the "
            "file is a sign of a USB worm rather than the harm itself, so only low impact is assumed. Exception: a "
            "USB device that presents itself as a CD drive still gets AutoRun, which the scan agent also looks at.",
        ),
        Detection(
            "usb_disguised_file",
            "A file on a USB drive made to look harmless (double extension, hidden program, shortcut that starts one)",
            "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "T1036.007 Masquerading: Double File Extension / T1091 Replication Through Removable Media",
            "Delivered on a drive (AV:P), needs no account (PR:N), and only works when the user opens it (UI:R), "
            "which is what the disguise is for. Opened, it runs with the user's rights: high impact on all three. "
            "A file that is confirmed as malware by its hash is the 'malicious_file' kind instead.",
        ),
        Detection(
            "malicious_command",
            "A command that is a known attack technique (LOLBAS), or that the classifier judges malicious",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "T1059 Command and Scripting Interpreter",
            "Run in the user's own session (AV:L, PR:L) with nobody needing to click (UI:N). A command written to "
            "download, run, hide or steal does whatever the user's account can do: high impact on all three. "
            "The specific technique (ATT&CK id) comes from the matching LOLBAS entry and is shown with the score.",
        ),
        Detection(
            "password_guessing",
            "Repeated failed logons (password guessing)",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "T1110 Brute Force",
            "Needs no account and no one's help (PR:N, UI:N). Success gives the attacker the account: high "
            "confidentiality and integrity, no direct availability loss.",
        ),
        Detection(
            "badusb",
            "A USB device that is a keyboard, followed at once by commands typed into a shell",
            "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "T1200 Hardware Additions / T1091 Replication Through Removable Media",
            "Plugged in by hand (AV:P) with no account (PR:N) and nobody having to click (UI:N): the device types "
            "the attacker's commands as the logged-in user, so all three impacts are high.",
        ),
        Detection(
            "phishing_url",
            "A visit to a web address that looks like phishing",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            "T1566.002 Phishing: Spearphishing Link",
            "Reached over the network (AV:N), no account needed (PR:N), the user has to open it and may type "
            "something in (UI:R). Typed credentials are lost (C:H); some account misuse follows (I:L).",
        ),
        Detection(
            "malicious_file",
            "A downloaded program that looks like malware",
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "T1204.002 User Execution: Malicious File",
            "Runs locally once the user opens it (UI:R). Malware can take whatever the user's session can reach: "
            "high impact on all three.",
        ),
        Detection(
            "unusual_activity",
            "Something this computer's user does, at a time or in a burst that is not theirs",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "T1078 Valid Accounts",
            "The user's own account doing things it has done before, but at an unusual hour or in an unusual "
            "burst. It could be the owner or someone using the account; nothing says what was reached, so "
            "only low confidentiality and integrity impact is assumed.",
        ),
        Detection(
            "new_privileged_logon",
            "A first sign-in that is given special privileges",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            "T1078 Valid Accounts",
            "Windows adds this event at every sign-in of an administrator account; seen for the first time it only "
            "deserves a look.",
        ),
    ]
}

# A few plain words for each kind, for the one-line reason shown in the portal and on the
# lock screen ("what was it" rather than only "how bad").
SHORT = {
    "new_program": "program never run here",
    "admin_tool": "admin tool never run here",
    "high_risk_tool": "tool often abused to fetch or run payloads",
    "encoded_command": "encoded command line",
    "malicious_command": "malicious command",
    "usb_autorun": "autorun.inf on a USB drive",
    "usb_disguised_file": "disguised file on a USB drive",
    "password_guessing": "repeated failed logons",
    "badusb": "USB keyboard, then shell commands",
    "phishing_url": "phishing-like web address",
    "malicious_file": "malware-like download",
    "unusual_activity": "activity at an unusual time",
    "new_privileged_logon": "first privileged sign-in",
}

# Report Confidence (CVSS temporal metric): how sure we are the finding is real.
#   U  Unknown       the model or a rule is not convinced
#   R  Reasonable    a model or rule flags it, nothing independent confirms it
#   C  Confirmed     independently confirmed (the file hash or URL is on a threat-intelligence list)
CONFIDENCE = {"unknown": "U", "reasonable": "R", "confirmed": "C"}

# Environmental metrics (CR/IR/AR): how much the computer's role needs each of
# confidentiality, integrity, availability. M is the specification's default.
REQUIREMENTS_DEFAULT = {"CR": "M", "IR": "M", "AR": "M"}

# What the department of the computer's user changes (a judgement, written down here
# so it can be questioned; any department not listed uses the default above):
REQUIREMENTS_BY_DEPARTMENT: dict[str, dict[str, str]] = {
    "finance": {"CR": "H", "IR": "H"},  # payments, ledgers: secrecy and exact records
    "hr": {"CR": "H"},  # personal data of staff
    "legal": {"CR": "H"},  # privileged documents
    "management": {"CR": "H"},  # strategy, board papers
    "data": {"CR": "H"},  # bulk data sets
    "operations": {"AR": "H"},  # orders and logistics stop when it does
    "it": {"CR": "H", "IR": "H", "AR": "H"},  # holds the keys to other systems
}


def requirements_for(department: str | None) -> dict[str, str]:
    return {**REQUIREMENTS_DEFAULT, **REQUIREMENTS_BY_DEPARTMENT.get(department or "", {})}


# How a CVSS score becomes the portal's three labels. From `lock_from` (7.0, the start of
# the specification's High rating) it is Critical, and a Critical event locks the
# computer. Medium (4.0 and up) is a Warning. Below that it is only noted (Info).
MEDIUM_FROM = 4.0


def severity_for_score(score: float, lock_from: float) -> str:
    if score >= lock_from:
        return "Critical"
    if score >= MEDIUM_FROM:
        return "Warning"
    return "Info"


@dataclass(frozen=True)
class Result:
    detection: str
    vector: str  # full vector, with temporal and environmental metrics
    base: float
    score: float  # the environmental score, the one that is shown and acted on
    rating: str
    attack: str


def score_detection(
    key: str, confidence: str = "reasonable", requirements: dict[str, str] | None = None
) -> Result:
    """Score one detection of the CATALOG. `confidence` is 'unknown', 'reasonable' or
    'confirmed'; `requirements` is {'CR': 'M', 'IR': 'M', 'AR': 'M'} (L / M / H)."""
    detection = CATALOG[key]
    req = {**REQUIREMENTS_DEFAULT, **(requirements or {})}
    vector = detection.vector + f"/RC:{CONFIDENCE[confidence]}/CR:{req['CR']}/IR:{req['IR']}/AR:{req['AR']}"
    metrics = parse_vector(vector)
    final = environmental_score(metrics)
    return Result(key, vector, base_score(metrics), final, rating(final), detection.attack)


# ============================================================================
# self-test against the examples of the specification
# ============================================================================


def _self_test() -> None:
    # (vector, expected base score) from the CVSS v3.1 specification / FIRST calculator
    cases = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ]
    bad = 0
    for vector, expected in cases:
        got = base_score(parse_vector(vector))
        ok = abs(got - expected) < 1e-9
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {vector}  expected {expected}  got {got}")
    # Report Confidence can only lower a score: 9.8 x 0.96 = 9.408, which Roundup makes 9.5.
    top = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/RC:R")
    print("ok " if temporal_score(top) == 9.5 else "BAD", "temporal 9.8 with RC:R ->", temporal_score(top), "(expected 9.5)")
    bad += temporal_score(top) != 9.5
    print()
    print(f"{'detection':22} {'base':>5} {'score':>6}  rating    vector")
    for key in CATALOG:
        r = score_detection(key)
        print(f"{key:22} {r.base:>5} {r.score:>6}  {r.rating:9} {r.vector}")
    print("\nall calculator checks passed" if not bad else f"\n{bad} CHECK(S) FAILED")


if __name__ == "__main__":
    _self_test()
