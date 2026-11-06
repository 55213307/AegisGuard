"""The behavioral anomaly model, with everything it needs to run and nothing that touches the database.

Three parts, in order: the departments an employee can be in (what each means to the model), the features an
event is turned into, and the model itself (Isolation Forest plus the rules and command-line profiles around it).
"""

from __future__ import annotations

import math
import re
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

# ============================================================================
# departments: who works where, and what that means to the model
# ============================================================================
#
# The departments a company can put an employee in, and what each means to the
# behavior model.
#
# A department says two things about a computer's user, both only a starting point
# that their own activity takes over from:
#
#   - programs: what that kind of work normally runs. They seed the first baseline
#     (ml/baseline.py), so a new Finance computer starts out expecting accounting
#     software and a new Design computer expects Photoshop, instead of everyone
#     being measured against the same generic office day.
#   - how the command line is treated:
#       admin_ok  command prompts, admin tools and typed PowerShell are everyday work
#                 (developers, IT, security): learned as ordinary from day one.
#       adopt     flagged at first, but learned once it has become a habit (see
#                 registry.adopted_actions): for roles where a terminal comes and goes.
#       neither   always flagged: a clerk, accountant or designer has no reason to
#                 open one.
#
# "auto" is the default: nobody has to say anything, and the computer's own
# activity decides. Programs are lower-case process names. The weights are only
# relative to each other.

_OFFICE = {
    "explorer.exe": 3, "msedge.exe": 8, "outlook.exe": 4, "excel.exe": 5, "winword.exe": 5,
    "acrobat.exe": 3, "ms-teams.exe": 3, "notepad.exe": 2, "calc.exe": 1,
}  # fmt: skip

_SHELLS = {"cmd.exe": 4, "powershell.exe": 4, "windowsterminal.exe": 3}

_CLI_FLAGGED = "Command prompts and admin tools are flagged."
_CLI_NORMAL = "Command prompts and admin tools are treated as normal."
_CLI_LEARNED = "Command prompts are flagged at first, and learned if they become a habit."

DEPARTMENTS: dict[str, dict] = {
    "auto": {
        "label": "Auto (learn from activity)",
        "hint": "Nothing to set: AegisGuard starts strict and learns what is normal for this computer. " + _CLI_LEARNED,
        "admin_ok": False,
        "adopt": True,
        "programs": {},
    },
    "office": {
        "label": "Office / administration",
        "hint": "Reception, admin and general office work. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {},
    },
    "finance": {
        "label": "Finance & accounting",
        "hint": "Accounting and ERP software, spreadsheets. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {"excel.exe": 6, "saplogon.exe": 3, "qbw32.exe": 2, "calc.exe": 2, "acrobat.exe": 4, "msedge.exe": 4},
    },
    "hr": {
        "label": "Human resources",
        "hint": "Documents, spreadsheets, interviews on video calls. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {"winword.exe": 6, "excel.exe": 4, "outlook.exe": 5, "acrobat.exe": 4, "zoom.exe": 2, "ms-teams.exe": 4},
    },
    "sales": {
        "label": "Sales & marketing",
        "hint": "Presentations, CRM in the browser, social media and design tools. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {
            "powerpnt.exe": 6, "chrome.exe": 6, "outlook.exe": 5, "zoom.exe": 3, "slack.exe": 2, "whatsapp.exe": 2,
            "snippingtool.exe": 2, "mspaint.exe": 1,
        },
    },
    "support": {
        "label": "Customer support",
        "hint": "Ticketing in the browser, calls, remote-help tools. " + _CLI_LEARNED,
        "admin_ok": False,
        "adopt": True,
        "programs": {
            "chrome.exe": 8, "msedge.exe": 4, "zoom.exe": 3, "ms-teams.exe": 3, "slack.exe": 2, "anydesk.exe": 2,
            "teamviewer.exe": 1, "outlook.exe": 4,
        },
    },
    "operations": {
        "label": "Operations, logistics & procurement",
        "hint": "ERP, spreadsheets, label printing, supplier email. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {"excel.exe": 6, "saplogon.exe": 4, "chrome.exe": 4, "outlook.exe": 4, "bartender.exe": 1, "acrobat.exe": 3},
    },
    "legal": {
        "label": "Legal & compliance",
        "hint": "Document drafting and review. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {"winword.exe": 8, "acrobat.exe": 6, "outlook.exe": 4, "chrome.exe": 4, "excel.exe": 2},
    },
    "management": {
        "label": "Management & executives",
        "hint": "Email, presentations, video calls. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {"outlook.exe": 6, "powerpnt.exe": 5, "ms-teams.exe": 5, "excel.exe": 4, "zoom.exe": 3, "chrome.exe": 4},
    },
    "design": {
        "label": "Design & creative",
        "hint": "Photoshop, Illustrator, video editing. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {
            "photoshop.exe": 6, "illustrator.exe": 4, "indesign.exe": 2, "figma.exe": 3, "chrome.exe": 4,
            "adobe premiere pro.exe": 2, "afterfx.exe": 1, "creative cloud.exe": 2,
        },
    },
    "cad": {
        "label": "Engineering & CAD",
        "hint": "AutoCAD, SolidWorks, Revit and the spreadsheets around them. " + _CLI_FLAGGED,
        "admin_ok": False,
        "adopt": False,
        "programs": {"acad.exe": 6, "sldworks.exe": 4, "revit.exe": 3, "excel.exe": 4, "acrobat.exe": 3, "msedge.exe": 3},
    },
    "data": {
        "label": "Data & analytics",
        "hint": "Python, BI tools, databases. " + _CLI_LEARNED,
        "admin_ok": False,
        "adopt": True,
        "programs": {
            "python.exe": 5, "code.exe": 3, "excel.exe": 6, "pbidesktop.exe": 3, "rstudio.exe": 2, "tableau.exe": 2,
            "ssms.exe": 2, "dbeaver.exe": 2, "chrome.exe": 5,
        },
    },
    "software": {
        "label": "Software development",
        "hint": "Editors, compilers, git, containers. " + _CLI_NORMAL,
        "admin_ok": True,
        "adopt": False,
        "programs": {
            **_SHELLS, "code.exe": 8, "devenv.exe": 3, "git.exe": 3, "node.exe": 3, "python.exe": 3, "chrome.exe": 5,
            "postman.exe": 2, "docker desktop.exe": 1, "pycharm64.exe": 2, "idea64.exe": 2,
        },
    },
    "it": {
        "label": "IT & security",
        "hint": "Servers, remote sessions, management consoles, monitoring and investigation. " + _CLI_NORMAL,
        "admin_ok": True,
        "adopt": False,
        "programs": {
            **_SHELLS, "code.exe": 5, "chrome.exe": 4, "mstsc.exe": 3, "mmc.exe": 2, "regedit.exe": 1, "putty.exe": 2,
            "winscp.exe": 1, "ssh.exe": 2, "git.exe": 2, "python.exe": 2, "ipconfig.exe": 1, "ping.exe": 1,
            "wireshark.exe": 2, "netstat.exe": 1, "nslookup.exe": 1, "wevtutil.exe": 1,
        },
    },
}  # fmt: skip

DEFAULT_DEPARTMENT = "auto"
# Security is a part of IT in most companies, so it is not a department of its own.
# An account that was given it earlier keeps working as IT.
_ALIASES = {"security": "it"}


def normalize_department(department: str | None) -> str | None:
    """The department's own key (an old alias resolved), or None if there is no such department."""
    key = _ALIASES.get(department or "", department or DEFAULT_DEPARTMENT)
    return key if key in DEPARTMENTS else None


def department_info(department: str | None) -> dict:
    """The department's entry; an unknown or empty one is "auto"."""
    return DEPARTMENTS[normalize_department(department) or DEFAULT_DEPARTMENT]


def typical_programs(department: str | None) -> dict[str, int]:
    """What this kind of work normally runs, on top of an ordinary office day."""
    return {**_OFFICE, **department_info(department)["programs"]}


def department_catalog() -> list[dict]:
    """For the portal's pickers: key, label and what the choice means."""
    return [{"key": key, "label": d["label"], "hint": d["hint"]} for key, d in DEPARTMENTS.items()]


# ============================================================================
# features: turning an event into numbers
# ============================================================================
#
# Turn security events into numeric feature vectors for the behavioral
# anomaly model (Isolation Forest, per the IR).
#
# The model learns what an endpoint's user *normally does and when*, so only
# events that represent the user's own behavior are scored: logons, logoffs,
# and processes the user started. Processes the system starts on the user's
# behalf (creator is the machine account) say nothing about the user and are
# ignored.
#
# Each user action is described by:
#   - hour_sin / hour_cos: local time of day on a circle, so 23:00 and 00:00 sit
#     next to each other.
#   - hour_rarity: how unusual this hour of the day is for this endpoint, from
#     the share of the baseline's activity that falls in it (-log, as for
#     action_rarity). A user's activity profile by hour is the classic UEBA
#     signal; unlike the circle alone it makes an hour the baseline never has
#     stand out outright, whatever program is running.
#   - is_weekend
#   - action_rarity: how unusual the action itself is for this endpoint, from
#     its frequency in the baseline (-log of the relative frequency). The
#     action is the program for process events, the event type otherwise.
#   - rule_level_norm: Wazuh rule level 0-15 scaled to 0-1.
#   - is_auth_failure
#   - burst_5m / distinct_10m (context): how many actions this computer had in the
#     5 minutes before this one, and how many *different* ones in the 10 minutes
#     before. One event says little; a run of them is what a script, a dropper or
#     someone enumerating a machine looks like, however ordinary each step is.
#   - pair_rarity: how unusual it is for this program to be started by the program
#     that started it (powershell started by explorer is not powershell started by
#     a Word macro). Judged only once the model has seen enough parent/child pairs.
#
# The command line is judged separately (BehaviorModel._command_novelty), from these
# measures of it (command_stats, command_template): how long, how random-looking
# (entropy), how full of shell symbols, whether it holds a long encoded-looking string,
# and its shape (the program plus the names of the options it was given, values left out).
#
# Rows are plain dicts (see ml/dataset.py): event_time, rule_level, event_type,
# event_user, windows_event_id, process_name, creator.

# The endpoints' local time (Malaysia, no DST). Hour-of-day features use it.
LOCAL_TZ = timezone(timedelta(hours=8))

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "hour_rarity", "is_weekend", "action_rarity", "rule_level_norm", "is_auth_failure",
    "burst_5m", "distinct_10m", "pair_rarity",
]  # fmt: skip

# A random-looking run this long: an encoded or compressed blob, not words or a path.
_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")
_SHELL_SYMBOLS = frozenset("^`$@{}[]()+%;,|&!~*")
_ARGUMENT = re.compile(r'"[^"]*"|\S+')
MAX_COMMAND_LENGTH = 2000

BURST_WINDOW = timedelta(minutes=5)
VARIETY_WINDOW = timedelta(minutes=10)

# Two lists of programs a clerk's baseline never has, treated differently:
#
# MAINTENANCE_TOOLS are Windows servicing and .NET/installer helpers: in the
# real data they come from Windows Update and the AegisGuard installer, not
# from the person at the keyboard. They are noise, so they are not user
# actions at all: neither learned from nor scored.
MAINTENANCE_TOOLS = {
    "dismhost.exe", "dism.exe", "choice.exe", "timeout.exe", "cvtres.exe", "csc.exe", "ngentask.exe", "ngen.exe",
    "mscorsvw.exe", "wusa.exe", "sdbinst.exe", "compattelrunner.exe", "wermgr.exe", "werfault.exe",
    "conhost.exe", "openconsole.exe",
}  # fmt: skip

# ADMIN_TOOLS are what an intruder or a careless insider would run and a clerk
# normally doesn't. They are left out of the baseline when training, but still
# scored as user actions, so one appearing is flagged as never seen.
ADMIN_TOOLS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe", "net.exe", "net1.exe", "reg.exe",
    "regedit.exe", "sc.exe", "auditpol.exe", "wmic.exe", "mmc.exe", "whoami.exe", "msiexec.exe", "taskkill.exe",
    "schtasks.exe", "certutil.exe", "tasklist.exe", "findstr.exe", "find.exe", "ping.exe", "curl.exe",
    "icacls.exe", "takeown.exe", "attrib.exe", "setx.exe", "bitsadmin.exe",
    "ipconfig.exe", "systeminfo.exe", "nslookup.exe", "netstat.exe", "arp.exe", "route.exe", "nltest.exe",
    "hostname.exe", "quser.exe", "query.exe", "tracert.exe", "pathping.exe", "getmac.exe", "nbtstat.exe",
    "netsh.exe", "driverquery.exe", "wevtutil.exe", "vssadmin.exe", "bcdedit.exe", "cipher.exe", "gpresult.exe",
    "secedit.exe", "runas.exe", "mshta.exe", "wscript.exe", "cscript.exe",
}  # fmt: skip

# HIGH_RISK_TOOLS are the part of that list that is mostly used to attack or to
# tamper with the machine (downloading, hiding, wiping, impersonating). They stay
# suspicious whoever is at the keyboard; the rest of ADMIN_TOOLS is everyday
# work for IT and security staff (see DEPARTMENTS).
HIGH_RISK_TOOLS = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "wscript.exe", "cscript.exe", "vssadmin.exe", "bcdedit.exe",
    "runas.exe",
}  # fmt: skip

# Whether command-line and admin tooling is ordinary for an employee depends on their
# department (ml/departments.py): a developer or IT person lives in cmd and PowerShell, an
# accountant never opens them. Where it is expected, those tools are learned like any other
# program instead of being flagged on sight.


def admin_ok_for(department: str | None) -> bool:
    return department_info(department)["admin_ok"]


def adopts_habits(department: str | None) -> bool:
    return department_info(department)["adopt"]


# Whatever a command prompt starts was typed by a person, whatever the program.
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe", "wt.exe"}

_NOT_PEOPLE = {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
_USER_EVENT_TYPES = {"Login Success", "Login Failed", "Logoff", "Special Privileges"}


def is_person(name: str | None) -> bool:
    return bool(name) and not name.endswith("$") and name not in _NOT_PEOPLE and not name.startswith(("DWM-", "UMFD-"))


def is_user_action(row: dict) -> bool:
    """True for events that describe the user's behavior."""
    if row["windows_event_id"] == "4688":
        return is_person(row.get("creator")) and (row.get("process_name") or "") not in MAINTENANCE_TOOLS
    if row["windows_event_id"] == "4104":  # a command typed into PowerShell
        return is_person(row.get("creator"))
    return row["event_type"] in _USER_EVENT_TYPES


def is_admin_tool(row: dict, admin_ok: bool = False) -> bool:
    """A process creation of admin tooling: left out of the baseline when
    training, but still scored, so it stands out as never seen. With `admin_ok`
    (IT and security staff) everyday admin tooling and commands typed into a
    shell are ordinary, so only HIGH_RISK_TOOLS still count."""
    if row["windows_event_id"] == "4104":  # typing commands into PowerShell
        return not admin_ok
    if row["windows_event_id"] != "4688":
        return False
    name = row.get("process_name") or ""
    if name in HIGH_RISK_TOOLS:
        return True
    if admin_ok:
        return False
    return name in ADMIN_TOOLS or (row.get("parent_process") or "") in SHELLS


def action_key(row: dict) -> str:
    """What the user did: the program they ran, or the kind of event."""
    if row["windows_event_id"] == "4688":
        return "proc:" + (row.get("process_name") or "?").lower()
    return "type:" + (row["event_type"] or "?")


def local_hour(event_time: datetime) -> int:
    return event_time.astimezone(LOCAL_TZ).hour


def is_weekend(event_time: datetime) -> bool:
    return event_time.astimezone(LOCAL_TZ).weekday() >= 5


def command_stats(command_line: str | None) -> tuple[float, float, float, float]:
    """(log length, character entropy, share of shell symbols, has a long
    encoded-looking string) of a command line; zeros for none."""
    text = (command_line or "")[:MAX_COMMAND_LENGTH]
    if not text:
        return 0.0, 0.0, 0.0, 0.0
    counts = Counter(text)
    entropy = -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())
    symbols = sum(n for ch, n in counts.items() if ch in _SHELL_SYMBOLS) / len(text)
    return math.log1p(len(text)), entropy, symbols, 1.0 if _BLOB.search(text) else 0.0


def command_options(command_line: str | None) -> tuple[str, ...]:
    """The names of the options a command line was given (what starts with - or /),
    sorted, values dropped: its shape, whatever the files and numbers in it."""
    names = set()
    for token in _ARGUMENT.findall((command_line or "")[:MAX_COMMAND_LENGTH])[1:]:  # the first is the program
        if len(token) > 1 and token[0] in "-/" and not token.startswith("//"):
            names.add(re.split(r"[=:]", token.lower(), maxsplit=1)[0])
    return tuple(sorted(names))[:8]


def command_template(program: str, command_line: str | None) -> str | None:
    """program + the options it was run with; None when there is no command line."""
    if not command_line:
        return None
    return program.lower() + " " + (",".join(command_options(command_line)) or "(no options)")


def add_context(rows: list[dict]) -> None:
    """Sets row["burst_5m"] and row["distinct_10m"] on every user action in `rows`:
    how many user actions the computer had in the 5 minutes before it, and how many
    different ones in the 10 minutes before. Works on any list of rows of one
    computer, in any order; the rows are changed in place. A row with a
    "_source" (a repeated copy of another row, used to weight training data) takes
    its original's values and is not itself counted."""
    actions = sorted((r for r in rows if "_source" not in r and is_user_action(r)), key=lambda r: r["event_time"])
    recent: deque = deque()
    variety: deque = deque()
    in_window: Counter = Counter()
    for r in actions:
        t = r["event_time"]
        while recent and t - recent[0] > BURST_WINDOW:
            recent.popleft()
        while variety and t - variety[0][0] > VARIETY_WINDOW:
            key = variety.popleft()[1]
            in_window[key] -= 1
            if in_window[key] <= 0:
                del in_window[key]
        r["burst_5m"] = len(recent)
        r["distinct_10m"] = len(in_window)
        key = action_key(r)
        recent.append(t)
        variety.append((t, key))
        in_window[key] += 1
    for r in rows:
        source = r.get("_source")
        if source is not None:
            r["burst_5m"], r["distinct_10m"] = source.get("burst_5m", 0), source.get("distinct_10m", 0)


def event_features(
    event_time: datetime,
    hour_rarity: float,
    action_rarity: float,
    rule_level: int = 0,
    auth_failure: bool = False,
    burst: int = 0,
    distinct: int = 0,
    pair_rarity: float = 0.0,
) -> list[float]:
    local = event_time.astimezone(LOCAL_TZ)
    angle = 2 * math.pi * (local.hour + local.minute / 60.0) / 24.0
    return [
        math.sin(angle),
        math.cos(angle),
        hour_rarity,
        1.0 if local.weekday() >= 5 else 0.0,
        action_rarity,
        max(0.0, min(1.0, (rule_level or 0) / 15.0)),
        1.0 if auth_failure else 0.0,
        math.log1p(burst),
        math.log1p(distinct),
        pair_rarity,
    ]


# ============================================================================
# the model
# ============================================================================
#
# Per-endpoint behavioral anomaly model.
#
# Isolation Forest (scikit-learn, the model and framework the IR selected),
# fitted on one endpoint's baseline of normal behavior, plus two things that
# turn its raw score into something usable:
#
#   - Calibration against the baseline. The forest's raw score is mapped to a
#     0-1 "behaviour" score so that the median baseline event is ~5 and only the
#     most anomalous 0.5% of the baseline itself reaches the alert threshold
#     (70). That bounds the false-alarm rate on normal behaviour by construction.
#   - A novelty factor. An Isolation Forest never extrapolates: something it has
#     never seen (a program this user has never run) looks no stranger to it
#     than the rarest thing it has seen. So an action absent from the baseline
#     gets its own high novelty score, combined with the behaviour score by
#     noisy-OR:  risk = 1 - (1 - behaviour) * (1 - novelty).
#
# No feature scaling is applied, as Isolation Forest doesn't need it (IR 2.3.8).

# Risk at/above this counts as an anomaly worth surfacing.
ANOMALY_RISK_THRESHOLD = 70
# Share of the baseline allowed to reach the threshold.
BASELINE_TAIL = 0.5  # percent
# Risk of a baseline-median event / of the baseline tail, which fix the
# logistic curve in _behaviour().
_MEDIAN_RISK, _TAIL_RISK = 0.05, 0.70
# What never having seen an action before is worth. Admin tooling, or an event
# type that has never occurred, is a strong signal. An ordinary program the
# user simply hasn't opened yet is only worth a look: on its own it stays well
# below the alert threshold, and it takes an unusual time of day as well to
# reach one (a computer is locked on Critical events, so a new calculator
# must not be one).
_NOVELTY_UNSEEN = 0.9
_NOVELTY_UNSEEN_PROGRAM = 0.4
# Windows adds this event to every sign-in of an administrator account by itself
# ("special privileges assigned to new logon"), so a computer whose user is an
# administrator produces one at each logon. The first one ever seen is not a stranger
# at the door: it is worth no more than a new program, never a lock.
_ROUTINE_EVENT_TYPES = {"Special Privileges"}
# Scores from here up get a written reason.
EXPLAIN_RISK_FROM = 50
# Parent/child pairs are only judged once the model has seen this many of them;
# until then a pair says nothing (a young model would call every pair strange).
MIN_PAIR_EVIDENCE = 300
# The command line is only judged once this many baseline actions carry one (older events
# and the assumed first baseline have none), and a program only once it has this many of its own.
MIN_COMMAND_EVIDENCE = 500
MIN_PROGRAM_COMMANDS = 20
# How much a command line has to differ before it counts, in the units of command_stats:
# a path a little longer than any before is not strange, one twice as long is.
_COMMAND_MARGINS = (0.7, 0.6, 0.05)
_COMMAND_NUMERIC = ("a very long command line", "a random-looking command line", "an unusually symbol-heavy command line")
# The features that make up one reason when explaining a score (indexes into FEATURE_NAMES).
_FACTORS = {"time": [0, 1, 2], "weekend": [3], "action": [4], "burst": [7], "variety": [8], "pair": [9]}
# A factor is named in the reason when taking it away lowers the anomaly by at least this share.
_FACTOR_MIN_SHARE = 0.15


def _hour_ranges(hours: set[int]) -> str:
    """{22,23,0,1,2} -> "22:00-03:00", wrapping past midnight."""
    if not hours:
        return "never"
    if len(hours) == 24:
        return "around the clock"
    runs = []
    for h in sorted(hours):
        if (h - 1) % 24 not in hours:  # start of a run
            end = h
            while (end + 1) % 24 in hours:
                end = (end + 1) % 24
            runs.append(f"{h:02d}:00-{(end + 1) % 24:02d}:00")
    return ", ".join(runs)


def _surprise_to_novelty(probability: float) -> float:
    """How strange something with this (smoothed) tail probability under the history
    is, 0-1: nothing for the ordinary, growing as it gets rarer than 1 in 30 and full at
    1 in 200. With little history even "never seen" is only a mild surprise (after 20
    runs, none; after 300, clear): the confidence grows with the evidence."""
    return min(1.0, max(0.0, (-math.log10(probability) - 1.5) / 1.2))


@dataclass
class CommandProfile:
    """How one program has been run on this computer."""

    n: int
    templates: Counter
    options: frozenset  # every option name this program has ever been given here
    blobs: int
    maxima: tuple[float, float, float]  # largest log length, entropy, symbol share seen


@dataclass
class Score:
    risk: int  # 0-100
    behaviour: float  # 0-1, from the Isolation Forest (when / how often)
    novelty: float  # 0-1, never seen this action before
    is_anomaly: bool
    command: float = 0.0  # 0-1, how surprising the command line is for this program here


class BehaviorModel:
    def __init__(
        self,
        n_estimators: int = 200,
        max_samples: int = 2048,
        random_state: int = 42,
        admin_ok: bool = False,
        adopted: frozenset = frozenset(),
        use_context: bool = True,
        use_command: bool = True,
        min_command_evidence: int = MIN_COMMAND_EVIDENCE,
        min_program_commands: int = MIN_PROGRAM_COMMANDS,
        requirements: dict | None = None,
    ) -> None:
        # CVSS environmental requirements (CR/IR/AR) of this computer's department, used to
        # score what the model flags (see services/cvss.py); None = the specification's default.
        self.requirements = requirements
        # Whether the command line is looked at; off only to measure what it adds.
        self.use_command = use_command
        self.min_command_evidence = min_command_evidence
        self.min_program_commands = min_program_commands
        # Whether the recent-activity features (burst, variety) are used; off only to measure what they add.
        self.use_context = use_context
        # Whether admin tooling is ordinary for whoever this model is of (IT, security).
        self.admin_ok = admin_ok
        # Action keys of admin tools this computer has made a habit of (learned, not declared).
        self.adopted = adopted
        self._n_estimators = n_estimators
        self._max_samples = max_samples
        self._random_state = random_state
        self._forest: IsolationForest | None = None
        self._counts: Counter = Counter()
        self._hours: Counter = Counter()
        self._weekend = 0
        self._total = 0
        self._median = 0.0
        self._tail = 0.0
        self._pairs: Counter = Counter()
        self._pair_total = 0
        self._pair_neutral = 0.0
        self._feature_medians: np.ndarray | None = None
        self._burst_usual = 0
        self._variety_usual = 0
        self._profiles: dict[str, CommandProfile] = {}
        self._command_ready = False
        self.trained_on = 0

    @property
    def fitted(self) -> bool:
        return self._forest is not None

    def _rarity(self, key: str) -> float:
        # Laplace-smoothed so unseen actions get a finite, maximal rarity.
        return -math.log((self._counts.get(key, 0) + 1) / (self._total + len(self._counts) + 1))

    def _hour_rarity(self, hour: int) -> float:
        # Same smoothing over the 24 hours of the day.
        return -math.log((self._hours.get(hour, 0) + 1) / (self._total + 24 + 1))

    def _pair_rarity(self, row: dict) -> float:
        parent = row.get("parent_process") or ""
        if self._pair_total < MIN_PAIR_EVIDENCE or not parent or row["windows_event_id"] != "4688":
            return self._pair_neutral
        pair = (parent, (row.get("process_name") or "").lower())
        return -math.log((self._pairs.get(pair, 0) + 1) / (self._pair_total + len(self._pairs) + 1))

    def _vector(self, row: dict) -> list[float]:
        return event_features(
            row["event_time"],
            self._hour_rarity(local_hour(row["event_time"])),
            self._rarity(action_key(row)),
            row["rule_level"],
            row["event_type"] == "Login Failed",
            row.get("burst_5m", 0) if self.use_context else 0,
            row.get("distinct_10m", 0) if self.use_context else 0,
            self._pair_rarity(row),
        )

    def fit(self, rows) -> "BehaviorModel":
        """Fit on the baseline rows: user actions are picked out, the rest
        ignored, and admin/maintenance tooling is left out of what counts as
        this user's normal behaviour."""
        actions = [r for r in rows if is_user_action(r) and (not is_admin_tool(r, self.admin_ok) or action_key(r) in self.adopted)]
        if not actions:
            raise ValueError("no user actions in the baseline to learn from")
        add_context(actions)  # what each action followed, from the baseline's own timeline
        self._counts = Counter(action_key(r) for r in actions)
        self._hours = Counter(local_hour(r["event_time"]) for r in actions)
        self._weekend = sum(1 for r in actions if is_weekend(r["event_time"]))
        self._total = len(actions)
        self._pairs = Counter(
            (r["parent_process"], (r.get("process_name") or "").lower())
            for r in actions
            if r["windows_event_id"] == "4688" and r.get("parent_process")
        )
        self._pair_total = sum(self._pairs.values())
        self._pair_neutral = 0.0
        if self._pair_total >= MIN_PAIR_EVIDENCE:  # a pair we cannot judge counts as the typical one
            self._pair_neutral = float(np.median([self._pair_rarity(r) for r in actions if r.get("parent_process")]))
        self._fit_commands(actions)
        x = np.asarray([self._vector(r) for r in actions], dtype=float)
        if x.shape[1] != len(FEATURE_NAMES):
            raise ValueError("feature vector does not match FEATURE_NAMES")
        self._forest = IsolationForest(
            n_estimators=self._n_estimators,
            max_samples=min(self._max_samples, len(actions)),
            random_state=self._random_state,
        ).fit(x)
        self._feature_medians = np.median(x, axis=0)
        self._burst_usual = int(np.percentile([r.get("burst_5m", 0) for r in actions], 95))
        self._variety_usual = int(np.percentile([r.get("distinct_10m", 0) for r in actions], 95))
        base = self._forest.decision_function(x)
        self._median = float(np.median(base))
        self._tail = float(np.percentile(base, BASELINE_TAIL))
        self.trained_on = len(actions)
        return self

    def _fit_commands(self, actions: list[dict]) -> None:
        """Learn how each program is usually run here: the shapes of its command lines, how
        long and random-looking they get, whether they ever hold an encoded-looking string."""
        with_command = [r for r in actions if r.get("command_line")]
        self._command_ready = self.use_command and len(with_command) >= self.min_command_evidence
        self._profiles = {}
        if not self._command_ready:
            return
        by_program: dict[str, list[dict]] = {}
        for r in with_command:
            by_program.setdefault((r.get("process_name") or "").lower(), []).append(r)
        for program, group in by_program.items():
            if len(group) < self.min_program_commands:
                continue
            stats = np.asarray([command_stats(r["command_line"]) for r in group])
            self._profiles[program] = CommandProfile(
                n=len(group),
                templates=Counter(command_template(program, r["command_line"]) for r in group),
                options=frozenset(o for r in group for o in command_options(r["command_line"])),
                blobs=int(stats[:, 3].sum()),
                maxima=(float(stats[:, 0].max()), float(stats[:, 1].max()), float(stats[:, 2].max())),
            )

    def _command_novelty(self, row: dict) -> tuple[float, str | None]:
        """(0-1, what is strange) about how this program was run, judged against how it
        has been run on this computer: an option set it never had, a long encoded-looking
        string it never held, a command line far longer or more random than any before.
        Nothing for a program with too little history, or when there is no command line."""
        line = row.get("command_line")
        program = (row.get("process_name") or "").lower()
        profile = self._profiles.get(program)
        if not self._command_ready or not line or profile is None:
            return 0.0, None
        best, why = 0.0, None

        def consider(probability: float, reason: str, weight: float = 1.0) -> None:
            nonlocal best, why
            novelty = weight * _surprise_to_novelty(probability)
            if novelty > best:
                best, why = novelty, reason

        if profile.templates.get(command_template(program, line), 0) == 0:
            # A new set of options: an update can add one, so one alone only counts a little;
            # several at once, on a program that has always been run the same way, count fully.
            unseen = [o for o in command_options(line) if o not in profile.options]
            if unseen:
                weight = min(1.0, 0.4 + 0.2 * len(unseen))
                consider(
                    1.0 / (profile.n + len(profile.templates) + 1),
                    f"{program} run with options it never had here ({' '.join(unseen[:3])})",
                    weight,
                )
        length, entropy, symbols, blob = command_stats(line)
        if blob and profile.blobs / profile.n < 0.01:
            consider((profile.blobs + 1) / (profile.n + 2), f"{program} run with a long encoded-looking string")
        for value, largest, margin, reason in zip((length, entropy, symbols), profile.maxima, _COMMAND_MARGINS, _COMMAND_NUMERIC):
            if value > largest + margin:
                consider(1.0 / (profile.n + 1), f"{program} run with {reason}")
        return best, why

    def _behaviour(self, raw: float) -> float:
        # 0 at the baseline median, 1 at the baseline tail, beyond for stranger.
        span = (self._median - self._tail) or 1e-9
        d = (self._median - raw) / span
        # Logistic through (d=0 -> _MEDIAN_RISK) and (d=1 -> _TAIL_RISK).
        k = math.log(_TAIL_RISK / (1 - _TAIL_RISK)) - math.log(_MEDIAN_RISK / (1 - _MEDIAN_RISK))
        d0 = -math.log(_MEDIAN_RISK / (1 - _MEDIAN_RISK)) / k
        return 1.0 / (1.0 + math.exp(-k * (d - d0)))

    def score_many(self, rows) -> list[Score]:
        """Score events. Rows that aren't user actions get risk 0."""
        if not self.fitted:
            raise RuntimeError("BehaviorModel is not fitted")
        rows = list(rows)
        idx = [i for i, r in enumerate(rows) if is_user_action(r)]
        out = [Score(0, 0.0, 0.0, False) for _ in rows]
        if not idx:
            return out
        x = np.asarray([self._vector(rows[i]) for i in idx], dtype=float)
        raws = self._forest.decision_function(x)
        for i, raw in zip(idx, raws):
            behaviour = self._behaviour(float(raw))
            novelty = 0.0
            if self._counts.get(action_key(rows[i]), 0) == 0:
                ordinary_program = (
                    rows[i]["windows_event_id"] == "4688"
                    and (not is_admin_tool(rows[i], self.admin_ok) or action_key(rows[i]) in self.adopted)
                ) or rows[i]["event_type"] in _ROUTINE_EVENT_TYPES
                novelty = _NOVELTY_UNSEEN_PROGRAM if ordinary_program else _NOVELTY_UNSEEN
            command, _ = self._command_novelty(rows[i])
            risk = int(round(100 * (1 - (1 - behaviour) * (1 - novelty) * (1 - command))))
            out[i] = Score(risk, behaviour, novelty, risk >= ANOMALY_RISK_THRESHOLD, command)
        return out

    def typical_time(self, like: datetime) -> datetime:
        """A usual moment for this endpoint: the busiest hour of its baseline,
        on a weekday of the week `like` falls in. Scoring an event as if it
        happened then judges what was done without holding its time of day or
        weekday against it (approved overtime)."""
        hour = self._hours.most_common(1)[0][0] if self._hours else 12
        local = like.astimezone(LOCAL_TZ)
        wednesday = local - timedelta(days=local.weekday()) + timedelta(days=2)
        return wednesday.replace(hour=hour, minute=30, second=0, microsecond=0)

    def score_one(self, row: dict) -> Score:
        return self.score_many([row])[0]

    def _factors(self, row: dict) -> list[tuple[str, float]]:
        """What made this event unusual to the forest, strongest first: for each
        group of features, the share of the event's anomaly that disappears when
        the group is replaced by the baseline's typical values."""
        x = np.asarray([self._vector(row)], dtype=float)
        trials = np.repeat(x, len(_FACTORS) + 1, axis=0)
        for i, indexes in enumerate(_FACTORS.values(), start=1):
            trials[i, indexes] = self._feature_medians[indexes]
        raws = self._forest.decision_function(trials)
        span = (self._median - self._tail) or 1e-9
        shares = [(name, float(raws[i] - raws[0]) / span) for i, name in enumerate(_FACTORS, start=1)]
        return sorted(shares, key=lambda p: p[1], reverse=True)

    def _phrase(self, factor: str, row: dict) -> str:
        what = row.get("process_name") or row.get("event_type") or "this activity"
        if factor == "time":
            hour = local_hour(row["event_time"])
            usual = {h for h, n in self._hours.items() if n / self._total >= 0.02}
            return f"unusual hour ({hour:02d}:00), normally active {_hour_ranges(usual)}"
        if factor == "weekend":
            return "weekend, when this computer is almost never active"
        if factor == "action":
            return f"rarely seen: {what}"
        if factor == "burst":
            return f"{row.get('burst_5m', 0)} actions in the last 5 min (usually up to {self._burst_usual})"
        if factor == "variety":
            return f"{row.get('distinct_10m', 0)} different actions in the last 10 min (usually up to {self._variety_usual})"
        if factor == "command":
            line = row.get("command_line") or ""
            options = command_options(line)
            if command_stats(line)[3]:
                return f"{what} run with a long encoded-looking string"
            if self._templates.get(command_template(what, line) or "", 0) == 0 and options:
                return f"{what} run with options it never had here ({' '.join(options[:3])})"
            return f"{what} run with an unusual command line"
        return f"{what} started by {row.get('parent_process')} (rarely seen)"

    def explain(self, row: dict, score: Score) -> str | None:
        """Why an elevated score is elevated, in words an administrator can
        act on (the IR asks for interpretable results), saying which part is the
        behavior model's judgement and which is a rule: "Behavior model: ... |
        Rule: ...". None for ordinary events."""
        if score.risk < EXPLAIN_RISK_FROM:
            return None
        what = row.get("process_name") or (f"PowerShell: {row['command']}" if row.get("command") else None) or row.get("event_type") or "this activity"
        parts = []
        if score.behaviour >= 0.3:  # the forest itself finds it unusual
            named = [self._phrase(name, row) for name, share in self._factors(row)[:2] if share >= _FACTOR_MIN_SHARE]
            parts.append("Behavior model: " + ("; ".join(named) if named else f"rare activity: {what}"))
        if score.command >= 0.3:  # learned from this program's own history, not a list
            parts.append("Command line: " + (self._command_novelty(row)[1] or "unusual"))
        if score.novelty:
            admin = row["windows_event_id"] in ("4688", "4104") and is_admin_tool(row, self.admin_ok)
            parts.append(f"Rule: {'admin tool' if admin else 'activity'} never seen on this endpoint: {what}")
        if not parts:
            parts.append(f"Behavior model: rare activity: {what}")
        return " | ".join(parts)[:200]
