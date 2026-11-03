"""Where the model's data comes from: loaders for the database and for dataset files, the automatic first
baseline, and the synthetic baseline generator (seed_baseline).
"""

from __future__ import annotations

import csv
import gzip
import json
import math
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timedelta, timezone

from app.services.ml.model import (
    ADMIN_TOOLS,
    LOCAL_TZ,
    MAINTENANCE_TOOLS,
    admin_ok_for,
    is_admin_tool,
    is_user_action,
    typical_programs,
)

# ============================================================================
# dataset: rows for the model, from the database or a file
# ============================================================================
#
# Load a training dataset as plain dicts, from either source:
#
#   - a CSV file exported by seed_baseline.py (the synthetic first baseline), or
#   - the security_events table (the endpoint's real events, once it has some).
#
# Both have the security_events format, so the model code doesn't care which
# one it is given. Switching from the synthetic baseline to real data is just a
# different source.

SEED_PREFIX = "seed-"
# Where AegisGuard keeps its scripts on an endpoint (lower case, for matching command lines).
OWN_PATH = r"\aegisguard" + "\\"

# Event types that are the user's own behavior (besides 4688 process creation).
_USER_EVENT_TYPES = ("Login Success", "Login Failed", "Logoff", "Special Privileges")


# Script block text that PowerShell logs by itself, not because a person typed it.
_PROMPT_BLOCKS = {"prompt", "$global:?", "$?", "exit", "cls", "clear", "clear-host"}


def powershell_command(details: dict | None) -> str | None:
    """The command a person typed into PowerShell (event 4104, a script block),
    or None when the block isn't that: run by the system or a service account,
    read from a script file (AegisGuard's own agent among them), or PowerShell's
    own bookkeeping such as the prompt."""
    win = (((details or {}).get("data") or {}).get("win")) or {}
    eventdata = win.get("eventdata") or {}
    sid = ((win.get("system") or {}).get("security") or {}).get("userID") or ""
    text = (eventdata.get("scriptBlockText") or "").strip()
    if not sid.startswith("S-1-5-21-") or eventdata.get("path") or not text:  # not a person, or from a file
        return None
    if str(eventdata.get("messageNumber") or "1") != "1":  # the rest of a long block
        return None
    lowered = text.lower()
    if lowered in _PROMPT_BLOCKS or lowered.startswith("$global:") or "psconsolehostreadline" in lowered:
        return None
    if "x-aegisguard-token" in lowered:  # a piece of the agent's own code (typing "AegisGuard" itself still counts)
        return None
    return " ".join(text.split())[:120]


def creator_of(details: dict | None) -> str | None:
    """Account that started a process (4688); the machine account when the
    system launched it on someone's behalf. For a PowerShell script block (4104)
    "user" when a person typed it, else SYSTEM."""
    eventdata = (((details or {}).get("data") or {}).get("win") or {}).get("eventdata") or {}
    if "scriptBlockText" in eventdata:
        return "user" if powershell_command(details) else "SYSTEM"
    # AegisGuard's own scripts (the screen agent starts PowerShell at every sign-in)
    # are the software at work, not the person: they must not look like admin tooling.
    if OWN_PATH in (eventdata.get("commandLine") or "").lower():
        return "SYSTEM"
    return eventdata.get("subjectUserName")


def model_row(
    event_time, rule_level, event_type, event_user, windows_event_id, process_name, creator, alert_id, parent_process=None,
    command=None, command_line=None,
) -> dict:
    return {
        "event_time": event_time,
        "rule_level": int(rule_level or 0),
        "event_type": event_type or None,
        "event_user": event_user or None,
        "windows_event_id": windows_event_id or None,
        "process_name": (process_name or "").lower(),
        "creator": creator if windows_event_id in ("4688", "4104") else None,
        # What was typed into PowerShell (4104), to say so in the reason.
        "command": command,
        # The full command line of a process (4688), or the typed script (4104), for the
        # command-line features; empty when the event has none (older events, baselines).
        "command_line": (command_line or "")[:2000] if windows_event_id in ("4688", "4104") else "",
        # What started it: a program started from a command prompt was typed by a person.
        "parent_process": (parent_process or "").rsplit("\\", 1)[-1].lower() if windows_event_id == "4688" else "",
        "is_seed": str(alert_id).startswith(SEED_PREFIX),
    }


def row_from_event(event: dict) -> dict:
    """A model row from a parsed alert (alerts.parse_alert's output, or a
    security_events row as a dict)."""
    eventdata = ((((event.get("details") or {}).get("data") or {}).get("win")) or {}).get("eventdata") or {}
    return model_row(
        event["event_time"],
        event["rule_level"],
        event["event_type"],
        event["event_user"],
        event["windows_event_id"],
        (eventdata.get("newProcessName") or "").rsplit("\\", 1)[-1],
        creator_of(event.get("details")),
        event.get("wazuh_alert_id") or "",
        eventdata.get("parentProcessName"),
        powershell_command(event.get("details")) if event["windows_event_id"] == "4104" else None,
        eventdata.get("commandLine") or eventdata.get("scriptBlockText"),
    )


# The CSV's details column is JSON text; pulling the one field we need with a
# regex is far faster than parsing every row's JSON.
_SUBJECT_RE = re.compile(r'"subjectUserName": "([^"]*)"')
_PARENT_RE = re.compile(r'"parentProcessName": "([^"]*)"')
_COMMAND_RE = re.compile(r'"commandLine": "((?:[^"\\]|\\.)*)"')


def progress(iterable, **kwargs):
    """tqdm progress bar when it's installed, the plain iterable otherwise."""
    try:
        from tqdm import tqdm
    except ImportError:
        return iterable
    return tqdm(iterable, **kwargs)


def load_csv(
    path: str, show_progress: bool = False, endpoint_id: int | None = None, user_actions_only: bool = False
) -> list[dict]:
    """Rows of a dataset file. `endpoint_id` keeps only that endpoint's rows;
    `user_actions_only` keeps only logons/logoffs/process creations, which is
    all the model learns from (so a huge file costs little memory)."""
    csv.field_size_limit(sys.maxsize)  # the details JSON column is large
    opener = gzip.open if path.endswith(".gz") else open
    rows = []
    with opener(path, "rt", newline="", encoding="utf-8") as handle:
        records = csv.DictReader(handle)
        if show_progress:
            records = progress(records, desc="Loading dataset", unit=" rows", unit_scale=True)
        for rec in records:
            if endpoint_id is not None and int(rec["endpoint_id"]) != endpoint_id:
                continue
            win_id = rec["windows_event_id"]
            if user_actions_only and win_id != "4688" and rec["event_type"] not in _USER_EVENT_TYPES:
                continue
            match = _SUBJECT_RE.search(rec["details"]) if win_id == "4688" else None
            parent = _PARENT_RE.search(rec["details"]) if win_id == "4688" else None
            command_line = _COMMAND_RE.search(rec["details"]) if win_id == "4688" else None
            rows.append(
                model_row(
                    datetime.fromisoformat(rec["event_time"]),
                    rec["rule_level"],
                    rec["event_type"],
                    rec["event_user"],
                    win_id,
                    rec["process_name"],
                    match.group(1) if match else None,
                    rec["wazuh_alert_id"],
                    parent.group(1).replace("\\\\", "\\") if parent else None,
                    command_line=json.loads('"' + command_line.group(1) + '"') if command_line and command_line.group(1) else None,
                )
            )
    return rows


def load_db(
    db,
    endpoint_id: int,
    include_seed: bool = True,
    since: datetime | None = None,
    user_actions_only: bool = False,
) -> list[dict]:
    """An endpoint's events from security_events. Only the columns the model
    needs are read (the two JSON fields are extracted by the database), so
    this stays fast on a large table. `user_actions_only` leaves out events
    that are not logons/logoffs/process creations, which the model ignores."""
    from sqlalchemy import func, or_

    from app.models.security_event import SecurityEvent as SE

    eventdata = SE.details["data"]["win"]["eventdata"]
    query = db.query(
        SE.event_time,
        SE.rule_level,
        SE.event_type,
        SE.event_user,
        SE.windows_event_id,
        SE.wazuh_alert_id,
        eventdata["newProcessName"].astext,
        eventdata["subjectUserName"].astext,
        eventdata["parentProcessName"].astext,
        func.coalesce(eventdata["commandLine"].astext, eventdata["scriptBlockText"].astext),
    ).filter(SE.endpoint_id == endpoint_id)
    if not include_seed:
        query = query.filter(~SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
    if since is not None:
        query = query.filter(SE.event_time >= since)
    if user_actions_only:
        query = query.filter(or_(SE.windows_event_id.in_(("4688", "4104")), SE.event_type.in_(_USER_EVENT_TYPES)))

    rows = []
    for t, level, etype, user, win_id, alert_id, process_path, creator, parent, command_line in query.order_by(SE.event_time).yield_per(5000):
        process = (process_path or "").rsplit("\\", 1)[-1]
        if win_id == "4104":  # only commands a person typed are stored (see ingest._store)
            creator = "user"
        rows.append(model_row(t, level, etype, user, win_id, process, creator, alert_id, parent, command_line=command_line))
    return rows


# ============================================================================
# baseline: the automatic first baseline
# ============================================================================
#
# Automatic first baseline for an endpoint that has no dataset file.
#
# A computer that was just enrolled has no history to learn from, so its first
# model is trained on a year of the persona's working pattern (see seed_baseline
# for the shifts), built here in memory from what the endpoint has actually done
# so far:
#
#   - the user's name and the programs they have run come from the endpoint's own
#     real events; a short list of typical office programs is mixed in while that
#     history is thin, so ordinary software the user simply hasn't opened yet
#     isn't mistaken for something never seen;
#   - how busy a signed-in hour is also comes from the real events (a default
#     until there are enough).
#
# This is the same kind of baseline as the dataset files made by
# seed_baseline.py --out, without the extra steps: the trainer builds it by
# itself the first time it sees the endpoint, and real data replaces it as it
# accumulates (see registry.py). Rows are model rows (ml/dataset.py).

# With this many distinct programs of its own, an endpoint is trusted on its own history.
ENOUGH_PROGRAMS = 8
DEFAULT_PER_HOUR = 30.0
# For IT and software people: commands typed into PowerShell, as a share of the programs they start.
TYPED_COMMAND_SHARE = 0.15
# A program often starts several processes at once (a browser opening is a dozen), so
# activity comes in clusters, not evenly: the model has to know that to tell a burst
# that is normal from one that is not.
CLUSTER_CHANCE = 0.25
CLUSTER_EXTRA_MEAN = 4  # processes added to a cluster, on average (1 + Poisson(3))
SEED_ALERT_ID = SEED_PREFIX + "auto"


def _profile(
    real_rows: list[dict], department: str | None = None, peers: Counter | None = None
) -> tuple[str, dict[str, float], float]:
    """(user name, program weights, user process events per signed-in hour).
    The programs come from three places: this computer's own history, what its
    department's other computers run (`peers`: program -> count, from colleagues
    in the same company), and what that kind of work normally runs."""
    admin_ok = admin_ok_for(department)
    users: Counter = Counter()
    programs: Counter = Counter()
    hours: Counter = Counter()
    for r in real_rows:
        if r["windows_event_id"] != "4688" or not is_user_action(r):
            continue
        if is_admin_tool(r, admin_ok) or r["process_name"] in MAINTENANCE_TOOLS:
            continue
        users[r["creator"]] += 1
        programs[r["process_name"]] += 1
        hours[r["event_time"].astimezone(LOCAL_TZ).replace(minute=0, second=0, microsecond=0)] += 1

    user = users.most_common(1)[0][0] if users else "user"
    weights: dict[str, float] = {}
    peers = peers or Counter()
    # How much each source counts. Colleagues' real activity is worth more than a generic
    # list, and the computer's own history more than either; a source that has nothing
    # to say gives its share to the others.
    parts = []
    if programs:
        parts.append((programs, 6.0))
    if peers:
        parts.append((peers, 3.0 if programs else 6.0))
    if len(programs) < ENOUGH_PROGRAMS:
        parts.append((Counter(typical_programs(department)), 1.0))
    share_total = sum(share for _, share in parts)
    for source, share in parts:
        source_total = sum(source.values())
        for name, n in source.items():
            weights[name] = weights.get(name, 0.0) + (share / share_total) * n / source_total
    counts = sorted(hours.values())
    per_hour = float(counts[len(counts) // 2]) if len(counts) >= 5 else DEFAULT_PER_HOUR
    return user, weights, min(max(per_hour, 10.0), 80.0)


def build_baseline(
    real_rows: list[dict],
    shift: Shift,
    days: int = 365,
    seed: int = 2026,
    now: datetime | None = None,
    department: str | None = None,
    peers: Counter | None = None,
) -> list[dict]:
    """A year of the shift's working pattern as model rows."""
    rng = random.Random(seed)
    now = now or datetime.now(LOCAL_TZ)
    admin_ok = admin_ok_for(department)
    # An administrator account gets this event at every sign-in: expect it once real events show it.
    privileged = any(r["event_type"] == "Special Privileges" for r in real_rows)
    user, weights, per_hour = _profile(real_rows, department, peers)
    names, probabilities = list(weights), list(weights.values())
    rows: list[dict] = []

    def add(when: datetime, event_type: str, win_id: str, process: str = "") -> None:
        rows.append(model_row(when, 3, event_type, user, win_id, process, user if win_id in ("4688", "4104") else None, SEED_ALERT_ID))

    for day in _shift_nights(days, rng, now.date()):
        signin = _at(day, shift.signin, 8, rng, shift.overnight)
        pause = _at(day, shift.break_at, 6, rng, shift.overnight)
        resume = pause + timedelta(minutes=rng.uniform(*shift.break_minutes))
        signout = _at(day, shift.signout, 6, rng, shift.overnight)

        add(signin, "Login Success", "4624")
        add(resume, "Login Success", "4624")  # unlocking after the break
        if privileged:
            add(signin + timedelta(milliseconds=rng.randint(1, 20)), "Special Privileges", "4672")
            add(resume + timedelta(milliseconds=rng.randint(1, 20)), "Special Privileges", "4672")
        add(resume + timedelta(milliseconds=rng.randint(2, 30)), "Logoff", "4634")
        add(signout, "Logoff", "4634")
        busy = rng.lognormvariate(0, 0.25)  # busier and quieter days
        for begin, end in ((signin, pause), (resume, signout)):
            hours = (end - begin).total_seconds() / 3600
            primaries = per_hour * busy * hours / (1 + CLUSTER_CHANCE * CLUSTER_EXTRA_MEAN)  # same volume, clustered
            for _ in range(_poisson(rng, primaries)):
                when = begin + (end - begin) * rng.random()
                program = rng.choices(names, probabilities)[0]
                add(when, "Process", "4688", program)
                if rng.random() < CLUSTER_CHANCE:
                    for _ in range(1 + _poisson(rng, CLUSTER_EXTRA_MEAN - 1)):
                        add(when + timedelta(seconds=rng.uniform(0.2, 6)), "Process", "4688", program)
            if admin_ok:  # commands typed into PowerShell are part of their day
                for _ in range(_poisson(rng, per_hour * busy * hours * TYPED_COMMAND_SHARE)):
                    add(begin + (end - begin) * rng.random(), "PowerShell Command", "4104")
    return [r for r in rows if r["event_time"] < now]


# ============================================================================
# seed_baseline: a synthetic year, made from an endpoint's own real events
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

@dataclass(frozen=True)
class Shift:
    """When the persona works: sign-in, the mid-shift break (when the screen is
    locked for a while, so no activity) and sign-out, as local clock times."""

    name: str
    signin: str
    break_at: str
    break_minutes: tuple[float, float]  # shortest and longest break
    signout: str
    overnight: bool  # runs past midnight, so early-morning times are the next day


def shift_from_hours(start: str, end: str) -> Shift:
    """The shift a company declared as "HH:MM" start and end times. An end
    before the start means it runs past midnight. The break falls in the middle
    of the day, and is shorter for a short day."""
    (sh, sm), (eh, em) = (map(int, start.split(":")), map(int, end.split(":")))
    first, last = sh * 60 + sm, eh * 60 + em
    length = (last - first) % (24 * 60)
    middle = (first + length // 2) % (24 * 60)
    return Shift(
        "declared",
        signin=start,
        break_at=f"{middle // 60:02d}:{middle % 60:02d}",
        break_minutes=(30, 60) if length >= 360 else (10, 20),
        signout=end,
        overnight=last <= first,
    )


NIGHT = Shift("night", signin="22:00", break_at="01:40", break_minutes=(20, 35), signout="06:00", overnight=True)
DAY = Shift("day", signin="09:00", break_at="12:30", break_minutes=(45, 70), signout="18:00", overnight=False)
SHIFTS = {s.name: s for s in (NIGHT, DAY)}


class NotEnoughEvents(ValueError):
    """The endpoint's real events can't supply templates for a synthetic baseline."""

_SYSTEM_ACCOUNTS = {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

# Programs the clerk's sessions never contain (see features.py).
_ADMIN_TOOLS = ADMIN_TOOLS | MAINTENANCE_TOOLS

# Commands Wazuh's configuration scan runs as SYSTEM to read settings.
_SCAN_TOOLS = _ADMIN_TOOLS | {"secedit.exe", "wevtutil.exe", "gpresult.exe", "bcdedit.exe", "manage-bde.exe"}
SCAN_INTERVAL = timedelta(hours=12)  # Wazuh SCA default

# Columns copied from the real row; time and ids are set per copy.
_COLUMNS = ("rule_id", "rule_level", "rule_description", "severity", "event_type", "event_user", "windows_event_id", "details")


def _is_person(name: str | None) -> bool:
    return bool(name) and not name.endswith("$") and name not in _SYSTEM_ACCOUNTS and not name.startswith(("DWM-", "UMFD-"))


def _process_name(details: dict) -> str:
    eventdata = (((details.get("data") or {}).get("win")) or {}).get("eventdata") or {}
    return (eventdata.get("newProcessName") or "").rsplit("\\", 1)[-1].lower()


def _parent_process(details: dict) -> str:
    eventdata = (((details.get("data") or {}).get("win")) or {}).get("eventdata") or {}
    return (eventdata.get("parentProcessName") or "").lower()


def _is_scan_process(row: dict) -> bool:
    """A check command run by the Wazuh agent's configuration scan."""
    if row["windows_event_id"] != "4688":
        return False
    parent = _parent_process(row["details"])
    return "ossec-agent" in parent or "wazuh" in parent or _process_name(row["details"]) in _SCAN_TOOLS


def _hour_bucket(t: datetime) -> datetime:
    return t.astimezone(LOCAL_TZ).replace(minute=0, second=0, microsecond=0)


def _median_per_hour(rows: list[dict], hours: set[datetime]) -> float:
    """Median events per hour over `hours` (an hour with none counts as 0)."""
    counts = Counter(_hour_bucket(r["event_time"]) for r in rows)
    values = sorted(counts.get(h, 0) for h in hours)
    mid = len(values) // 2
    return float(values[mid]) if len(values) % 2 else (values[mid - 1] + values[mid]) / 2


# --- what the real machine does ---------------------------------------------


@dataclass
class Templates:
    machine: list[dict]  # events with no person behind them
    session: list[dict]  # processes in the user's session
    logons: list[dict]
    logoffs: list[dict]
    scan_checks: list[dict]  # one per configuration check (the first scan reports all)
    scan_summaries: list[dict]
    scan_changes: list[dict]  # a check's status changed since the last scan
    scan_processes: list[dict]  # commands the scan runs
    machine_per_hour: float  # median, while the real machine was on
    session_per_hour: float  # median, while the user was signed in
    changes_per_scan: float
    processes_per_scan: float
    real_rows: int
    real_hours: int
    left_out: Counter  # real session events the clerk wouldn't produce


def classify(rows: list[dict]) -> Templates:
    """Sort an endpoint's real rows into templates and measure their rates.
    Each row is a dict with event_time plus the _COLUMNS."""
    machine, session, logons, logoffs = [], [], [], []
    checks: dict[str, dict] = {}
    summaries, changes, scan_processes = [], [], []
    left_out: Counter = Counter()
    for row in rows:
        if row["event_type"] == "Security Configuration":
            description = row["rule_description"] or ""
            if description.startswith("SCA summary"):
                summaries.append(row)
            elif "Status changed" in description:
                changes.append(row)
            else:
                checks.setdefault(description, row)
        elif not _is_person(row["event_user"]):
            (scan_processes if _is_scan_process(row) else machine).append(row)
        elif row["event_type"] == "Login Success":
            logons.append(row)
        elif row["event_type"] == "Logoff":
            logoffs.append(row)
        elif row["event_type"] == "Process" and _process_name(row["details"]) not in _ADMIN_TOOLS:
            session.append(row)
        else:
            left_out[_process_name(row["details"]) or row["event_type"]] += 1
    if not (machine and session and logons and logoffs):
        raise NotEnoughEvents(
            "Not enough real events to learn from: need machine events, session processes, "
            f"logons and logoffs (have {len(machine)}, {len(session)}, {len(logons)}, {len(logoffs)})."
        )
    hours_on = {_hour_bucket(r["event_time"]) for r in rows}
    session_hours = {_hour_bucket(r["event_time"]) for r in session + logons + logoffs}
    scans = max(1, len(summaries))
    return Templates(
        machine=machine,
        session=session,
        logons=logons,
        logoffs=logoffs,
        scan_checks=list(checks.values()),
        scan_summaries=summaries,
        scan_changes=changes,
        scan_processes=scan_processes,
        machine_per_hour=_median_per_hour(machine, hours_on),
        session_per_hour=_median_per_hour(session, session_hours),
        changes_per_scan=len(changes) / scans,
        processes_per_scan=len(scan_processes) / scans,
        real_rows=len(rows),
        real_hours=len(hours_on),
        left_out=left_out,
    )


def load_templates(db, endpoint_id: int) -> Templates:
    from app.models.security_event import SecurityEvent as SE

    events = (
        db.query(SE)
        .filter(SE.endpoint_id == endpoint_id, ~SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
        .order_by(SE.event_time)
        .all()
    )
    return classify([{"event_time": e.event_time, **{c: getattr(e, c) for c in _COLUMNS}} for e in events])


# --- the working calendar -----------------------------------------------------


def _shift_nights(days: int, rng: random.Random, today: date) -> list[date]:
    """Dates a shift starts on, over the last `days` days."""
    nights = [today - timedelta(days=d) for d in range(days, 0, -1)]
    workdays = [n for n in nights if n.weekday() < 5]
    off: set[date] = set()
    for block in (5, 5, 3):  # annual leave
        start = rng.randrange(0, len(workdays) - block)
        off.update(workdays[start : start + block])
    off.update(rng.sample(workdays, 8))  # sick days, public holidays
    shifts = [n for n in workdays if n not in off]
    shifts += [n for n in nights if n.weekday() >= 5 and rng.random() < 0.04]  # weekend overtime
    return sorted(shifts)


def _at(night: date, hhmm: str, jitter_minutes: float, rng: random.Random, overnight: bool = True) -> datetime:
    """A time on the shift that starts on `night`. On an overnight shift the
    hours before noon fall on the next morning."""
    hour, minute = map(int, hhmm.split(":"))
    day = night if (hour >= 12 or not overnight) else night + timedelta(days=1)
    base = datetime.combine(day, time(hour, minute), tzinfo=LOCAL_TZ)
    return base + timedelta(minutes=rng.gauss(0, jitter_minutes), milliseconds=rng.randint(0, 999))


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:  # normal approximation; Knuth's method underflows for large lambda
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= limit:
            return k - 1


# --- the year -----------------------------------------------------------------


def schedule(
    t: Templates,
    days: int = 365,
    seed: int = 2026,
    now: datetime | None = None,
    scale: float = 1.0,
    shift: Shift = NIGHT,
) -> list[tuple[datetime, dict]]:
    """(time, template) for every event of the year, oldest first. Only times
    before `now`. `scale` multiplies the hourly rates for a bigger dataset.
    Lightweight: rows are only built when written."""
    if scale != 1.0:
        t = replace(t, machine_per_hour=t.machine_per_hour * scale, session_per_hour=t.session_per_hour * scale)
    rng = random.Random(seed)
    now = now or datetime.now(LOCAL_TZ)
    start = datetime.combine(now.date() - timedelta(days=days), time(0), tzinfo=LOCAL_TZ)
    plan: list[tuple[datetime, dict]] = []

    # Machine events, around the clock.
    hour = start
    while hour < now:
        for _ in range(_poisson(rng, t.machine_per_hour)):
            plan.append((hour + timedelta(seconds=rng.uniform(0, 3600)), rng.choice(t.machine)))
        hour += timedelta(hours=1)

    # Configuration scans every 12 hours.
    if t.scan_summaries:
        scan_at = start + timedelta(minutes=rng.uniform(0, 60))
        first = True
        while scan_at < now:
            reports = list(t.scan_checks) if first else []
            if t.scan_changes:
                reports += [rng.choice(t.scan_changes) for _ in range(_poisson(rng, t.changes_per_scan))]
            reports.append(rng.choice(t.scan_summaries))
            for i, tpl in enumerate(reports):
                plan.append((scan_at + timedelta(seconds=30 + i * rng.uniform(0.05, 0.4)), tpl))
            for _ in range(_poisson(rng, t.processes_per_scan) if t.scan_processes else 0):
                plan.append((scan_at + timedelta(seconds=rng.uniform(0, 120)), rng.choice(t.scan_processes)))
            first = False
            scan_at += SCAN_INTERVAL + timedelta(minutes=rng.gauss(0, 3))

    # The user's night shifts.
    for night in _shift_nights(days, rng, now.date()):
        signin = _at(night, shift.signin, 8, rng, shift.overnight)
        lock = _at(night, shift.break_at, 6, rng, shift.overnight)
        unlock = lock + timedelta(minutes=rng.uniform(*shift.break_minutes))
        signout = _at(night, shift.signout, 6, rng, shift.overnight)
        if rng.random() < 0.1:  # occasional overtime
            signout += timedelta(minutes=rng.uniform(10, 45))

        plan.append((signin, rng.choice(t.logons)))
        plan.append((unlock, rng.choice(t.logons)))
        plan.append((unlock + timedelta(milliseconds=rng.randint(2, 30)), rng.choice(t.logoffs)))
        plan.append((signout, rng.choice(t.logoffs)))

        busy = rng.lognormvariate(0, 0.25)  # busier and quieter nights
        for begin, end in ((signin, lock), (unlock, signout)):
            hours = (end - begin).total_seconds() / 3600
            for _ in range(_poisson(rng, t.session_per_hour * busy * hours)):
                plan.append((begin + (end - begin) * rng.random(), rng.choice(t.session)))

    plan = [p for p in plan if p[0] < now]
    plan.sort(key=lambda p: p[0])
    return plan


def build_rows(plan: list[tuple[datetime, dict]], endpoint_id: int, seed: int = 2026):
    """Turn the plan into security_events rows (without endpoint_id /
    unique_id), lazily, with alert ids and event record ids in time order."""
    rng = random.Random(seed + 1)
    record_id = rng.randint(100_000, 200_000)
    for seq, (t, tpl) in enumerate(plan, start=1):
        record_id += rng.randint(1, 4)
        details = dict(tpl["details"])
        data = dict(details.get("data") or {})
        win = dict(data.get("win") or {})
        if win.get("system"):
            system = dict(win["system"])
            utc = t.astimezone(timezone.utc)
            system["systemTime"] = utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond:06d}0Z"
            system["eventRecordID"] = str(record_id)
            win["system"] = system
            data["win"] = win
            details["data"] = data
        details["seed"] = True
        row = {c: tpl[c] for c in _COLUMNS}
        row.update(details=details, event_time=t, wazuh_alert_id=f"{SEED_PREFIX}{endpoint_id}-{seq:07d}")
        yield row


# --- writing ------------------------------------------------------------------


def delete_seed(db, endpoint_id: int) -> int:
    from app.models.security_event import SecurityEvent as SE

    deleted = (
        db.query(SE)
        .filter(SE.endpoint_id == endpoint_id, SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted


def write_seed(db, endpoint_id: int, unique_id: int, rows, total: int, batch: int = 2000) -> int:
    """Replaces this endpoint's seed rows with `rows`, in batches."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.security_event import SecurityEvent as SE

    print(f"Removed {delete_seed(db, endpoint_id)} old seed rows.")
    inserted, chunk = 0, []

    def flush() -> int:
        # rowcount is -1 for a multi-row ON CONFLICT insert, so count RETURNING.
        stmt = (
            pg_insert(SE.__table__)
            .values(chunk)
            .on_conflict_do_nothing(index_elements=["wazuh_alert_id"])
            .returning(SE.id)
        )
        n = len(db.execute(stmt).fetchall())
        db.commit()
        return n

    for row in rows:
        chunk.append({**row, "endpoint_id": endpoint_id, "unique_id": unique_id})
        if len(chunk) == batch:
            inserted += flush()
            chunk = []
            if inserted % 50_000 < batch:
                print(f"  {inserted:,} / {total:,}")
    if chunk:
        inserted += flush()
    return inserted


# --- dataset file -------------------------------------------------------------

# security_events' columns, plus two pulled out of details for convenience.
DATASET_COLUMNS = (
    "wazuh_alert_id", "endpoint_id", "unique_id", "event_time", "rule_id", "rule_level", "rule_description",
    "severity", "event_type", "event_user", "windows_event_id", "process_name", "parent_process", "details",
)  # fmt: skip


def write_dataset(path: str, rows, endpoint_id: int, unique_id: int, total: int) -> int:
    """Writes the rows to a CSV file (gzipped if the name ends in .gz) in the
    security_events format, without touching the database."""
    opener = gzip.open if path.endswith(".gz") else open
    written = 0
    with opener(path, "wt", newline="", encoding="utf-8") as handle:
        out = csv.writer(handle)
        out.writerow(DATASET_COLUMNS)
        for row in rows:
            details = row["details"]
            out.writerow([
                row["wazuh_alert_id"], endpoint_id, unique_id, row["event_time"].isoformat(), row["rule_id"],
                row["rule_level"], row["rule_description"], row["severity"], row["event_type"], row["event_user"],
                row["windows_event_id"], _process_name(details), _parent_process(details).rsplit("\\", 1)[-1],
                json.dumps(details, ensure_ascii=False),
            ])  # fmt: skip
            written += 1
            if written % 100_000 == 0:
                print(f"  {written:,} / {total:,}")
    return written


# --- CLI ----------------------------------------------------------------------
