"""Load a training dataset as plain dicts, from either source:

  - a CSV file exported by seed_baseline.py (the synthetic first baseline), or
  - the security_events table (the endpoint's real events, once it has some).

Both have the security_events format, so the model code doesn't care which
one it is given. Switching from the synthetic baseline to real data is just a
different source.
"""

from __future__ import annotations

import csv
import gzip
import re
import sys
from datetime import datetime

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
    command=None,
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
    )


# The CSV's details column is JSON text; pulling the one field we need with a
# regex is far faster than parsing every row's JSON.
_SUBJECT_RE = re.compile(r'"subjectUserName": "([^"]*)"')
_PARENT_RE = re.compile(r'"parentProcessName": "([^"]*)"')


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
    from sqlalchemy import or_

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
    ).filter(SE.endpoint_id == endpoint_id)
    if not include_seed:
        query = query.filter(~SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
    if since is not None:
        query = query.filter(SE.event_time >= since)
    if user_actions_only:
        query = query.filter(or_(SE.windows_event_id == "4688", SE.event_type.in_(_USER_EVENT_TYPES)))

    rows = []
    for t, level, etype, user, win_id, alert_id, process_path, creator, parent in query.order_by(SE.event_time).yield_per(5000):
        process = (process_path or "").rsplit("\\", 1)[-1]
        rows.append(model_row(t, level, etype, user, win_id, process, creator, alert_id, parent))
    return rows
