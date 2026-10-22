"""Turn security events into numeric feature vectors for the behavioral
anomaly model (Isolation Forest, per the IR).

The model learns what an endpoint's user *normally does and when*, so only
events that represent the user's own behavior are scored: logons, logoffs,
and processes the user started. Processes the system starts on the user's
behalf (creator is the machine account) say nothing about the user and are
ignored.

Each user action is described by:
  - hour_sin / hour_cos: local time of day on a circle, so 23:00 and 00:00 sit
    next to each other.
  - hour_rarity: how unusual this hour of the day is for this endpoint, from
    the share of the baseline's activity that falls in it (-log, as for
    action_rarity). A user's activity profile by hour is the classic UEBA
    signal; unlike the circle alone it makes an hour the baseline never has
    stand out outright, whatever program is running.
  - is_weekend
  - action_rarity: how unusual the action itself is for this endpoint, from
    its frequency in the baseline (-log of the relative frequency). The
    action is the program for process events, the event type otherwise.
  - rule_level_norm: Wazuh rule level 0-15 scaled to 0-1.
  - is_auth_failure

Rows are plain dicts (see ml/dataset.py): event_time, rule_level, event_type,
event_user, windows_event_id, process_name, creator.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

# The endpoints' local time (Malaysia, no DST). Hour-of-day features use it.
LOCAL_TZ = timezone(timedelta(hours=8))

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "hour_rarity", "is_weekend", "action_rarity", "rule_level_norm", "is_auth_failure",
]  # fmt: skip

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
}  # fmt: skip

_NOT_PEOPLE = {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
_USER_EVENT_TYPES = {"Login Success", "Login Failed", "Logoff", "Special Privileges"}


def is_person(name: str | None) -> bool:
    return bool(name) and not name.endswith("$") and name not in _NOT_PEOPLE and not name.startswith(("DWM-", "UMFD-"))


def is_user_action(row: dict) -> bool:
    """True for events that describe the user's behavior."""
    if row["windows_event_id"] == "4688":
        return is_person(row.get("creator")) and (row.get("process_name") or "") not in MAINTENANCE_TOOLS
    return row["event_type"] in _USER_EVENT_TYPES


def is_admin_tool(row: dict) -> bool:
    """A process creation of admin tooling: left out of the baseline when
    training, but still scored, so it stands out as never seen."""
    return row["windows_event_id"] == "4688" and (row.get("process_name") or "") in ADMIN_TOOLS


def action_key(row: dict) -> str:
    """What the user did: the program they ran, or the kind of event."""
    if row["windows_event_id"] == "4688":
        return "proc:" + (row.get("process_name") or "?").lower()
    return "type:" + (row["event_type"] or "?")


def local_hour(event_time: datetime) -> int:
    return event_time.astimezone(LOCAL_TZ).hour


def is_weekend(event_time: datetime) -> bool:
    return event_time.astimezone(LOCAL_TZ).weekday() >= 5


def event_features(
    event_time: datetime, hour_rarity: float, action_rarity: float, rule_level: int = 0, auth_failure: bool = False
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
    ]
