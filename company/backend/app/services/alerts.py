"""Turn a raw Wazuh alert (one JSON object from alerts.json) into the fields
we store. Pure functions — no DB, no I/O — so they're easy to test."""

from datetime import datetime
from typing import Any


def severity_for_level(level: int) -> str:
    """Wazuh rule level 0-15 → the three labels the portal shows."""
    if level >= 12:
        return "Critical"
    if level >= 7:
        return "Warning"
    return "Info"


# Wazuh groups a rule under several tags; map the ones we care about to a
# short, readable event type. First match wins; otherwise we fall back to the
# rule's most specific group.
_GROUP_LABELS: list[tuple[str, str]] = [
    ("authentication_failed", "Login Failed"),
    ("authentication_success", "Login Success"),
    ("account_changed", "Account Changed"),
    ("win_authentication_failed", "Login Failed"),
    ("usb", "USB Device"),
    ("malware", "Malware"),
    ("virus", "Malware"),
    ("rootcheck", "Policy / Rootcheck"),
    ("vulnerability-detector", "Vulnerability"),
    ("sca", "Security Configuration"),
    ("firewall", "Firewall"),
    ("ossec", "Agent / System"),
    ("syscheck", "File Integrity"),
    ("process", "Process"),
]

# "wef" is the group Wazuh's Windows Event Forwarding rules (67xxx) put on
# logons, logoffs and process creation; it says nothing about the event.
_GENERIC_GROUPS = {"windows", "wazuh", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13", "wef"}

# For Windows Security events whose rule groups don't say what happened (the
# WEF rules above), the event ID does.
_WINDOWS_EVENT_LABELS: dict[str, str] = {
    "4624": "Login Success",
    "4625": "Login Failed",
    "4634": "Logoff",
    "4647": "Logoff",
    "4672": "Special Privileges",
    "4688": "Process",
    "4720": "Account Created",
    "4726": "Account Deleted",
    "4738": "Account Changed",
    "4740": "Account Locked",
    "1102": "Audit Log Cleared",
}


def _event_type(groups: list[str], decoder: str | None, windows_event_id: str | None = None) -> str | None:
    # Wazuh group names sometimes carry stray whitespace (e.g. " WEF").
    groups = [g.strip() for g in groups]
    for keyword, label in _GROUP_LABELS:
        if any(keyword in g for g in groups):
            return label
    if windows_event_id in _WINDOWS_EVENT_LABELS:
        return _WINDOWS_EVENT_LABELS[windows_event_id]
    for g in reversed(groups):  # last group is usually the most specific
        if g and g.lower() not in _GENERIC_GROUPS:
            return g.replace("_", " ").title()
    if decoder:
        return decoder.replace("_", " ").title()
    return None


# Common places a username shows up across Wazuh decoders.
_USER_KEYS = ("dstuser", "srcuser", "targetUserName", "subjectUserName", "user")


def _extract_user(alert: dict[str, Any]) -> str | None:
    data = alert.get("data") or {}
    eventdata = ((data.get("win") or {}).get("eventdata")) or {}
    for source in (eventdata, data):
        for key in _USER_KEYS:
            value = source.get(key)
            if value and value not in ("-", "N/A"):
                return str(value)[:120]
    return None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def agent_id_of(alert: dict[str, Any]) -> str | None:
    """The reporting agent's id, or None for the manager's own alerts (000)."""
    agent_id = (alert.get("agent") or {}).get("id")
    if not agent_id or agent_id == "000":
        return None
    return agent_id


def parse_alert(alert: dict[str, Any]) -> dict[str, Any] | None:
    """Fields for a security_events row, minus endpoint_id/unique_id (which the
    ingester fills from the agent id). Returns None if the alert is unusable."""
    alert_id = alert.get("id")
    rule = alert.get("rule") or {}
    event_time = _parse_time(alert.get("timestamp"))
    if not alert_id or not rule or event_time is None:
        return None

    level = int(rule.get("level", 0))
    groups = rule.get("groups") or []
    data = alert.get("data") or {}
    win_system = (data.get("win") or {}).get("system") or {}
    windows_event_id = str(win_system.get("eventID"))[:20] if win_system.get("eventID") else None

    return {
        "wazuh_alert_id": str(alert_id)[:64],
        "event_time": event_time,
        "rule_id": str(rule.get("id"))[:20] if rule.get("id") else None,
        "rule_level": level,
        "rule_description": (rule.get("description") or "")[:500] or None,
        "severity": severity_for_level(level),
        "event_type": _event_type(groups, (alert.get("decoder") or {}).get("name"), windows_event_id),
        "event_user": _extract_user(alert),
        "windows_event_id": windows_event_id,
        "details": {
            "rule_groups": groups,
            "decoder": (alert.get("decoder") or {}).get("name"),
            "location": alert.get("location"),
            "full_log": alert.get("full_log"),
            "data": data or None,
        },
    }
