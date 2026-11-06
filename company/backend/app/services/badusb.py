"""BadUSB: a USB device that pretends to be a keyboard and types commands.

A "BadUSB" device (a Rubber Ducky, a Digispark, a reprogrammed flash drive...) is recognised by
Windows as an ordinary keyboard and then types a short script faster than any person can: Win+R,
"powershell ...", Enter. Antivirus never sees a file; what can be seen is the order of two events:

    1. Windows records that a new external device was recognised (event 6416, "Audit PNP Activity"),
       with the device's class and ids. The installer turns this audit on.
    2. A few seconds later a shell or a PowerShell command starts.

A person who plugs in a keyboard needs more than a few seconds to sit down and open a command
prompt; a device that injects keystrokes does not. So a command that starts within BADUSB_WINDOW
seconds after a keyboard was plugged in is what this module looks for. It is a rule, not a model:
there is no public labelled data of BadUSB attacks to learn from, and the rule is easy to explain.

This module only decides things from the events' fields (no database, no web code); the scoring of
what it finds (CVSS, kind "badusb") is in services/cvss.py and ml/runtime.py.

The device fields of event 6416 are those of Microsoft's documentation (DeviceId, DeviceDescription,
ClassId, ClassName, VendorIds, CompatibleIds):
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-6416
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

DEVICE_EVENT = "6416"

# Programs that run a typed command. 4104 (what is typed into PowerShell) counts too.
SHELL_PROGRAMS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "windowsterminal.exe"}

# USB class 03 (HID), subclass 01 (boot interface), protocol 01 (keyboard): what a USB keyboard says it is.
_HID_KEYBOARD = "class_03&subclass_01&prot_01"
_VID_PID = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)


def _eventdata(details: dict[str, Any] | None) -> dict[str, Any]:
    return ((((details or {}).get("data") or {}).get("win")) or {}).get("eventdata") or {}


def _field(data: dict[str, Any], name: str) -> str:
    """A field of the event, whatever the case of its first letter (Wazuh writes 'deviceId')."""
    for key, value in data.items():
        if key.lower() == name.lower() and value:
            return str(value)
    return ""


def keyboard_description(details: dict[str, Any] | None) -> str | None:
    """For the details of a 'new external device recognised' event (6416): a short description of the
    device if it is a keyboard, None if it is anything else (a flash drive, a mouse, a phone...)."""
    data = _eventdata(details)
    if not data:
        return None
    text = " ".join(_field(data, k) for k in ("deviceId", "vendorIds", "compatibleIds")).lower()
    description = _field(data, "deviceDescription")
    class_name = _field(data, "className")
    if not (class_name.lower() == "keyboard" or _HID_KEYBOARD in text or "keyboard" in description.lower()):
        return None
    ids = _VID_PID.search(_field(data, "deviceId") + " " + _field(data, "vendorIds"))
    name = description or class_name or "keyboard"
    return f"{name} (VID_{ids.group(1).upper()} PID_{ids.group(2).upper()})" if ids else name


def is_shell(row: dict[str, Any]) -> bool:
    """A command typed or started by a person: a shell starting (4688) or a PowerShell command (4104)."""
    if row.get("windows_event_id") == "4104":
        return True
    return row.get("windows_event_id") == "4688" and (row.get("process_name") or "").lower() in SHELL_PROGRAMS


def keyboard_before(plugged: list[tuple[datetime, str]], when: datetime, window: timedelta) -> tuple[float, str] | None:
    """(seconds since, description) of the latest keyboard plugged in during the `window` before `when`."""
    best = None
    for t, description in plugged:
        gap = (when - t).total_seconds()
        if 0 <= gap <= window.total_seconds() and (best is None or gap < best[0]):
            best = (gap, description)
    return best
