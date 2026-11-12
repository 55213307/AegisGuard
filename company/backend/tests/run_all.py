"""Run every check in this folder, one after the other, and say which ones failed.

    python tests/run_all.py            (from company/backend, with the project's virtual environment)
    python tests/run_all.py -v         also print what each check printed

The checks are scripts, not unit tests: each sets up an in-memory SQLite database or loads the saved models, runs a
part of the system the way it runs in use, and prints what happened. A check fails here when it ends with an error
or prints a line starting with BAD; read its output (-v, or run the file on its own) to judge the numbers it prints.
None of them touches the real database or the network. Some need the datasets folder and the saved models
(ml_models/*.joblib): without them those checks fail and say what is missing.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
verbose = "-v" in sys.argv
failed = []
for script in sorted(HERE.glob("test_*.py")):
    started = time.time()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run([sys.executable, str(script)], cwd=HERE.parent, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    output = result.stdout + result.stderr
    bad = result.returncode != 0 or "Traceback (most recent call last)" in output or any(line.startswith("BAD") for line in output.splitlines())
    print(f"{'FAIL' if bad else 'ok  '}  {script.name:<28} {time.time() - started:5.1f}s")
    if bad:
        failed.append(script.name)
    if verbose or bad:
        print("\n".join("      " + line for line in output.strip().splitlines()[-40 if bad and not verbose else 0:]))
print(f"\n{len(failed)} failed: {', '.join(failed)}" if failed else "\nall checks passed")
sys.exit(1 if failed else 0)
