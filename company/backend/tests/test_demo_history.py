"""demo_plan + build_rows(demo=True) on endpoint 8's real events (no database)."""
import csv
import gzip
import json
import sys
from collections import Counter
from datetime import datetime, time

from _paths import BACKEND, DATA, DATASETS  # noqa: E402  (tests/_paths.py)
sys.path.insert(0, str(BACKEND))
from app.services.ml import runtime
from app.services.ml.data import SEED_PREFIX, build_rows, classify, demo_plan, row_from_event
from app.services.ml.model import LOCAL_TZ, is_user_action
from app.services.ml.tools import evaluate_split

rows = []
with gzip.open(str(DATASETS / "endpoint-8.csv.gz"), "rt", encoding="utf-8", newline="") as f:
    for r in csv.DictReader(f):
        r["event_time"] = datetime.fromisoformat(r["event_time"])
        r["details"] = json.loads(r["details"])
        r["rule_level"] = int(r["rule_level"])
        rows.append(r)
t = classify(rows)
print("templates:", len(t.session), "session,", len(t.logons), "logons,", len(t.logoffs), "logoffs")

plan = demo_plan(t, 2200, 21, (time(9, 0), time(18, 0)))
demo = list(build_rows(plan, 8, demo=True))
print("plan:", len(plan), plan[0][0].date(), "->", plan[-1][0].date())
print("alert ids look like:", [d["wazuh_alert_id"] for d in demo[:3]], "| any seed- prefix:", any(d["wazuh_alert_id"].startswith(SEED_PREFIX) for d in demo))
print("ids unique:", len({d["wazuh_alert_id"] for d in demo}) == len(demo), "| flagged in details:", all(d["details"].get("demo") for d in demo))
print("weekdays only:", {d["event_time"].astimezone(LOCAL_TZ).weekday() for d in demo}, "| hours:", sorted({d["event_time"].astimezone(LOCAL_TZ).hour for d in demo}))
print("templates untouched (no demo flag leaked):", not any(r["details"].get("demo") for r in rows))

# the system's own view of them
model_rows = []
for d in demo:
    model_rows.append(row_from_event({**d, "event_user": d["event_user"]}))
user = [r for r in model_rows if is_user_action(r)]
print("user actions the model counts:", len(user), "| distinct programs:", len({r["process_name"] for r in user if r["process_name"]}))
span = (max(r["event_time"] for r in user) - min(r["event_time"] for r in user)).days
print("span days:", span, "(needs", runtime.settings.ml_min_real_days, ") | actions needed:", runtime.settings.ml_min_real_actions)

# real mode selection, as train_endpoint would do it
chosen, mode, excluded, n = runtime.select_training_rows(user, None, lambda n_real: [])
print("select_training_rows ->", mode, "| clean actions:", n)

report = evaluate_split(user)
print("80/20 test on the demo history:", {k: round(v, 3) for k, v in report["metrics"].items()}, report["confusion"])
