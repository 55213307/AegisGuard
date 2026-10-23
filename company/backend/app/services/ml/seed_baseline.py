"""A year of synthetic logs, as the training dataset for the anomaly model.

The demo endpoint has only a couple of weeks of real history, so a year of it
is generated from the endpoint's *own* real events, in exactly the format the
ingester stores them:

  - Every generated row is a copy of a real security_events row from this
    endpoint (same rule, description, event type, user, Windows event and
    details JSON), given a new time, alert id and event record id.
  - How many events happen per hour is measured from the real data too, so the
    year has the same volume and mix as the real machine.
  - Three kinds of events are replayed differently:
      machine events (no person behind them: SYSTEM processes, application
      logs, agent start/stop) happen around the clock, as on a workstation
      that stays on, at the real machine's *median* hourly rate (the real
      history is mostly start-up bursts, which the mean would inflate);
      CIS configuration scans (SCA) run every 12 hours like Wazuh's own
      schedule: the first reports every check, later ones a summary plus the
      occasional status change, each with the burst of check commands
      (auditpol, secedit...) the agent runs as SYSTEM;
      session events (the user's logons, logoffs and the processes in their
      session) happen only during the user's working hours: by default night
      shifts, 22:00-06:00 local time (--shift day: 09:00-18:00), on shifts
      starting Monday to Friday, minus leave.
  - The night-shift user is a clerk, not an administrator, so admin tooling
    seen in the real data (powershell, cmd, reg, net... mostly our own
    installer at work) is left out of their sessions, as are admin-only
    events such as special-privilege logons.

Generated rows are marked so they can always be told apart and removed:
wazuh_alert_id starts with "seed-" and details["seed"] is true.

Usage, from company/backend on the server:
  .venv/bin/python -m app.services.ml.seed_baseline --endpoint-id 6            # preview, writes nothing
  .venv/bin/python -m app.services.ml.seed_baseline --endpoint-id 6 --write    # (re)write the year
  .venv/bin/python -m app.services.ml.seed_baseline --endpoint-id 6 --delete   # remove it
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter
import csv
import gzip
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timedelta, timezone

from app.services.ml.features import ADMIN_TOOLS, LOCAL_TZ, MAINTENANCE_TOOLS  # LOCAL_TZ: Malaysia time, the endpoints' local time
SEED_PREFIX = "seed-"


@dataclass(frozen=True)
class Shift:
    """When the persona works: sign-in, the mid-shift break (when the screen is
    locked for a while, so no activity) and sign-out, as local clock times."""

    name: str
    signin: str
    break_at: str
    break_minutes: tuple[float, float]  # shortest and longest break
    signout: str
    overnight: bool  # runs past midnight, so early-morning times are the next day


def shift_from_hours(start: str, end: str) -> Shift:
    """The shift a company declared as "HH:MM" start and end times. An end
    before the start means it runs past midnight. The break falls in the middle
    of the day, and is shorter for a short day."""
    (sh, sm), (eh, em) = (map(int, start.split(":")), map(int, end.split(":")))
    first, last = sh * 60 + sm, eh * 60 + em
    length = (last - first) % (24 * 60)
    middle = (first + length // 2) % (24 * 60)
    return Shift(
        "declared",
        signin=start,
        break_at=f"{middle // 60:02d}:{middle % 60:02d}",
        break_minutes=(30, 60) if length >= 360 else (10, 20),
        signout=end,
        overnight=last <= first,
    )


NIGHT = Shift("night", signin="22:00", break_at="01:40", break_minutes=(20, 35), signout="06:00", overnight=True)
DAY = Shift("day", signin="09:00", break_at="12:30", break_minutes=(45, 70), signout="18:00", overnight=False)
SHIFTS = {s.name: s for s in (NIGHT, DAY)}


class NotEnoughEvents(ValueError):
    """The endpoint's real events can't supply templates for a synthetic baseline."""

_SYSTEM_ACCOUNTS = {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

# Programs the clerk's sessions never contain (see features.py).
_ADMIN_TOOLS = ADMIN_TOOLS | MAINTENANCE_TOOLS

# Commands Wazuh's configuration scan runs as SYSTEM to read settings.
_SCAN_TOOLS = _ADMIN_TOOLS | {"secedit.exe", "wevtutil.exe", "gpresult.exe", "bcdedit.exe", "manage-bde.exe"}
SCAN_INTERVAL = timedelta(hours=12)  # Wazuh SCA default

# Columns copied from the real row; time and ids are set per copy.
_COLUMNS = ("rule_id", "rule_level", "rule_description", "severity", "event_type", "event_user", "windows_event_id", "details")


def _is_person(name: str | None) -> bool:
    return bool(name) and not name.endswith("$") and name not in _SYSTEM_ACCOUNTS and not name.startswith(("DWM-", "UMFD-"))


def _process_name(details: dict) -> str:
    eventdata = (((details.get("data") or {}).get("win")) or {}).get("eventdata") or {}
    return (eventdata.get("newProcessName") or "").rsplit("\\", 1)[-1].lower()


def _parent_process(details: dict) -> str:
    eventdata = (((details.get("data") or {}).get("win")) or {}).get("eventdata") or {}
    return (eventdata.get("parentProcessName") or "").lower()


def _is_scan_process(row: dict) -> bool:
    """A check command run by the Wazuh agent's configuration scan."""
    if row["windows_event_id"] != "4688":
        return False
    parent = _parent_process(row["details"])
    return "ossec-agent" in parent or "wazuh" in parent or _process_name(row["details"]) in _SCAN_TOOLS


def _hour_bucket(t: datetime) -> datetime:
    return t.astimezone(LOCAL_TZ).replace(minute=0, second=0, microsecond=0)


def _median_per_hour(rows: list[dict], hours: set[datetime]) -> float:
    """Median events per hour over `hours` (an hour with none counts as 0)."""
    counts = Counter(_hour_bucket(r["event_time"]) for r in rows)
    values = sorted(counts.get(h, 0) for h in hours)
    mid = len(values) // 2
    return float(values[mid]) if len(values) % 2 else (values[mid - 1] + values[mid]) / 2


# --- what the real machine does ---------------------------------------------


@dataclass
class Templates:
    machine: list[dict]  # events with no person behind them
    session: list[dict]  # processes in the user's session
    logons: list[dict]
    logoffs: list[dict]
    scan_checks: list[dict]  # one per configuration check (the first scan reports all)
    scan_summaries: list[dict]
    scan_changes: list[dict]  # a check's status changed since the last scan
    scan_processes: list[dict]  # commands the scan runs
    machine_per_hour: float  # median, while the real machine was on
    session_per_hour: float  # median, while the user was signed in
    changes_per_scan: float
    processes_per_scan: float
    real_rows: int
    real_hours: int
    left_out: Counter  # real session events the clerk wouldn't produce


def classify(rows: list[dict]) -> Templates:
    """Sort an endpoint's real rows into templates and measure their rates.
    Each row is a dict with event_time plus the _COLUMNS."""
    machine, session, logons, logoffs = [], [], [], []
    checks: dict[str, dict] = {}
    summaries, changes, scan_processes = [], [], []
    left_out: Counter = Counter()
    for row in rows:
        if row["event_type"] == "Security Configuration":
            description = row["rule_description"] or ""
            if description.startswith("SCA summary"):
                summaries.append(row)
            elif "Status changed" in description:
                changes.append(row)
            else:
                checks.setdefault(description, row)
        elif not _is_person(row["event_user"]):
            (scan_processes if _is_scan_process(row) else machine).append(row)
        elif row["event_type"] == "Login Success":
            logons.append(row)
        elif row["event_type"] == "Logoff":
            logoffs.append(row)
        elif row["event_type"] == "Process" and _process_name(row["details"]) not in _ADMIN_TOOLS:
            session.append(row)
        else:
            left_out[_process_name(row["details"]) or row["event_type"]] += 1
    if not (machine and session and logons and logoffs):
        raise NotEnoughEvents(
            "Not enough real events to learn from: need machine events, session processes, "
            f"logons and logoffs (have {len(machine)}, {len(session)}, {len(logons)}, {len(logoffs)})."
        )
    hours_on = {_hour_bucket(r["event_time"]) for r in rows}
    session_hours = {_hour_bucket(r["event_time"]) for r in session + logons + logoffs}
    scans = max(1, len(summaries))
    return Templates(
        machine=machine,
        session=session,
        logons=logons,
        logoffs=logoffs,
        scan_checks=list(checks.values()),
        scan_summaries=summaries,
        scan_changes=changes,
        scan_processes=scan_processes,
        machine_per_hour=_median_per_hour(machine, hours_on),
        session_per_hour=_median_per_hour(session, session_hours),
        changes_per_scan=len(changes) / scans,
        processes_per_scan=len(scan_processes) / scans,
        real_rows=len(rows),
        real_hours=len(hours_on),
        left_out=left_out,
    )


def load_templates(db, endpoint_id: int) -> Templates:
    from app.models.security_event import SecurityEvent as SE

    events = (
        db.query(SE)
        .filter(SE.endpoint_id == endpoint_id, ~SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
        .order_by(SE.event_time)
        .all()
    )
    return classify([{"event_time": e.event_time, **{c: getattr(e, c) for c in _COLUMNS}} for e in events])


# --- the working calendar -----------------------------------------------------


def _shift_nights(days: int, rng: random.Random, today: date) -> list[date]:
    """Dates a shift starts on, over the last `days` days."""
    nights = [today - timedelta(days=d) for d in range(days, 0, -1)]
    workdays = [n for n in nights if n.weekday() < 5]
    off: set[date] = set()
    for block in (5, 5, 3):  # annual leave
        start = rng.randrange(0, len(workdays) - block)
        off.update(workdays[start : start + block])
    off.update(rng.sample(workdays, 8))  # sick days, public holidays
    shifts = [n for n in workdays if n not in off]
    shifts += [n for n in nights if n.weekday() >= 5 and rng.random() < 0.04]  # weekend overtime
    return sorted(shifts)


def _at(night: date, hhmm: str, jitter_minutes: float, rng: random.Random, overnight: bool = True) -> datetime:
    """A time on the shift that starts on `night`. On an overnight shift the
    hours before noon fall on the next morning."""
    hour, minute = map(int, hhmm.split(":"))
    day = night if (hour >= 12 or not overnight) else night + timedelta(days=1)
    base = datetime.combine(day, time(hour, minute), tzinfo=LOCAL_TZ)
    return base + timedelta(minutes=rng.gauss(0, jitter_minutes), milliseconds=rng.randint(0, 999))


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:  # normal approximation; Knuth's method underflows for large lambda
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        k += 1
        p *= rng.random()
        if p <= limit:
            return k - 1


# --- the year -----------------------------------------------------------------


def schedule(
    t: Templates,
    days: int = 365,
    seed: int = 2026,
    now: datetime | None = None,
    scale: float = 1.0,
    shift: Shift = NIGHT,
) -> list[tuple[datetime, dict]]:
    """(time, template) for every event of the year, oldest first. Only times
    before `now`. `scale` multiplies the hourly rates for a bigger dataset.
    Lightweight: rows are only built when written."""
    if scale != 1.0:
        t = replace(t, machine_per_hour=t.machine_per_hour * scale, session_per_hour=t.session_per_hour * scale)
    rng = random.Random(seed)
    now = now or datetime.now(LOCAL_TZ)
    start = datetime.combine(now.date() - timedelta(days=days), time(0), tzinfo=LOCAL_TZ)
    plan: list[tuple[datetime, dict]] = []

    # Machine events, around the clock.
    hour = start
    while hour < now:
        for _ in range(_poisson(rng, t.machine_per_hour)):
            plan.append((hour + timedelta(seconds=rng.uniform(0, 3600)), rng.choice(t.machine)))
        hour += timedelta(hours=1)

    # Configuration scans every 12 hours.
    if t.scan_summaries:
        scan_at = start + timedelta(minutes=rng.uniform(0, 60))
        first = True
        while scan_at < now:
            reports = list(t.scan_checks) if first else []
            if t.scan_changes:
                reports += [rng.choice(t.scan_changes) for _ in range(_poisson(rng, t.changes_per_scan))]
            reports.append(rng.choice(t.scan_summaries))
            for i, tpl in enumerate(reports):
                plan.append((scan_at + timedelta(seconds=30 + i * rng.uniform(0.05, 0.4)), tpl))
            for _ in range(_poisson(rng, t.processes_per_scan) if t.scan_processes else 0):
                plan.append((scan_at + timedelta(seconds=rng.uniform(0, 120)), rng.choice(t.scan_processes)))
            first = False
            scan_at += SCAN_INTERVAL + timedelta(minutes=rng.gauss(0, 3))

    # The user's night shifts.
    for night in _shift_nights(days, rng, now.date()):
        signin = _at(night, shift.signin, 8, rng, shift.overnight)
        lock = _at(night, shift.break_at, 6, rng, shift.overnight)
        unlock = lock + timedelta(minutes=rng.uniform(*shift.break_minutes))
        signout = _at(night, shift.signout, 6, rng, shift.overnight)
        if rng.random() < 0.1:  # occasional overtime
            signout += timedelta(minutes=rng.uniform(10, 45))

        plan.append((signin, rng.choice(t.logons)))
        plan.append((unlock, rng.choice(t.logons)))
        plan.append((unlock + timedelta(milliseconds=rng.randint(2, 30)), rng.choice(t.logoffs)))
        plan.append((signout, rng.choice(t.logoffs)))

        busy = rng.lognormvariate(0, 0.25)  # busier and quieter nights
        for begin, end in ((signin, lock), (unlock, signout)):
            hours = (end - begin).total_seconds() / 3600
            for _ in range(_poisson(rng, t.session_per_hour * busy * hours)):
                plan.append((begin + (end - begin) * rng.random(), rng.choice(t.session)))

    plan = [p for p in plan if p[0] < now]
    plan.sort(key=lambda p: p[0])
    return plan


def build_rows(plan: list[tuple[datetime, dict]], endpoint_id: int, seed: int = 2026):
    """Turn the plan into security_events rows (without endpoint_id /
    unique_id), lazily, with alert ids and event record ids in time order."""
    rng = random.Random(seed + 1)
    record_id = rng.randint(100_000, 200_000)
    for seq, (t, tpl) in enumerate(plan, start=1):
        record_id += rng.randint(1, 4)
        details = dict(tpl["details"])
        data = dict(details.get("data") or {})
        win = dict(data.get("win") or {})
        if win.get("system"):
            system = dict(win["system"])
            utc = t.astimezone(timezone.utc)
            system["systemTime"] = utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond:06d}0Z"
            system["eventRecordID"] = str(record_id)
            win["system"] = system
            data["win"] = win
            details["data"] = data
        details["seed"] = True
        row = {c: tpl[c] for c in _COLUMNS}
        row.update(details=details, event_time=t, wazuh_alert_id=f"{SEED_PREFIX}{endpoint_id}-{seq:07d}")
        yield row


# --- writing ------------------------------------------------------------------


def delete_seed(db, endpoint_id: int) -> int:
    from app.models.security_event import SecurityEvent as SE

    deleted = (
        db.query(SE)
        .filter(SE.endpoint_id == endpoint_id, SE.wazuh_alert_id.like(SEED_PREFIX + "%"))
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted


def write_seed(db, endpoint_id: int, unique_id: int, rows, total: int, batch: int = 2000) -> int:
    """Replaces this endpoint's seed rows with `rows`, in batches."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.models.security_event import SecurityEvent as SE

    print(f"Removed {delete_seed(db, endpoint_id)} old seed rows.")
    inserted, chunk = 0, []

    def flush() -> int:
        # rowcount is -1 for a multi-row ON CONFLICT insert, so count RETURNING.
        stmt = (
            pg_insert(SE.__table__)
            .values(chunk)
            .on_conflict_do_nothing(index_elements=["wazuh_alert_id"])
            .returning(SE.id)
        )
        n = len(db.execute(stmt).fetchall())
        db.commit()
        return n

    for row in rows:
        chunk.append({**row, "endpoint_id": endpoint_id, "unique_id": unique_id})
        if len(chunk) == batch:
            inserted += flush()
            chunk = []
            if inserted % 50_000 < batch:
                print(f"  {inserted:,} / {total:,}")
    if chunk:
        inserted += flush()
    return inserted


# --- dataset file -------------------------------------------------------------

# security_events' columns, plus two pulled out of details for convenience.
DATASET_COLUMNS = (
    "wazuh_alert_id", "endpoint_id", "unique_id", "event_time", "rule_id", "rule_level", "rule_description",
    "severity", "event_type", "event_user", "windows_event_id", "process_name", "parent_process", "details",
)  # fmt: skip


def write_dataset(path: str, rows, endpoint_id: int, unique_id: int, total: int) -> int:
    """Writes the rows to a CSV file (gzipped if the name ends in .gz) in the
    security_events format, without touching the database."""
    opener = gzip.open if path.endswith(".gz") else open
    written = 0
    with opener(path, "wt", newline="", encoding="utf-8") as handle:
        out = csv.writer(handle)
        out.writerow(DATASET_COLUMNS)
        for row in rows:
            details = row["details"]
            out.writerow([
                row["wazuh_alert_id"], endpoint_id, unique_id, row["event_time"].isoformat(), row["rule_id"],
                row["rule_level"], row["rule_description"], row["severity"], row["event_type"], row["event_user"],
                row["windows_event_id"], _process_name(details), _parent_process(details).rsplit("\\", 1)[-1],
                json.dumps(details, ensure_ascii=False),
            ])  # fmt: skip
            written += 1
            if written % 100_000 == 0:
                print(f"  {written:,} / {total:,}")
    return written


# --- CLI ----------------------------------------------------------------------


def _print_preview(t: Templates, plan: list[tuple[datetime, dict]]) -> None:
    print(f"learned from {t.real_rows:,} real events over {t.real_hours} hours the machine was on:")
    print(f"  machine events : {len(t.machine):,} templates, median {t.machine_per_hour:.1f} per hour")
    print(f"  config scans   : {len(t.scan_summaries)} seen; {len(t.scan_checks)} checks reported on the first scan, "
          f"then ~{t.changes_per_scan:.1f} status changes and ~{t.processes_per_scan:.0f} check commands per scan")  # fmt: skip
    print(f"  session events : {len(t.session):,} process templates, median {t.session_per_hour:.1f} per signed-in hour; "
          f"{len(t.logons)} logons, {len(t.logoffs)} logoffs")  # fmt: skip
    if t.left_out:
        print("  left out (admin/maintenance): " + ", ".join(f"{k}={v}" for k, v in t.left_out.most_common()))
    programs = Counter(_process_name(r["details"]) for r in t.session)
    print("  user programs kept: " + ", ".join(f"{k}={v}" for k, v in programs.most_common(15)))

    first, last = plan[0][0], plan[-1][0]
    size_mb = sum(len(json.dumps(tpl["details"])) for _, tpl in plan) / 1e6
    print(f"\nyear: {first:%Y-%m-%d} .. {last:%Y-%m-%d}   rows={len(plan):,}   ~{size_mb:,.0f} MB of details JSON")
    print("types : " + ", ".join(f"{k}={v:,}" for k, v in Counter(tpl["event_type"] for _, tpl in plan).most_common()))
    users = Counter(tpl["event_user"] if _is_person(tpl["event_user"]) else "(machine)" for _, tpl in plan)
    print("users : " + ", ".join(f"{k}={v:,}" for k, v in users.most_common()))
    person = Counter(t_.astimezone(LOCAL_TZ).hour for t_, tpl in plan if _is_person(tpl["event_user"]))
    print("user events by hour: " + "  ".join(f"{h:02d}:{person[h]:,}" for h in range(24) if person[h]))

    # A slice of one mid-year shift start, everything that happened.
    mid = plan[len(plan) // 2][0].date()
    while mid.weekday() != 2:  # a Wednesday
        mid += timedelta(days=1)
    lo = datetime.combine(mid, time(21, 50), tzinfo=LOCAL_TZ)
    sample = [p for p in plan if lo <= p[0] < lo + timedelta(minutes=25)][:20]
    print(f"\nsample: {mid:%a %Y-%m-%d} from 21:50 (first {len(sample)} events)")
    for t_, tpl in sample:
        proc = _process_name(tpl["details"])
        print(f"  {t_.astimezone(LOCAL_TZ):%H:%M:%S}  {tpl['event_type'] or '-':<22} {tpl['windows_event_id'] or '-':<5} "
              f"{tpl['rule_id'] or '-':<6} {tpl['event_user'] or '-':<24} {proc or (tpl['rule_description'] or '')[:40]}")  # fmt: skip


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a year of an endpoint's logs as the anomaly model's dataset.")
    parser.add_argument("--endpoint-id", type=int, required=True)
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--seed", type=int, default=2026, help="random seed, for a reproducible year")
    parser.add_argument("--scale", type=float, default=1.0, help="multiply the hourly rates (bigger dataset)")
    parser.add_argument("--shift", choices=sorted(SHIFTS), default="night", help="the persona's working hours (default: night, 22:00-06:00; day is 09:00-18:00)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--out", help="write the dataset to this CSV file (.csv.gz to compress); no database writes")
    action.add_argument("--write", action="store_true", help="replace this endpoint's seed rows in the database")
    action.add_argument("--delete", action="store_true", help="remove this endpoint's seed rows")
    args = parser.parse_args()

    from app.db.session import SessionLocal
    from app.models.endpoint import Endpoint

    db = SessionLocal()
    endpoint = db.get(Endpoint, args.endpoint_id)
    if endpoint is None:
        raise SystemExit(f"No endpoint with id {args.endpoint_id}.")
    if args.delete:
        print(f"Deleted {delete_seed(db, endpoint.id):,} seed rows for endpoint {endpoint.id}.")
        return

    try:
        templates = load_templates(db, endpoint.id)
    except NotEnoughEvents as exc:
        raise SystemExit(str(exc))
    plan = schedule(templates, days=args.days, seed=args.seed, scale=args.scale, shift=SHIFTS[args.shift])
    _print_preview(templates, plan)

    if args.out:
        rows = build_rows(plan, endpoint.id, seed=args.seed)
        written = write_dataset(args.out, rows, endpoint.id, endpoint.unique_id, total=len(plan))
        print(f"\nWrote {written:,} rows to {args.out}.")
    elif args.write:
        rows = build_rows(plan, endpoint.id, seed=args.seed)
        inserted = write_seed(db, endpoint.id, endpoint.unique_id, rows, total=len(plan))
        print(f"\nWrote {inserted:,} seed rows for endpoint {endpoint.id}.")
    else:
        print("\nPreview only — nothing written. Add --write to store these rows.")


if __name__ == "__main__":
    main()
