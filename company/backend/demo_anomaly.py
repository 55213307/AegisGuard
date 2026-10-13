"""Standalone, self-contained demo of the behavioral anomaly model.

This does NOT touch the database or the running app. It trains the exact same
Isolation Forest model used in production (app/services/ml) on a synthetic
"night-shift" baseline, then shows how the risk score changes across the hours
of a day — low when the user is normally active (night), high during the day.

Run it from the backend directory:

    python demo_anomaly.py

It prints a risk table and writes `anomaly_demo.html` — a single file you can
open in any browser and screenshot for the presentation. No matplotlib or
other extra libraries needed.
"""

from datetime import datetime, timezone

from app.services.ml import profiles
from app.services.ml.features import event_features
from app.services.ml.model import ANOMALY_RISK_THRESHOLD, RiskModel

PROFILE = profiles.NIGHT_SHIFT
GREEN, RED, GREY, INK = "#3ddc84", "#fb7185", "#8aa0c0", "#0a1120"


def build_model(profile):
    baseline = profiles.generate_baseline(profile, days=42, seed=1)
    model = RiskModel().fit([event_features(t, lvl) for t, lvl in baseline])
    return model, baseline


def risk_by_hour(model):
    """Score one routine event at each hour of a weekday (level 4)."""
    weekday = datetime(2026, 10, 12, 0, tzinfo=timezone.utc)  # a Monday
    out = []
    for hour in range(24):
        feat = event_features(weekday.replace(hour=hour), 4)
        out.append(model.score_one(feat).risk)
    return out


def baseline_counts_by_hour(baseline):
    counts = [0] * 24
    for t, _ in baseline:
        counts[t.hour] += 1
    return counts


def render_html(profile, risks, counts):
    # SVG geometry
    w, h = 820, 380
    left, right, top, bottom = 56, 24, 28, 56
    pw, ph = w - left - right, h - top - bottom
    step = pw / 24
    max_count = max(counts) or 1

    def x(hour):
        return left + hour * step + step / 2

    def y_risk(r):
        return top + ph * (1 - r / 100)

    parts = []
    # gridlines + y labels (risk)
    for r in range(0, 101, 25):
        yy = y_risk(r)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{w-right}" y2="{yy:.1f}" stroke="#223049" stroke-width="1"/>')
        parts.append(f'<text x="{left-10}" y="{yy+4:.1f}" fill="{GREY}" font-size="12" text-anchor="end">{r}</text>')
    # threshold line
    ty = y_risk(ANOMALY_RISK_THRESHOLD)
    parts.append(f'<line x1="{left}" y1="{ty:.1f}" x2="{w-right}" y2="{ty:.1f}" stroke="{RED}" stroke-width="1.5" stroke-dasharray="6 4"/>')
    parts.append(f'<text x="{w-right}" y="{ty-8:.1f}" fill="{RED}" font-size="12" text-anchor="end">anomaly threshold ({ANOMALY_RISK_THRESHOLD})</text>')

    # baseline activity bars (grey, scaled to lower third)
    bar_zone = ph * 0.9
    for hour, c in enumerate(counts):
        bh = (c / max_count) * (ph * 0.35)
        bx = x(hour) - step * 0.32
        parts.append(
            f'<rect x="{bx:.1f}" y="{top+ph-bh:.1f}" width="{step*0.64:.1f}" height="{bh:.1f}" '
            f'fill="#2a3b57" opacity="0.7" rx="2"><title>{c} normal events at {hour:02d}:00</title></rect>'
        )

    # risk points + connecting line
    pts = " ".join(f"{x(hr):.1f},{y_risk(r):.1f}" for hr, r in enumerate(risks))
    parts.append(f'<polyline points="{pts}" fill="none" stroke="#5b7cfa" stroke-width="2"/>')
    for hr, r in enumerate(risks):
        color = RED if r >= ANOMALY_RISK_THRESHOLD else GREEN
        parts.append(
            f'<circle cx="{x(hr):.1f}" cy="{y_risk(r):.1f}" r="4.5" fill="{color}">'
            f'<title>{hr:02d}:00 — risk {r}</title></circle>'
        )

    # x labels (every 3h)
    for hour in range(0, 24, 3):
        parts.append(f'<text x="{x(hour):.1f}" y="{h-bottom+20}" fill="{GREY}" font-size="12" text-anchor="middle">{hour:02d}:00</text>')
    parts.append(f'<text x="{left+pw/2:.1f}" y="{h-10}" fill="{GREY}" font-size="12" text-anchor="middle">Hour of day</text>')
    parts.append(f'<text x="16" y="{top+ph/2:.1f}" fill="{GREY}" font-size="12" text-anchor="middle" transform="rotate(-90 16 {top+ph/2:.1f})">Risk score</text>')

    svg = f'<svg viewBox="0 0 {w} {h}" width="100%" xmlns="http://www.w3.org/2000/svg">{"".join(parts)}</svg>'

    active = ", ".join(f"{hh:02d}:00" for hh in sorted(profile.active_hours))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>AegisGuard — Behavioral Anomaly Demo</title>
<style>
  body {{ margin:0; background:{INK}; color:#e6eefc; font-family:Inter,Segoe UI,system-ui,sans-serif; padding:32px; }}
  .card {{ max-width:900px; margin:0 auto; background:#111a2e; border:1px solid #223049; border-radius:16px; padding:28px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  p {{ color:#aab8d4; line-height:1.5; }}
  .legend {{ display:flex; gap:20px; flex-wrap:wrap; margin:14px 0 6px; font-size:13px; }}
  .legend span {{ display:inline-flex; align-items:center; gap:7px; }}
  .dot {{ width:11px; height:11px; border-radius:50%; display:inline-block; }}
  .bar {{ width:13px; height:11px; border-radius:2px; background:#2a3b57; display:inline-block; }}
</style></head>
<body><div class="card">
  <h1>Behavioral Anomaly Detection &mdash; {profile.label}</h1>
  <p>The Isolation Forest model learned this user's <b>normal</b> behaviour from the baseline
  (active hours: {active}). The blue line is the <b>risk score</b> the model assigns to activity
  at each hour of the day. Activity during the user's normal night hours scores low (green);
  the same activity during the day is far from the baseline and scores high (red) &mdash; flagged
  as an anomaly.</p>
  <div class="legend">
    <span><span class="dot" style="background:{GREEN}"></span>Normal (risk &lt; {ANOMALY_RISK_THRESHOLD})</span>
    <span><span class="dot" style="background:{RED}"></span>Anomaly (risk &ge; {ANOMALY_RISK_THRESHOLD})</span>
    <span><span class="bar"></span>Normal activity volume (baseline)</span>
  </div>
  {svg}
</div></body></html>"""


def main():
    model, baseline = build_model(PROFILE)
    risks = risk_by_hour(model)
    counts = baseline_counts_by_hour(baseline)

    print(f"Profile: {PROFILE.label}   (baseline samples: {len(baseline)})")
    print("Hour  Risk  Verdict")
    for hour, r in enumerate(risks):
        verdict = "ANOMALY" if r >= ANOMALY_RISK_THRESHOLD else "normal"
        print(f"{hour:02d}:00  {r:4d}  {verdict}")

    html = render_html(PROFILE, risks, counts)
    with open("anomaly_demo.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\nWrote anomaly_demo.html — open it in a browser for the presentation chart.")


if __name__ == "__main__":
    main()
