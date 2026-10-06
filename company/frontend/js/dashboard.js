// Company dashboard: one /api/dashboard call feeds the stat cards, the 7-day
// alert chart, the severity donut, the service grid and recent alerts.

const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITY_COLORS = { Info: "#3ddc84", Warning: "#fbbf24", Critical: "#fb7185" };
const SEVERITY_DOT = { Critical: "danger", Warning: "warning", Info: "success" };

function renderWelcomeHeading() {
  const el = document.getElementById("welcomeHeading");
  if (!el) return;
  const hour = new Date().getHours();
  const part = hour < 12 ? "Morning" : hour < 18 ? "Afternoon" : "Evening";
  el.textContent = `Good ${part}, ${sessionStorage.getItem("username") || "there"}`;
}

function renderStats(stats) {
  const map = {
    totalEndpoints: stats.total_endpoints,
    online: stats.online,
    offline: stats.offline,
    events24h: stats.events_24h,
    critical24h: stats.critical_24h,
    platformStatus: stats.platform_status,
  };
  document.querySelectorAll("[data-stat]").forEach((el) => {
    const value = map[el.dataset.stat];
    if (value !== undefined) el.textContent = value;
  });
}

function svgEl(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

let lastTimeline = [];

// Sized to its container (which flexes to fill the row), so the bars get
// taller without the viewBox stretch distorting the text. animate=true grows
// the bars up from the baseline on first render.
function renderTimelineChart(points, animate = false) {
  lastTimeline = points;
  const host = document.getElementById("eventsChart");
  host.innerHTML = "";
  const width = host.clientWidth || 640;
  const height = host.clientHeight || 180;
  const padBottom = 24;
  const padTop = 18;
  const plot = Math.max(10, height - padTop - padBottom);
  const baseline = padTop + plot;
  const max = Math.max(1, ...points.map((p) => p.count));
  const slot = width / points.length;
  const barW = Math.min(52, slot * 0.5);

  const svg = svgEl("svg", {
    class: "chart-svg",
    viewBox: `0 0 ${width} ${height}`,
    preserveAspectRatio: "none",
    role: "img",
  });

  const bars = [];
  points.forEach((p, i) => {
    const cx = i * slot + slot / 2;
    const barH = p.count > 0 ? Math.max((p.count / max) * plot, 3) : 0;
    const y = baseline - barH;
    const rect = svgEl("rect", {
      class: "chart-bar", x: cx - barW / 2, width: barW, rx: 4,
      y: animate ? baseline : y, height: animate ? 0 : barH,
      style: `transition-delay:${i * 40}ms`,
    });
    svg.appendChild(rect);
    bars.push({ rect, y, barH });
    if (p.count > 0) {
      const value = svgEl("text", { class: "chart-value", x: cx, y: y - 7, "text-anchor": "middle" });
      value.textContent = p.count;
      svg.appendChild(value);
    }
    const label = svgEl("text", { class: "chart-axis", x: cx, y: height - 7, "text-anchor": "middle" });
    label.textContent = new Date(p.date).toLocaleDateString("en-US", { month: "short", day: "numeric" });
    svg.appendChild(label);
  });

  host.appendChild(svg);

  if (animate) {
    // Paint the flat (height 0) state first, then apply the real heights so
    // the CSS transition has something to animate between.
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        bars.forEach(({ rect, y, barH }) => {
          rect.setAttribute("y", y);
          rect.setAttribute("height", barH);
        });
      })
    );
  }
}

function renderSeverityDonut(severity, animate = false) {
  const host = document.getElementById("severityDonut");
  host.innerHTML = "";
  const order = ["Critical", "Warning", "Info"];
  const total = order.reduce((sum, k) => sum + (severity[k] || 0), 0);

  const size = 140;
  const r = 52;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const svg = svgEl("svg", { class: "donut-svg", viewBox: `0 0 ${size} ${size}` });

  const arcs = [];
  if (total === 0) {
    svg.appendChild(svgEl("circle", { cx, cy, r, fill: "none", stroke: "var(--border)", "stroke-width": 18 }));
  } else {
    let offset = 0;
    for (const key of order) {
      const value = severity[key] || 0;
      if (!value) continue;
      const len = (value / total) * circumference;
      const circle = svgEl("circle", {
        cx, cy, r, fill: "none", stroke: SEVERITY_COLORS[key], "stroke-width": 18,
        "stroke-dasharray": animate ? `0 ${circumference}` : `${len} ${circumference - len}`,
        "stroke-dashoffset": -offset,
        transform: `rotate(-90 ${cx} ${cy})`,
      });
      svg.appendChild(circle);
      arcs.push({ circle, len });
      offset += len;
    }
  }
  const totalText = svgEl("text", { class: "donut-total", x: cx, y: cy - 2, "text-anchor": "middle" });
  totalText.textContent = total;
  svg.appendChild(totalText);
  const totalLabel = svgEl("text", { class: "donut-sub", x: cx, y: cy + 16, "text-anchor": "middle" });
  totalLabel.textContent = "alerts";
  svg.appendChild(totalLabel);
  host.appendChild(svg);

  if (animate) {
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        arcs.forEach(({ circle, len }) => circle.setAttribute("stroke-dasharray", `${len} ${circumference - len}`));
      })
    );
  }

  const legend = document.createElement("ul");
  legend.className = "donut-legend";
  legend.innerHTML = order
    .map(
      (k) => `<li><span class="legend-dot" style="background:${SEVERITY_COLORS[k]}"></span>${k}<span class="legend-count">${severity[k] || 0}</span></li>`
    )
    .join("");
  host.appendChild(legend);
}

function renderServices(services) {
  const order = ["api_server", "database", "wazuh_manager", "ingestion"];
  document.querySelectorAll("#serviceGrid .service-card").forEach((card, i) => {
    const s = services[order[i]];
    if (!s) return;
    card.querySelector(".service-dot").dataset.status = s.status;
    card.querySelector(".service-state").textContent = s.label;
  });
}

function renderAlerts(alerts) {
  const list = document.getElementById("alertList");
  list.innerHTML = "";
  if (!alerts.length) {
    list.innerHTML = `<li class="alert-item"><span class="alert-text"><span class="alert-title">No alerts yet.</span></span></li>`;
    return;
  }
  list.innerHTML = alerts
    .map(
      (a) => `
      <li class="alert-item">
        <span class="alert-dot ${SEVERITY_DOT[a.severity] || "success"}"></span>
        <span class="alert-text">
          <span class="alert-title">${escapeHtml(a.rule_description || a.event_type || a.severity)}</span>
          <span class="alert-meta">${escapeHtml(a.endpoint_name)} &middot; ${timeAgo(a.event_time)}</span>
        </span>
      </li>`
    )
    .join("");
}

let animatedOnce = false;

async function loadDashboard() {
  try {
    const data = await apiFetch("/api/dashboard");
    renderStats(data.stats);
    // Animate only on the first load, not on the periodic refresh.
    renderTimelineChart(data.timeline_7d, !animatedOnce);
    renderSeverityDonut(data.severity_7d, !animatedOnce);
    renderServices(data.services);
    renderAlerts(data.recent_alerts);
    animatedOnce = true;
  } catch (err) {
    console.error("Failed to load dashboard", err);
  }
}

// The bar chart is sized to its container, so re-render it when the window
// resizes (no animation).
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (lastTimeline.length) renderTimelineChart(lastTimeline, false);
  }, 150);
});

renderWelcomeHeading();
loadDashboard();
setInterval(loadDashboard, 30000);
