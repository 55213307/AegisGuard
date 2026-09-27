requireAuth();

const logoutBtn = document.getElementById("logoutBtn");
const welcomeHeading = document.getElementById("welcomeHeading");

logoutBtn.addEventListener("click", () => {
  clearSession();
  window.location.href = "login.html";
});

function getTimeOfDayGreeting(hour = new Date().getHours()) {
  if (hour < 12) return "Morning";
  if (hour < 18) return "Afternoon";
  return "Evening";
}

function renderWelcomeHeading() {
  if (!welcomeHeading) return;
  const username = sessionStorage.getItem("username") || "Admin";
  welcomeHeading.textContent = `Good ${getTimeOfDayGreeting()} ${username}`;
}

renderWelcomeHeading();

function renderStats(data) {
  const map = {
    totalCustomers: data.total_customers,
    activeCustomers: data.active_customers,
    monitoringAccounts: data.monitoring_accounts,
    lockedAccounts: data.locked_accounts,
    pendingAccounts: data.pending_accounts,
    platformStatus: data.platform_status,
  };

  document.querySelectorAll("[data-stat]").forEach((el) => {
    const value = map[el.dataset.stat];
    if (value !== undefined) {
      el.textContent = value;
    }
  });
}

async function loadDashboardSummary() {
  // Only dashboard.html has these stat cards; other pages that also load
  // this script (for the shared sidebar/logout) can skip the fetch.
  if (document.querySelectorAll("[data-stat]").length === 0) return;

  try {
    const summary = await apiFetch("/api/dashboard/summary");
    renderStats(summary);
  } catch (err) {
    console.error("Failed to load dashboard summary", err);
  }
}

loadDashboardSummary();

const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, value));
  return el;
}

function formatShortDate(isoDate) {
  const [, month, day] = isoDate.split("-");
  return `${Number(month)}/${Number(day)}`;
}

function timeAgo(isoString) {
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(isoString).toLocaleDateString();
}

async function loadCustomerGrowth() {
  const svg = document.getElementById("growthChart");
  if (!svg) return;

  try {
    const data = await apiFetch("/api/dashboard/customer-growth?days=14");
    renderGrowthChart(svg, data.points);
  } catch (err) {
    console.error("Failed to load customer growth", err);
  }
}

function renderGrowthChart(svg, points) {
  svg.innerHTML = "";
  const width = 640;
  const height = 200;
  const paddingBottom = 24;
  const paddingTop = 12;
  const plotHeight = height - paddingBottom - paddingTop;

  const maxCount = Math.max(1, ...points.map((p) => p.count));
  const barWidth = width / points.length;
  const barGap = 8;
  const baselineY = paddingTop + plotHeight;

  const bars = [];

  points.forEach((point, index) => {
    const barHeight = (point.count / maxCount) * plotHeight;
    const x = index * barWidth + barGap / 2;
    const y = paddingTop + (plotHeight - barHeight);

    // Start every bar flat at the baseline, then grow it in on the next
    // frame — the CSS transition on height/y (see dashboard.css) animates
    // the change, with a per-bar delay below for a left-to-right sweep.
    const rect = svgEl("rect", {
      class: "growth-bar",
      x,
      y: baselineY,
      width: Math.max(barWidth - barGap, 2),
      height: 0,
      rx: 3,
      style: `transition-delay: ${index * 35}ms`,
    });
    bars.push({ rect, y, height: Math.max(barHeight, 2) });
    const title = svgEl("title");
    title.textContent = `${formatShortDate(point.date)}: ${point.count} new customer${point.count === 1 ? "" : "s"}`;
    rect.appendChild(title);
    svg.appendChild(rect);

    // Value label above each bar — starts a few px lower and transparent,
    // then rises into place with the same per-bar delay as its bar so the
    // number arrives right as the bar finishes growing.
    const labelY = y - 8;
    const valueLabel = svgEl("text", {
      class: "growth-value-label",
      x: x + (barWidth - barGap) / 2,
      y: labelY + 6,
      "text-anchor": "middle",
      style: `transition-delay: ${index * 35 + 200}ms`,
    });
    valueLabel.textContent = point.count;
    bars[bars.length - 1].valueLabel = valueLabel;
    bars[bars.length - 1].labelY = labelY;
    svg.appendChild(valueLabel);

    // Label every other day so the axis doesn't get crowded.
    if (index % 2 === 0) {
      const label = svgEl("text", {
        class: "growth-axis-label",
        x: x + (barWidth - barGap) / 2,
        y: height - 6,
        "text-anchor": "middle",
      });
      label.textContent = formatShortDate(point.date);
      svg.appendChild(label);
    }
  });

  // Force the browser to paint the flat (height: 0) state before applying
  // the real values, otherwise it collapses the two into one frame and
  // there's nothing to transition between.
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      bars.forEach(({ rect, y, height: h, valueLabel, labelY }) => {
        rect.setAttribute("y", y);
        rect.setAttribute("height", h);
        valueLabel.setAttribute("y", labelY);
        valueLabel.classList.add("visible");
      });
    });
  });
}

const STATUS_COLORS = { active: "#59d69c", pending: "#f2b240", locked: "#ed5966" };
const STATUS_LABELS = { active: "Active", pending: "Pending", locked: "Locked" };

async function loadAccountStatusDistribution() {
  const svg = document.getElementById("statusDonut");
  const legend = document.getElementById("statusLegend");
  if (!svg || !legend) return;

  try {
    const summary = await apiFetch("/api/accounts/summary");
    renderStatusDonut(svg, legend, summary);
  } catch (err) {
    console.error("Failed to load account status distribution", err);
  }
}

function renderStatusDonut(svg, legend, summary) {
  svg.innerHTML = "";
  legend.innerHTML = "";

  const segments = ["active", "pending", "locked"].map((key) => ({ key, value: summary[key] }));
  const total = summary.total;

  const cx = 70;
  const cy = 70;
  const r = 52;
  const strokeWidth = 20;
  const circumference = 2 * Math.PI * r;
  const gapDegrees = total > 0 ? 3 : 0;

  const arcs = [];

  if (total === 0) {
    svg.appendChild(svgEl("circle", { cx, cy, r, fill: "none", stroke: "var(--panel-border)", "stroke-width": strokeWidth }));
  } else {
    let offsetDegrees = -90;
    segments.forEach((segment) => {
      if (segment.value === 0) return;
      const segmentDegrees = (segment.value / total) * 360 - gapDegrees;
      const dashLength = (segmentDegrees / 360) * circumference;

      // Drawn at length 0 first; the real dash length is applied a frame
      // later so the CSS transition (dashboard.css) can animate the arc
      // sweeping into place instead of just appearing.
      const circle = svgEl("circle", {
        cx,
        cy,
        r,
        fill: "none",
        stroke: STATUS_COLORS[segment.key],
        "stroke-width": strokeWidth,
        "stroke-dasharray": `0 ${circumference}`,
        transform: `rotate(${offsetDegrees} ${cx} ${cy})`,
      });
      arcs.push({ circle, dashLength: Math.max(dashLength, 0) });
      const title = svgEl("title");
      title.textContent = `${STATUS_LABELS[segment.key]}: ${segment.value}`;
      circle.appendChild(title);
      svg.appendChild(circle);

      offsetDegrees += (segment.value / total) * 360;
    });
  }

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      arcs.forEach(({ circle, dashLength }) => {
        circle.setAttribute("stroke-dasharray", `${dashLength} ${circumference}`);
      });
    });
  });

  const totalValue = svgEl("text", { class: "donut-total-value", x: cx, y: cy - 2 });
  totalValue.textContent = total;
  svg.appendChild(totalValue);
  const totalLabel = svgEl("text", { class: "donut-total-label", x: cx, y: cy + 16 });
  totalLabel.textContent = "Accounts";
  svg.appendChild(totalLabel);

  segments.forEach((segment) => {
    const li = document.createElement("li");
    li.className = "status-legend-item";
    li.innerHTML = `
      <span class="status-legend-dot" style="background:${STATUS_COLORS[segment.key]}"></span>
      <span>${STATUS_LABELS[segment.key]}</span>
      <span class="status-legend-count">${segment.value}</span>
    `;
    legend.appendChild(li);
  });
}

async function loadRecentActivities() {
  const list = document.getElementById("activityList");
  if (!list) return;

  try {
    const data = await apiFetch("/api/dashboard/activities?limit=8");
    renderActivityList(list, data.items);
  } catch (err) {
    console.error("Failed to load recent activities", err);
  }
}

function renderActivityList(list, items) {
  list.innerHTML = "";

  if (items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "activity-item";
    empty.innerHTML = `<span class="activity-description">No administrative activity yet.</span>`;
    list.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.className = "activity-item";
    li.innerHTML = `
      <span class="activity-description">${item.description}</span>
      <span class="activity-meta">${item.admin_name || "System"} &middot; ${timeAgo(item.created_time)}</span>
    `;
    list.appendChild(li);
  });
}

loadCustomerGrowth();
loadAccountStatusDistribution();
loadRecentActivities();
