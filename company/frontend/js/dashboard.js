const welcomeHeading = document.getElementById("welcomeHeading");

function getTimeOfDayGreeting(hour = new Date().getHours()) {
  if (hour < 12) return "Morning";
  if (hour < 18) return "Afternoon";
  return "Evening";
}

function renderWelcomeHeading() {
  if (!welcomeHeading) return;
  const username = sessionStorage.getItem("username") || "Admin";
  welcomeHeading.textContent = `Good ${getTimeOfDayGreeting()}, ${username}`;
}

renderWelcomeHeading();

function renderStats(data) {
  const map = {
    totalEndpoints: data.total_endpoints,
    normalEndpoints: data.normal_endpoints,
    monitoringEndpoints: data.monitoring_endpoints,
    lockedEndpoints: data.locked_endpoints,
    pendingEndpoints: data.pending_endpoints,
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
  try {
    const summary = await apiFetch("/api/dashboard/summary");
    renderStats(summary);
  } catch (err) {
    console.error("Failed to load dashboard summary", err);
  }
}

function timeAgo(isoString) {
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} day${days === 1 ? "" : "s"} ago`;
  return new Date(isoString).toLocaleDateString();
}

const SEVERITY_DOT = { critical: "danger", warning: "warning", info: "success" };

function renderAlerts(items) {
  const list = document.getElementById("alertList");
  if (!list) return;
  list.innerHTML = "";

  if (!items || items.length === 0) {
    list.innerHTML = `<li class="alert-item"><span class="alert-text"><span class="alert-title">No recent alerts.</span></span></li>`;
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.className = "alert-item";
    li.innerHTML = `
      <span class="alert-dot ${SEVERITY_DOT[item.severity] || "success"}"></span>
      <span class="alert-text">
        <span class="alert-title">${item.description}</span>
        <span class="alert-meta">${item.endpoint_name} &middot; ${timeAgo(item.created_time)}</span>
      </span>
    `;
    list.appendChild(li);
  });
}

async function loadRecentAlerts() {
  try {
    const data = await apiFetch("/api/dashboard/alerts?limit=6");
    renderAlerts(data.items);
  } catch (err) {
    console.error("Failed to load recent alerts", err);
  }
}

function renderServiceStatus(services) {
  const grid = document.getElementById("serviceGrid");
  if (!grid || !services) return;

  const cards = grid.querySelectorAll(".service-card");
  const order = ["api_server", "database", "ml_engine", "file_storage"];

  cards.forEach((card, index) => {
    const key = order[index];
    const service = services[key];
    if (!service) return;
    card.querySelector(".service-dot").dataset.status = service.status;
    card.querySelector(".service-state").textContent = service.label;
  });
}

async function loadServiceStatus() {
  try {
    const data = await apiFetch("/api/dashboard/service-status");
    renderServiceStatus(data);
  } catch (err) {
    console.error("Failed to load platform service status", err);
  }
}

loadDashboardSummary();
loadRecentAlerts();
loadServiceStatus();
