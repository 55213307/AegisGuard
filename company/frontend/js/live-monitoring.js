const STATUS_BADGE_CLASS = {
  normal: "badge-success",
  suspicious: "badge-warning",
  locked: "badge-danger",
  offline: "badge-warning",
};

const STATUS_LABEL = {
  normal: "Normal",
  suspicious: "Suspicious",
  locked: "Locked",
  offline: "Offline",
};

let allEndpoints = [];

const grid = document.getElementById("endpointGrid");
const searchInput = document.getElementById("searchInput");
const statusFilter = document.getElementById("statusFilter");

function renderEndpointGrid() {
  const query = searchInput.value.trim().toLowerCase();
  const status = statusFilter.value;

  const filtered = allEndpoints.filter((endpoint) => {
    const matchesQuery =
      !query ||
      endpoint.hostname.toLowerCase().includes(query) ||
      (endpoint.user || "").toLowerCase().includes(query);
    const matchesStatus = !status || endpoint.status === status;
    return matchesQuery && matchesStatus;
  });

  grid.innerHTML = "";

  if (filtered.length === 0) {
    grid.innerHTML = `<p class="empty-state">No endpoints match your search.</p>`;
    return;
  }

  filtered.forEach((endpoint) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "endpoint-card";
    card.innerHTML = `
      <div class="endpoint-card-preview">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/></svg>
      </div>
      <div class="endpoint-card-body">
        <div class="endpoint-card-row">
          <span class="endpoint-card-name">${endpoint.hostname}</span>
          <span class="badge ${STATUS_BADGE_CLASS[endpoint.status] || "badge-success"}">${STATUS_LABEL[endpoint.status] || endpoint.status}</span>
        </div>
        <p class="endpoint-card-user">User: ${endpoint.user || "--"}</p>
      </div>
    `;
    card.addEventListener("click", () => openEndpointDetail(endpoint.id));
    grid.appendChild(card);
  });
}

async function loadEndpoints() {
  try {
    const data = await apiFetch("/api/endpoints");
    allEndpoints = data.items || [];
    renderEndpointGrid();
  } catch (err) {
    console.error("Failed to load endpoints", err);
    grid.innerHTML = `<p class="empty-state">Could not load endpoints. Please try again later.</p>`;
  }
}

searchInput.addEventListener("input", renderEndpointGrid);
statusFilter.addEventListener("change", renderEndpointGrid);

/* Endpoint detail modal */
const detailScrim = document.getElementById("detailScrim");
const closeDetailBtn = document.getElementById("closeDetailBtn");
const detailHostname = document.getElementById("detailHostname");
const detailStatusBadge = document.getElementById("detailStatusBadge");
const detailInfoList = document.getElementById("detailInfoList");
const detailActivityList = document.getElementById("detailActivityList");
const forceRefreshBtn = document.getElementById("forceRefreshBtn");
const isolateBtn = document.getElementById("isolateBtn");
const lockAccountBtn = document.getElementById("lockAccountBtn");

let activeEndpointId = null;

const INFO_FIELDS = [
  ["Assigned User", "user"],
  ["IP Address", "ip_address"],
  ["Operating System", "os"],
  ["Agent Version", "agent_version"],
  ["Last Seen", "last_seen"],
  ["Risk Score", "risk_score"],
];

function renderEndpointDetail(detail) {
  detailHostname.textContent = detail.hostname;
  detailStatusBadge.className = `badge ${STATUS_BADGE_CLASS[detail.status] || "badge-success"}`;
  detailStatusBadge.textContent = STATUS_LABEL[detail.status] || detail.status;

  detailInfoList.innerHTML = INFO_FIELDS.map(
    ([label, key]) => `
      <div class="info-row">
        <dt>${label}</dt>
        <dd>${detail[key] ?? "--"}</dd>
      </div>
    `
  ).join("");

  const activity = detail.recent_activity || [];
  detailActivityList.innerHTML = activity.length
    ? activity
        .map(
          (event) => `
        <div class="activity-row">
          <span class="activity-time">${event.time}</span>
          <span class="badge ${STATUS_BADGE_CLASS[event.severity] || "badge-success"}">${event.event_type}</span>
          <span class="activity-desc">${event.description}</span>
        </div>
      `
        )
        .join("")
    : `<p class="empty-state">No recent activity recorded.</p>`;
}

async function openEndpointDetail(endpointId) {
  activeEndpointId = endpointId;
  detailScrim.classList.add("open");
  try {
    const detail = await apiFetch(`/api/endpoints/${endpointId}`);
    renderEndpointDetail(detail);
  } catch (err) {
    console.error("Failed to load endpoint detail", err);
  }
}

function closeEndpointDetail() {
  detailScrim.classList.remove("open");
  activeEndpointId = null;
}

closeDetailBtn.addEventListener("click", closeEndpointDetail);
detailScrim.addEventListener("click", (event) => {
  if (event.target === detailScrim) closeEndpointDetail();
});

async function performEndpointAction(action) {
  if (!activeEndpointId) return;
  try {
    await apiFetch(`/api/endpoints/${activeEndpointId}/${action}`, { method: "POST" });
    const detail = await apiFetch(`/api/endpoints/${activeEndpointId}`);
    renderEndpointDetail(detail);
    loadEndpoints();
  } catch (err) {
    console.error(`Failed to ${action} endpoint`, err);
  }
}

forceRefreshBtn.addEventListener("click", () => performEndpointAction("refresh"));
isolateBtn.addEventListener("click", () => performEndpointAction("isolate"));
lockAccountBtn.addEventListener("click", () => performEndpointAction("lock-account"));

loadEndpoints();
