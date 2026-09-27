const SEVERITY_BADGE_CLASS = {
  critical: "badge-danger",
  warning: "badge-warning",
  info: "badge-success",
};

const SEVERITY_LABEL = {
  critical: "Critical",
  warning: "Warning",
  info: "Info",
};

let allLogs = [];

const tableBody = document.getElementById("logsTableBody");
const searchInput = document.getElementById("logSearchInput");
const severityFilter = document.getElementById("severityFilter");
const eventTypeFilter = document.getElementById("eventTypeFilter");
const dateRangeFilter = document.getElementById("dateRangeFilter");
const exportLogsBtn = document.getElementById("exportLogsBtn");

function formatTimestamp(isoString) {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function populateEventTypeOptions() {
  const types = [...new Set(allLogs.map((log) => log.event_type))].sort();
  eventTypeFilter.innerHTML = `<option value="">Event Type: All</option>` +
    types.map((type) => `<option value="${type}">${type}</option>`).join("");
}

function renderLogsTable() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const eventType = eventTypeFilter.value;

  const filtered = allLogs.filter((log) => {
    const matchesQuery =
      !query ||
      log.endpoint_name.toLowerCase().includes(query) ||
      (log.user || "").toLowerCase().includes(query) ||
      log.description.toLowerCase().includes(query);
    const matchesSeverity = !severity || log.severity === severity;
    const matchesEventType = !eventType || log.event_type === eventType;
    return matchesQuery && matchesSeverity && matchesEventType;
  });

  if (filtered.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">No log entries match your filters.</td></tr>`;
    return;
  }

  tableBody.innerHTML = filtered
    .map(
      (log) => `
        <tr>
          <td>${formatTimestamp(log.timestamp)}</td>
          <td>${log.endpoint_name}</td>
          <td>${log.user || "--"}</td>
          <td>${log.event_type}</td>
          <td><span class="badge ${SEVERITY_BADGE_CLASS[log.severity] || "badge-success"}">${SEVERITY_LABEL[log.severity] || log.severity}</span></td>
          <td>${log.description}</td>
        </tr>
      `
    )
    .join("");
}

async function loadLogs() {
  const days = dateRangeFilter.value;
  try {
    const data = await apiFetch(`/api/security-logs?days=${days}`);
    allLogs = data.items || [];
    populateEventTypeOptions();
    renderLogsTable();
  } catch (err) {
    console.error("Failed to load security logs", err);
    tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">Could not load security logs. Please try again later.</td></tr>`;
  }
}

searchInput.addEventListener("input", renderLogsTable);
severityFilter.addEventListener("change", renderLogsTable);
eventTypeFilter.addEventListener("change", renderLogsTable);
dateRangeFilter.addEventListener("change", loadLogs);

exportLogsBtn.addEventListener("click", () => {
  window.open(`/api/security-logs/export?days=${dateRangeFilter.value}`, "_blank");
});

loadLogs();
