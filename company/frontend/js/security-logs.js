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

function getFilteredLogs() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const eventType = eventTypeFilter.value;

  return allLogs.filter((log) => {
    const matchesQuery =
      !query ||
      log.endpoint_name.toLowerCase().includes(query) ||
      (log.user || "").toLowerCase().includes(query) ||
      log.description.toLowerCase().includes(query);
    const matchesSeverity = !severity || log.severity === severity;
    const matchesEventType = !eventType || log.event_type === eventType;
    return matchesQuery && matchesSeverity && matchesEventType;
  });
}

function renderLogsTable() {
  const filtered = getFilteredLogs();

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

function csvCell(value) {
  const text = value == null ? "" : String(value);
  // Quote if the cell contains a comma, quote or newline; double embedded quotes.
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

// Exports exactly what the filters currently show — so narrowing Severity to
// Critical/Warning exports only the problematic entries, not the full log.
exportLogsBtn.addEventListener("click", () => {
  const rows = getFilteredLogs();
  if (rows.length === 0) return;

  const header = ["Timestamp", "Endpoint", "User", "Event Type", "Severity", "Description"];
  const lines = [header.map(csvCell).join(",")];
  for (const log of rows) {
    lines.push([
      formatTimestamp(log.timestamp),
      log.endpoint_name,
      log.user || "",
      log.event_type || "",
      SEVERITY_LABEL[log.severity] || log.severity,
      log.description || "",
    ].map(csvCell).join(","));
  }

  // BOM so Excel reads UTF-8 correctly.
  const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "").replace(/(\d{8})(\d{4})/, "$1-$2");
  link.href = url;
  link.download = `aegisguard-security-logs-${stamp}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

loadLogs();
