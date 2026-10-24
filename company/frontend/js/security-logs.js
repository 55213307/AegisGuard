// Info-level events (routine logons, configuration scans) never reach this
// page — the backend already leaves them out, so only these two matter here.
const SEVERITY_BADGE_CLASS = {
  critical: "badge-danger",
  warning: "badge-warning",
};

const SEVERITY_LABEL = {
  critical: "Critical",
  warning: "Warning",
};

let allLogs = [];

const tableBody = document.getElementById("logsTableBody");
const searchInput = document.getElementById("logSearchInput");
const severityFilter = document.getElementById("severityFilter");
const eventTypeFilter = document.getElementById("eventTypeFilter");
const endpointFilter = document.getElementById("endpointFilter");
const userFilter = document.getElementById("userFilter");
const riskFilter = document.getElementById("riskFilter");
const dateRangeFilter = document.getElementById("dateRangeFilter");
const exportLogsBtn = document.getElementById("exportLogsBtn");
const downloadReportBtn = document.getElementById("downloadReportBtn");

function formatTimestamp(isoString) {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// Rebuilds a filter's options from the loaded logs, keeping whatever was
// selected if it's still one of them (it drops out otherwise, e.g. an
// endpoint with no events left in a newly picked date range).
function populateOptions(select, values, placeholder) {
  const current = select.value;
  select.innerHTML =
    `<option value="">${placeholder}</option>` + values.map((v) => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join("");
  if (values.includes(current)) select.value = current;
}

function populateFilterOptions() {
  populateOptions(eventTypeFilter, [...new Set(allLogs.map((log) => log.event_type).filter(Boolean))].sort(), "Event Type: All");
  populateOptions(endpointFilter, [...new Set(allLogs.map((log) => log.endpoint_name).filter(Boolean))].sort(), "Endpoint: All");
  populateOptions(userFilter, [...new Set(allLogs.map((log) => log.user).filter(Boolean))].sort(), "User: All");
}

function getFilteredLogs() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const eventType = eventTypeFilter.value;
  const endpoint = endpointFilter.value;
  const user = userFilter.value;
  const risk = riskFilter.value;
  const minRisk = risk === "anomaly" ? RISK_ANOMALY_THRESHOLD : risk === "elevated" ? 50 : null;

  return allLogs.filter((log) => {
    const matchesQuery =
      !query ||
      log.endpoint_name.toLowerCase().includes(query) ||
      (log.user || "").toLowerCase().includes(query) ||
      log.description.toLowerCase().includes(query);
    const matchesSeverity = !severity || log.severity === severity;
    const matchesEventType = !eventType || log.event_type === eventType;
    const matchesEndpoint = !endpoint || log.endpoint_name === endpoint;
    const matchesUser = !user || log.user === user;
    const matchesRisk = minRisk === null || (log.risk_score != null && log.risk_score >= minRisk);
    return matchesQuery && matchesSeverity && matchesEventType && matchesEndpoint && matchesUser && matchesRisk;
  });
}

// Plain-English list of whatever filters are narrowing the table right now,
// for the PDF report to say up front what it does and doesn't cover.
function describeFilters() {
  const parts = [];
  const days = dateRangeFilter.options[dateRangeFilter.selectedIndex].textContent;
  parts.push(days);
  if (severityFilter.value) parts.push(`Severity: ${SEVERITY_LABEL[severityFilter.value]}`);
  if (eventTypeFilter.value) parts.push(`Event Type: ${eventTypeFilter.value}`);
  if (endpointFilter.value) parts.push(`Endpoint: ${endpointFilter.value}`);
  if (userFilter.value) parts.push(`User: ${userFilter.value}`);
  if (riskFilter.value) parts.push(riskFilter.options[riskFilter.selectedIndex].textContent);
  if (searchInput.value.trim()) parts.push(`Search: "${searchInput.value.trim()}"`);
  return parts.join("; ");
}

function riskCell(log) {
  const style = riskStyle(log.risk_score);
  if (!style) return "--";
  return `<span class="badge ${style.badge}" title="${escapeHtml(style.label)}">${log.risk_score}</span>`;
}

function renderLogsTable() {
  const filtered = getFilteredLogs();

  if (filtered.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="7" class="empty-state">No log entries match your filters.</td></tr>`;
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
          <td>${riskCell(log)}</td>
          <td>${log.description}${log.risk_reason ? `<span class="risk-reason">${escapeHtml(log.risk_reason)}</span>` : ""}</td>
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
    populateFilterOptions();
    renderLogsTable();
  } catch (err) {
    console.error("Failed to load security logs", err);
    tableBody.innerHTML = `<tr><td colspan="7" class="empty-state">Could not load security logs. Please try again later.</td></tr>`;
  }
}

searchInput.addEventListener("input", renderLogsTable);
severityFilter.addEventListener("change", renderLogsTable);
riskFilter.addEventListener("change", renderLogsTable);
eventTypeFilter.addEventListener("change", renderLogsTable);
endpointFilter.addEventListener("change", renderLogsTable);
userFilter.addEventListener("change", renderLogsTable);
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

  const header = ["Timestamp", "Endpoint", "User", "Event Type", "Severity", "Risk Score", "Risk Reason", "Description"];
  const lines = [header.map(csvCell).join(",")];
  for (const log of rows) {
    lines.push([
      formatTimestamp(log.timestamp),
      log.endpoint_name,
      log.user || "",
      log.event_type || "",
      SEVERITY_LABEL[log.severity] || log.severity,
      log.risk_score == null ? "" : log.risk_score,
      log.risk_reason || "",
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

// Exports exactly the rows the table currently shows — same filters as the
// CSV export, formatted as a branded PDF.
downloadReportBtn.addEventListener("click", async () => {
  const rows = getFilteredLogs();
  downloadReportBtn.disabled = true;
  const original = downloadReportBtn.textContent;
  downloadReportBtn.textContent = "Preparing report…";
  try {
    await apiDownload("/api/security-logs/report", "aegisguard-security-report.pdf", {
      body: { items: rows, filters_summary: describeFilters() },
    });
  } catch (err) {
    await Dialogs.notice({ title: "Could not create the report", message: err.message || "Please try again." });
  } finally {
    downloadReportBtn.disabled = false;
    downloadReportBtn.textContent = original;
  }
});

loadLogs();
