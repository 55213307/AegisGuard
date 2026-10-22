// Small display helpers shared by the portal pages.

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

function timeAgo(isoOrDate) {
  if (!isoOrDate) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(isoOrDate).getTime()) / 1000));
  if (seconds < 5) return "Just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} day${days === 1 ? "" : "s"} ago`;
  return new Date(isoOrDate).toLocaleDateString("en-US");
}

// endpoint_status values from the API -> badge class and live-dot state.
const ENDPOINT_STATUS_STYLE = {
  Online: { badge: "badge-success", dot: "online" },
  Offline: { badge: "badge-danger", dot: "offline" },
  Connecting: { badge: "badge-warning", dot: "pending" },
  "Not installed": { badge: "badge-warning", dot: "" },
  Unknown: { badge: "badge-warning", dot: "" },
};

function endpointStatusStyle(status) {
  return ENDPOINT_STATUS_STYLE[status] || ENDPOINT_STATUS_STYLE.Unknown;
}

// Behavioral anomaly score (0-100, from the ML model) -> badge style. 70 is
// the alert threshold the model is calibrated to; null means "not scored".
const RISK_ANOMALY_THRESHOLD = 70;

function riskStyle(score) {
  if (score == null) return null;
  if (score >= RISK_ANOMALY_THRESHOLD) return { badge: "badge-danger", label: "High" };
  if (score >= 50) return { badge: "badge-warning", label: "Elevated" };
  return { badge: "badge-success", label: "Normal" };
}
