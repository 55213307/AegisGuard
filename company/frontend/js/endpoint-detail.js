// Endpoint detail dialog (Figma "06 Endpoint Detail"), shared by Account
// Management and Live Monitoring. Both pages include the same markup
// (#detailScrim). While open, it shows the computer's screen live: one
// frame per second, which also tells the screen agent to speed up.

const EndpointDetail = (() => {
  const LIVE_REFRESH_MS = 1000;
  // Frames older than this are shown as stale rather than "live".
  const STALE_AFTER_SECONDS = 15;

  const scrim = document.getElementById("detailScrim");
  const errorEl = document.getElementById("detailError");
  const refreshBtn = document.getElementById("detailRefreshBtn");
  const downloadBtn = document.getElementById("detailDownloadBtn");
  const screenImg = document.getElementById("detailScreenImg");
  const placeholder = document.getElementById("detailScreenPlaceholder");
  const liveDot = document.getElementById("detailLiveDot");
  const liveText = document.getElementById("detailLiveText");
  const activityEl = document.getElementById("detailActivity");

  const SEVERITY_BADGE = { Critical: "badge-danger", Warning: "badge-warning", Info: "badge-success" };

  let account = null;
  let onChanged = () => {};
  let liveTimer = null;
  let frameTime = null;
  let frameUrl = null;

  function describeStatus() {
    switch (account.endpoint_status) {
      case "Online":
        return `Online · last seen ${timeAgo(account.last_seen_time).toLowerCase()}`;
      case "Offline":
        return `Offline · last seen ${timeAgo(account.last_seen_time).toLowerCase()}`;
      case "Connecting":
        return "Connecting to AegisGuard…";
      case "Not installed":
        return "Not installed yet · download the installer and run it on this computer";
      default:
        return "Status unavailable · the monitoring service can't be reached";
    }
  }

  function renderLiveLine() {
    const ageSeconds = frameTime ? (Date.now() - frameTime) / 1000 : null;
    if (ageSeconds !== null && ageSeconds < STALE_AFTER_SECONDS) {
      liveDot.dataset.state = "online";
      liveText.textContent = `Live · updated ${timeAgo(new Date(frameTime)).toLowerCase()}`;
    } else if (ageSeconds !== null) {
      liveDot.dataset.state = "offline";
      liveText.textContent = `Screen not updating · last frame ${timeAgo(new Date(frameTime)).toLowerCase()}`;
    } else {
      liveDot.dataset.state = endpointStatusStyle(account.endpoint_status).dot;
      liveText.textContent = describeStatus();
    }
  }

  function showFrame(blob, ageSeconds) {
    const url = URL.createObjectURL(blob);
    screenImg.onload = () => {
      if (frameUrl) URL.revokeObjectURL(frameUrl);
      frameUrl = url;
    };
    screenImg.src = url;
    screenImg.hidden = false;
    // placeholder is an <svg>: it has no .hidden property, only the attribute.
    placeholder.toggleAttribute("hidden", true);
    frameTime = Date.now() - (Number.isFinite(ageSeconds) ? ageSeconds * 1000 : 0);
  }

  function clearFrame() {
    screenImg.hidden = true;
    screenImg.removeAttribute("src");
    placeholder.toggleAttribute("hidden", false);
    if (frameUrl) URL.revokeObjectURL(frameUrl);
    frameUrl = null;
    frameTime = null;
  }

  async function pollScreen() {
    const current = account;
    if (!current) return;
    try {
      if (current.endpoint_name) {
        const result = await apiFetchImage(`/api/accounts/${current.id}/screen?live=true`);
        if (account !== current) return; // dialog closed or switched meanwhile
        if (result) showFrame(result.blob, Number(result.headers.get("X-Frame-Age")));
      }
    } catch (err) {
      console.error("Failed to load screen frame", err);
    }
    if (account === current) {
      renderLiveLine();
      liveTimer = setTimeout(pollScreen, LIVE_REFRESH_MS);
    }
  }

  function render(next) {
    account = next;
    const style = endpointStatusStyle(account.endpoint_status);
    document.getElementById("detailTitle").textContent = account.endpoint_name || account.employee_username;
    const badge = document.getElementById("detailStatusBadge");
    badge.className = `badge ${style.badge}`;
    badge.textContent = account.endpoint_status;

    const rows = [
      ["Assigned User", account.employee_username],
      ["IP Address", account.ip_address || "—"],
      ["Operating System", account.os_name || "—"],
      ["Agent Version", account.agent_version || "—"],
      ["Last Seen", timeAgo(account.last_seen_time)],
      ["Risk Score", "—"],
    ];
    document.getElementById("detailInfoList").innerHTML = rows
      .map(([label, value]) => `<div class="info-row"><dt>${label}</dt><dd>${escapeHtml(value)}</dd></div>`)
      .join("");
    renderLiveLine();
  }

  function formatEventTime(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "";
    const sameDay = date.toDateString() === new Date().toDateString();
    const time = date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
    return sameDay ? time : `${date.toLocaleDateString("en-US", { month: "short", day: "numeric" })} ${time}`;
  }

  async function loadActivity(forAccount) {
    activityEl.innerHTML = `<p class="detail-empty">Loading recent activity…</p>`;
    try {
      const data = await apiFetch(`/api/accounts/${forAccount.id}/events?limit=15`);
      if (account !== forAccount) return; // dialog switched/closed meanwhile
      if (!data.items.length) {
        activityEl.innerHTML = `<p class="detail-empty">No activity recorded for this endpoint yet.</p>`;
        return;
      }
      activityEl.innerHTML = data.items
        .map((e) => {
          const label = e.event_type || e.severity;
          const badge = SEVERITY_BADGE[e.severity] || "badge-success";
          const desc = e.rule_description || "";
          const user = e.event_user ? ` · ${escapeHtml(e.event_user)}` : "";
          return `
            <div class="activity-row">
              <span class="activity-time">${escapeHtml(formatEventTime(e.event_time))}</span>
              <span class="badge ${badge}">${escapeHtml(label)}</span>
              <span class="activity-desc">${escapeHtml(desc)}${user}</span>
            </div>`;
        })
        .join("");
    } catch (err) {
      if (account !== forAccount) return;
      activityEl.innerHTML = `<p class="detail-empty">Could not load recent activity.</p>`;
    }
  }

  function open(nextAccount, options = {}) {
    close();
    onChanged = options.onChanged || (() => {});
    errorEl.textContent = "";
    render(nextAccount);
    scrim.classList.add("open");
    pollScreen();
    loadActivity(nextAccount);
  }

  function close() {
    clearTimeout(liveTimer);
    liveTimer = null;
    account = null;
    clearFrame();
    scrim.classList.remove("open");
  }

  document.getElementById("closeDetailBtn").addEventListener("click", close);
  scrim.addEventListener("click", (event) => {
    if (event.target === scrim) close();
  });

  refreshBtn.addEventListener("click", async () => {
    if (!account) return;
    errorEl.textContent = "";
    refreshBtn.disabled = true;
    try {
      render(await apiFetch(`/api/accounts/${account.id}`));
      onChanged();
    } catch (err) {
      errorEl.textContent = err.message || "Could not refresh this endpoint. Please try again.";
    } finally {
      refreshBtn.disabled = false;
    }
  });

  downloadBtn.addEventListener("click", async () => {
    if (!account) return;
    errorEl.textContent = "";
    downloadBtn.disabled = true;
    try {
      await apiDownload(`/api/accounts/${account.id}/installer`, `AegisGuard-Installer-${account.employee_username}.cmd`);
      onChanged();
    } catch (err) {
      errorEl.textContent = err.message || "Could not download the installer. Please try again.";
    } finally {
      downloadBtn.disabled = false;
    }
  });

  return { open, close };
})();
