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
  const lockBtn = document.getElementById("detailLockBtn");
  const lockBanner = document.getElementById("detailLockBanner");
  const overtimeBtn = document.getElementById("detailOvertimeBtn");
  const overtimeBanner = document.getElementById("detailOvertimeBanner");
  const maintenanceBanner = document.getElementById("detailMaintenanceBanner");
  const downloadBtn =document.getElementById("detailDownloadBtn");
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

  // How far the behavior model has got in learning this computer's own activity.
  function learningText(a) {
    if (!a.endpoint_name) return "—";
    if (!a.learning_state) return "Not trained yet";
    if (a.learning_state === "learned") return "Learned from this computer";
    return `Learning · ${a.learning_actions} of ${a.learning_needed} actions`;
  }

  function riskText(score) {
    const style = riskStyle(score);
    return style ? `${score} \u00b7 ${style.label}` : "—";
  }

  const isLocked = () => account && account.employee_status === "Locked";

  // The lock banner and the Lock / Unlock button follow the account's state.
  function renderLock() {
    const locked = isLocked();
    lockBanner.hidden = !locked;
    if (locked) {
      const since = account.locked_at ? ` since ${timeAgo(account.locked_at).toLowerCase()}` : "";
      lockBanner.textContent = `This computer is locked${since}. ${account.lock_reason || ""}`.trim();
    }
    lockBtn.textContent = locked ? "Unlock Computer" : "Lock Computer";
    lockBtn.className = locked ? "btn btn-primary" : "btn btn-ghost";
    lockBtn.disabled = !account.endpoint_name; // nothing to lock until a computer is enrolled
  }

  // "22:00" -> minutes from now until the next 22:00; "3" or "1.5" -> that many hours.
  // null when it isn't one of those, or is longer than 12 hours.
  function overtimeMinutes(text) {
    let minutes;
    const clock = text.match(/^(\d{1,2}):(\d{2})$/);
    if (clock) {
      if (Number(clock[1]) > 23 || Number(clock[2]) > 59) return null;
      const target = new Date();
      target.setHours(Number(clock[1]), Number(clock[2]), 0, 0);
      if (target <= new Date()) target.setDate(target.getDate() + 1);
      minutes = Math.ceil((target - new Date()) / 60000);
    } else if (/^\d+(\.\d+)?$/.test(text)) {
      minutes = Math.round(parseFloat(text) * 60);
    } else {
      return null;
    }
    return minutes >= 1 && minutes <= 720 ? minutes : null;
  }

  const overtimeActive = () => account && account.overtime_until && new Date(account.overtime_until) > new Date();

  // While overtime is approved, working late or at a weekend isn't treated as suspicious.
  function renderOvertime() {
    const active = overtimeActive();
    overtimeBanner.hidden = !active;
    if (active) {
      const until = new Date(account.overtime_until).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
      overtimeBanner.textContent = `Overtime approved until ${until}. Working outside the usual hours isn't flagged; what is run still is.`;
    }
    overtimeBtn.textContent = active ? "End Overtime" : "Allow Overtime";
    overtimeBtn.disabled = !account.endpoint_name;
  }

  const clock = (iso) => new Date(iso).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  const hasWindow = () => account && account.maintenance_from && account.maintenance_until;
  const windowActive = () => hasWindow() && new Date(account.maintenance_until) > new Date();

  // While the installer is at work its events aren't checked; say from when to when.
  function renderMaintenance() {
    maintenanceBanner.hidden = !windowActive();
    if (windowActive()) {
      maintenanceBanner.textContent = `Setup exemption ${clock(account.maintenance_from)} to ${clock(account.maintenance_until)}. Events from this computer aren't checked until then.`;
    }
  }

  function render(next) {
    account = next;
    const style = endpointStatusStyle(account.endpoint_status);
    document.getElementById("detailTitle").textContent = account.endpoint_name || account.employee_username;
    const badge = document.getElementById("detailStatusBadge");
    badge.className = `badge ${style.badge}`;
    badge.textContent = account.endpoint_status;

    renderLock();
    renderOvertime();
    renderMaintenance();

    const rows = [
      ["Assigned User", account.employee_username],
      ["IP Address", account.ip_address || "—"],
      ["Operating System", account.os_name || "—"],
      ["Agent Version", account.agent_version || "—"],
      ["Last Seen", timeAgo(account.last_seen_time)],
      ["Risk Score (24h peak)", riskText(account.risk_24h)],
      ["Behavior Model", learningText(account)],
    ];
    if (hasWindow()) {
      const day = new Date(account.maintenance_from).toLocaleDateString("en-US", { month: "short", day: "numeric" });
      rows.push(["Setup Exemption", `${day}, ${clock(account.maintenance_from)} to ${clock(account.maintenance_until)}`]);
    }
    const hours = account.work_start && account.work_end ? `${account.work_start}\u2013${account.work_end}` : "Learned from activity";
    document.getElementById("detailInfoList").innerHTML =
      rows.map(([label, value]) => `<div class="info-row"><dt>${label}</dt><dd>${escapeHtml(value)}</dd></div>`).join("") +
      `<div class="info-row"><dt>Working Hours</dt><dd>${escapeHtml(hours)} ${account.endpoint_name ? `<button type="button" class="link-btn" id="detailHoursBtn">Edit</button>` : ""}</dd></div>`;
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
    activityEl.innerHTML = `<p class="detail-empty">Loading recent problems…</p>`;
    try {
      const data = await apiFetch(`/api/accounts/${forAccount.id}/events?limit=15`);
      if (account !== forAccount) return; // dialog switched/closed meanwhile
      if (!data.items.length) {
        activityEl.innerHTML = `<p class="detail-empty">No problems detected on this endpoint.</p>`;
        return;
      }
      activityEl.innerHTML = data.items
        .map((e) => {
          const label = e.event_type || e.severity;
          const badge = SEVERITY_BADGE[e.severity] || "badge-success";
          const desc = e.rule_description || "";
          const user = e.event_user ? ` · ${escapeHtml(e.event_user)}` : "";
          const risk = riskStyle(e.risk_score);
          const riskBadge = risk ? `<span class="badge ${risk.badge}">${e.risk_score}</span> ` : "";
          const reason = e.risk_reason ? `<span class="risk-reason">${escapeHtml(e.risk_reason)}</span>` : "";
          return `
            <div class="activity-row">
              <span class="activity-time">${escapeHtml(formatEventTime(e.event_time))}</span>
              <span class="badge ${badge}">${escapeHtml(label)}</span>
              <span class="activity-desc">${riskBadge}${escapeHtml(desc)}${user}${reason}</span>
            </div>`;
        })
        .join("");
    } catch (err) {
      if (account !== forAccount) return;
      activityEl.innerHTML = `<p class="detail-empty">Could not load recent problems.</p>`;
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

  // Declare (or clear) the employee's working hours; the behavior model is retrained
  // right away, so it learns the new hours without waiting.
  async function editWorkHours() {
    if (!account || !account.endpoint_name) return;
    const current = account.work_start && account.work_end ? `${account.work_start}-${account.work_end}` : "";
    const answer = window.prompt(
      `Working hours for ${account.endpoint_name}, as start-end in 24-hour time, e.g. 09:00-18:00.\nLeave it empty to let AegisGuard learn them from the computer's activity.`,
      current
    );
    if (answer === null) return;
    const text = answer.trim();
    let request = { method: "DELETE" };
    if (text) {
      const parts = text.match(/^(\d{1,2}:\d{2})\s*(?:-|\u2013|to)\s*(\d{1,2}:\d{2})$/i);
      if (!parts) {
        errorEl.textContent = "Enter the hours like 09:00-18:00.";
        return;
      }
      request = { method: "PUT", body: { start: parts[1], end: parts[2] } };
    }
    errorEl.textContent = "";
    try {
      render(await apiFetch(`/api/accounts/${account.id}/work-hours`, request));
      onChanged();
    } catch (err) {
      errorEl.textContent = err.message || "Could not save the working hours. Please try again.";
    }
  }

  document.getElementById("detailInfoList").addEventListener("click", (event) => {
    if (event.target.id === "detailHoursBtn") editWorkHours();
  });

  overtimeBtn.addEventListener("click", async () => {
    if (!account) return;
    let request = { method: "DELETE" };
    if (!overtimeActive()) {
      const answer = window.prompt(
        `Allow overtime on ${account.endpoint_name || account.employee_username} until what time (24-hour, e.g. 22:00), or for how many hours (e.g. 3)?`,
        "3"
      );
      if (answer === null) return;
      const minutes = overtimeMinutes(answer.trim());
      if (minutes === null) {
        errorEl.textContent = "Enter a time like 22:00, or a number of hours like 3 (at most 12 hours).";
        return;
      }
      request = { method: "POST", body: { minutes } };
    }
    errorEl.textContent = "";
    overtimeBtn.disabled = true;
    try {
      render(await apiFetch(`/api/accounts/${account.id}/overtime`, request));
      onChanged();
    } catch (err) {
      errorEl.textContent = err.message || "Could not change overtime. Please try again.";
    } finally {
      overtimeBtn.disabled = !account || !account.endpoint_name;
    }
  });

  lockBtn.addEventListener("click", async () => {
    if (!account) return;
    const locking = !isLocked();
    if (locking && !window.confirm(`Lock ${account.endpoint_name || account.employee_username}? The user will be locked out of this computer until you unlock it here.`)) return;
    errorEl.textContent = "";
    lockBtn.disabled = true;
    try {
      render(await apiFetch(`/api/accounts/${account.id}/${locking ? "lock" : "unlock"}`, { method: "POST" }));
      onChanged();
    } catch (err) {
      errorEl.textContent = err.message || "Could not change the lock. Please try again.";
    } finally {
      lockBtn.disabled = !account || !account.endpoint_name;
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
