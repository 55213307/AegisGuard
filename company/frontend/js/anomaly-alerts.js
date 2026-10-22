// Pop-up and sound alerts for behavior anomalies, on every portal page.
//
// Polls /api/anomalies/feed every few seconds. The first poll of a session
// only sets a cursor (stored in localStorage, so moving between pages neither
// replays nor misses anything); after that each new anomaly the ML model flags
// shows a toast and sounds an alarm. A "anomaly-detected" event is also fired,
// so the page can refresh what it shows (Live Monitoring marks the computer).
//
// Browsers only let a page make sound after the user has interacted with it,
// so an alarm that arrives before that waits and plays on the first click.

(function () {
  if (typeof getToken !== "function" || !getToken()) return;

  const POLL_MS = 5000;
  const CURSOR_KEY = "anomalyAlertCursor";
  const MUTE_KEY = "anomalyAlertMuted";
  const MAX_AGE_MS = 10 * 60 * 1000; // never alert about anomalies older than this
  const MAX_TOASTS = 4;
  const TOAST_MS = 60 * 1000;

  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      localStorage.setItem(key, value);
    } catch (err) {
      return null; // storage blocked: alerts still work, just per page load
    }
  }

  const isMuted = () => store(MUTE_KEY) === "1";

  function getCursor() {
    const value = store(CURSOR_KEY);
    return value === null ? null : Number(value);
  }

  // --- sound ---------------------------------------------------------------

  let audioCtx = null;
  let soundPending = false;

  function audio() {
    if (!audioCtx) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return null;
      audioCtx = new Ctx();
    }
    return audioCtx;
  }

  function audioRunning() {
    return !!audioCtx && audioCtx.state === "running";
  }

  // Two-tone siren, three cycles. Returns false if the browser won't let us
  // play yet (no user interaction with the page so far).
  function playAlarm() {
    const ctx = audio();
    if (!ctx) return true;
    if (ctx.state === "suspended") ctx.resume().catch(() => {});
    if (ctx.state !== "running") return false;

    const start = ctx.currentTime + 0.02;
    for (let i = 0; i < 3; i++) {
      const at = start + i * 0.6;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "square";
      osc.frequency.setValueAtTime(880, at);
      osc.frequency.setValueAtTime(620, at + 0.3);
      gain.gain.setValueAtTime(0.0001, at);
      gain.gain.exponentialRampToValueAtTime(0.14, at + 0.03);
      gain.gain.setValueAtTime(0.14, at + 0.52);
      gain.gain.exponentialRampToValueAtTime(0.0001, at + 0.58);
      osc.connect(gain).connect(ctx.destination);
      osc.start(at);
      osc.stop(at + 0.6);
    }
    return true;
  }

  function soundAlarm() {
    if (isMuted()) return;
    if (!playAlarm()) soundPending = true;
  }

  function unlockAudio() {
    const ctx = audio();
    if (!ctx) return;
    const ready = ctx.state === "running" ? Promise.resolve() : ctx.resume();
    ready
      .then(() => {
        document.querySelectorAll(".anomaly-toast-hint").forEach((el) => el.remove());
        if (soundPending && audioRunning()) {
          soundPending = false;
          if (!isMuted()) playAlarm();
        }
      })
      .catch(() => {});
  }

  ["pointerdown", "keydown"].forEach((name) => window.addEventListener(name, unlockAudio, { passive: true }));

  // --- pop-ups -------------------------------------------------------------

  function toastHost() {
    let host = document.getElementById("anomalyToasts");
    if (!host) {
      host = document.createElement("div");
      host.id = "anomalyToasts";
      host.setAttribute("aria-live", "assertive");
      document.body.appendChild(host);
    }
    return host;
  }

  function showToast(alert) {
    const host = toastHost();
    while (host.children.length >= MAX_TOASTS) host.firstElementChild.remove();

    const toast = document.createElement("div");
    toast.className = "anomaly-toast" + (alert.severity === "Critical" ? " anomaly-toast-critical" : "");
    toast.setAttribute("role", "alert");
    const needsHint = !isMuted() && !audioRunning();
    toast.innerHTML = `
      <div class="anomaly-toast-icon" aria-hidden="true">!</div>
      <div class="anomaly-toast-body">
        <p class="anomaly-toast-title">Behavior anomaly detected <span class="badge badge-danger">${alert.risk_score}</span></p>
        <p class="anomaly-toast-endpoint">${escapeHtml(alert.endpoint_name)}</p>
        <p class="anomaly-toast-reason">${escapeHtml(alert.risk_reason || alert.description || "Unusual activity")}</p>
        ${needsHint ? `<p class="anomaly-toast-hint">Click anywhere on the page to enable the alert sound.</p>` : ""}
        <div class="anomaly-toast-actions">
          <a class="anomaly-toast-link" href="live-monitoring.html">Live Monitoring</a>
          <a class="anomaly-toast-link" href="security-logs.html">Security Logs</a>
          <button type="button" class="anomaly-toast-mute">${isMuted() ? "Unmute sound" : "Mute sound"}</button>
        </div>
      </div>
      <button type="button" class="anomaly-toast-close" aria-label="Dismiss">&times;</button>`;

    toast.querySelector(".anomaly-toast-close").addEventListener("click", () => toast.remove());
    toast.querySelector(".anomaly-toast-mute").addEventListener("click", (event) => {
      store(MUTE_KEY, isMuted() ? "0" : "1");
      event.target.textContent = isMuted() ? "Unmute sound" : "Mute sound";
    });
    host.appendChild(toast);
    setTimeout(() => toast.remove(), TOAST_MS);
  }

  // --- polling -------------------------------------------------------------

  async function poll() {
    try {
      const cursor = getCursor();
      const data = await apiFetch(cursor === null ? "/api/anomalies/feed" : `/api/anomalies/feed?after_id=${cursor}`);
      store(CURSOR_KEY, String(Math.max(data.latest_id, cursor || 0)));

      const fresh = data.items.filter((a) => Date.now() - new Date(a.event_time).getTime() < MAX_AGE_MS);
      if (fresh.length) {
        fresh.forEach(showToast);
        soundAlarm();
        window.dispatchEvent(new CustomEvent("anomaly-detected", { detail: fresh }));
      }
    } catch (err) {
      // Network blip or expired session (apiFetch redirects to login): try again next time.
    }
  }

  poll();
  setInterval(poll, POLL_MS);
})();
