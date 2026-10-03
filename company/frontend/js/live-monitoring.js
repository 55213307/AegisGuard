// Live Monitoring: one card per employee computer with a screen thumbnail.
// Thumbnails refresh every few seconds; clicking a card opens the endpoint
// detail dialog, which switches that computer to one frame per second.

const THUMBNAIL_REFRESH_MS = 5000;
const STATUS_REFRESH_MS = 30000;
const ICON_MONITOR = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/></svg>`;

const grid = document.getElementById("endpointGrid");
const searchInput = document.getElementById("searchInput");
const statusFilter = document.getElementById("statusFilter");

let allEndpoints = [];
// Object URL of each card's current thumbnail, keyed by employee id.
const thumbnailUrls = new Map();

function filteredEndpoints() {
  const query = searchInput.value.trim().toLowerCase();
  const status = statusFilter.value;
  return allEndpoints.filter((account) => {
    const matchesQuery =
      !query ||
      account.employee_username.toLowerCase().includes(query) ||
      account.employee_email.toLowerCase().includes(query);
    return matchesQuery && (!status || account.endpoint_status === status);
  });
}

function renderGrid() {
  const visible = filteredEndpoints();
  grid.innerHTML = "";

  if (visible.length === 0) {
    grid.innerHTML = allEndpoints.length === 0
      ? `<p class="empty-state">No computers yet. Create an employee account in Account Management and run its installer.</p>`
      : `<p class="empty-state">No computers match your search.</p>`;
    return;
  }

  visible.forEach((account) => {
    const style = endpointStatusStyle(account.endpoint_status);
    const card = document.createElement("button");
    card.type = "button";
    card.className = "endpoint-card";
    card.dataset.accountId = account.id;
    const thumbnail = thumbnailUrls.get(account.id);
    card.innerHTML = `
      <div class="endpoint-card-preview">
        ${thumbnail ? `<img class="endpoint-card-img" src="${thumbnail}" alt="" />` : ICON_MONITOR}
      </div>
      <div class="endpoint-card-body">
        <div class="endpoint-card-row">
          <span class="endpoint-card-name">${escapeHtml(account.endpoint_name || account.employee_username)}</span>
          <span class="badge ${style.badge}">${escapeHtml(account.endpoint_status)}</span>
        </div>
        <p class="endpoint-card-user">Last seen: ${timeAgo(account.last_seen_time)}</p>
      </div>
    `;
    card.addEventListener("click", () => EndpointDetail.open(account, { onChanged: loadEndpoints }));
    grid.appendChild(card);
  });
}

async function loadEndpoints() {
  try {
    const data = await apiFetch("/api/accounts");
    allEndpoints = data.items;
    renderGrid();
  } catch (err) {
    console.error("Failed to load endpoints", err);
    grid.innerHTML = `<p class="empty-state">Could not load computers. Please try again later.</p>`;
  }
}

async function refreshThumbnails() {
  // Only computers that have a screen agent can have frames.
  for (const account of allEndpoints.filter((a) => a.endpoint_name)) {
    try {
      const result = await apiFetchImage(`/api/accounts/${account.id}/screen`);
      if (!result) continue;
      const url = URL.createObjectURL(result.blob);
      const previous = thumbnailUrls.get(account.id);
      thumbnailUrls.set(account.id, url);

      // Swap just this card's image instead of re-rendering the whole grid.
      const preview = grid.querySelector(`[data-account-id="${account.id}"] .endpoint-card-preview`);
      if (preview) preview.innerHTML = `<img class="endpoint-card-img" src="${url}" alt="" />`;
      if (previous) URL.revokeObjectURL(previous);
    } catch (err) {
      console.error("Failed to load thumbnail", err);
    }
  }
}

searchInput.addEventListener("input", renderGrid);
statusFilter.addEventListener("change", renderGrid);

async function start() {
  await loadEndpoints();
  await refreshThumbnails();
  setInterval(refreshThumbnails, THUMBNAIL_REFRESH_MS);
  setInterval(loadEndpoints, STATUS_REFRESH_MS);
}

start();
