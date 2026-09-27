const ICON_EYE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`;
const ICON_LOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="10.5" width="13" height="9" rx="1.6"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 7 0v2.7"/></svg>`;
const ICON_UNLOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="10.5" width="13" height="9" rx="1.6"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 6.7-1.4"/></svg>`;
const ICON_TRASH = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 7h16"/><path d="M9 7V4.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V7"/><path d="M6 7l1 12.5A1.5 1.5 0 0 0 8.5 21h7a1.5 1.5 0 0 0 1.5-1.5L18 7"/></svg>`;

const ROLE_LABEL = { employee: "Employee", administrator: "Administrator" };

let allAccounts = [];

const tableBody = document.getElementById("accountsTableBody");
const searchInput = document.getElementById("accountSearchInput");

function timeAgo(isoString) {
  if (!isoString) return "--";
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} day${days === 1 ? "" : "s"} ago`;
  return new Date(isoString).toLocaleDateString();
}

function renderAccountsTable() {
  const query = searchInput.value.trim().toLowerCase();
  const filtered = allAccounts.filter(
    (account) =>
      !query ||
      account.username.toLowerCase().includes(query) ||
      account.email.toLowerCase().includes(query)
  );

  if (filtered.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">No accounts match your search.</td></tr>`;
    return;
  }

  tableBody.innerHTML = filtered
    .map((account) => {
      const isLocked = account.status === "locked";
      const toggleIcon = isLocked ? ICON_UNLOCK : ICON_LOCK;
      const toggleClass = isLocked ? "icon-btn-success" : "icon-btn-warning";
      const toggleAction = isLocked ? "unlock" : "lock";
      const statusBadgeClass = isLocked ? "badge-danger" : "badge-success";
      const statusLabel = isLocked ? "Locked" : "Active";

      return `
        <tr data-account-id="${account.id}">
          <td class="cell-primary">${account.username}</td>
          <td>${account.email}</td>
          <td>${ROLE_LABEL[account.role] || account.role}</td>
          <td><span class="badge ${statusBadgeClass}">${statusLabel}</span></td>
          <td>${timeAgo(account.last_login)}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn" type="button" data-action="view" title="View">${ICON_EYE}</button>
              <button class="icon-btn ${toggleClass}" type="button" data-action="${toggleAction}" title="${isLocked ? "Unlock" : "Lock"}">${toggleIcon}</button>
              <button class="icon-btn icon-btn-danger" type="button" data-action="delete" title="Delete">${ICON_TRASH}</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
}

async function loadAccounts() {
  try {
    const data = await apiFetch("/api/accounts");
    allAccounts = data.items || [];
    renderAccountsTable();
  } catch (err) {
    console.error("Failed to load accounts", err);
    tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">Could not load accounts. Please try again later.</td></tr>`;
  }
}

searchInput.addEventListener("input", renderAccountsTable);

tableBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;

  const row = button.closest("tr");
  const accountId = row.dataset.accountId;
  const action = button.dataset.action;

  if (action === "view") {
    window.location.href = `live-monitoring.html?account=${encodeURIComponent(accountId)}`;
    return;
  }

  if (action === "delete") {
    const confirmed = window.confirm("Remove this account? This cannot be undone.");
    if (!confirmed) return;
  }

  try {
    if (action === "delete") {
      await apiFetch(`/api/accounts/${accountId}`, { method: "DELETE" });
    } else {
      await apiFetch(`/api/accounts/${accountId}/${action}`, { method: "POST" });
    }
    loadAccounts();
  } catch (err) {
    console.error(`Failed to ${action} account`, err);
  }
});

/* Create Account modal */
const createScrim = document.getElementById("createAccountScrim");
const openCreateBtn = document.getElementById("openCreateAccountBtn");
const closeCreateBtn = document.getElementById("closeCreateAccountBtn");
const cancelCreateBtn = document.getElementById("cancelCreateAccountBtn");
const createForm = document.getElementById("createAccountForm");
const createError = document.getElementById("createAccountError");

function openCreateModal() {
  createForm.reset();
  createError.textContent = "";
  createScrim.classList.add("open");
}

function closeCreateModal() {
  createScrim.classList.remove("open");
}

openCreateBtn.addEventListener("click", openCreateModal);
closeCreateBtn.addEventListener("click", closeCreateModal);
cancelCreateBtn.addEventListener("click", closeCreateModal);
createScrim.addEventListener("click", (event) => {
  if (event.target === createScrim) closeCreateModal();
});

createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  createError.textContent = "";

  const username = document.getElementById("newUsername").value.trim();
  const email = document.getElementById("newEmail").value.trim();
  const role = document.getElementById("newRole").value;
  const password = document.getElementById("newPassword").value.trim();

  if (!username || !email) {
    createError.textContent = "Username and email are required.";
    return;
  }

  const submitBtn = createForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;

  try {
    await apiFetch("/api/accounts", {
      method: "POST",
      body: { username, email, role, password: password || undefined },
    });
    closeCreateModal();
    loadAccounts();
  } catch (err) {
    createError.textContent = err.message || "Could not create the account. Please try again.";
  } finally {
    submitBtn.disabled = false;
  }
});

loadAccounts();
