const ICON_EYE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`;
const ICON_LOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="10.5" width="13" height="9" rx="1.6"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 7 0v2.7"/></svg>`;
const ICON_UNLOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="10.5" width="13" height="9" rx="1.6"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 6.7-1.4"/></svg>`;
const ICON_TRASH = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 7h16"/><path d="M9 7V4.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V7"/><path d="M6 7l1 12.5A1.5 1.5 0 0 0 8.5 21h7a1.5 1.5 0 0 0 1.5-1.5L18 7"/></svg>`;

let allAccounts = [];

const tableBody = document.getElementById("accountsTableBody");
const searchInput = document.getElementById("accountSearchInput");

function renderAccountsTable() {
  const query = searchInput.value.trim().toLowerCase();
  const filtered = allAccounts.filter(
    (account) =>
      !query ||
      account.employee_username.toLowerCase().includes(query) ||
      account.employee_email.toLowerCase().includes(query)
  );

  if (filtered.length === 0) {
    const message = allAccounts.length === 0
      ? "No employee accounts yet. Use Create Account to add one."
      : "No accounts match your search.";
    tableBody.innerHTML = `<tr><td colspan="5" class="empty-state">${message}</td></tr>`;
    return;
  }

  tableBody.innerHTML = filtered
    .map((account) => {
      const isLocked = account.employee_status === "Locked";
      return `
        <tr data-account-id="${account.id}">
          <td class="cell-primary">${escapeHtml(account.employee_username)}</td>
          <td>${escapeHtml(account.employee_email)}</td>
          <td><span class="badge ${isLocked ? "badge-danger" : "badge-success"}">${isLocked ? "Locked" : "Active"}</span></td>
          <td>${timeAgo(account.last_seen_time)}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn" type="button" data-action="view" title="View">${ICON_EYE}</button>
              <button class="icon-btn ${isLocked ? "icon-btn-success" : "icon-btn-warning"}" type="button" data-action="${isLocked ? "unlock" : "lock"}" title="${isLocked ? "Unlock" : "Lock"}">${isLocked ? ICON_UNLOCK : ICON_LOCK}</button>
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
    allAccounts = data.items;
    renderAccountsTable();
  } catch (err) {
    console.error("Failed to load accounts", err);
    tableBody.innerHTML = `<tr><td colspan="5" class="empty-state">Could not load accounts. Please try again later.</td></tr>`;
  }
}

searchInput.addEventListener("input", renderAccountsTable);

tableBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;

  const accountId = Number(button.closest("tr").dataset.accountId);
  const account = allAccounts.find((a) => a.id === accountId);
  const action = button.dataset.action;

  if (action === "view") {
    EndpointDetail.open(account, { onChanged: loadAccounts });
    return;
  }

  if (action === "delete" && !confirm(`Delete ${account.employee_username}'s account? Their computer will stop being monitored.`)) return;

  button.disabled = true;
  try {
    if (action === "delete") {
      await apiFetch(`/api/accounts/${accountId}`, { method: "DELETE" });
    } else {
      await apiFetch(`/api/accounts/${accountId}/${action}`, { method: "POST" });
    }
    await loadAccounts();
  } catch (err) {
    alert(err.message || "Could not update this account. Please try again.");
    button.disabled = false;
  }
});

/* Installer download (one per employee's computer) */
async function downloadInstaller(account, button, errorEl) {
  errorEl.textContent = "";
  button.disabled = true;
  try {
    await apiDownload(`/api/accounts/${account.id}/installer`, `AegisGuard-Installer-${account.employee_username}.cmd`);
    loadAccounts();
  } catch (err) {
    errorEl.textContent = err.message || "Could not download the installer. Please try again.";
  } finally {
    button.disabled = false;
  }
}

/* "Account Created" dialog */
const createdScrim = document.getElementById("createdScrim");
const createdError = document.getElementById("createdError");
const createdDownloadBtn = document.getElementById("createdDownloadBtn");
let createdAccount = null;

function showCreated(account) {
  createdAccount = account;
  createdError.textContent = "";
  document.getElementById("createdHelper").textContent =
    `Download the installer and run it on ${account.employee_username}'s computer to start monitoring it.`;
  createdScrim.classList.add("open");
}

createdDownloadBtn.addEventListener("click", () => {
  if (createdAccount) downloadInstaller(createdAccount, createdDownloadBtn, createdError);
});

document.getElementById("closeCreatedBtn").addEventListener("click", () => {
  createdScrim.classList.remove("open");
  createdAccount = null;
});

/* Create Account dialog */
const createScrim = document.getElementById("createAccountScrim");
const createForm = document.getElementById("createAccountForm");
const createError = document.getElementById("createAccountError");

function openCreateModal() {
  createForm.reset();
  createError.textContent = "";
  createScrim.classList.add("open");
  document.getElementById("newUsername").focus();
}

function closeCreateModal() {
  createScrim.classList.remove("open");
}

document.getElementById("openCreateAccountBtn").addEventListener("click", openCreateModal);
document.getElementById("closeCreateAccountBtn").addEventListener("click", closeCreateModal);
document.getElementById("cancelCreateAccountBtn").addEventListener("click", closeCreateModal);
createScrim.addEventListener("click", (event) => {
  if (event.target === createScrim) closeCreateModal();
});

createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  createError.textContent = "";

  const username = document.getElementById("newUsername").value.trim();
  const email = document.getElementById("newEmail").value.trim();

  if (!username || !email) {
    createError.textContent = "Username and email are required.";
    return;
  }

  const submitBtn = createForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;

  try {
    const created = await apiFetch("/api/accounts", {
      method: "POST",
      body: { employee_username: username, employee_email: email },
    });
    closeCreateModal();
    showCreated(created);
    loadAccounts();
  } catch (err) {
    createError.textContent = err.message || "Could not create the account. Please try again.";
  } finally {
    submitBtn.disabled = false;
  }
});

loadAccounts();
