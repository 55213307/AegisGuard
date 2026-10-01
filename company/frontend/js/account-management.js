const ICON_EYE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`;
const ICON_LOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="10.5" width="13" height="9" rx="1.6"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 7 0v2.7"/></svg>`;
const ICON_UNLOCK = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5.5" y="10.5" width="13" height="9" rx="1.6"/><path d="M8.5 10.5V7.8a3.5 3.5 0 0 1 6.7-1.4"/></svg>`;
const ICON_TRASH = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 7h16"/><path d="M9 7V4.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V7"/><path d="M6 7l1 12.5A1.5 1.5 0 0 0 8.5 21h7a1.5 1.5 0 0 0 1.5-1.5L18 7"/></svg>`;

const currentUsername = sessionStorage.getItem("username") || "";

let allAccounts = [];

const tableBody = document.getElementById("accountsTableBody");
const searchInput = document.getElementById("accountSearchInput");

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

function timeAgo(isoString) {
  if (!isoString) return "Never";
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

function isSelf(account) {
  return account.employee_username === currentUsername;
}

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
    tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">${message}</td></tr>`;
    return;
  }

  tableBody.innerHTML = filtered
    .map((account) => {
      const isLocked = account.employee_status === "Locked";
      // An administrator can't lock or delete their own account (the API
      // refuses too), so those buttons are disabled on their own row.
      const selfAttr = isSelf(account) ? 'disabled title="You can\'t change your own account"' : "";
      return `
        <tr data-account-id="${account.id}">
          <td class="cell-primary">${escapeHtml(account.employee_username)}${isSelf(account) ? " (you)" : ""}</td>
          <td>${escapeHtml(account.employee_email)}</td>
          <td>${escapeHtml(account.employee_role)}</td>
          <td><span class="badge ${isLocked ? "badge-danger" : "badge-success"}">${isLocked ? "Locked" : "Active"}</span></td>
          <td>${timeAgo(account.last_login_time)}</td>
          <td>
            <div class="row-actions">
              <button class="icon-btn" type="button" data-action="view" title="View">${ICON_EYE}</button>
              <button class="icon-btn ${isLocked ? "icon-btn-success" : "icon-btn-warning"}" type="button" data-action="${isLocked ? "unlock" : "lock"}" title="${isLocked ? "Unlock" : "Lock"}" ${selfAttr}>${isLocked ? ICON_UNLOCK : ICON_LOCK}</button>
              <button class="icon-btn icon-btn-danger" type="button" data-action="delete" title="Delete" ${selfAttr}>${ICON_TRASH}</button>
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
    tableBody.innerHTML = `<tr><td colspan="6" class="empty-state">Could not load accounts. Please try again later.</td></tr>`;
  }
}

searchInput.addEventListener("input", renderAccountsTable);

tableBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button || button.disabled) return;

  const accountId = Number(button.closest("tr").dataset.accountId);
  const account = allAccounts.find((a) => a.id === accountId);
  const action = button.dataset.action;

  if (action === "view") {
    openDetail(account);
    return;
  }

  if (action === "delete" && !confirm(`Delete ${account.employee_username}'s account? This cannot be undone.`)) return;
  if (action === "lock" && !confirm(`Lock ${account.employee_username}? They will be signed out immediately.`)) return;

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

/* One-time credentials dialog (after create / reset password) */
const credentialsScrim = document.getElementById("credentialsScrim");
const credentialsTitle = document.getElementById("credentialsTitle");

function showCredentials(title, credentials) {
  credentialsTitle.textContent = title;
  document.getElementById("credUrl").textContent = new URL(loginPageUrl(), window.location.href).href;
  document.getElementById("credUsername").textContent = credentials.employee_username;
  document.getElementById("credPassword").textContent = credentials.initial_password;
  credentialsScrim.classList.add("open");
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = original), 1200);
  } catch (err) {
    alert("Could not copy automatically. Please select and copy the text manually.");
  }
}

credentialsScrim.addEventListener("click", (event) => {
  const copyBtn = event.target.closest("[data-copy]");
  if (copyBtn) copyText(document.getElementById(copyBtn.dataset.copy).textContent, copyBtn);
});

document.getElementById("copyAllCredentialsBtn").addEventListener("click", (event) => {
  const text = ["credUrl", "credUsername", "credPassword"]
    .map((id, i) => `${["Login URL", "Username", "Password"][i]}: ${document.getElementById(id).textContent}`)
    .join("\n");
  copyText(text, event.currentTarget);
});

document.getElementById("closeCredentialsBtn").addEventListener("click", () => {
  credentialsScrim.classList.remove("open");
});

/* Account detail dialog */
const detailScrim = document.getElementById("detailScrim");
const detailError = document.getElementById("detailError");
const resetPasswordBtn = document.getElementById("resetPasswordBtn");
let detailAccount = null;

function describePassword(account) {
  return account.must_change_password ? "Temporary — not yet changed" : "Changed by employee";
}

function openDetail(account) {
  detailAccount = account;
  detailError.textContent = "";
  document.getElementById("detailUsername").textContent = account.employee_username;
  const fields = [
    ["Email", account.employee_email],
    ["Role", account.employee_role],
    ["Status", account.employee_status],
    ["Password", describePassword(account)],
    ["Last Login", timeAgo(account.last_login_time)],
    ["Created", new Date(account.created_time).toLocaleString()],
  ];
  document.getElementById("detailFields").innerHTML = fields
    .map(([label, value]) => `<div class="cred-row"><dt>${label}</dt><dd>${escapeHtml(value)}</dd></div>`)
    .join("");
  resetPasswordBtn.style.display = isSelf(account) ? "none" : "";
  detailScrim.classList.add("open");
}

function closeDetail() {
  detailScrim.classList.remove("open");
  detailAccount = null;
}

document.getElementById("closeDetailBtn").addEventListener("click", closeDetail);
detailScrim.addEventListener("click", (event) => {
  if (event.target === detailScrim) closeDetail();
});

resetPasswordBtn.addEventListener("click", async () => {
  if (!detailAccount) return;
  if (!confirm(`Issue a new temporary password for ${detailAccount.employee_username}? Their current password will stop working.`)) return;
  resetPasswordBtn.disabled = true;
  try {
    const credentials = await apiFetch(`/api/accounts/${detailAccount.id}/reset-password`, { method: "POST" });
    closeDetail();
    showCredentials("Password Reset", credentials);
    loadAccounts();
  } catch (err) {
    detailError.textContent = err.message || "Could not reset the password. Please try again.";
  } finally {
    resetPasswordBtn.disabled = false;
  }
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
  const role = document.getElementById("newRole").value;
  const temporaryPassword = document.getElementById("newPassword").value;

  if (!username || !email) {
    createError.textContent = "Username and email are required.";
    return;
  }

  const submitBtn = createForm.querySelector("button[type=submit]");
  submitBtn.disabled = true;

  try {
    const created = await apiFetch("/api/accounts", {
      method: "POST",
      body: {
        employee_username: username,
        employee_email: email,
        employee_role: role,
        temporary_password: temporaryPassword || null,
      },
    });
    closeCreateModal();
    showCredentials("Account Created", created.credentials);
    loadAccounts();
  } catch (err) {
    createError.textContent = err.message || "Could not create the account. Please try again.";
  } finally {
    submitBtn.disabled = false;
  }
});

loadAccounts();
