requireAuth();

const tableBody = document.getElementById("accountTableBody");
const tabsBar = document.getElementById("amTabsBar");
const searchInput = document.getElementById("accountSearch");
const companyFilter = document.getElementById("companyFilter");
const sortFilter = document.getElementById("sortFilter");
const pagination = document.getElementById("pagination");
const paginationSummary = document.getElementById("paginationSummary");

const drawer = document.getElementById("accountDrawer");
const drawerBackdrop = document.getElementById("drawerBackdrop");
const drawerCloseBtn = document.getElementById("drawerCloseBtn");
const drawerActions = document.getElementById("drawerActions");

let activeFilter = "all";
let currentAccounts = [];
let searchDebounceTimer = null;

// The API doesn't paginate yet — it returns every matching account in one
// response — so the page-number buttons are hidden rather than faked.
pagination.querySelector(".am-pagination-pages").style.display = "none";

const STATUS_MAP = { active: "Active", pending: "Pending", locked: "Locked" };

function getInitials(name) {
  return name.trim().charAt(0).toUpperCase();
}

async function populateCompanyFilter() {
  try {
    const companies = await apiFetch("/api/customers");
    companies
      .map((c) => c.company_name)
      .sort()
      .forEach((name) => {
        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        companyFilter.appendChild(option);
      });
  } catch (err) {
    console.error("Failed to load companies for filter", err);
  }
}

async function loadSummary() {
  try {
    const summary = await apiFetch("/api/accounts/summary");
    document.querySelectorAll("[data-stat]").forEach((el) => {
      const key = el.dataset.stat;
      if (summary[key] !== undefined) el.textContent = summary[key];
    });
  } catch (err) {
    console.error("Failed to load account summary", err);
  }
}

function createRowElement(account) {
  const row = document.createElement("div");
  row.className = "am-row";
  row.dataset.id = account.id;

  row.innerHTML = `
    <div class="am-row-name">
      <span class="am-avatar">${getInitials(account.customer_name)}</span>
      <span class="am-row-name-text">${account.customer_name}</span>
    </div>
    <div class="am-row-company">${account.company_name}</div>
    <div class="am-row-status"><span class="am-status-pill" data-status="${account.customer_status}">${account.customer_status}</span></div>
    <div class="am-row-actions">
      <button class="am-action-btn am-action-view" type="button">View</button>
      <button class="am-action-btn am-action-delete" type="button">Delete</button>
    </div>
  `;

  return row;
}

async function loadAccounts() {
  const params = new URLSearchParams();
  if (activeFilter !== "all") params.set("status", STATUS_MAP[activeFilter]);
  if (companyFilter.value) params.set("company", companyFilter.value);
  if (searchInput.value.trim()) params.set("search", searchInput.value.trim());
  params.set("sort", sortFilter.value);

  tableBody.innerHTML = `<div class="am-empty-row">Loading accounts&hellip;</div>`;

  try {
    const data = await apiFetch(`/api/accounts?${params.toString()}`);
    currentAccounts = data.items;
    renderTable(data.items);
  } catch (err) {
    console.error("Failed to load accounts", err);
    tableBody.innerHTML = `<div class="am-empty-row">Could not load accounts. Please try again.</div>`;
  }
}

function renderTable(items) {
  tableBody.innerHTML = "";

  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "placeholder-body am-empty-row";
    empty.innerHTML = "<p>No accounts to display for this view.</p>";
    tableBody.appendChild(empty);
    paginationSummary.textContent = "";
    return;
  }

  items.forEach((account) => tableBody.appendChild(createRowElement(account)));
  paginationSummary.textContent = `Showing ${items.length} of ${items.length} accounts`;
}

tabsBar.addEventListener("click", (event) => {
  const btn = event.target.closest(".am-tab");
  if (!btn) return;
  tabsBar.querySelectorAll(".am-tab").forEach((t) => t.classList.remove("active"));
  btn.classList.add("active");
  activeFilter = btn.dataset.filter;
  loadAccounts();
});

searchInput.addEventListener("input", () => {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(loadAccounts, 300);
});

[companyFilter, sortFilter].forEach((el) => {
  el.addEventListener("change", loadAccounts);
});

function buildActionButtons(account) {
  drawerActions.innerHTML = "";

  if (account.customer_status === "Pending") {
    drawerActions.innerHTML = `
      <button class="am-drawer-btn am-btn-approve" type="button" data-action="approve">Approve</button>
      <button class="am-drawer-btn am-btn-reject" type="button" data-action="reject">Reject</button>
    `;
  } else if (account.customer_status === "Active") {
    drawerActions.innerHTML = `
      <button class="am-drawer-btn am-btn-lock" type="button" data-action="lock">Lock Account</button>
    `;
  } else if (account.customer_status === "Locked") {
    drawerActions.innerHTML = `
      <button class="am-drawer-btn am-btn-unlock" type="button" data-action="unlock">Unlock Account</button>
    `;
  }

  drawerActions.insertAdjacentHTML(
    "beforeend",
    `<button class="am-drawer-btn am-btn-lock" type="button" data-action="reset-password">Reset Password</button>`
  );
}

function describePasswordState(account) {
  if (!account.has_password) return "Not issued — use Reset Password";
  return account.must_change_password ? "Issued, not yet changed" : "Changed by company";
}

function openDrawer(account) {
  drawer.dataset.accountId = account.id;

  document.getElementById("drawerAvatar").textContent = getInitials(account.customer_name);
  document.getElementById("drawerName").textContent = account.customer_name;
  document.getElementById("drawerCompanySub").textContent = account.company_name;
  document.getElementById("drawerFullName").textContent = account.customer_name;
  document.getElementById("drawerEmail").textContent = account.customer_email;
  document.getElementById("drawerPhone").textContent = account.contact_number || "—";
  document.getElementById("drawerCompany").textContent = account.company_name;
  document.getElementById("drawerDate").textContent = new Date(account.submitted_time).toLocaleDateString();
  document.getElementById("drawerOperator").textContent = account.operator_name || "—";
  document.getElementById("drawerPasswordState").textContent = describePasswordState(account);
  document.getElementById("drawerLoginUrl").textContent = account.login_url;
  document.getElementById("drawerRemarks").textContent = account.remark
    ? `Remarks: ${account.remark}`
    : "No additional remarks.";

  const pill = document.getElementById("drawerStatusPill");
  pill.textContent = account.customer_status;
  pill.dataset.status = account.customer_status;

  buildActionButtons(account);

  drawer.classList.add("open");
  drawerBackdrop.classList.add("open");
}

function closeDrawer() {
  drawer.classList.remove("open");
  drawerBackdrop.classList.remove("open");
  delete drawer.dataset.accountId;
}

tableBody.addEventListener("click", (event) => {
  const row = event.target.closest(".am-row");
  if (!row) return;
  const account = currentAccounts.find((a) => a.id === Number(row.dataset.id));
  if (!account) return;

  if (event.target.closest(".am-action-view")) {
    openDrawer(account);
  } else if (event.target.closest(".am-action-delete")) {
    if (!confirm(`Delete ${account.customer_name}'s account? This cannot be undone.`)) return;
    apiFetch(`/api/accounts/${account.id}`, { method: "DELETE" })
      .then(() => {
        loadAccounts();
        loadSummary();
      })
      .catch((err) => alert(err.message || "Could not delete this account."));
  }
});

drawerActions.addEventListener("click", async (event) => {
  const btn = event.target.closest("[data-action]");
  if (!btn) return;

  const accountId = drawer.dataset.accountId;
  const action = btn.dataset.action;

  if (action === "reset-password") {
    if (!confirm("Issue a new portal password? The current one will stop working immediately.")) return;
    btn.disabled = true;
    try {
      const credentials = await apiFetch(`/api/accounts/${accountId}/reset-password`, { method: "POST" });
      closeDrawer();
      loadAccounts();
      showPortalCredentials(credentials, { title: `New Password for ${credentials.login_username}` });
    } catch (err) {
      alert(err.message || "Could not reset the password. Please try again.");
      btn.disabled = false;
    }
    return;
  }

  btn.disabled = true;

  try {
    await apiFetch(`/api/accounts/${accountId}/${action}`, { method: "POST" });
    closeDrawer();
    loadAccounts();
    loadSummary();
  } catch (err) {
    alert(err.message || "Could not update this account. Please try again.");
    btn.disabled = false;
  }
});

drawerCloseBtn.addEventListener("click", closeDrawer);
drawerBackdrop.addEventListener("click", closeDrawer);

populateCompanyFilter();
loadSummary();
loadAccounts();
