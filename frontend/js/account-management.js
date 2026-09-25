// TODO: no backend yet — load the real list here once it exists, e.g.
// fetch("/api/accounts").then(r => r.json()).then(renderAccounts);
const accounts = [];

const tableBody = document.getElementById("accountTableBody");
const tabsBar = document.getElementById("amTabsBar");
const searchInput = document.getElementById("accountSearch");
const companyFilter = document.getElementById("companyFilter");
const roleFilter = document.getElementById("roleFilter");
const sortFilter = document.getElementById("sortFilter");
const pagination = document.getElementById("pagination");
const paginationSummary = document.getElementById("paginationSummary");

const drawer = document.getElementById("accountDrawer");
const drawerBackdrop = document.getElementById("drawerBackdrop");
const drawerCloseBtn = document.getElementById("drawerCloseBtn");
const drawerActions = document.getElementById("drawerActions");

let activeFilter = "all";

function populateCompanyFilter() {
  const companies = [...new Set(accounts.map((a) => a.company))].sort();
  companies.forEach((company) => {
    const option = document.createElement("option");
    option.value = company;
    option.textContent = company;
    companyFilter.appendChild(option);
  });
}

function updateTabCounts() {
  const counts = { all: accounts.length, active: 0, pending: 0, locked: 0 };
  accounts.forEach((a) => {
    if (a.status === "Active") counts.active += 1;
    if (a.status === "Pending") counts.pending += 1;
    if (a.status === "Locked") counts.locked += 1;
  });
  Object.entries(counts).forEach(([key, value]) => {
    const el = tabsBar.querySelector(`[data-count="${key}"]`);
    if (el) el.textContent = `(${value})`;
  });
}

function getInitials(name) {
  return name.trim().charAt(0).toUpperCase();
}

function getFilteredAccounts() {
  const statusMap = { active: "Active", pending: "Pending", locked: "Locked" };
  const query = searchInput.value.trim().toLowerCase();
  const companyValue = companyFilter.value;
  const roleValue = roleFilter.value;

  let list = accounts.filter((a) => {
    if (activeFilter !== "all" && a.status !== statusMap[activeFilter]) return false;
    if (companyValue && a.company !== companyValue) return false;
    if (roleValue && a.role !== roleValue) return false;
    if (query) {
      const haystack = `${a.name} ${a.email} ${a.company}`.toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });

  const sortValue = sortFilter.value;
  list = [...list].sort((a, b) => {
    if (sortValue === "name") return a.name.localeCompare(b.name);
    if (sortValue === "oldest") return a.date.localeCompare(b.date);
    return b.date.localeCompare(a.date); // newest
  });

  return list;
}

function createRowElement(account) {
  const row = document.createElement("div");
  row.className = "am-row";
  row.dataset.id = account.id;

  row.innerHTML = `
    <div class="am-row-name">
      <span class="am-avatar">${getInitials(account.name)}</span>
      <span class="am-row-name-text">${account.name}</span>
    </div>
    <div class="am-row-company">${account.company}</div>
    <div class="am-row-role">${account.role}</div>
    <div class="am-row-status"><span class="am-status-pill" data-status="${account.status}">${account.status}</span></div>
    <div class="am-row-actions">
      <button class="am-action-btn am-action-view" type="button">View</button>
      <button class="am-action-btn am-action-delete" type="button">Delete</button>
    </div>
  `;

  return row;
}

function renderTable() {
  const filtered = getFilteredAccounts();
  tableBody.innerHTML = "";

  if (accounts.length === 0) {
    const empty = document.createElement("div");
    empty.className = "placeholder-body am-empty-row";
    empty.innerHTML =
      "<p>No accounts to display yet &mdash; this list will populate once the backend API is connected.</p>";
    tableBody.appendChild(empty);
    pagination.style.display = "none";
    return;
  }

  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "am-empty-row";
    empty.textContent = "No accounts match your filters.";
    tableBody.appendChild(empty);
  } else {
    filtered.forEach((account) => tableBody.appendChild(createRowElement(account)));
  }

  pagination.style.display = "";
  paginationSummary.textContent =
    activeFilter === "all"
      ? `Showing 1–${filtered.length} of ${accounts.length} accounts`
      : `Showing ${filtered.length} of ${filtered.length} accounts`;
}

tabsBar.addEventListener("click", (event) => {
  const btn = event.target.closest(".am-tab");
  if (!btn) return;
  tabsBar.querySelectorAll(".am-tab").forEach((t) => t.classList.remove("active"));
  btn.classList.add("active");
  activeFilter = btn.dataset.filter;
  renderTable();
});

[searchInput, companyFilter, roleFilter, sortFilter].forEach((el) => {
  el.addEventListener("input", renderTable);
  el.addEventListener("change", renderTable);
});

function buildActionButtons(account) {
  drawerActions.innerHTML = "";

  if (account.status === "Pending") {
    drawerActions.innerHTML = `
      <button class="am-drawer-btn am-btn-approve" type="button" data-action="approve">Approve</button>
      <button class="am-drawer-btn am-btn-reject" type="button" data-action="reject">Reject</button>
    `;
  } else if (account.status === "Active") {
    drawerActions.innerHTML = `
      <button class="am-drawer-btn am-btn-lock" type="button" data-action="lock">Lock Account</button>
    `;
  } else if (account.status === "Locked") {
    drawerActions.innerHTML = `
      <button class="am-drawer-btn am-btn-unlock" type="button" data-action="unlock">Unlock Account</button>
    `;
  }
}

function openDrawer(account) {
  document.getElementById("drawerAvatar").textContent = getInitials(account.name);
  document.getElementById("drawerName").textContent = account.name;
  document.getElementById("drawerCompanySub").textContent = account.company;
  document.getElementById("drawerFullName").textContent = account.name;
  document.getElementById("drawerEmail").textContent = account.email;
  document.getElementById("drawerCompany").textContent = account.company;
  document.getElementById("drawerRole").textContent = account.role;
  document.getElementById("drawerDate").textContent = account.date;
  document.getElementById("drawerOperator").textContent = account.operator;
  document.getElementById("drawerRemarks").textContent = `Remarks: ${account.remarks}`;

  const pill = document.getElementById("drawerStatusPill");
  pill.textContent = account.status;
  pill.dataset.status = account.status;

  buildActionButtons(account);

  drawer.classList.add("open");
  drawerBackdrop.classList.add("open");
}

function closeDrawer() {
  drawer.classList.remove("open");
  drawerBackdrop.classList.remove("open");
}

tableBody.addEventListener("click", (event) => {
  const row = event.target.closest(".am-row");
  if (!row) return;
  const account = accounts.find((a) => a.id === Number(row.dataset.id));
  if (!account) return;

  if (event.target.closest(".am-action-view")) {
    openDrawer(account);
  } else if (event.target.closest(".am-action-delete")) {
    // TODO: call the C# backend to delete this account, e.g.
    // fetch(`/api/accounts/${account.id}`, { method: "DELETE" })
    console.log("Delete account", account.id);
  }
});

drawerActions.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-action]");
  if (!btn) return;
  // TODO: call the C# backend to update account status, e.g.
  // fetch(`/api/accounts/${id}/${action}`, { method: "POST" })
  console.log("Account action:", btn.dataset.action);
  closeDrawer();
});

drawerCloseBtn.addEventListener("click", closeDrawer);
drawerBackdrop.addEventListener("click", closeDrawer);

populateCompanyFilter();
updateTabCounts();
renderTable();
