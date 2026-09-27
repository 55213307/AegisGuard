requireAuth();

const logoutBtn = document.getElementById("logoutBtn");
const welcomeHeading = document.getElementById("welcomeHeading");

logoutBtn.addEventListener("click", () => {
  clearSession();
  window.location.href = "login.html";
});

function getTimeOfDayGreeting(hour = new Date().getHours()) {
  if (hour < 12) return "Morning";
  if (hour < 18) return "Afternoon";
  return "Evening";
}

function renderWelcomeHeading() {
  if (!welcomeHeading) return;
  const username = sessionStorage.getItem("username") || "Admin";
  welcomeHeading.textContent = `Good ${getTimeOfDayGreeting()} ${username}`;
}

renderWelcomeHeading();

function renderStats(data) {
  const map = {
    totalCustomers: data.total_customers,
    activeCustomers: data.active_customers,
    monitoringAccounts: data.monitoring_accounts,
    lockedAccounts: data.locked_accounts,
    pendingAccounts: data.pending_accounts,
    platformStatus: data.platform_status,
  };

  document.querySelectorAll("[data-stat]").forEach((el) => {
    const value = map[el.dataset.stat];
    if (value !== undefined) {
      el.textContent = value;
    }
  });
}

async function loadDashboardSummary() {
  // Only dashboard.html has these stat cards; other pages that also load
  // this script (for the shared sidebar/logout) can skip the fetch.
  if (document.querySelectorAll("[data-stat]").length === 0) return;

  try {
    const summary = await apiFetch("/api/dashboard/summary");
    renderStats(summary);
  } catch (err) {
    console.error("Failed to load dashboard summary", err);
  }
}

loadDashboardSummary();
