requireAuth();

const logoutBtn = document.getElementById("logoutBtn");

if (logoutBtn) {
  logoutBtn.addEventListener("click", () => {
    clearSession();
    goToLogin();
  });
}

if (!canManageAccounts()) {
  document.querySelectorAll('.nav-item[href="account-management.html"]').forEach((link) => link.remove());
  if (window.location.pathname.endsWith("/account-management.html")) {
    window.location.href = "dashboard.html";
  }
}
