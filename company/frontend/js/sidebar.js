requireAuth();

const logoutBtn = document.getElementById("logoutBtn");

if (logoutBtn) {
  logoutBtn.addEventListener("click", () => {
    clearSession();
    goToLogin();
  });
}

