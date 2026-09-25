const logoutBtn = document.getElementById("logoutBtn");
const welcomeHeading = document.getElementById("welcomeHeading");

logoutBtn.addEventListener("click", () => {
  // TODO: call the C# backend to invalidate the session once auth exists.
  window.location.href = "login.html";
});

function getTimeOfDayGreeting(hour = new Date().getHours()) {
  if (hour < 12) return "Morning";
  if (hour < 18) return "Afternoon";
  return "Evening";
}

function renderWelcomeHeading() {
  if (!welcomeHeading) return;
  // TODO: once the backend exists, use the authenticated user's real
  // display name instead of what was typed into the login form.
  const username = sessionStorage.getItem("username") || "Admin";
  welcomeHeading.textContent = `Good ${getTimeOfDayGreeting()} ${username}`;
}

renderWelcomeHeading();

// TODO: replace with real data from the C# backend, e.g.
// fetch("/api/dashboard/summary").then(r => r.json()).then(renderStats);
function renderStats(data) {
  document.querySelectorAll("[data-stat]").forEach((el) => {
    const key = el.dataset.stat;
    if (data[key] !== undefined) {
      el.textContent = data[key];
    }
  });
}
