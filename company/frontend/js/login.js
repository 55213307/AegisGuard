const form = document.getElementById("loginForm");
const card = document.getElementById("loginCard");
const errorMessage = document.getElementById("errorMessage");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");

function clearFieldErrors() {
  usernameInput.classList.remove("error");
  passwordInput.classList.remove("error");
}

function shakeCard() {
  card.classList.remove("shake");
  void card.offsetWidth;
  card.classList.add("shake");
}

function showError(message, fieldsToMark) {
  errorMessage.textContent = message;
  clearFieldErrors();
  fieldsToMark.forEach((field) => field.classList.add("error"));
  shakeCard();
}

function clearError() {
  errorMessage.textContent = "";
  clearFieldErrors();
}

[usernameInput, passwordInput].forEach((input) => {
  input.addEventListener("input", () => {
    if (input.classList.contains("error")) {
      clearError();
    }
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    const emptyFields = [
      !username ? usernameInput : null,
      !password ? passwordInput : null,
    ].filter(Boolean);
    showError("Please enter both username and password.", emptyFields);
    return;
  }

  const submitBtn = form.querySelector(".login-submit");
  submitBtn.disabled = true;

  try {
    const result = await apiFetch("/api/auth/login", {
      method: "POST",
      body: { username, password },
      skipAuthRedirect: true,
    });

    clearError();
    setSession(result.access_token, result.user.display_name || result.user.username);

    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 300);
  } catch (err) {
    showError(err.message || "Username or password wrong, please try again.", [usernameInput, passwordInput]);
  } finally {
    submitBtn.disabled = false;
  }
});
