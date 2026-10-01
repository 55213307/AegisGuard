const form = document.getElementById("loginForm");
const card = document.getElementById("loginCard");
const subtitle = document.getElementById("loginSubtitle");
const errorMessage = document.getElementById("errorMessage");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const submitBtn = form.querySelector(".login-submit");

// Each company signs in through its own link (login.html?c=<token>), issued
// by the AegisGuard admin when the company was created.
const loginToken = new URLSearchParams(window.location.search).get("c") || getLoginToken();

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

function disableForm(message) {
  errorMessage.textContent = message;
  usernameInput.disabled = true;
  passwordInput.disabled = true;
  submitBtn.disabled = true;
}

async function loadPortal() {
  if (!loginToken) {
    disableForm("Please open the login link provided by your AegisGuard administrator.");
    return;
  }

  try {
    const portal = await apiFetch(`/api/auth/portal/${encodeURIComponent(loginToken)}`, { skipAuthRedirect: true });
    setLoginToken(loginToken);
    subtitle.textContent = `Sign in to ${portal.company_name}`;
    if (!usernameInput.value) usernameInput.value = portal.company_name;
    passwordInput.focus();
  } catch (err) {
    disableForm(err.message || "This login link is not valid.");
  }
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

  submitBtn.disabled = true;

  try {
    const result = await apiFetch("/api/auth/login", {
      method: "POST",
      body: { login_token: loginToken, username, password },
      skipAuthRedirect: true,
    });

    clearError();
    setSession(result.access_token, result.user, result.must_change_password);
    window.location.href = result.must_change_password ? "change-password.html" : "dashboard.html";
  } catch (err) {
    showError(err.message || "Username or password wrong, please try again.", [usernameInput, passwordInput]);
    submitBtn.disabled = false;
  }
});

loadPortal();
