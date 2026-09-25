const form = document.getElementById("loginForm");
const errorMessage = document.getElementById("errorMessage");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const windowsSignInBtn = document.getElementById("windowsSignIn");

// TEMP: stand-in for the real C# auth endpoint until it exists.
// Replace this whole function with a fetch("/api/auth/login", ...) call.
function fakeAuthenticate(username, password) {
  return username === "tester1" && password === "1234";
}

function clearFieldErrors() {
  usernameInput.classList.remove("error", "success");
  passwordInput.classList.remove("error", "success");
}

function shakeCard() {
  const card = form;
  card.classList.remove("shake");
  // force reflow so the animation can restart on consecutive errors
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

form.addEventListener("submit", (event) => {
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

  // TODO: replace with a real call to the C# backend once the API is ready.
  const success = fakeAuthenticate(username, password);

  if (!success) {
    showError("Username or password wrong, please try again.", [usernameInput, passwordInput]);
    return;
  }

  clearError();
  usernameInput.classList.add("success");
  passwordInput.classList.add("success");
  console.log("Sign in attempt", { username, rememberMe: form.rememberMe.checked });

  // TODO: once the backend exists, store the real signed-in user info
  // (e.g. from the auth response) instead of the raw form value.
  sessionStorage.setItem("username", username);

  setTimeout(() => {
    window.location.href = "dashboard.html";
  }, 500);
});

windowsSignInBtn.addEventListener("click", () => {
  // TODO: wire up Windows/SSO sign-in once the backend auth flow is defined.
  console.log("Windows sign-in clicked");
});
