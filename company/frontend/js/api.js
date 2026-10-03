// Shared helper for talking to the FastAPI backend, which serves this same
// frontend (same origin), so plain relative paths work.

const TOKEN_KEY = "accessToken";
const USERNAME_KEY = "username";
const MUST_CHANGE_KEY = "mustChangePassword";
// Which company's login link was used. Kept in localStorage (it's just the
// login URL, not a secret) so logging out or an expired session returns to
// that company's own login page instead of a page with no company.
const LOGIN_TOKEN_KEY = "companyLoginToken";

// Must match PASSWORD_CHANGE_REQUIRED in backend app/api/deps.py.
const PASSWORD_CHANGE_REQUIRED = "Password change required";

function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

function setSession(token, user, mustChangePassword) {
  sessionStorage.setItem(TOKEN_KEY, token);
  sessionStorage.setItem(USERNAME_KEY, user.display_name);
  sessionStorage.setItem(MUST_CHANGE_KEY, mustChangePassword ? "1" : "0");
}

function markPasswordChanged() {
  sessionStorage.setItem(MUST_CHANGE_KEY, "0");
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USERNAME_KEY);
  sessionStorage.removeItem(MUST_CHANGE_KEY);
}

function getLoginToken() {
  return localStorage.getItem(LOGIN_TOKEN_KEY);
}

function setLoginToken(loginToken) {
  localStorage.setItem(LOGIN_TOKEN_KEY, loginToken);
}

function loginPageUrl() {
  const loginToken = getLoginToken();
  return loginToken ? `login.html?c=${encodeURIComponent(loginToken)}` : "login.html";
}

function goToLogin() {
  window.location.href = loginPageUrl();
}

// Call at the top of any page that requires a signed-in company. Pages other
// than change-password.html also require the issued password to be replaced.
function requireAuth({ allowPasswordChangePending = false } = {}) {
  if (!getToken()) {
    goToLogin();
    return;
  }
  if (!allowPasswordChangePending && sessionStorage.getItem(MUST_CHANGE_KEY) === "1") {
    window.location.href = "change-password.html";
  }
}

/**
 * Wrapper around fetch() that adds the JWT, parses JSON, and normalizes
 * errors. On a 401 it clears the session and bounces to the login page,
 * unless skipAuthRedirect is set (used by the login call itself, where a 401
 * just means "wrong credentials", not "session expired").
 */
async function apiFetch(path, { method = "GET", body, skipAuthRedirect = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (networkError) {
    throw new Error("Could not reach the server. Please check your connection and try again.");
  }

  if (response.status === 401 && !skipAuthRedirect) {
    clearSession();
    goToLogin();
    throw new Error("Session expired");
  }

  if (response.status === 204) {
    return null;
  }

  let data = null;
  const text = await response.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (parseError) {
      data = null;
    }
  }

  if (response.status === 403 && data && data.detail === PASSWORD_CHANGE_REQUIRED) {
    window.location.href = "change-password.html";
    throw new Error(PASSWORD_CHANGE_REQUIRED);
  }

  if (!response.ok) {
    throw new Error(extractErrorMessage(data));
  }

  return data;
}

// Downloads a file from an authenticated endpoint (a plain <a href> can't
// send the Bearer token) and saves it under the server-provided filename.
async function apiDownload(path, fallbackName) {
  let response;
  try {
    response = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } });
  } catch (networkError) {
    throw new Error("Could not reach the server. Please check your connection and try again.");
  }
  if (response.status === 401) {
    clearSession();
    goToLogin();
    throw new Error("Session expired");
  }
  if (!response.ok) {
    let data = null;
    try {
      data = await response.json();
    } catch (parseError) {
      data = null;
    }
    throw new Error(extractErrorMessage(data));
  }

  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = match ? match[1] : fallbackName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// Fetches an authenticated image. Returns { blob, headers }, or null when the
// server has nothing to show yet (404).
async function apiFetchImage(path) {
  const response = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` }, cache: "no-store" });
  if (response.status === 401) {
    clearSession();
    goToLogin();
    throw new Error("Session expired");
  }
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`Image request failed (${response.status})`);
  return { blob: await response.blob(), headers: response.headers };
}

// FastAPI returns validation errors (422) as a list of {msg, ...} objects.
function extractErrorMessage(data) {
  const fallback = "Something went wrong. Please try again.";
  if (!data || !data.detail) return fallback;
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail) && data.detail[0] && data.detail[0].msg) {
    return data.detail[0].msg.replace(/^Value error, /, "");
  }
  return fallback;
}
