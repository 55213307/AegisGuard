// Shared helper for talking to the FastAPI backend, which serves this same
// frontend (same origin), so plain relative paths work.

const TOKEN_KEY = "accessToken";
const USERNAME_KEY = "username";

function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

function setSession(token, username) {
  sessionStorage.setItem(TOKEN_KEY, token);
  sessionStorage.setItem(USERNAME_KEY, username);
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USERNAME_KEY);
}

// Call at the top of any page that requires a signed-in user.
function requireAuth() {
  if (!getToken()) {
    window.location.href = "login.html";
  }
}

/**
 * Wrapper around fetch() that adds the JWT, parses JSON, and normalizes
 * errors. On a 401 it clears the session and bounces to login.html, unless
 * skipAuthRedirect is set (used by the login call itself, where a 401 just
 * means "wrong credentials", not "session expired").
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
    window.location.href = "login.html";
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

  if (!response.ok) {
    const detail = data && data.detail ? data.detail : "Something went wrong. Please try again.";
    throw new Error(typeof detail === "string" ? detail : "Something went wrong. Please try again.");
  }

  return data;
}
