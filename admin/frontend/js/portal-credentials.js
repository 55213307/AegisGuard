// Shows a company's portal login details right after they're issued. The
// password is only returned by the API at that moment (only its hash is
// stored), so this dialog is the admin's one chance to copy it.
function showPortalCredentials(credentials, { title = "Company Portal Login" } = {}) {
  const backdrop = document.createElement("div");
  backdrop.className = "pc-backdrop";
  backdrop.innerHTML = `
    <div class="pc-dialog" role="dialog" aria-modal="true" aria-labelledby="pcTitle">
      <h2 class="pc-title" id="pcTitle"></h2>
      <p class="pc-helper">Send these to the company. The password is shown only once and must be changed on first login.</p>
      <dl class="pc-fields">
        <div class="pc-field"><dt>Login URL</dt><dd><code data-field="login_url"></code><button type="button" class="pc-copy" data-copy="login_url">Copy</button></dd></div>
        <div class="pc-field"><dt>Username</dt><dd><code data-field="login_username"></code><button type="button" class="pc-copy" data-copy="login_username">Copy</button></dd></div>
        <div class="pc-field"><dt>Password</dt><dd><code data-field="initial_password"></code><button type="button" class="pc-copy" data-copy="initial_password">Copy</button></dd></div>
      </dl>
      <div class="pc-actions">
        <button type="button" class="pc-copy-all">Copy All</button>
        <button type="button" class="pc-done">Done</button>
      </div>
    </div>
  `;

  backdrop.querySelector(".pc-title").textContent = title;
  backdrop.querySelectorAll("[data-field]").forEach((el) => {
    el.textContent = credentials[el.dataset.field];
  });

  async function copy(text, button) {
    try {
      await navigator.clipboard.writeText(text);
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => (button.textContent = original), 1200);
    } catch (err) {
      alert("Could not copy automatically. Please select and copy the text manually.");
    }
  }

  backdrop.addEventListener("click", (event) => {
    const copyBtn = event.target.closest("[data-copy]");
    if (copyBtn) {
      copy(credentials[copyBtn.dataset.copy], copyBtn);
    } else if (event.target.closest(".pc-copy-all")) {
      copy(
        `Login URL: ${credentials.login_url}\nUsername: ${credentials.login_username}\nPassword: ${credentials.initial_password}`,
        event.target.closest(".pc-copy-all")
      );
    } else if (event.target.closest(".pc-done")) {
      backdrop.remove();
    }
  });

  document.body.appendChild(backdrop);
}
