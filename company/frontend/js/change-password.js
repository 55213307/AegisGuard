requireAuth({ allowPasswordChangePending: true });

const form = document.getElementById("changePasswordForm");
const card = document.getElementById("loginCard");
const errorMessage = document.getElementById("errorMessage");
const currentInput = document.getElementById("currentPassword");
const newInput = document.getElementById("newPassword");
const confirmInput = document.getElementById("confirmPassword");
const submitBtn = form.querySelector(".login-submit");
const inputs = [currentInput, newInput, confirmInput];

function showError(message, fieldsToMark) {
  errorMessage.textContent = message;
  inputs.forEach((input) => input.classList.remove("error"));
  fieldsToMark.forEach((field) => field.classList.add("error"));
  card.classList.remove("shake");
  void card.offsetWidth;
  card.classList.add("shake");
}

inputs.forEach((input) => {
  input.addEventListener("input", () => {
    errorMessage.textContent = "";
    input.classList.remove("error");
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const currentPassword = currentInput.value;
  const newPassword = newInput.value;

  const empty = inputs.filter((input) => !input.value);
  if (empty.length) {
    showError("Please fill in all fields.", empty);
    return;
  }
  if (newPassword !== confirmInput.value) {
    showError("New passwords do not match.", [newInput, confirmInput]);
    return;
  }

  submitBtn.disabled = true;

  try {
    await apiFetch("/api/auth/change-password", {
      method: "POST",
      body: { current_password: currentPassword, new_password: newPassword },
    });
    markPasswordChanged();
    window.location.href = "dashboard.html";
  } catch (err) {
    const field = /current/i.test(err.message) ? [currentInput] : [newInput, confirmInput];
    showError(err.message, field);
    submitBtn.disabled = false;
  }
});
