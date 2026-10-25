// In-page replacements for the browser's confirm / prompt / alert boxes, in the
// portal's own style. Each returns a promise:
//   Dialogs.confirm({ title, message, confirmLabel, danger })  -> true / false
//   Dialogs.prompt({ title, message, value, placeholder, confirmLabel, validate })
//                                                              -> the text, or null if cancelled
//   Dialogs.choose({ title, message, options, value, confirmLabel })
//                                                              -> the chosen option's value, or null if cancelled
//   Dialogs.notice({ title, message })                         -> resolves when closed
// `validate(text)` returns an error to show inside the dialog (it stays open) or a
// falsy value to accept. Text is always set with textContent, never as HTML.
const Dialogs = (() => {
  let counter = 0;

  function open({ title, message, input, select, confirmLabel, cancelLabel, danger, validate }) {
    return new Promise((resolve) => {
      const id = `agDialog${++counter}`;
      const previousFocus = document.activeElement;
      const scrim = document.createElement("div");
      scrim.className = "ag-dialog-scrim";
      scrim.innerHTML = `
        <div class="ag-dialog" role="dialog" aria-modal="true" aria-labelledby="${id}Title">
          <h2 class="ag-dialog-title" id="${id}Title"></h2>
          <p class="ag-dialog-message"></p>
          ${input ? `<input type="text" class="ag-dialog-input" autocomplete="off" spellcheck="false" />` : ""}
          ${select ? `<select class="ag-dialog-input"></select>` : ""}
          <p class="ag-dialog-error" role="alert"></p>
          <div class="ag-dialog-actions">
            ${cancelLabel ? `<button type="button" class="ag-dialog-btn" data-role="cancel"></button>` : ""}
            <button type="button" class="ag-dialog-btn ag-dialog-btn-primary${danger ? " ag-dialog-btn-danger" : ""}" data-role="ok"></button>
          </div>
        </div>`;

      const field = scrim.querySelector(".ag-dialog-input");
      const errorEl = scrim.querySelector(".ag-dialog-error");
      const okBtn = scrim.querySelector('[data-role="ok"]');
      const cancelBtn = scrim.querySelector('[data-role="cancel"]');
      scrim.querySelector(".ag-dialog-title").textContent = title || "";
      const messageEl = scrim.querySelector(".ag-dialog-message");
      messageEl.textContent = message || "";
      messageEl.hidden = !message;
      okBtn.textContent = confirmLabel;
      if (cancelBtn) cancelBtn.textContent = cancelLabel;
      if (input) {
        field.value = input.value || "";
        field.placeholder = input.placeholder || "";
      }
      if (select) {
        for (const option of select.options) {
          const el = document.createElement("option");
          el.value = option.value;
          el.textContent = option.label;
          field.appendChild(el);
        }
        field.value = select.value;
      }

      function close(result) {
        document.removeEventListener("keydown", onKey, true);
        scrim.remove();
        if (previousFocus && previousFocus.focus) previousFocus.focus();
        resolve(result);
      }

      function accept() {
        if (!field) return close(true);
        const text = field.value.trim();
        const problem = validate && validate(text);
        if (problem) {
          errorEl.textContent = problem;
          field.focus();
          return;
        }
        close(text);
      }

      const dismiss = () => close(field ? null : false);

      function onKey(event) {
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          dismiss();
        } else if (event.key === "Enter" && event.target.tagName !== "BUTTON") {
          event.preventDefault();
          accept();
        } else if (event.key === "Tab") {
          // keep focus inside the dialog
          const items = [...scrim.querySelectorAll("input, select, button")];
          const first = items[0];
          const last = items[items.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
          }
        }
      }

      scrim.addEventListener("mousedown", (event) => {
        if (event.target === scrim && cancelLabel) dismiss();
      });
      okBtn.addEventListener("click", accept);
      if (cancelBtn) cancelBtn.addEventListener("click", dismiss);
      if (field) field.addEventListener("input", () => (errorEl.textContent = ""));

      document.addEventListener("keydown", onKey, true);
      document.body.appendChild(scrim);
      if (field) {
        field.focus();
        if (field.select) field.select(); // a <select> has nothing to highlight
      } else {
        // a destructive question starts on Cancel so Enter can't delete by accident
        (danger && cancelBtn ? cancelBtn : okBtn).focus();
      }
    });
  }

  return {
    confirm: ({ title, message, confirmLabel = "Confirm", danger = false }) =>
      open({ title, message, confirmLabel, cancelLabel: "Cancel", danger }),
    prompt: ({ title, message, value, placeholder, confirmLabel = "Save", validate }) =>
      open({ title, message, input: { value, placeholder }, confirmLabel, cancelLabel: "Cancel", validate }),
    choose: ({ title, message, options, value, confirmLabel = "Save" }) =>
      open({ title, message, select: { options, value }, confirmLabel, cancelLabel: "Cancel" }),
    notice: ({ title = "Notice", message }) => open({ title, message, confirmLabel: "OK" }),
  };
})();
