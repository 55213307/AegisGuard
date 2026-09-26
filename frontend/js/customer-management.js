requireAuth();

const addCustomerForm = document.getElementById("addCustomerForm");
const directorySearch = document.getElementById("directorySearch");
const rowList = document.getElementById("directoryRowList");
const emptyState = document.getElementById("directoryEmptyState");
const overflowNote = document.getElementById("queueOverflowNote");

const MAX_VISIBLE_QUEUE = 4;

// Source of truth for the whole queue, visible rows AND the ones waiting
// off-screen. DOM only ever renders the first MAX_VISIBLE_QUEUE entries.
// Read-only: a customer leaves this list only once its admin account is
// approved (Active) in Account Management, so there's nothing to click here.
let queue = [];

function updateEmptyState() {
  emptyState.style.display = queue.length === 0 ? "flex" : "none";
}

function updateOverflowNote() {
  const hidden = queue.length - MAX_VISIBLE_QUEUE;
  if (hidden > 0) {
    overflowNote.textContent = `+${hidden} more waiting in queue`;
    overflowNote.style.display = "block";
  } else {
    overflowNote.textContent = "";
    overflowNote.style.display = "none";
  }
}

function renumberVisibleRows() {
  const rows = Array.from(rowList.querySelectorAll(".cm-row"));
  rows.forEach((row, index) => {
    row.querySelector(".cm-queue-badge").textContent = index + 1;
  });
}

function createRowElement(item, { animateIn = false } = {}) {
  const li = document.createElement("li");
  li.className = animateIn ? "cm-row cm-row-enter" : "cm-row";
  li.dataset.id = item.id;

  li.innerHTML = `
    <div class="cm-row-info">
      <p class="cm-row-company"></p>
      <p class="cm-row-detail"></p>
    </div>
    <span class="cm-queue-badge"></span>
  `;

  li.querySelector(".cm-row-company").textContent = item.company_name;
  li.querySelector(".cm-row-detail").textContent = `ID: ${item.customer_code}`;

  if (animateIn) {
    li.addEventListener("animationend", () => li.classList.remove("cm-row-enter"), { once: true });
  }

  return li;
}

function renderInitialQueue() {
  rowList.innerHTML = "";
  queue.slice(0, MAX_VISIBLE_QUEUE).forEach((item) => {
    rowList.appendChild(createRowElement(item));
  });
  renumberVisibleRows();
  updateEmptyState();
  updateOverflowNote();
}

async function loadQueue() {
  try {
    const data = await apiFetch("/api/customers/queue");
    queue = data.items;
    renderInitialQueue();
  } catch (err) {
    console.error("Failed to load activation queue", err);
    emptyState.querySelector("p").textContent =
      "Could not load the activation queue. Please refresh the page.";
    emptyState.style.display = "flex";
  }
}

addCustomerForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(addCustomerForm);
  const payload = {
    company_name: formData.get("companyName")?.trim(),
    contact_person: formData.get("contactPerson")?.trim() || null,
    contact_email: formData.get("contactEmail")?.trim(),
    area_code: formData.get("areaCode") || null,
    contact_number: formData.get("contactNumber")?.trim() || null,
    remark: formData.get("remark")?.trim() || null,
  };

  const submitBtn = addCustomerForm.querySelector(".cm-submit-btn");
  submitBtn.disabled = true;

  try {
    // Creating the customer also creates its Pending admin account, so it
    // joins the back of this queue immediately.
    const created = await apiFetch("/api/customers", { method: "POST", body: payload });
    queue.push(created);

    const visibleRows = rowList.querySelectorAll(".cm-row");
    if (visibleRows.length < MAX_VISIBLE_QUEUE) {
      rowList.appendChild(createRowElement(created, { animateIn: true }));
      renumberVisibleRows();
    }

    updateEmptyState();
    updateOverflowNote();
    addCustomerForm.reset();
  } catch (err) {
    console.error("Failed to create customer", err);
    alert(err.message || "Could not create this customer. Please try again.");
  } finally {
    submitBtn.disabled = false;
  }
});

directorySearch.addEventListener("input", () => {
  const query = directorySearch.value.trim().toLowerCase();

  rowList.querySelectorAll(".cm-row").forEach((row) => {
    const company = row.querySelector(".cm-row-company").textContent.toLowerCase();
    const detail = row.querySelector(".cm-row-detail").textContent.toLowerCase();
    const matches = company.includes(query) || detail.includes(query);
    row.style.display = matches ? "" : "none";
  });
});

loadQueue();
