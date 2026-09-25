const addCustomerForm = document.getElementById("addCustomerForm");
const directorySearch = document.getElementById("directorySearch");
const rowList = document.getElementById("directoryRowList");
const emptyState = document.getElementById("directoryEmptyState");
const overflowNote = document.getElementById("queueOverflowNote");

const MAX_VISIBLE_QUEUE = 4;

// TODO: once the backend exists, load the real queue here instead of
// starting empty, e.g. fetch("/api/customers/queue").then(...).
let nextCustomerNumber = 1;

// Source of truth for the whole queue, visible rows AND the ones waiting
// off-screen. DOM only ever renders the first MAX_VISIBLE_QUEUE entries.
const queue = [];

function formatCustomerNumber(n) {
  return String(n).padStart(3, "0");
}

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
  const rows = Array.from(rowList.querySelectorAll(".cm-row:not(.cm-row-exit)"));
  rows.forEach((row, index) => {
    row.querySelector(".cm-queue-badge").textContent = index + 1;
  });
}

function createRowElement(item) {
  const li = document.createElement("li");
  li.className = "cm-row cm-row-enter";
  li.dataset.id = item.id;

  li.innerHTML = `
    <div class="cm-row-info">
      <p class="cm-row-company"></p>
      <p class="cm-row-detail"></p>
    </div>
    <span class="cm-queue-badge"></span>
    <button class="cm-activate-btn" type="button" title="Activate this customer">&#10003;</button>
  `;

  li.querySelector(".cm-row-company").textContent = item.company;
  li.querySelector(".cm-row-detail").textContent = `ID: ${item.id}`;

  li.addEventListener(
    "animationend",
    () => li.classList.remove("cm-row-enter"),
    { once: true }
  );

  return li;
}

updateEmptyState();
updateOverflowNote();

function addCustomerToQueue(companyName) {
  const item = { id: `AG-CUS-${formatCustomerNumber(nextCustomerNumber)}`, company: companyName };
  nextCustomerNumber += 1;
  // New customers join the back of the line.
  queue.push(item);

  const visibleRows = rowList.querySelectorAll(".cm-row:not(.cm-row-exit)");
  if (visibleRows.length < MAX_VISIBLE_QUEUE) {
    // There's still room on screen — show it sliding in at the bottom.
    rowList.appendChild(createRowElement(item));
    renumberVisibleRows();
  }
  // Otherwise it just waits off-screen; the overflow note below picks it up.

  updateEmptyState();
  updateOverflowNote();
}

function fadeOutRow(row) {
  if (row.classList.contains("cm-row-exit")) return;

  row.classList.add("cm-row-exit");
  row.addEventListener(
    "animationend",
    () => {
      row.remove();
      renumberVisibleRows();
      updateEmptyState();
      updateOverflowNote();
      revealNextQueuedRow();
    },
    { once: true }
  );
}

// After a visible row is removed for good (activated), pull the next
// waiting customer (if any) into the now-empty 4th slot.
function revealNextQueuedRow() {
  const visibleCount = rowList.querySelectorAll(".cm-row:not(.cm-row-exit)").length;
  if (visibleCount >= MAX_VISIBLE_QUEUE) return;

  const nextItem = queue[visibleCount];
  if (!nextItem) return;

  rowList.appendChild(createRowElement(nextItem));
  renumberVisibleRows();
  updateOverflowNote();
}

function activateRow(row) {
  if (row.classList.contains("cm-row-exit")) return;

  const customerId = row.dataset.id;
  const queueIndex = queue.findIndex((item) => item.id === customerId);
  if (queueIndex !== -1) queue.splice(queueIndex, 1);

  // TODO: call the C# backend to mark this customer as activated, e.g.
  // fetch(`/api/customers/${customerId}/activate`, { method: "POST" })
  fadeOutRow(row);
}

rowList.addEventListener("click", (event) => {
  const btn = event.target.closest(".cm-activate-btn");
  if (!btn) return;
  const row = btn.closest(".cm-row");
  if (row) activateRow(row);
});

addCustomerForm.addEventListener("submit", (event) => {
  event.preventDefault();

  const formData = new FormData(addCustomerForm);
  const payload = Object.fromEntries(formData.entries());

  // TODO: replace with a real call to the C# backend, e.g.
  // fetch("/api/customers", { method: "POST", body: JSON.stringify(payload) })
  console.log("Create customer", payload);

  addCustomerToQueue(payload.companyName);

  addCustomerForm.reset();
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
