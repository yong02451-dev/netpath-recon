const $ = (id) => document.getElementById(id);

const modeButtons = document.querySelectorAll(".mode");
const moduleRows = $("module-rows");
const activeBox = $("active");

const MODE_NAMES = { full: "Full recon", path: "Network path + recon", individual: "Individual modules" };

let modules = [];
let mode = "full";
let socket = null;
let rowRefs = new Map();
let counts = { ok: 0, skipped: 0, error: 0 };

// IMPORTANT: everything below uses textContent, never innerHTML.
// Module data comes from remote servers and can contain attacker-controlled
// text. textContent keeps it inert: it can never run as HTML or script.

function td(text, cls) {
  const cell = document.createElement("td");
  cell.textContent = text === null || text === undefined || text === "" ? "n/a" : String(text);
  if (cls) cell.className = cls;
  return cell;
}

function tr(cells, cls) {
  const row = document.createElement("tr");
  if (cls) row.className = cls;
  row.append(...cells);
  return row;
}

function tierCell(tier) {
  return td(tier === "active" ? "Active" : "Passive", tier === "active" ? "ta" : "tp");
}

// ---------- Start view: module picker, built from GET /modules ----------

function unavailable(m) {
  if (m.tier === "active" && !activeBox.checked) return "Needs active checks";
  if (m.needs_key && !m.key_configured) return "Needs API key";
  return null;
}

function renderModules() {
  moduleRows.replaceChildren();
  rowRefs = new Map();

  const groups = [
    { label: "Passive: public sources, no key", dot: "g", test: (m) => m.tier !== "active" && !m.needs_key },
    { label: "Passive: needs an API key", dot: "k", test: (m) => m.tier !== "active" && m.needs_key },
    { label: "Active: contacts the target, opt-in", dot: "a", test: (m) => m.tier === "active" },
  ];

  for (const group of groups) {
    const members = modules.filter(group.test);
    if (members.length === 0) continue;

    const header = document.createElement("tr");
    header.className = "grp";
    const headerCell = document.createElement("td");
    headerCell.colSpan = 5;
    const dot = document.createElement("span");
    dot.className = `dot ${group.dot}`;
    headerCell.append(dot, group.label);
    header.append(headerCell);
    moduleRows.append(header);

    for (const m of members) {
      const box = document.createElement("input");
      box.type = "checkbox";
      box.setAttribute("aria-label", `Select ${m.name}`);
      box.checked = !unavailable(m);   // start with every available module ticked

      const boxCell = document.createElement("td");
      boxCell.append(box);
      const tier = document.createElement("td");
      const row = tr([boxCell, td(m.name), td(m.description, "m"), td(m.source, "m"), tier]);

      moduleRows.append(row);
      rowRefs.set(m.id, { module: m, row, box, tier });
    }
  }
  refreshModuleStates();
}

function refreshModuleStates() {
  for (const ref of rowRefs.values()) {
    const reason = unavailable(ref.module);
    ref.row.classList.toggle("off", Boolean(reason));
    ref.box.disabled = Boolean(reason) || mode !== "individual";
    if (reason) ref.box.checked = false;
    ref.tier.textContent = reason || (ref.module.tier === "active" ? "Active" : "Passive");
    ref.tier.className = ref.module.needs_key && !ref.module.key_configured
      ? "tk" : (ref.module.tier === "active" ? "ta" : "tp");
  }
}

function selectedIds() {
  return [...rowRefs.values()]
    .filter((ref) => ref.box.checked && !ref.box.disabled)
    .map((ref) => ref.module.id);
}

async function loadModules() {
  try {
    const response = await fetch("/modules");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    modules = await response.json();
    renderModules();
  } catch (err) {
    $("form-error").textContent = "Could not load the module list. Is the server running?";
  }
}

function setMode(next) {
  mode = next;
  for (const button of modeButtons) {
    const selected = button.dataset.mode === mode;
    button.classList.toggle("sel", selected);
    button.querySelector(".glyph").textContent = selected ? "◉" : "○";
  }
  $("module-section").classList.toggle("dim", mode !== "individual");
  refreshModuleStates();
  $("path-note").classList.toggle("hidden", mode !== "path");
}

modeButtons.forEach((button) => {
  button.addEventListener("click", () => setMode(button.dataset.mode));
});

activeBox.addEventListener("change", () => {
  $("active-label").textContent = `Active checks: ${activeBox.checked ? "ON" : "OFF"}`;
  refreshModuleStates();
});

// ---------- Views ----------

function showView(name) {
  $("view-start").classList.toggle("hidden", name !== "start");
  $("view-results").classList.toggle("hidden", name !== "results");
}

function backToStart() {
  if (socket) {
    socket.close();
    socket = null;
  }
  showView("start");
}

$("nav-recon").addEventListener("click", backToStart);
$("new-run").addEventListener("click", backToStart);

// ---------- Results view ----------

function setRunStatus(text, cls) {
  const el = $("run-status");
  el.textContent = text;
  el.className = cls;
}

function resetResults(target, active) {
  counts = { ok: 0, skipped: 0, error: 0 };
  for (const id of ["result-modules", "result-observations", "raw-data"]) {
    $(id).replaceChildren();
  }
  $("result-target").textContent = target;
  $("result-mode").textContent = `Mode: ${MODE_NAMES[mode]}`;
  $("path-section").classList.toggle("hidden", mode !== "path");
  Path.reset(target);
  const flag = $("result-active");
  flag.textContent = `Active checks: ${active ? "ON" : "OFF"}`;
  flag.className = "ta";
}

function addResult(result) {
  counts[result.status] = (counts[result.status] || 0) + 1;

  const dot = document.createElement("span");
  dot.className = `dot ${{ ok: "g", skipped: "a", error: "r" }[result.status] || "a"}`;
  const statusCell = document.createElement("td");
  statusCell.append(dot, result.status);

  const note = result.status === "ok"
    ? `${result.observations.length} observations · ${result.duration_ms} ms`
    : (result.error || result.note);

  $("result-modules").append(tr([
    td(result.name), statusCell, td(result.source, "m"), tierCell(result.tier), td(note, "m"),
  ]));

  for (const o of result.observations) {
    $("result-observations").append(tr([
      td(o.text), td(o.category), td(o.evidence, "m"), td(o.source, "m"), tierCell(o.tier),
    ]));
  }

  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = `${result.name} (${result.status})`;
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify(
    result.status === "ok" ? result.data : { status: result.status, error: result.error, note: result.note },
    null, 2,
  );
  details.append(summary, pre);
  $("raw-data").append(details);
}

function startRun(target, moduleIds, active) {
  if (socket) socket.close();

  resetResults(target, active);
  showView("results");
  setRunStatus("connecting...", "running");

  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const endpoint = mode === "path" ? "/ws/trace" : "/ws/recon";
  const ws = new WebSocket(`${protocol}://${location.host}${endpoint}`);
  socket = ws;
  let finished = false;

  ws.onopen = () => {
    setRunStatus("running modules...", "running");
    ws.send(JSON.stringify({ target, modules: moduleIds, active }));
  };

  ws.onmessage = (message) => {
    if (socket !== ws) return;   // ignore a run the user already left
    const evt = JSON.parse(message.data);
    if (Path.stages.has(evt.stage)) {
      Path.handle(evt.stage, evt.data);
      return;
    }
    if (evt.stage === "module") {
      addResult(evt.data);
    } else if (evt.stage === "done") {
      finished = true;
      setRunStatus(`done: ${counts.ok} ok · ${counts.skipped} skipped · ${counts.error} error`, "done");
    } else if (evt.stage === "error") {
      finished = true;
      setRunStatus(evt.data.message || "error", "error");
    }
  };

  ws.onerror = () => setRunStatus("connection error", "error");
  ws.onclose = () => {
    if (!finished && socket === ws) setRunStatus("stopped early", "error");
  };
}

// ---------- Submit ----------

$("run-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const formError = $("form-error");
  formError.textContent = "";

  const target = $("target").value.trim();
  if (!target) {
    formError.textContent = "Enter a domain or IPv4 address.";
    return;
  }

  let moduleIds = null;   // null means "every module"
  if (mode === "individual") {
    moduleIds = selectedIds();
    if (moduleIds.length === 0) {
      formError.textContent = "Pick at least one module.";
      return;
    }
  }

  // activeBox.checked is a real boolean; the server only honors a literal true
  startRun(target, moduleIds, activeBox.checked);
});

setMode("full");
loadModules();