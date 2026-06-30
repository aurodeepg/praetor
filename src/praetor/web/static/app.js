// Praetor Web UI — render the live war-room feed from the gateway WebSocket.
// Each message is a Frame: { phase, narration, badge, cls, message, reason, ledger[] }.

const $ = (id) => document.getElementById(id);
const MAX_FEED = 40;

function setConn(ok) {
  const el = $("conn");
  el.textContent = ok ? "live" : "disconnected";
  el.className = "conn " + (ok ? "on" : "off");
}

function renderLedger(rows) {
  const tbody = $("ledger").querySelector("tbody");
  tbody.innerHTML = "";
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr class="empty"><td colspan="5">no live authority</td></tr>';
    return;
  }
  for (const w of rows) {
    const low = w.remaining <= Math.max(1, Math.floor(w.ttl / 3));
    const tr = document.createElement("tr");
    tr.className = "flash";
    tr.innerHTML =
      `<td class="agent">${w.agent}</td>` +
      `<td>${w.capability}</td>` +
      `<td class="scope">${w.scope}</td>` +
      `<td class="trust">${w.trust}</td>` +
      `<td class="${low ? "ttl-low" : "ttl-ok"}">${w.remaining}s</td>`;
    tbody.appendChild(tr);
  }
}

function pushFeed(frame) {
  const feed = $("feed");
  const li = document.createElement("li");
  const reason = frame.reason ? `<div class="reason">↳ ${frame.reason}</div>` : "";
  li.innerHTML =
    `<span class="badge ${frame.cls}">${frame.badge}</span>` +
    `<div><div class="msg">${frame.message}</div>${reason}</div>`;
  feed.prepend(li);
  while (feed.children.length > MAX_FEED) feed.removeChild(feed.lastChild);
}

function apply(frame) {
  if (frame.error) return; // e.g. unknown scenario
  $("phase").textContent = frame.phase;
  $("narration").textContent = frame.narration;
  renderLedger(frame.ledger);
  pushFeed(frame);
}

let ws = null;
let scenario = "phase1-war-room";

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/api/ws/demo?scenario=${encodeURIComponent(scenario)}`);
  ws.onopen = () => setConn(true);
  ws.onmessage = (ev) => apply(JSON.parse(ev.data));
  ws.onclose = () => {
    setConn(false);
    setTimeout(connect, 1500); // auto-reconnect (with the current scenario)
  };
  ws.onerror = () => ws.close();
}

function switchScenario(key) {
  scenario = key;
  $("feed").innerHTML = "";
  renderLedger([]);
  $("narration").textContent = "Opening scenario…";
  if (ws) ws.close(); // onclose reconnects with the new scenario
}

async function initScenarioPicker() {
  const sel = $("scenario");
  try {
    const list = await (await fetch("/api/scenarios")).json();
    for (const s of list) {
      const opt = document.createElement("option");
      opt.value = s.key;
      opt.textContent = s.title;
      sel.appendChild(opt);
    }
    sel.value = scenario;
    sel.onchange = () => switchScenario(sel.value);
  } catch {
    sel.style.display = "none"; // API unavailable — fall back to default stream
  }
}

// ── orchestrator composer: POST /api/compose → fit ranking (read-only preview) ──
function renderCompose(res) {
  const note = $("compose-note");
  const table = $("compose-table");
  const tbody = table.querySelector("tbody");
  tbody.innerHTML = "";
  if (!res.ranked || res.ranked.length === 0) {
    note.textContent = res.note || "no viable agent";
    table.hidden = true;
    return;
  }
  note.innerHTML = res.chosen
    ? `would admit <strong>${res.chosen}</strong> — fit ${res.fit.score.toFixed(3)} ` +
      `<span class="reason">(${res.fit.rationale})</span>`
    : (res.note || "no viable agent");
  for (const f of res.ranked) {
    const tr = document.createElement("tr");
    if (f.agent === res.chosen) tr.className = "chosen";
    tr.innerHTML =
      `<td>${f.score.toFixed(3)}</td><td class="agent">${f.agent}</td>` +
      `<td>${f.capability}</td><td>${f.capability_match.toFixed(2)}</td>` +
      `<td>${f.trust.toFixed(2)}</td><td>${f.budget.toFixed(0)}</td>` +
      `<td>${f.availability.toFixed(0)}</td>`;
    tbody.appendChild(tr);
  }
  table.hidden = false;
}

function initComposer() {
  const form = $("compose-form");
  if (!form) return;
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    const requirement = $("compose-input").value.trim();
    if (!requirement) return;
    $("compose-note").textContent = "composing…";
    try {
      const res = await fetch("/api/compose", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ requirement }),
      });
      renderCompose(await res.json());
    } catch {
      $("compose-note").textContent = "compose unavailable";
    }
  };
}

initScenarioPicker();
initComposer();
connect();
