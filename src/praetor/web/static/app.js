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
  $("phase").textContent = frame.phase;
  $("narration").textContent = frame.narration;
  renderLedger(frame.ledger);
  pushFeed(frame);
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/ws/demo`);
  ws.onopen = () => setConn(true);
  ws.onmessage = (ev) => apply(JSON.parse(ev.data));
  ws.onclose = () => {
    setConn(false);
    setTimeout(connect, 1500); // auto-reconnect
  };
  ws.onerror = () => ws.close();
}

connect();
