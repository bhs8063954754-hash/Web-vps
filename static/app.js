/* QWERTY VPS - frontend application */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const state = {
  user: null,
  csrf: null,
  view: "overview",
  statsWs: null,
  logsWs: null,
  logsPaused: false,
  logsBuffer: [],
  chartData: { cpu: [], ram: [], labels: [], max: 40 },
  monitorData: { cpu: [], ram: [], net: [], max: 30 },
  currentFileDir: "",
  apps: [],
};

/* ---------------- helpers ---------------- */
function fmtBytes(b) {
  if (!b) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtRate(bps) { return fmtBytes(bps) + "/s"; }
function escapeHtml(s) {
  var map = { 38: "amp", 60: "lt", 62: "gt", 34: "quot", 39: "#39" };
  return String(s).replace(/[&<>"']/g, function (c) {
    return "&" + map[c.charCodeAt(0)] + ";";
  });
}

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body && typeof opts.body !== "string" && !(opts.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  if (state.csrf && ["POST", "PUT", "DELETE", "PATCH"].includes(opts.method || "GET")) {
    headers["X-CSRF-Token"] = state.csrf;
  }
  const res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
  let data;
  try { data = await res.json(); } catch { data = { ok: false, error: "Invalid response" }; }
  if (res.status === 401) { forceLogout(); throw new Error("Unauthorized"); }
  return data;
}

function toast(msg, type = "info", ms = 3500) {
  const c = $("#toast-container");
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateX(40px)"; setTimeout(() => el.remove(), 300); }, ms);
}

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

/* ---------------- auth ---------------- */
async function bootstrap() {
  try {
    const me = await api("/api/me");
    if (me.ok) { enterApp(me.user); }
  } catch { /* not logged in */ }
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#login-btn");
  btn.disabled = true;
  $(".btn-spinner", btn) && show($(".btn-spinner", btn));
  const username = $("#username").value.trim();
  const password = $("#password").value;
  try {
    const r = await api("/api/login", { method: "POST", body: { username, password } });
    if (r.ok) {
      toast("Welcome back!", "success");
      await fetchCsrf();
      enterApp({ username: r.username, is_admin: r.is_admin });
    } else {
      toast(r.error || "Login failed", "error");
    }
  } catch (err) {
    toast("Connection error", "error");
  }
  btn.disabled = false;
  const sp = $(".btn-spinner", btn); if (sp) hide(sp);
});

async function fetchCsrf() {
  try { const r = await api("/api/csrf"); if (r.ok) state.csrf = r.csrf; } catch {}
}

function enterApp(user) {
  state.user = user;
  hide($("#login-screen"));
  show($("#app-shell"));
  $("#user-chip").textContent = "👤 " + user.username + (user.is_admin ? "  ·  Admin" : "");
  $$(".admin-only").forEach((el) => user.is_admin ? show(el) : hide(el));
  switchView("overview");
  startStatsWs();
  startLogsWs();
  loadOverview();
  loadServerInfo();
}

function forceLogout() {
  state.user = null;
  hide($("#app-shell"));
  show($("#login-screen"));
  if (state.statsWs) { state.statsWs.close(); state.statsWs = null; }
  if (state.logsWs) { state.logsWs.close(); state.logsWs = null; }
}

$("#logout-btn").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  toast("Logged out", "info");
  forceLogout();
});

/* ---------------- navigation ---------------- */
$$(".nav-item").forEach((item) => {
  item.addEventListener("click", () => {
    switchView(item.dataset.view);
    closeSidebar();
  });
});

function switchView(view) {
  state.view = view;
  $$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  $$(".view").forEach((v) => v.classList.add("hidden"));
  const target = $("#view-" + view);
  if (target) show(target);
  $("#page-title").textContent = view.charAt(0).toUpperCase() + view.slice(1);

  if (view === "overview") { loadOverview(); loadServerInfo(); }
  if (view === "applications") loadApps();
  if (view === "console") loadConsoleApps();
  if (view === "files") loadFiles("");
  if (view === "backups") loadBackups();
  if (view === "settings") loadSettings();
  if (view === "admin") loadAdmin();
}

/* ---------------- mobile sidebar ---------------- */
$("#menu-toggle").addEventListener("click", () => {
  $("#sidebar").classList.toggle("open");
  $("#backdrop").classList.toggle("hidden");
});
$("#backdrop").addEventListener("click", closeSidebar);
function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#backdrop").classList.add("hidden");
}

/* ---------------- overview ---------------- */
async function loadOverview() {
  refreshStats();
}

async function loadServerInfo() {
  try {
    const r = await api("/api/server");
    if (!r.ok) return;
    const s = r.server;
    $("#server-info").innerHTML = `
      <div class="k">Status</div><div class="v"><span class="badge online">${s.status.toUpperCase()}</span></div>
      <div class="k">Hostname</div><div class="v">${escapeHtml(s.hostname)}</div>
      <div class="k">OS</div><div class="v">${escapeHtml(s.os)}</div>
      <div class="k">Uptime</div><div class="v">${escapeHtml(s.uptime)}</div>
      <div class="k">Load</div><div class="v">${escapeHtml(s.load)}</div>`;
    if (state.view === "settings") {
      $("#settings-server").innerHTML = $("#server-info").innerHTML;
    }
  } catch {}
}

function refreshStats() {
  // stats arrive via websocket; this is a fallback poll
  api("/api/stats").then((r) => { if (r.ok) updateStats(r.stats); }).catch(() => {});
}

function updateStats(s) {
  $("#stat-cpu").textContent = s.cpu.toFixed(1) + "%";
  setBar("#bar-cpu", s.cpu);
  $("#stat-ram").textContent = fmtBytes(s.ram_used) + " / " + fmtBytes(s.ram_total);
  setBar("#bar-ram", s.ram_percent);
  $("#stat-disk").textContent = fmtBytes(s.disk_used) + " / " + fmtBytes(s.disk_total);
  setBar("#bar-disk", s.disk_percent);
  $("#stat-network").innerHTML = `↓ ${fmtRate(s.network_in)}<br>↑ ${fmtRate(s.network_out)}`;
  $("#stat-uptime").textContent = fmtUptime(s.uptime);

  // chart history
  pushChart(state.chartData, s.cpu, s.ram_percent);
  drawChart($("#chart-stats"), state.chartData, ["#6366f1", "#22c55e"], ["CPU", "RAM"]);

  if (state.view === "monitoring") {
    pushChart(state.monitorData, s.cpu, s.ram_percent, s.network_in);
    drawMonitor($("#chart-monitor"), state.monitorData);
  }
}

function setBar(sel, pct) {
  const el = $(sel); if (!el) return;
  el.style.width = Math.min(100, pct) + "%";
  el.classList.toggle("high", pct > 80);
}

function fmtUptime(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return `${d}d ${String(h).padStart(2, "0")}h ${String(m).padStart(2, "0")}m`;
}

function pushChart(cd, cpu, ram, net) {
  cd.labels.push("");
  cd.cpu.push(cpu);
  cd.ram.push(ram);
  if (net !== undefined) cd.net.push(net);
  if (cd.cpu.length > cd.max) { cd.cpu.shift(); cd.ram.shift(); cd.labels.shift(); if (cd.net) cd.net.shift(); }
}

/* ---------------- canvas charts ---------------- */
function drawChart(canvas, cd, colors, labels) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width = canvas.offsetWidth * 2;
  const h = canvas.height = canvas.offsetHeight * 2;
  ctx.clearRect(0, 0, w, h);
  if (cd.cpu.length < 2) return;
  const pad = 12;
  const series = [{ data: cd.cpu, color: colors[0] }, { data: cd.ram, color: colors[1] }];
  if (cd.net && cd.net.length) series.push({ data: cd.net, color: "#f59e0b" });
  series.forEach((s) => {
    ctx.beginPath();
    s.data.forEach((v, i) => {
      const x = pad + (i / (cd.max - 1)) * (w - pad * 2);
      const y = h - pad - (Math.min(100, v) / 100) * (h - pad * 2);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 3;
    ctx.shadowColor = s.color;
    ctx.shadowBlur = 10;
    ctx.stroke();
  });
  // legend
  ctx.shadowBlur = 0;
  ctx.font = "20px sans-serif";
  labels.forEach((l, i) => {
    ctx.fillStyle = colors[i];
    ctx.fillRect(w - 180, 14 + i * 26, 14, 14);
    ctx.fillStyle = "#8b95ad";
    ctx.fillText(l, w - 160, 28 + i * 26);
  });
}

function drawMonitor(canvas, cd) {
  drawChart(canvas, cd, ["#6366f1", "#22c55e", "#f59e0b"], ["CPU %", "RAM %", "NET in"]);
}

/* ---------------- server controls ---------------- */
$$("[data-action]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const action = btn.dataset.action;
    if (!confirm(`Run ${action.toUpperCase()} on the server?`)) return;
    try {
      const r = await api(`/api/server/${action}`, { method: "POST" });
      toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
    } catch (e) { toast("Action failed", "error"); }
  });
});

/* ---------------- websockets ---------------- */
function wsUrl(path) {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}${path}`;
}

function startStatsWs() {
  if (state.statsWs) state.statsWs.close();
  const ws = new WebSocket(wsUrl("/ws/stats"));
  ws.onmessage = (ev) => {
    try { updateStats(JSON.parse(ev.data)); } catch {}
  };
  ws.onclose = () => { if (state.user) setTimeout(startStatsWs, 3000); };
  state.statsWs = ws;
}

function startLogsWs() {
  if (state.logsWs) state.logsWs.close();
  state.logsBuffer = [];
  const ws = new WebSocket(wsUrl("/ws/logs"));
  ws.onmessage = (ev) => {
    try {
      const entry = JSON.parse(ev.data);
      appendLog(entry);
    } catch {}
  };
  ws.onclose = () => { if (state.user) setTimeout(startLogsWs, 3000); };
  state.logsWs = ws;
}

function appendLog(entry) {
  if (state.logsPaused) { state.logsBuffer.push(entry); return; }
  const term = $("#log-terminal");
  if (!term) return;
  const line = document.createElement("div");
  line.className = "line";
  line.innerHTML = `<span class="ts">[${escapeHtml(entry.ts)}]</span> <span class="lvl-${escapeHtml(entry.level)}">${escapeHtml(entry.level)}</span> ${escapeHtml(entry.message)}`;
  term.appendChild(line);
  if (term.children.length > 400) term.removeChild(term.firstChild);
  term.scrollTop = term.scrollHeight;
}

$("#log-clear").addEventListener("click", () => { $("#log-terminal").innerHTML = ""; });
$("#log-pause").addEventListener("click", () => {
  state.logsPaused = true;
  hide($("#log-pause")); show($("#log-resume"));
});
$("#log-resume").addEventListener("click", () => {
  state.logsPaused = false;
  state.logsBuffer.forEach(appendLog);
  state.logsBuffer = [];
  hide($("#log-resume")); show($("#log-pause"));
});
$("#log-download").addEventListener("click", () => {
  const text = $$("#log-terminal .line").map((l) => l.textContent).join("\n");
  const blob = new Blob([text], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "qwerty-logs.txt";
  a.click();
});

/* ---------------- applications ---------------- */
async function loadApps() {
  try {
    const r = await api("/api/apps");
    if (!r.ok) return;
    state.apps = r.apps;
    const tbody = $("#apps-table tbody");
    const empty = $("#apps-empty");
    tbody.innerHTML = "";
    if (!r.apps.length) { show(empty); return; }
    hide(empty);
    r.apps.forEach((a) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="row-name">${escapeHtml(a.name)}</td>
        <td>${escapeHtml(a.runtime)}</td>
        <td>${a.port}</td>
        <td><span class="badge ${a.status}">${a.status.toUpperCase()}</span></td>
        <td>${a.cpu.toFixed(1)}%</td>
        <td>${fmtBytes(a.ram)}</td>
        <td>
          <div class="row-actions">
            <button class="btn btn-success btn-sm" data-app-start="${a.id}">Start</button>
            <button class="btn btn-danger btn-sm" data-app-stop="${a.id}">Stop</button>
            <button class="btn btn-warn btn-sm" data-app-restart="${a.id}">Restart</button>
            <button class="btn btn-sm" data-app-del="${a.id}">Delete</button>
          </div>
        </td>`;
      tbody.appendChild(tr);
    });
    bindAppActions();
  } catch {}
}

function bindAppActions() {
  $$("[data-app-start]").forEach((b) => b.onclick = () => appAction(b.dataset.appStart, "start"));
  $$("[data-app-stop]").forEach((b) => b.onclick = () => appAction(b.dataset.appStop, "stop"));
  $$("[data-app-restart]").forEach((b) => b.onclick = () => appAction(b.dataset.appRestart, "restart"));
  $$("[data-app-del]").forEach((b) => b.onclick = () => deleteApp(b.dataset.appDel));
}

async function appAction(id, action) {
  try {
    const r = await api(`/api/apps/${id}/${action}`, { method: "POST" });
    toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
    loadApps();
  } catch {}
}

async function deleteApp(id) {
  if (!confirm("Delete this application?")) return;
  const r = await api(`/api/apps/${id}`, { method: "DELETE" });
  toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
  loadApps();
}

$("#new-app-btn").addEventListener("click", () => {
  openModal("New Application", `
    <div>
      <label>Name</label>
      <input type="text" id="m-app-name" placeholder="my-app" />
    </div>
    <div>
      <label>Runtime</label>
      <select id="m-app-runtime" class="select">
        <option value="python">Python</option>
        <option value="node">Node.js</option>
      </select>
    </div>
    <div>
      <label>Port</label>
      <input type="number" id="m-app-port" value="8080" min="2" max="65535" />
    </div>
    <button class="btn btn-primary btn-block" id="m-app-create">Create Application</button>
  `);
  $("#m-app-create").onclick = async () => {
    const name = $("#m-app-name").value.trim();
    const runtime = $("#m-app-runtime").value;
    const port = parseInt($("#m-app-port").value);
    const r = await api("/api/apps", { method: "POST", body: { name, runtime, port } });
    toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
    if (r.ok) { closeModal(); loadApps(); }
  };
});

/* ---------------- console ---------------- */
async function loadConsoleApps() {
  try {
    const r = await api("/api/apps");
    if (!r.ok) return;
    const sel = $("#console-app-select");
    sel.innerHTML = '<option value="">— select app —</option>' +
      r.apps.map((a) => `<option value="${a.id}">${escapeHtml(a.name)} (${a.status})</option>`).join("");
  } catch {}
}

$$("[data-console]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const id = $("#console-app-select").value;
    if (!id) { toast("Select an application first", "warn"); return; }
    const action = btn.dataset.console;
    const term = $("#app-terminal");
    if (action === "logs") {
      const r = await api(`/api/apps/${id}/console/logs`, { method: "POST" });
      term.innerHTML = r.logs ? escapeHtml(r.logs) : '<span class="muted">No logs yet.</span>';
      term.scrollTop = term.scrollHeight;
      return;
    }
    const r = await api(`/api/apps/${id}/console/${action}`, { method: "POST" });
    toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
    if (r.stderr) { term.innerHTML = escapeHtml(r.stderr); term.scrollTop = term.scrollHeight; }
  });
});

/* ---------------- files ---------------- */
async function loadFiles(rel) {
  state.currentFileDir = rel;
  try {
    const r = await api("/api/files" + (rel ? "?path=" + encodeURIComponent(rel) : ""));
    if (!r.ok) { toast(r.error, "error"); return; }
    const tbody = $("#files-table tbody");
    const empty = $("#files-empty");
    tbody.innerHTML = "";
    renderBreadcrumb(r.path);
    if (!r.items.length) { show(empty); return; }
    hide(empty);
    r.items.forEach((it) => {
      const tr = document.createElement("tr");
      const open = it.type === "dir" ? `onclick="openDir('${escapeHtml((r.path === "." ? "" : r.path + "/") + it.name)}')"` : "";
      tr.innerHTML = `
        <td><span class="link" ${open}>${it.type === "dir" ? "📁 " : "📄 "}${escapeHtml(it.name)}</span></td>
        <td>${it.type}</td>
        <td>${it.type === "file" ? fmtBytes(it.size) : "—"}</td>
        <td>${escapeHtml(it.modified)}</td>
        <td>
          <div class="row-actions">
            ${it.type === "file" ? `<button class="btn btn-sm" data-dl="${escapeHtml((r.path === "." ? "" : r.path + "/") + it.name)}">Download</button>` : ""}
            <button class="btn btn-sm" data-rename="${escapeHtml((r.path === "." ? "" : r.path + "/") + it.name)}">Rename</button>
            <button class="btn btn-danger btn-sm" data-rm="${escapeHtml((r.path === "." ? "" : r.path + "/") + it.name)}">Delete</button>
          </div>
        </td>`;
      tbody.appendChild(tr);
    });
    bindFileActions();
  } catch {}
}

window.openDir = function (p) { loadFiles(p); };

function renderBreadcrumb(path) {
  const bc = $("#file-breadcrumb");
  if (path === "." || !path) { bc.innerHTML = '<a data-dir="">/</a>'; }
  else {
    const parts = path.split("/");
    let acc = "";
    let html = '<a data-dir="">/</a>';
    parts.forEach((p) => {
      acc = acc ? acc + "/" + p : p;
      html += `<span class="sep">/</span><a data-dir="${escapeHtml(acc)}">${escapeHtml(p)}</a>`;
    });
    bc.innerHTML = html;
  }
  $$("#file-breadcrumb a").forEach((a) => a.onclick = () => loadFiles(a.dataset.dir));
}

function bindFileActions() {
  $$("[data-dl]").forEach((b) => b.onclick = () => downloadFile(b.dataset.dl));
  $$("[data-rm]").forEach((b) => b.onclick = () => deleteFile(b.dataset.rm));
  $$("[data-rename]").forEach((b) => b.onclick = () => renameFile(b.dataset.rename));
}

function downloadFile(p) {
  window.location.href = "/api/files/download?path=" + encodeURIComponent(p);
}

async function deleteFile(p) {
  if (!confirm("Delete this item?")) return;
  const r = await api("/api/files", { method: "DELETE", body: { path: p } });
  toast(r.ok ? "Deleted" : r.error, r.ok ? "success" : "error");
  loadFiles(state.currentFileDir);
}

function renameFile(p) {
  openModal("Rename", `
    <div><label>New name</label><input type="text" id="m-rename" value="${escapeHtml(p.split("/").pop())}" /></div>
    <button class="btn btn-primary btn-block" id="m-rename-go">Rename</button>`);
  $("#m-rename-go").onclick = async () => {
    const r = await api("/api/files/rename", { method: "POST", body: { path: p, name: $("#m-rename").value } });
    toast(r.ok ? "Renamed" : r.error, r.ok ? "success" : "error");
    if (r.ok) { closeModal(); loadFiles(state.currentFileDir); }
  };
}

$("#mkdir-btn").addEventListener("click", () => {
  openModal("New Folder", `
    <div><label>Folder name</label><input type="text" id="m-mkdir" placeholder="new-folder" /></div>
    <button class="btn btn-primary btn-block" id="m-mkdir-go">Create</button>`);
  $("#m-mkdir-go").onclick = async () => {
    const r = await api("/api/files/mkdir", { method: "POST", body: { path: state.currentFileDir, name: $("#m-mkdir").value } });
    toast(r.ok ? "Folder created" : r.error, r.ok ? "success" : "error");
    if (r.ok) { closeModal(); loadFiles(state.currentFileDir); }
  };
});

$("#upload-btn").addEventListener("click", () => $("#upload-input").click());
$("#upload-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  fd.append("path", state.currentFileDir);
  try {
    const r = await api("/api/files/upload", { method: "POST", body: fd });
    toast(r.ok ? "Uploaded " + r.name : r.error, r.ok ? "success" : "error");
    if (r.ok) loadFiles(state.currentFileDir);
  } catch { toast("Upload failed", "error"); }
  e.target.value = "";
});

/* ---------------- backups ---------------- */
async function loadBackups() {
  try {
    const r = await api("/api/backups");
    if (!r.ok) return;
    const tbody = $("#backups-table tbody");
    const empty = $("#backups-empty");
    tbody.innerHTML = "";
    if (!r.backups.length) { show(empty); return; }
    hide(empty);
    r.backups.forEach((b) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="row-name">${escapeHtml(b.filename)}</td>
        <td>${fmtBytes(b.size)}</td>
        <td>${escapeHtml(b.created_at)}</td>
        <td>
          <div class="row-actions">
            <button class="btn btn-sm" data-bk-dl="${b.id}">Download</button>
            <button class="btn btn-danger btn-sm" data-bk-rm="${b.id}">Delete</button>
          </div>
        </td>`;
      tbody.appendChild(tr);
    });
    $$("[data-bk-dl]").forEach((b) => b.onclick = () => { window.location.href = `/api/backups/${b.dataset.bkDl}/download`; });
    $$("[data-bk-rm]").forEach((b) => b.onclick = async () => {
      if (!confirm("Delete this backup?")) return;
      const r = await api(`/api/backups/${b.dataset.bkRm}`, { method: "DELETE" });
      toast(r.ok ? "Deleted" : r.error, r.ok ? "success" : "error");
      loadBackups();
    });
  } catch {}
}

$("#create-backup-btn").addEventListener("click", async () => {
  openModal("Create Backup", `
    <div><label>Application (optional)</label>
      <select id="m-bk-app" class="select"><option value="">Entire hosting root</option></select>
    </div>
    <button class="btn btn-primary btn-block" id="m-bk-go">Create Backup</button>`);
  const sel = $("#m-bk-app");
  try {
    const r = await api("/api/apps");
    r.apps.forEach((a) => sel.insertAdjacentHTML("beforeend", `<option value="${a.id}">${escapeHtml(a.name)}</option>`));
  } catch {}
  $("#m-bk-go").onclick = async () => {
    const body = {};
    if (sel.value) body.application_id = parseInt(sel.value);
    const r = await api("/api/backups", { method: "POST", body });
    toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
    if (r.ok) { closeModal(); loadBackups(); }
  };
});

/* ---------------- settings ---------------- */
async function loadSettings() {
  try {
    const me = await api("/api/me");
    const srv = await api("/api/server");
    $("#settings-profile").innerHTML = `
      <div class="k">Username</div><div class="v">${escapeHtml(me.user.username)}</div>
      <div class="k">Role</div><div class="v">${me.user.is_admin ? "Administrator" : "User"}</div>
      <div class="k">Member since</div><div class="v">${escapeHtml(me.user.created_at)}</div>
      <div class="k">Session</div><div class="v"><span class="badge online">ACTIVE</span></div>`;
    if (srv.ok) {
      const s = srv.server;
      $("#settings-server").innerHTML = `
        <div class="k">Status</div><div class="v"><span class="badge online">${s.status.toUpperCase()}</span></div>
        <div class="k">Hostname</div><div class="v">${escapeHtml(s.hostname)}</div>
        <div class="k">OS</div><div class="v">${escapeHtml(s.os)}</div>
        <div class="k">Uptime</div><div class="v">${escapeHtml(s.uptime)}</div>`;
    }
  } catch {}
}

/* ---------------- admin ---------------- */
async function loadAdmin() {
  try {
    const [ov, users, apps, logs] = await Promise.all([
      api("/api/admin/overview"),
      api("/api/admin/users"),
      api("/api/admin/apps"),
      api("/api/admin/logs"),
    ]);
    if (ov.ok) {
      const o = ov.overview;
      $("#admin-cards").innerHTML = [
        ["Total Users", o.total_users, "👤"],
        ["Total Apps", o.total_apps, "▣"],
        ["Online Apps", o.online_apps, "●"],
        ["Total Backups", o.total_backups, "⬡"],
        ["CPU", o.cpu.toFixed(1) + "%", "⚙"],
        ["RAM", o.ram.toFixed(1) + "%", "▤"],
        ["Disk", o.disk.toFixed(1) + "%", "▣"],
      ].map(([t, v, ico]) => `
        <div class="card glass stat-card">
          <div class="stat-head"><span class="stat-ico">${ico}</span> ${t}</div>
          <div class="stat-val">${v}</div>
        </div>`).join("");
    }
    if (logs.ok) {
      $("#admin-logs-table tbody").innerHTML = logs.logs.map((l) => `
        <tr><td>${escapeHtml(l.created_at)}</td><td>${escapeHtml(l.username || "—")}</td>
        <td>${escapeHtml(l.action)}</td><td><span class="badge ${l.status === "success" ? "running" : "stopped"}">${l.status.toUpperCase()}</span></td></tr>`).join("");
    }
    if (apps.ok) {
      $("#admin-apps-table tbody").innerHTML = apps.apps.map((a) => `
        <tr><td class="row-name">${escapeHtml(a.name)}</td><td>${escapeHtml(a.runtime)}</td>
        <td>${a.user_id}</td><td>${a.port}</td>
        <td><span class="badge ${a.status}">${a.status.toUpperCase()}</span></td>
        <td><div class="row-actions">
          ${a.status === "disabled"
            ? `<button class="btn btn-success btn-sm" data-adm-enable="${a.id}">Enable</button>`
            : `<button class="btn btn-warn btn-sm" data-adm-disable="${a.id}">Disable</button>`}
          <button class="btn btn-danger btn-sm" data-adm-del="${a.id}">Delete</button>
        </div></td></tr>`).join("");
      $$("[data-adm-disable]").forEach((b) => b.onclick = () => adminApp(b.dataset.admDisable, "disable"));
      $$("[data-adm-enable]").forEach((b) => b.onclick = () => adminApp(b.dataset.admEnable, "enable"));
      $$("[data-adm-del]").forEach((b) => b.onclick = () => adminApp(b.dataset.admDel, "delete"));
    }
  } catch {}
}

async function adminApp(id, action) {
  if (action === "delete" && !confirm("Delete this application permanently?")) return;
  const path = action === "delete" ? `/api/admin/apps/${id}` : `/api/admin/apps/${id}/${action}`;
  const method = action === "delete" ? "DELETE" : "POST";
  const r = await api(path, { method });
  toast(r.ok ? r.message : r.error, r.ok ? "success" : "error");
  loadAdmin();
}

/* ---------------- modal ---------------- */
function openModal(title, bodyHtml) {
  $("#modal-title").textContent = title;
  $("#modal-body").innerHTML = bodyHtml;
  show($("#modal"));
}
function closeModal() { hide($("#modal")); }
$("#modal-close").addEventListener("click", closeModal);
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });

/* ---------------- init ---------------- */
bootstrap();
