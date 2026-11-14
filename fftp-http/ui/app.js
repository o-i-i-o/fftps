/* fftp-http Web 管理界面逻辑（原生 JS，无外部依赖） */
"use strict";

// ---------- 工具 ----------

const $ = (id) => document.getElementById(id);
const state = { user: null, shuttingDown: false };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtSize(n) {
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

function fmtTime(ts) {
  // "2026-10-21T23:20:27.559+08:00" → "23:20:27"
  const m = /T(\d{2}:\d{2}:\d{2})/.exec(ts || "");
  return m ? m[1] : (ts || "");
}

function fmtDateTime(ts) {
  // RFC3339 → "2026-10-21 23:20"；空值（如 last_login=null）→ "—"
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(ts || "");
  return m ? `${m[1]} ${m[2]}` : "—";
}

let toastTimer = null;
function toast(msg, isErr) {
  const el = $("toast");
  el.textContent = msg;
  el.className = "toast" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), isErr ? 6000 : 3000);
}

function errMsg(e) {
  return e && e.message ? String(e.message) : String(e);
}

// ---------- API 封装 ----------

async function api(path, opts = {}) {
  const init = {
    method: opts.method || "GET",
    headers: {},
    credentials: "same-origin",
  };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (e) {
    setOffline(true, "网络错误：" + e.message);
    throw { message: "网络错误：" + e.message };
  }
  if (res.status === 401) {
    showLogin(false);
    throw { message: "未登录或会话过期" };
  }
  if (res.status === 502 || res.status === 503) {
    setOffline(true);
    let msg = "fftpd 未连接";
    try { msg = (await res.json()).error.message; } catch (_) { /* 忽略 */ }
    throw { message: msg };
  }
  setOffline(false);
  let data = null;
  try { data = await res.json(); } catch (_) { /* 空响应 */ }
  if (!res.ok) {
    throw { message: data && data.error ? data.error.message : "HTTP " + res.status };
  }
  return data;
}

function setOffline(off, note) {
  $("offline").classList.toggle("hidden", !off);
  if (note) $("offline").textContent = note;
  const dot = $("conn-dot"), text = $("conn-text");
  if (off) { dot.className = "dot bad"; text.textContent = "未连接"; }
  else { dot.className = "dot ok"; text.textContent = "已连接"; }
}

// ---------- 登录 / 登出 ----------

function showLogin(clearForm) {
  $("login").classList.remove("hidden");
  if (clearForm !== false) { $("login-user").value = ""; $("login-pass").value = ""; }
  $("login-user").focus();
}

async function boot() {
  $("login").classList.add("hidden");
  $("topbar").classList.remove("hidden");
  $("main").classList.remove("hidden");
  $("whoami").textContent = state.user || "";
  try {
    const st = await api("/api/status");
    fillIdentity(st);
  } catch (e) { /* 离线横幅已展示 */ }
  switchTab("service");
  startConnPoll();
  startPresence();
  loadIdleStatus();
  loadSystemService();
  startIdlePoll();
}

function fillIdentity(st) {
  $("whoami").textContent = state.user || "";
  $("st-version").textContent = st.version;
  $("st-config").textContent = st.config_path;
  $("st-users").textContent = st.users_path;
  $("st-endpoint").textContent = st.endpoint;
  $("about-version").textContent = st.version;
  $("about-config").textContent = st.config_path;
  $("about-users").textContent = st.users_path;
  $("about-endpoint").textContent = st.endpoint;
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const errEl = $("login-err");
  errEl.classList.add("hidden");
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ username: $("login-user").value.trim(), password: $("login-pass").value }),
    });
    if (res.ok) {
      state.user = $("login-user").value.trim();
      await boot();
    } else {
      let msg = "登录失败";
      try { msg = (await res.json()).error.message; } catch (_) { /* 忽略 */ }
      if (res.status === 401) msg = "用户名或口令错误";
      errEl.textContent = msg;
      errEl.classList.remove("hidden");
    }
  } catch (e) {
    errEl.textContent = "网络错误：" + e.message;
    errEl.classList.remove("hidden");
  }
});

$("btn-logout").addEventListener("click", async () => {
  stopConnPoll();
  stopLogStream();
  stopFopStream();
  stopPresence();
  stopIdlePoll();
  try { await fetch("/api/logout", { method: "POST", credentials: "same-origin" }); } catch (_) { /* 忽略 */ }
  state.user = null;
  $("main").classList.add("hidden");
  $("topbar").classList.add("hidden");
  $("offline").classList.add("hidden");
  showLogin();
});

// ---------- Tab 切换 ----------

const TABS = ["service", "config", "users", "proglog", "filelog", "about"];

function switchTab(name) {
  for (const t of TABS) {
    $("tab-" + t).classList.toggle("hidden", t !== name);
  }
  document.querySelectorAll("#tabs button").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === name);
  });
  if (name === "service") { refreshStatus(); loadIdleStatus(); loadSystemService(); }
  if (name === "config") loadConfigPage();
  if (name === "users") loadUsers();
  if (name === "proglog") { startLogStream(); loadLogFileList(); }
  else stopLogStream();
  if (name === "filelog") { startFopStream(); loadFileOpList(); }
  else stopFopStream();
  if (name === "about") refreshStatus();
}

document.querySelectorAll("#tabs button").forEach((b) => {
  b.addEventListener("click", () => switchTab(b.dataset.tab));
});

// ---------- 连接状态轮询（顶栏圆点） ----------

let connTimer = null;
function startConnPoll() {
  stopConnPoll();
  connTimer = setInterval(async () => {
    try {
      const r = await fetch("/api/daemon", { credentials: "same-origin" });
      if (r.status === 401) { showLogin(false); return; }
      const d = await r.json();
      setOffline(!d.connected);
      if (!d.connected) $("offline").textContent = "fftpd 连接断开，正在重连…（恢复后自动可用）";
    } catch (_) { /* 网络错误保持现状 */ }
  }, 5000);
}
function stopConnPoll() { clearInterval(connTimer); connTimer = null; }

// ---------- 页面心跳与用户活动（空闲自动关闭判定） ----------

// 每个标签页独立标识：多标签页中任一可见即视为有页面
const PAGE_ID = (crypto.randomUUID ? crypto.randomUUID()
  : String(Date.now()) + "-" + Math.random().toString(16).slice(2));
// 心跳间隔：需小于服务端页面过期阈值（75 秒）
const HEARTBEAT_MS = 15000;
let presenceTimer = null;
let lastActivityPing = 0;

function sendHeartbeat(visible, keepalive) {
  if (!state.user || state.shuttingDown) return;
  fetch("/api/heartbeat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    keepalive: !!keepalive,
    body: JSON.stringify({ page_id: PAGE_ID, visible: !!visible }),
  }).catch(() => { /* 服务关闭/网络抖动时忽略 */ });
}

function startPresence() {
  stopPresence();
  sendHeartbeat(document.visibilityState === "visible");
  presenceTimer = setInterval(() => {
    sendHeartbeat(document.visibilityState === "visible");
  }, HEARTBEAT_MS);
}

function stopPresence() {
  if (presenceTimer) {
    clearInterval(presenceTimer);
    presenceTimer = null;
    // 主动告知页面已离开，避免等待服务端过期
    sendHeartbeat(false, true);
  }
}

// 真实用户操作（节流到 15 秒一次；后台轮询/SSE 不计入）
function pingActivity() {
  if (!state.user || state.shuttingDown) return;
  const now = Date.now();
  if (now - lastActivityPing < 15000) return;
  lastActivityPing = now;
  fetch("/api/activity", { method: "POST", credentials: "same-origin" }).catch(() => {});
}
for (const ev of ["pointerdown", "keydown", "wheel", "touchstart"]) {
  window.addEventListener(ev, pingActivity, { passive: true });
}

document.addEventListener("visibilitychange", () => {
  if (!state.user || state.shuttingDown) return;
  sendHeartbeat(document.visibilityState === "visible");
  if (document.visibilityState === "visible") loadIdleStatus();
});

window.addEventListener("pagehide", () => {
  if (state.user && !state.shuttingDown) sendHeartbeat(false, true);
});

// ---------- 空闲自动关闭配置 ----------

let idleTimer = null;
let idleWarned = false;

function startIdlePoll() {
  stopIdlePoll();
  idleTimer = setInterval(() => {
    if (!state.shuttingDown && !$("tab-service").classList.contains("hidden")) {
      loadIdleStatus();
    }
  }, 10000);
}

function stopIdlePoll() {
  if (idleTimer) { clearInterval(idleTimer); idleTimer = null; }
}

function fillIdleForm(s) {
  $("idle-enabled").checked = !!s.enabled;
  $("idle-mode").value = s.mode === "no_activity" ? "no_activity" : "no_page";
  $("idle-timeout").value = s.timeout_secs;
  $("idle-warn").value = s.warn_secs;
}

function renderIdleStatus(s) {
  const badge = $("idle-badge");
  badge.textContent = s.enabled ? "已启用" : "未启用";
  badge.className = "badge " + (s.enabled ? "on" : "off");
  if (!s.enabled) {
    $("idle-status").textContent = "未启用自动关闭。";
    idleWarned = false;
    return;
  }
  const mins = Math.max(0, Math.ceil(s.remaining_secs / 60));
  $("idle-status").textContent =
    `当前可见页面 ${s.visible_pages} 个，距自动关闭约 ${mins} 分钟（${s.remaining_secs} 秒）。`;
  if (s.warn_secs > 0 && s.remaining_secs <= s.warn_secs) {
    if (!idleWarned) {
      idleWarned = true;
      toast(`Web 服务将在约 ${s.remaining_secs} 秒后自动关闭（在页面上操作可重新计时）`, true);
    }
  } else if (s.remaining_secs > s.warn_secs + 5) {
    idleWarned = false;
  }
}

async function loadIdleStatus() {
  try {
    const s = await api("/api/idle");
    fillIdleForm(s);
    renderIdleStatus(s);
  } catch (_) { /* 离线/未登录已由统一处理 */ }
}

$("idle-reload").addEventListener("click", loadIdleStatus);

$("idle-save").addEventListener("click", async () => {
  const timeout = parseInt($("idle-timeout").value, 10);
  const warn = parseInt($("idle-warn").value, 10);
  if (!Number.isFinite(timeout) || timeout < 30) {
    toast("空闲时长必须是不小于 30 的整数（秒）", true);
    return;
  }
  const warnSecs = Number.isFinite(warn) && warn > 0 ? warn : 0;
  if (warnSecs > timeout) { toast("关闭前提示不能大于空闲时长", true); return; }
  try {
    const s = await api("/api/idle", {
      method: "PUT",
      body: {
        enabled: $("idle-enabled").checked,
        timeout_secs: timeout,
        mode: $("idle-mode").value,
        warn_secs: warnSecs,
      },
    });
    fillIdleForm(s);
    renderIdleStatus(s);
    toast("空闲设置已保存");
  } catch (e) { toast(errMsg(e), true); }
});

$("web-shutdown").addEventListener("click", async () => {
  if (!confirm("确认关闭 Web 管理服务（fftp-http）？\n\nfftpd 与 FTP/SFTP 传输不受影响；关闭后本页面将无法继续操作，需从桌面快捷方式重新启动。")) return;
  try {
    await api("/api/self-shutdown", { method: "POST" });
    showShutdownNotice();
  } catch (e) { toast(errMsg(e), true); }
});

function showShutdownNotice() {
  state.shuttingDown = true;
  state.user = null;
  stopConnPoll();
  stopLogStream();
  stopFopStream();
  stopPresence();
  stopIdlePoll();
  $("main").classList.add("hidden");
  $("topbar").classList.add("hidden");
  $("offline").classList.add("hidden");
  $("login").classList.add("hidden");
  $("shutdown-notice").classList.remove("hidden");
}

// ---------- 系统服务（fftpd） ----------

const SYS_ACT_LABELS = {
  start: "启动 fftpd",
  stop: "停止 fftpd",
  restart: "重启 fftpd",
  install: "安装/修复服务",
  uninstall: "卸载服务",
  "autostart-on": "开启开机自启",
  "autostart-off": "关闭开机自启",
};

async function loadSystemService() {
  try {
    const s = await api("/api/system-service/status");
    $("sys-svc-platform").textContent = s.platform || "—";
    $("sys-svc-detail").textContent = s.detail || "—";
    const badge = $("sys-svc-badge");
    if (!s.installed) {
      badge.textContent = "未安装";
      badge.className = "badge off";
    } else if (s.running) {
      badge.textContent = s.autostart ? "运行中 · 自启" : "运行中";
      badge.className = "badge on";
    } else {
      badge.textContent = s.autostart ? "已安装 · 未运行 · 自启" : "已安装 · 未运行";
      badge.className = "badge off";
    }
  } catch (e) {
    $("sys-svc-badge").textContent = "检测失败";
    $("sys-svc-badge").className = "badge off";
    $("sys-svc-detail").textContent = errMsg(e);
  }
}

$("sys-refresh").addEventListener("click", loadSystemService);

document.querySelectorAll("[data-sys-act]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const act = btn.dataset.sysAct;
    const label = SYS_ACT_LABELS[act] || act;
    const needsConfirm = ["uninstall", "autostart-off", "stop", "restart"].includes(act);
    if (needsConfirm && !confirm(`确认${label}？`)) return;
    btn.disabled = true;
    btn.classList.add("busy");
    try {
      const r = await api("/api/system-service/" + act, { method: "POST" });
      toast((r.message || label + "完成") + (r.output ? "：" + r.output : ""));
      setTimeout(() => { loadSystemService(); refreshStatus(); }, 800);
    } catch (e) {
      toast(errMsg(e), true);
    } finally {
      btn.disabled = false;
      btn.classList.remove("busy");
    }
  });
});


// ---------- 服务状态与操作 ----------

async function refreshStatus() {
  try {
    const st = await api("/api/status");
    $("ftp-badge").textContent = st.ftp_running ? "运行中" : "已停止";
    $("ftp-badge").className = "badge " + (st.ftp_running ? "on" : "off");
    $("sftp-badge").textContent = st.sftp_running ? "运行中" : "已停止";
    $("sftp-badge").className = "badge " + (st.sftp_running ? "on" : "off");
    fillIdentity(st);
    setOffline(false);
  } catch (_) { /* 离线横幅已处理 */ }
}

setInterval(() => {
  if (!$("tab-service").classList.contains("hidden")) refreshStatus();
}, 5000);

document.querySelectorAll("[data-svc]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const { svc, act } = btn.dataset;
    if (act !== "start" && !confirm(`确认${act === "stop" ? "停止" : "重启"} ${svc === "all" ? "全部服务" : svc.toUpperCase()} 服务？`)) return;
    try {
      await api("/api/service/" + act, { method: "POST", body: { which: svc } });
      toast(`${svc === "all" ? "全部服务" : svc.toUpperCase()} ${act} 指令已发送`);
      setTimeout(refreshStatus, 800);
    } catch (e) { toast(errMsg(e), true); }
  });
});

$("btn-shutdown").addEventListener("click", async () => {
  if (!confirm("确认关停 fftpd 守护进程？FTP/SFTP 服务与 IPC 控制面将全部停止。")) return;
  try {
    await api("/api/shutdown", { method: "POST" });
    toast("fftpd 关停指令已发送");
    setOffline(true, "fftpd 已关停，等待重新启动");
  } catch (e) { toast(errMsg(e), true); }
});

// ---------- SSE 实时流（程序日志 / 文件操作共用骨架） ----------

function createStream(cfg) {
  // cfg: { url, eventName, tabId, stateEl, pauseBtn, clearBtn,
  //        onEntry(entry), onNotice(text), onReset() }
  const st = { es: null, paused: false, timer: null };
  const active = () => !$("tab-" + cfg.tabId).classList.contains("hidden");

  function connect() {
    const es = new EventSource(cfg.url);
    st.es = es;
    es.addEventListener(cfg.eventName, (ev) => {
      try { cfg.onEntry(JSON.parse(ev.data)); } catch (_) { /* 忽略坏帧 */ }
    });
    es.addEventListener("notice", (ev) => cfg.onNotice(String(ev.data)));
    es.onopen = () => { cfg.stateEl.textContent = "已连接"; };
    es.onerror = () => {
      es.close();
      st.es = null;
      if (st.paused || !active()) {
        cfg.stateEl.textContent = "已断开";
        return;
      }
      cfg.stateEl.textContent = "连接断开，2 秒后重连…";
      st.timer = setTimeout(connect, 2000);
    };
  }

  function start() {
    if (st.es || !state.user) return;
    st.paused = false;
    cfg.pauseBtn.textContent = "暂停";
    cfg.stateEl.textContent = "连接中…";
    cfg.onReset();
    connect();
  }

  function stop() {
    clearTimeout(st.timer);
    if (st.es) { st.es.close(); st.es = null; }
    st.paused = false;
    cfg.stateEl.textContent = "";
  }

  cfg.pauseBtn.addEventListener("click", () => {
    if (st.paused) {
      cfg.onReset();
      connect();
      st.paused = false;
      cfg.pauseBtn.textContent = "暂停";
    } else {
      st.paused = true;
      clearTimeout(st.timer);
      if (st.es) { st.es.close(); st.es = null; }
      cfg.pauseBtn.textContent = "继续";
      cfg.stateEl.textContent = "已暂停";
    }
  });
  cfg.clearBtn.addEventListener("click", cfg.onReset);

  return { start, stop };
}

// ---------- 程序日志：实时流（左） ----------

function logLine(entry) {
  const div = document.createElement("div");
  div.className = "line";
  const extra = [entry.client_ip, entry.username, entry.action].filter(Boolean).join(" ");
  const raw = [entry.timestamp, entry.level, entry.source, entry.message, extra].filter(Boolean).join(" ");
  div.dataset.filter = raw;
  div.innerHTML =
    `<span class="t-dim">${escapeHtml(fmtTime(entry.timestamp))}</span> ` +
    `<span class="lvl-${escapeHtml(entry.level)}">${escapeHtml(entry.level)}</span> ` +
    `<span class="t-dim">[${escapeHtml(entry.source)}]</span> ` +
    escapeHtml(entry.message) +
    (extra ? ` <span class="t-dim">(${escapeHtml(extra)})</span>` : "");
  div.classList.toggle("filtered", !matchesFilter(raw, $("log-filter").value));
  return div;
}

function matchesFilter(raw, query) {
  const q = String(query || "").trim().toLowerCase();
  return !q || String(raw || "").toLowerCase().includes(q);
}

function applyLogFilter(view, query) {
  for (const el of view.children) {
    el.classList.toggle("filtered", !matchesFilter(el.dataset.filter || el.textContent, query));
  }
}

function applyTableFilter(wrap, query) {
  for (const tr of wrap.querySelectorAll("tbody tr")) {
    tr.classList.toggle("filtered", !matchesFilter(tr.dataset.filter || tr.textContent, query));
  }
}

$("log-filter").addEventListener("input", () => applyLogFilter($("log-view"), $("log-filter").value));
$("logfile-filter").addEventListener("input", () => applyLogFilter($("logfile-view"), $("logfile-filter").value));
$("fop-filter").addEventListener("input", () => applyTableFilter($("fop-live"), $("fop-filter").value));
$("fileop-filter").addEventListener("input", () => applyTableFilter($("fileop-view"), $("fileop-filter").value));

function appendLog(entry) {
  const view = $("log-view");
  view.appendChild(logLine(entry));
  while (view.childElementCount > 5000) view.removeChild(view.firstChild);
  if ($("log-autoscroll").checked) view.scrollTop = view.scrollHeight;
}

function appendSysLine(text) {
  const view = $("log-view");
  const div = document.createElement("div");
  div.className = "sysline";
  div.textContent = "— " + text + " —";
  view.appendChild(div);
  if ($("log-autoscroll").checked) view.scrollTop = view.scrollHeight;
}

const logStream = createStream({
  url: "/api/logs/stream?tail=200",
  eventName: "log",
  tabId: "proglog",
  stateEl: $("log-state"),
  pauseBtn: $("log-pause"),
  clearBtn: $("log-clear"),
  onEntry: appendLog,
  onNotice: appendSysLine,
  onReset: () => { $("log-view").textContent = ""; },
});
const startLogStream = logStream.start;
const stopLogStream = logStream.stop;

// ---------- 程序日志：历史文件（右，下拉选择） ----------

async function loadLogFileList() {
  const sel = $("logfile-select");
  const view = $("logfile-view");
  try {
    const { files } = await api("/api/logs/files");
    sel.textContent = "";
    if (!files.length) {
      sel.innerHTML = '<option value="">（暂无日志文件）</option>';
      view.textContent = "（暂无日志文件）";
      return;
    }
    for (const f of files) {
      const opt = document.createElement("option");
      opt.value = f.path;
      opt.textContent = f.name;
      opt.title = f.path;
      sel.appendChild(opt);
    }
    loadLogFileContent();
  } catch (e) {
    sel.innerHTML = '<option value="">加载失败</option>';
    view.textContent = "加载失败：" + errMsg(e);
  }
}

async function loadLogFileContent() {
  const sel = $("logfile-select");
  const path = sel.value;
  if (!path) return;
  const view = $("logfile-view");
  view.textContent = "加载中…";
  try {
    const { entries } = await api("/api/logs/content", {
      method: "POST",
      body: { path, count: parseInt($("logfile-count").value, 10) },
    });
    view.textContent = "";
    for (const e of entries) view.appendChild(logLine(e));
    if (!entries.length) view.textContent = "（无记录）";
    applyLogFilter(view, $("logfile-filter").value);
    view.scrollTop = view.scrollHeight;
  } catch (e) {
    view.textContent = "加载失败：" + errMsg(e);
  }
}

$("logfile-refresh").addEventListener("click", loadLogFileContent);
$("logfile-count").addEventListener("change", loadLogFileContent);
$("logfile-select").addEventListener("change", loadLogFileContent);

// ---------- 文件日志：实时流（左） ----------

const FOP_LIVE_MAX = 500;

function buildOpTable() {
  const table = document.createElement("table");
  table.className = "optable";
  table.innerHTML =
    "<thead><tr><th>时间</th><th>用户</th><th>客户端</th><th>操作</th><th>路径</th>" +
    "<th>大小</th><th>协议</th><th>结果</th><th>消息</th></tr></thead><tbody></tbody>";
  return table;
}

function opRow(e) {
  const tr = document.createElement("tr");
  tr.dataset.filter = [
    e.timestamp, e.username, e.client_ip, e.operation, e.file_path,
    e.file_size, e.protocol, e.success ? "成功" : "失败", e.message,
  ].filter((v) => v != null).join(" ");
  tr.classList.toggle("filtered", !matchesFilter(tr.dataset.filter, $("fop-filter").value));
  tr.innerHTML =
    `<td>${escapeHtml(fmtTime(e.timestamp))}</td>` +
    `<td>${escapeHtml(e.username)}</td>` +
    `<td>${escapeHtml(e.client_ip)}</td>` +
    `<td>${escapeHtml(e.operation)}</td>` +
    `<td class="path">${escapeHtml(e.file_path)}</td>` +
    `<td>${escapeHtml(fmtSize(e.file_size))}</td>` +
    `<td>${escapeHtml(e.protocol)}</td>` +
    `<td class="${e.success ? "op-ok" : "op-fail"}">${e.success ? "成功" : "失败"}</td>` +
    `<td class="path">${escapeHtml(e.message)}</td>`;
  return tr;
}

function appendFopEntry(entry) {
  const wrap = $("fop-live");
  let table = wrap.querySelector("table");
  if (!table) {
    wrap.textContent = "";
    table = buildOpTable();
    wrap.appendChild(table);
  }
  const tbody = table.tBodies[0];
  tbody.appendChild(opRow(entry));
  while (tbody.rows.length > FOP_LIVE_MAX) tbody.deleteRow(0);
  if ($("fop-autoscroll").checked) wrap.scrollTop = wrap.scrollHeight;
}

function appendFopNotice(text) {
  const wrap = $("fop-live");
  const p = document.createElement("p");
  p.className = "hint";
  p.textContent = "— " + text + " —";
  wrap.appendChild(p);
  wrap.scrollTop = wrap.scrollHeight;
}

const fopStream = createStream({
  url: "/api/fileop/stream?tail=100",
  eventName: "fileop",
  tabId: "filelog",
  stateEl: $("fop-state"),
  pauseBtn: $("fop-pause"),
  clearBtn: $("fop-clear"),
  onEntry: appendFopEntry,
  onNotice: appendFopNotice,
  onReset: () => { $("fop-live").textContent = ""; },
});
const startFopStream = fopStream.start;
const stopFopStream = fopStream.stop;

// ---------- 文件日志：历史文件（右，下拉选择） ----------

async function loadFileOpList() {
  const sel = $("fileop-select");
  const view = $("fileop-view");
  try {
    const { files } = await api("/api/fileop/files");
    sel.textContent = "";
    if (!files.length) {
      sel.innerHTML = '<option value="">（暂无文件操作日志）</option>';
      view.textContent = "（暂无文件操作日志）";
      return;
    }
    for (const f of files) {
      const opt = document.createElement("option");
      opt.value = f.path;
      opt.textContent = f.name;
      opt.title = f.path;
      sel.appendChild(opt);
    }
    loadFileOpContent();
  } catch (e) {
    sel.innerHTML = '<option value="">加载失败</option>';
    view.textContent = "加载失败：" + errMsg(e);
  }
}

async function loadFileOpContent() {
  const sel = $("fileop-select");
  const path = sel.value;
  if (!path) return;
  const view = $("fileop-view");
  view.textContent = "加载中…";
  try {
    const { entries } = await api("/api/fileop/content", {
      method: "POST",
      body: { path, count: parseInt($("fileop-count").value, 10) },
    });
    view.textContent = "";
    if (!entries.length) { view.textContent = "（无记录）"; return; }
    const table = buildOpTable();
    const tbody = table.tBodies[0];
    for (const e of entries) tbody.appendChild(opRow(e));
    view.appendChild(table);
    applyTableFilter(view, $("fileop-filter").value);
    view.scrollTop = view.scrollHeight;
  } catch (e) {
    view.textContent = "加载失败：" + errMsg(e);
  }
}

$("fileop-refresh").addEventListener("click", loadFileOpContent);
$("fileop-count").addEventListener("change", loadFileOpContent);
$("fileop-select").addEventListener("change", loadFileOpContent);

// ---------- 配置页（日志设置卡片 + config.toml 表单化） ----------

const LOG_LEVELS = ["error", "warn", "info", "debug", "trace"];
let cfgToml = ""; // 最近一次拉取的 config.toml 原文（保存时补齐表单外字段）

// 轻量解析 config.toml：段名（如 "ftp"、"ftp.ftps"）→ { 键: 值 }（值均为标量/数组）
function parseTomlSections(toml) {
  const secs = { "": {} };
  let cur = "";
  for (const rawLine of String(toml).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const head = /^\[([A-Za-z0-9_.]+)\]$/.exec(line);
    if (head) { cur = head[1]; if (!secs[cur]) secs[cur] = {}; continue; }
    const m = /^([A-Za-z0-9_]+)\s*=\s*(.+?)(\s+#.*)?$/.exec(line);
    if (!m) continue;
    if (!secs[cur]) secs[cur] = {};
    secs[cur][m[1]] = parseTomlValue(m[2].trim());
  }
  return secs;
}

function parseTomlValue(v) {
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  if (v === "true") return true;
  if (v === "false") return false;
  if (/^-?\d+$/.test(v)) return parseInt(v, 10);
  if (v.startsWith("[") && v.endsWith("]")) {
    const inner = v.slice(1, -1).trim();
    if (!inner) return [];
    const strs = [...inner.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
    if (strs.length) return strs;
    return inner.split(",").map((s) => s.trim()).filter(Boolean).map(Number);
  }
  return v;
}

async function loadConfigPage() {
  try {
    const content = (await api("/api/config")).content;
    fillConfigForm(content);
    fillLogForm(content);
  } catch (_) { /* 离线横幅已处理 */ }
}

async function refreshCfgToml() {
  try { cfgToml = (await api("/api/config")).content; } catch (_) { /* 忽略 */ }
}

// 日志设置卡片（[logging]；独立保存走 /api/log-config，热生效不重启服务）
function fillLogForm(content) {
  cfgToml = content;
  const lg = parseTomlSections(content)["logging"] || {};
  $("lc-dir").value = typeof lg.log_dir === "string" ? lg.log_dir : "";
  $("lc-level").value = LOG_LEVELS.includes(lg.log_level) ? lg.log_level : "info";
  $("lc-size").value = lg.max_log_size ? Math.max(1, Math.round(lg.max_log_size / 1048576)) : "";
  $("lc-files").value = Number.isFinite(lg.max_log_files) ? lg.max_log_files : "";
  $("lc-gui").checked = lg.enable_gui_logging !== false;
}

$("lc-reload").addEventListener("click", loadConfigPage);

$("lc-save").addEventListener("click", async () => {
  const mb = parseInt($("lc-size").value, 10);
  const files = parseInt($("lc-files").value, 10);
  if (!Number.isFinite(mb) || mb < 1) { toast("单文件上限（MB）必须为正整数", true); return; }
  if (!Number.isFinite(files) || files < 1) { toast("保留文件数必须为正整数", true); return; }
  try {
    await api("/api/log-config", {
      method: "PUT",
      body: {
        log_dir: $("lc-dir").value.trim(),
        log_level: $("lc-level").value,
        max_log_size: mb * 1048576,
        max_log_files: files,
        enable_gui_logging: $("lc-gui").checked,
      },
    });
    refreshCfgToml();
    toast("日志设置已保存");
  } catch (e) { toast(errMsg(e), true); }
});

// FTP / FTPS / SFTP / 安全：表单 → TOML → SaveConfig（fftpd 校验并热重载）
function fillConfigForm(content) {
  const s = parseTomlSections(content);
  const ftp = s["ftp"] || {}, ftps = s["ftp.ftps"] || {}, sftp = s["sftp"] || {}, sec = s["security"] || {};
  const num = (v, d) => (Number.isFinite(v) ? v : d);
  const txt = (v, d = "") => (typeof v === "string" ? v : d);
  const bool = (v, d = false) => (typeof v === "boolean" ? v : d);
  const arr = (v) => (Array.isArray(v) ? v : []);

  $("cf-enabled").checked = bool(ftp.enabled, true);
  $("cf-bind-ip").value = txt(ftp.bind_ip, "0.0.0.0");
  $("cf-port").value = num(ftp.port, 21);
  $("cf-welcome").value = txt(ftp.welcome_message, "Welcome to fftpd");
  $("cf-encoding").value = txt(ftp.encoding, "UTF-8");
  $("cf-conn-mode").value = txt(ftp.connection_mode, "passive_only");
  $("cf-anonymous").checked = bool(ftp.allow_anonymous);
  $("cf-anon-home").value = txt(ftp.anonymous_home);
  $("cf-passive-lo").value = num(arr(ftp.passive_ports)[0], 50000);
  $("cf-passive-hi").value = num(arr(ftp.passive_ports)[1], 51000);
  $("cf-speed").value = num(ftp.max_speed_kbps, 0);
  $("cf-masquerade").value = txt(ftp.masquerade_address);
  $("cf-idle-timeout").value = num(ftp.idle_timeout, 15);
  $("cf-pooled").checked = bool(ftp.pooled_listener_mode);
  $("cf-nat").checked = bool(ftp.allow_nat_clients, true);
  $("cf-root").value = txt(ftp.ftp_root);

  $("cf-ftps-enabled").checked = bool(ftps.enabled);
  $("cf-ftps-require").checked = bool(ftps.require_ssl);
  $("cf-ftps-cert").value = txt(ftps.cert_path);
  $("cf-ftps-key").value = txt(ftps.key_path);

  $("cf-sftp-enabled").checked = bool(sftp.enabled, true);
  $("cf-sftp-bind-ip").value = txt(sftp.bind_ip, "0.0.0.0");
  $("cf-sftp-port").value = num(sftp.port, 2222);
  $("cf-sftp-host-key").value = txt(sftp.host_key_path);
  $("cf-sftp-max-auth").value = num(sftp.max_auth_attempts, 3);
  $("cf-sftp-auth-timeout").value = num(sftp.auth_timeout, 60);
  $("cf-sftp-sessions").value = num(sftp.max_sessions_per_user, 5);
  $("cf-sftp-rotation").value = num(sftp.host_key_rotation_days, 0);

  $("cf-sec-max-conn").value = num(sec.max_connections, 100);
  $("cf-sec-max-conn-ip").value = num(sec.max_connections_per_ip, 10);
  $("cf-sec-allowed").value = arr(sec.allowed_ips).join(", ");
  $("cf-sec-denied").value = arr(sec.denied_ips).join(", ");
  $("cf-sec-f2b").checked = bool(sec.fail2ban_enabled);
  $("cf-sec-f2b-threshold").value = num(sec.fail2ban_threshold, 5);
  $("cf-sec-f2b-time").value = num(sec.fail2ban_ban_time, 3600);
  $("cf-symlinks").checked = bool(sec.allow_symlinks);
  $("cf-sec-max-login").value = num(sec.max_login_attempts, 5);
}

function buildConfigToml() {
  const errs = [];
  const str = (id) => $(id).value.trim();
  const q = (s) => '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  const cidrs = (id) => str(id).split(/[\s,、]+/).filter(Boolean);
  const reqInt = (id, label, min, max) => {
    const v = parseInt($(id).value, 10);
    if (!Number.isFinite(v) || v < min || (max !== undefined && v > max)) {
      errs.push(label);
      return min;
    }
    return v;
  };
  const port = (id, label) => reqInt(id, label, 1, 65535);
  const sel = (id) => $(id).value;

  const lo = port("cf-passive-lo", "被动端口下限");
  const hi = port("cf-passive-hi", "被动端口上限");
  if (!errs.includes("被动端口下限") && !errs.includes("被动端口上限") && lo > hi) {
    errs.push("被动端口区间（下限 ≤ 上限）");
  }

  // [logging] 不在表单覆盖范围内：沿用最近拉取的原文，避免整体保存时被默认值覆盖
  const lg = parseTomlSections(cfgToml)["logging"] || {};
  const lgDefault = {
    log_dir: "", log_level: "info", max_log_files: 10,
    max_log_size: 10485760, enable_json: false, enable_gui_logging: true,
  };

  const lines = [];
  lines.push("[ftp]");
  lines.push(`enabled = ${$("cf-enabled").checked}`);
  lines.push(`bind_ip = ${q(str("cf-bind-ip") || "0.0.0.0")}`);
  lines.push(`port = ${port("cf-port", "FTP 端口")}`);
  lines.push(`welcome_message = ${q(str("cf-welcome"))}`);
  lines.push(`encoding = ${q(str("cf-encoding") || "UTF-8")}`);
  lines.push(`connection_mode = ${q(sel("cf-conn-mode"))}`);
  lines.push(`allow_anonymous = ${$("cf-anonymous").checked}`);
  lines.push(`anonymous_home = ${q(str("cf-anon-home"))}`);
  lines.push(`passive_ports = [${lo}, ${hi}]`);
  lines.push(`max_speed_kbps = ${reqInt("cf-speed", "单连接限速", 0)}`);
  lines.push(`masquerade_address = ${q(str("cf-masquerade"))}`);
  lines.push(`idle_timeout = ${reqInt("cf-idle-timeout", "空闲超时", 1)}`);
  lines.push(`pooled_listener_mode = ${$("cf-pooled").checked}`);
  lines.push(`allow_nat_clients = ${$("cf-nat").checked}`);
  lines.push(`ftp_root = ${q(str("cf-root"))}`);
  lines.push("");
  lines.push("[ftp.ftps]");
  lines.push(`enabled = ${$("cf-ftps-enabled").checked}`);
  lines.push(`require_ssl = ${$("cf-ftps-require").checked}`);
  lines.push(`cert_path = ${q(str("cf-ftps-cert"))}`);
  lines.push(`key_path = ${q(str("cf-ftps-key"))}`);
  lines.push("");
  lines.push("[sftp]");
  lines.push(`enabled = ${$("cf-sftp-enabled").checked}`);
  lines.push(`bind_ip = ${q(str("cf-sftp-bind-ip") || "0.0.0.0")}`);
  lines.push(`port = ${port("cf-sftp-port", "SFTP 端口")}`);
  lines.push(`host_key_path = ${q(str("cf-sftp-host-key"))}`);
  lines.push(`max_auth_attempts = ${reqInt("cf-sftp-max-auth", "最大认证尝试", 1)}`);
  lines.push(`auth_timeout = ${reqInt("cf-sftp-auth-timeout", "认证超时", 1)}`);
  lines.push(`max_sessions_per_user = ${reqInt("cf-sftp-sessions", "单用户最大会话", 1)}`);
  lines.push(`host_key_rotation_days = ${reqInt("cf-sftp-rotation", "主机密钥轮换天数", 0)}`);
  lines.push("");
  lines.push("[security]");
  lines.push(`max_connections = ${reqInt("cf-sec-max-conn", "全局最大并发连接", 1)}`);
  lines.push(`max_connections_per_ip = ${reqInt("cf-sec-max-conn-ip", "单 IP 最大并发连接", 1)}`);
  lines.push(`allowed_ips = [${cidrs("cf-sec-allowed").map(q).join(", ")}]`);
  lines.push(`denied_ips = [${cidrs("cf-sec-denied").map(q).join(", ")}]`);
  lines.push(`fail2ban_enabled = ${$("cf-sec-f2b").checked}`);
  lines.push(`fail2ban_threshold = ${reqInt("cf-sec-f2b-threshold", "触发封禁失败次数", 1)}`);
  lines.push(`fail2ban_ban_time = ${reqInt("cf-sec-f2b-time", "封禁时长", 1)}`);
  lines.push(`allow_symlinks = ${$("cf-symlinks").checked}`);
  lines.push(`max_login_attempts = ${reqInt("cf-sec-max-login", "最大登录尝试次数", 1)}`);
  lines.push("");
  lines.push("[logging]");
  for (const key of Object.keys(lgDefault)) {
    const v = lg[key] !== undefined ? lg[key] : lgDefault[key];
    lines.push(typeof v === "string" ? `${key} = ${q(v)}` : `${key} = ${v}`);
  }

  return { toml: lines.join("\n") + "\n", errs };
}

$("config-reload").addEventListener("click", loadConfigPage);

$("config-save").addEventListener("click", async () => {
  const { toml, errs } = buildConfigToml();
  if (errs.length) { toast("请修正后再保存：" + errs.join("、"), true); return; }
  try {
    const res = await api("/api/config", { method: "PUT", body: { content: toml } });
    // fftpd 返回规范化后的配置：回填表单与原文缓存
    if (res && typeof res.content === "string") {
      fillConfigForm(res.content);
      fillLogForm(res.content);
    } else {
      refreshCfgToml();
    }
    toast("配置已保存");
  } catch (e) { toast("保存失败：" + errMsg(e), true); }
});

// ---------- 用户（列表 + 弹窗编辑） ----------

let usersCache = null;   // 解析后的 users.json 对象 { users: { 用户名: User } }
let editingUser = null;  // 弹窗正在编辑的用户名；null = 新增

const PERM_KEYS = ["can_read", "can_list", "can_write", "can_append",
  "can_mkdir", "can_rmdir", "can_delete", "can_rename"];
const PERM_LABELS = {
  can_read: "读取", can_list: "列目录", can_write: "写入", can_append: "续传",
  can_mkdir: "建目录", can_rmdir: "删目录", can_delete: "删除", can_rename: "重命名",
};

async function loadUsers() {
  try {
    const { content } = await api("/api/users");
    usersCache = JSON.parse(content);
    if (!usersCache || typeof usersCache !== "object" || !usersCache.users) {
      usersCache = { users: {} };
    }
    renderUsers();
    $("users-text").value = content;
  } catch (e) { toast("加载用户库失败：" + errMsg(e), true); }
}

function renderUsers() {
  const wrap = $("users-table");
  const users = usersCache.users;
  const names = Object.keys(users).sort((a, b) => a.localeCompare(b));
  if (!names.length) {
    wrap.innerHTML = '<p class="hint">（暂无用户，点击右上角「添加用户」创建）</p>';
    return;
  }
  const table = document.createElement("table");
  table.className = "optable";
  table.innerHTML =
    "<thead><tr><th>用户名</th><th>主目录</th><th>权限</th><th>配额</th><th>限速</th>" +
    "<th>状态</th><th>最后登录</th><th>操作</th></tr></thead>";
  const tbody = document.createElement("tbody");
  for (const name of names) {
    const u = users[name];
    const p = u.permissions || {};
    const perms = PERM_KEYS.filter((k) => p[k]).map((k) => PERM_LABELS[k]).join("、") || "—";
    const quota = p.quota_mb != null ? escapeHtml(String(p.quota_mb)) + " MB" : "不限";
    const speed = p.speed_limit_kbps != null ? escapeHtml(String(p.speed_limit_kbps)) + " KB/s" : "不限";
    const status = u.enabled
      ? '<span class="badge on">启用</span>'
      : '<span class="badge off">禁用</span>';
    const admin = u.is_admin ? '<span class="badge role">管理员</span>' : "";
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="uname">${escapeHtml(name)}${admin}</td>` +
      `<td class="path">${escapeHtml(u.home_dir || "")}</td>` +
      `<td class="perm">${escapeHtml(perms)}</td>` +
      `<td>${quota}</td><td>${speed}</td>` +
      `<td>${status}</td>` +
      `<td>${escapeHtml(fmtDateTime(u.last_login))}</td>` +
      `<td class="row-actions">` +
      `<button type="button" class="btn" data-edit="${escapeHtml(name)}">编辑</button>` +
      `<button type="button" class="btn ghost danger-link" data-del="${escapeHtml(name)}">删除</button></td>`;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.textContent = "";
  wrap.appendChild(table);
  wrap.querySelectorAll("[data-edit]").forEach((b) =>
    b.addEventListener("click", () => openUserDialog(b.dataset.edit)));
  wrap.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", () => deleteUser(b.dataset.del)));
}

// users.json → 服务端校验落盘 + 热重载；成功返回 true
async function saveUsersCache() {
  const content = JSON.stringify(usersCache, null, 2) + "\n";
  const res = await api("/api/users", { method: "PUT", body: { content } });
  $("users-text").value = res && typeof res.content === "string" ? res.content : content;
}

function openUserDialog(name) {
  editingUser = name || null;
  const u = name && usersCache ? usersCache.users[name] : null;
  $("user-dlg-title").textContent = name ? "编辑用户：" + name : "添加用户";
  $("user-dlg-err").classList.add("hidden");
  $("ud-name").value = name || "";
  $("ud-name").disabled = !!name;
  $("ud-pass").value = "";
  $("ud-pass").placeholder = name ? "留空则不修改口令" : "登录口令";
  $("ud-home").value = u ? u.home_dir : "";
  $("ud-enabled").checked = u ? u.enabled !== false : true;
  $("ud-admin").checked = u ? !!u.is_admin : false;
  const p = (u && u.permissions) || {};
  for (const k of PERM_KEYS) $("ud-" + k).checked = p[k] !== false;
  $("ud-quota").value = p.quota_mb != null ? p.quota_mb : "";
  $("ud-speed").value = p.speed_limit_kbps != null ? p.speed_limit_kbps : "";
  $("user-dialog").classList.remove("hidden");
  refreshHomeSuggestions();
  $("ud-name").focus();
}

function closeUserDialog() {
  $("user-dialog").classList.add("hidden");
  editingUser = null;
}

// 主目录候选：按当前用户名请求服务端建议（本地路径计算，不发往 fftpd）
let homeSuggestTimer = null;
async function refreshHomeSuggestions() {
  const name = $("ud-name").value.trim();
  const list = $("ud-home-list");
  if (!name) { list.innerHTML = ""; return; }
  try {
    const res = await api("/api/user-directories/suggest", {
      method: "POST",
      body: { username: name },
    });
    const dirs = res.directories || [];
    list.innerHTML = dirs
      .map((d) => `<option value="${escapeHtml(d)}"></option>`)
      .join("");
    // 新增用户时默认填入桌面根目录，编辑已有用户时绝不覆盖
    if (!editingUser && !$("ud-home").value.trim() && dirs.length) {
      $("ud-home").value = dirs[0];
    }
  } catch (_) { /* 建议失败不影响手工填写 */ }
}

$("ud-name").addEventListener("input", () => {
  clearTimeout(homeSuggestTimer);
  homeSuggestTimer = setTimeout(refreshHomeSuggestions, 300);
});

function showDlgErr(msg) {
  const el = $("user-dlg-err");
  el.textContent = msg;
  el.classList.remove("hidden");
}

$("user-add").addEventListener("click", () => openUserDialog(null));
$("ud-cancel").addEventListener("click", closeUserDialog);

$("user-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!usersCache) usersCache = { users: {} };
  const name = $("ud-name").value.trim();
  const pass = $("ud-pass").value;
  const home = $("ud-home").value.trim();
  if (!name || /[\s/\\]/.test(name)) { showDlgErr("用户名不能为空，且不能包含空白或路径分隔符"); return; }
  if (!home) { showDlgErr("主目录不能为空"); return; }
  if (!editingUser && !pass) { showDlgErr("请输入登录口令"); return; }
  try {
    const prev = editingUser ? usersCache.users[editingUser] : null;
    let password_hash;
    if (pass) {
      password_hash = (await api("/api/user-hash", { method: "POST", body: { password: pass } })).hash;
    } else {
      password_hash = prev.password_hash; // 编辑且未填口令：沿用原哈希
    }
    const perms = {};
    for (const k of PERM_KEYS) perms[k] = $("ud-" + k).checked;
    const quota = parseInt($("ud-quota").value, 10);
    const speed = parseInt($("ud-speed").value, 10);
    perms.quota_mb = Number.isFinite(quota) ? quota : null;
    perms.speed_limit_kbps = Number.isFinite(speed) ? speed : null;
    const user = {
      username: name,
      password_hash,
      home_dir: home,
      permissions: perms,
      created_at: prev ? prev.created_at : new Date().toISOString(),
      last_login: prev ? prev.last_login : null,
      enabled: $("ud-enabled").checked,
      is_admin: $("ud-admin").checked,
    };
    const backup = JSON.stringify(usersCache);
    if (editingUser) delete usersCache.users[editingUser];
    usersCache.users[name] = user;
    try {
      await saveUsersCache();
      toast(editingUser ? "用户已更新：" + name : "用户已添加：" + name);
      closeUserDialog();
      renderUsers();
    } catch (e) {
      usersCache = JSON.parse(backup); // 保存失败：回滚前端缓存
      showDlgErr(errMsg(e));
    }
  } catch (e) { showDlgErr(errMsg(e)); }
});

async function deleteUser(name) {
  if (!confirm(`确认删除用户 ${name}？将立即写入用户库并热生效。`)) return;
  const backup = JSON.stringify(usersCache);
  delete usersCache.users[name];
  try {
    await saveUsersCache();
    toast("用户已删除：" + name);
    renderUsers();
  } catch (e) {
    usersCache = JSON.parse(backup);
    toast("删除失败：" + errMsg(e), true);
  }
}

// 高级模式：JSON 原文
$("users-reload").addEventListener("click", loadUsers);
$("users-save").addEventListener("click", async () => {
  try {
    await api("/api/users", { method: "PUT", body: { content: $("users-text").value } });
    toast("用户库已保存");
    await loadUsers();
  } catch (e) { toast("保存失败：" + errMsg(e), true); }
});

// ---------- 目录辅助 ----------

$("dirs-ensure").addEventListener("click", async () => {
  try {
    await api("/api/user-directories/ensure", { method: "POST" });
    toast("已为全部用户补建主目录");
  } catch (e) { toast(errMsg(e), true); }
});

$("dirs-create").addEventListener("click", async () => {
  const path = $("dirs-path").value.trim();
  if (!path) { toast("请输入目录路径", true); return; }
  try {
    await api("/api/user-directory", { method: "POST", body: { path } });
    toast("目录已创建：" + path);
  } catch (e) { toast(errMsg(e), true); }
});

$("dirs-perms").addEventListener("click", async () => {
  const path = $("dirs-path").value.trim();
  if (!path) { toast("请输入目录路径", true); return; }
  try {
    await api("/api/directory-permissions", { method: "POST", body: { path } });
    toast("目录权限已设置：" + path);
  } catch (e) { toast(errMsg(e), true); }
});

// ---------- Web 管理员账户（fftp-http 自身登录账户） ----------

let adminsCache = [];   // [{ username }]
let editingAdmin = null;

function resetAdminForm() {
  editingAdmin = null;
  $("ad-name").value = "";
  $("ad-name").disabled = false;
  $("ad-pass").value = "";
  $("ad-pass").placeholder = "登录口令";
  $("ad-submit").textContent = "添加账户";
  $("ad-cancel-edit").classList.add("hidden");
  $("admin-dlg-err").classList.add("hidden");
}

async function openAdminDialog() {
  resetAdminForm();
  $("admin-dialog").classList.remove("hidden");
  await loadAdmins();
}

function closeAdminDialog() {
  $("admin-dialog").classList.add("hidden");
}

async function loadAdmins() {
  try {
    const res = await api("/api/admin-users");
    adminsCache = (res.users || []).map((u) => u.username);
    renderAdmins();
  } catch (e) {
    $("admin-table").textContent = "加载失败：" + errMsg(e);
  }
}

function renderAdmins() {
  const wrap = $("admin-table");
  if (!adminsCache.length) {
    wrap.innerHTML = '<p class="hint">（暂无账户）</p>';
    return;
  }
  const table = document.createElement("table");
  table.className = "optable";
  table.innerHTML = "<thead><tr><th>用户名</th><th>操作</th></tr></thead>";
  const tbody = document.createElement("tbody");
  for (const name of adminsCache) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="uname">${escapeHtml(name)}` +
      (name === state.user ? '<span class="badge role">当前</span>' : "") +
      `</td>` +
      `<td class="row-actions">` +
      `<button type="button" class="btn" data-aedit="${escapeHtml(name)}">编辑</button>` +
      `<button type="button" class="btn ghost danger-link" data-adel="${escapeHtml(name)}">删除</button></td>`;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.textContent = "";
  wrap.appendChild(table);
  wrap.querySelectorAll("[data-aedit]").forEach((b) =>
    b.addEventListener("click", () => startEditAdmin(b.dataset.aedit)));
  wrap.querySelectorAll("[data-adel]").forEach((b) =>
    b.addEventListener("click", () => deleteAdmin(b.dataset.adel)));
}

function startEditAdmin(name) {
  editingAdmin = name;
  $("ad-name").value = name;
  $("ad-name").disabled = true;
  $("ad-pass").value = "";
  $("ad-pass").placeholder = "留空则不修改口令";
  $("ad-submit").textContent = "更新账户";
  $("ad-cancel-edit").classList.remove("hidden");
  $("admin-dlg-err").classList.add("hidden");
  $("ad-pass").focus();
}

function showAdminErr(msg) {
  const el = $("admin-dlg-err");
  el.textContent = msg;
  el.classList.remove("hidden");
}

// 保存全量列表：带 password 的条目为新增/改密，其余沿用服务端现有哈希
async function saveAdmins(list) {
  const res = await api("/api/admin-users", { method: "PUT", body: { users: list } });
  adminsCache = (res.users || []).map((u) => u.username);
  renderAdmins();
}

$("btn-admin-settings").addEventListener("click", openAdminDialog);
$("ad-close").addEventListener("click", closeAdminDialog);
$("ad-cancel-edit").addEventListener("click", resetAdminForm);

$("admin-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = $("ad-name").value.trim();
  const pass = $("ad-pass").value;
  if (!name) { showAdminErr("用户名不能为空"); return; }
  const list = adminsCache.map((u) => ({ username: u }));
  if (editingAdmin) {
    if (pass) {
      const entry = list.find((u) => u.username === editingAdmin);
      if (entry) entry.password = pass;
    }
  } else {
    if (!pass) { showAdminErr("请输入登录口令"); return; }
    if (list.some((u) => u.username === name)) { showAdminErr("用户名已存在"); return; }
    list.push({ username: name, password: pass });
  }
  try {
    await saveAdmins(list);
    toast(editingAdmin ? "账户已更新：" + editingAdmin : "账户已添加：" + name);
    resetAdminForm();
  } catch (e) { showAdminErr(errMsg(e)); }
});

async function deleteAdmin(name) {
  if (!confirm(`确认删除 Web 管理员 ${name}？保存后立即生效，该账户将无法再登录。`)) return;
  try {
    await saveAdmins(adminsCache.filter((u) => u !== name).map((u) => ({ username: u })));
    toast("账户已删除：" + name);
  } catch (e) { toast("删除失败：" + errMsg(e), true); }
}

// ---------- 启动 ----------

// 刷新页面时先探测既有会话：有效则直接进入，无需重新登录。
(async function start() {
  try {
    const me = await api("/api/me");
    state.user = me.username;
    await boot();
  } catch (_) {
    // 未登录/会话过期时 api() 已弹出登录框；网络错误同样回到登录界面。
    showLogin(false);
  }
})();
