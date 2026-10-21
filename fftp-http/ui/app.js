/* fftp-http Web 管理界面逻辑（原生 JS，无外部依赖） */
"use strict";

// ---------- 工具 ----------

const $ = (id) => document.getElementById(id);
const state = { user: null };

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
  try {
    const st = await api("/api/status");
    fillIdentity(st);
  } catch (e) { /* 离线横幅已展示 */ }
  switchTab("service");
  startConnPoll();
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
  stopStream();
  try { await fetch("/api/logout", { method: "POST", credentials: "same-origin" }); } catch (_) { /* 忽略 */ }
  state.user = null;
  $("main").classList.add("hidden");
  $("topbar").classList.add("hidden");
  $("offline").classList.add("hidden");
  showLogin();
});

// ---------- Tab 切换 ----------

const TABS = ["service", "config", "users", "logs", "logfiles", "fileop", "about"];

function switchTab(name) {
  for (const t of TABS) {
    $("tab-" + t).classList.toggle("hidden", t !== name);
  }
  document.querySelectorAll("#tabs button").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === name);
  });
  if (name === "service") { refreshStatus(); loadLogConfig(); }
  if (name === "config") loadConfig();
  if (name === "users") loadUsers();
  if (name === "logs") startStream();
  else stopStream();
  if (name === "logfiles") loadLogFileList();
  if (name === "fileop") loadFileOpList();
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

// ---------- 服务状态与操作 ----------

let statusTimer = null;

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

function armStatusPoll() {
  clearInterval(statusTimer);
  statusTimer = setInterval(() => {
    if ($("tab-service").classList.contains("hidden")) return;
    refreshStatus();
  }, 5000);
}

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

// ---------- 日志设置（[logging] 段） ----------

// 轻量解析 config.toml 的 [logging] 段（值均为标量）
function parseLoggingSection(toml) {
  const out = {};
  let inSec = false;
  for (const rawLine of toml.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("[") && line.endsWith("]")) {
      inSec = line === "[logging]";
      continue;
    }
    if (!inSec || !line || line.startsWith("#")) continue;
    const m = /^([A-Za-z0-9_]+)\s*=\s*(.+?)(\s+#.*)?$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    else if (v === "true") v = true;
    else if (v === "false") v = false;
    else if (/^-?\d+$/.test(v)) v = parseInt(v, 10);
    out[m[1]] = v;
  }
  return out;
}

async function loadLogConfig() {
  try {
    const { content } = await api("/api/config");
    const lg = parseLoggingSection(content);
    $("lc-dir").value = lg.log_dir || "";
    $("lc-level").value = ["error", "warn", "info", "debug", "trace"].includes(lg.log_level) ? lg.log_level : "info";
    $("lc-size").value = lg.max_log_size ? Math.max(1, Math.round(lg.max_log_size / 1048576)) : "";
    $("lc-files").value = lg.max_log_files || "";
    $("lc-gui").checked = !!lg.enable_gui_logging;
  } catch (_) { /* 离线横幅已处理 */ }
}

$("lc-reload").addEventListener("click", loadLogConfig);

$("logcfg-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
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
    toast("日志设置已保存");
  } catch (e) { toast(errMsg(e), true); }
});

// ---------- 配置 / 用户编辑 ----------

async function loadConfig() {
  try {
    const { content } = await api("/api/config");
    $("config-text").value = content;
  } catch (_) { /* 离线横幅已处理 */ }
}

$("config-reload").addEventListener("click", loadConfig);
$("config-save").addEventListener("click", async () => {
  try {
    await api("/api/config", { method: "PUT", body: { content: $("config-text").value } });
    toast("配置已保存");
  } catch (e) { toast("保存失败：" + errMsg(e), true); }
});

async function loadUsers() {
  try {
    const { content } = await api("/api/users");
    $("users-text").value = content;
  } catch (_) { /* 离线横幅已处理 */ }
}

$("users-reload").addEventListener("click", loadUsers);
$("users-save").addEventListener("click", async () => {
  try {
    await api("/api/users", { method: "PUT", body: { content: $("users-text").value } });
    toast("用户库已保存");
  } catch (e) { toast("保存失败：" + errMsg(e), true); }
});

// ---------- 目录辅助 ----------

$("dirs-ensure").addEventListener("click", async () => {
  try {
    await api("/api/user-directories/ensure", { method: "POST" });
    toast("已为全部用户补建主目录");
  } catch (e) { toast(errMsg(e), true); }
});

$("dirs-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
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

// ---------- 实时日志（SSE） ----------

const logState = { es: null, paused: false, reconnect: null };

function appendLog(entry) {
  const view = $("log-view");
  const div = document.createElement("div");
  div.className = "line";
  const extra = [entry.client_ip, entry.username, entry.action].filter(Boolean).join(" ");
  div.innerHTML =
    `<span class="t-dim">${escapeHtml(fmtTime(entry.timestamp))}</span> ` +
    `<span class="lvl-${escapeHtml(entry.level)}">${escapeHtml(entry.level)}</span> ` +
    `<span class="t-dim">[${escapeHtml(entry.source)}]</span> ` +
    escapeHtml(entry.message) +
    (extra ? ` <span class="t-dim">(${escapeHtml(extra)})</span>` : "");
  view.appendChild(div);
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

function startStream() {
  if (logState.es || !state.user) return;
  logState.paused = false;
  $("log-pause").textContent = "暂停";
  $("log-state").textContent = "连接中…";
  $("log-view").textContent = "";
  connectStream();
}

function connectStream() {
  const es = new EventSource("/api/logs/stream?tail=200");
  logState.es = es;
  es.addEventListener("log", (ev) => {
    try { appendLog(JSON.parse(ev.data)); } catch (_) { /* 忽略坏帧 */ }
  });
  es.addEventListener("notice", (ev) => appendSysLine(ev.data));
  es.onopen = () => { $("log-state").textContent = "已连接"; };
  es.onerror = () => {
    es.close();
    logState.es = null;
    if (logState.paused || $("tab-logs").classList.contains("hidden")) {
      $("log-state").textContent = "已断开";
      return;
    }
    $("log-state").textContent = "连接断开，2 秒后重连…";
    logState.reconnect = setTimeout(connectStream, 2000);
  };
}

function stopStream() {
  clearTimeout(logState.reconnect);
  if (logState.es) { logState.es.close(); logState.es = null; }
  logState.paused = false;
  $("log-state").textContent = "";
}

$("log-pause").addEventListener("click", () => {
  if (logState.paused) {
    $("log-view").textContent = "";
    connectStream();
    logState.paused = false;
    $("log-pause").textContent = "暂停";
  } else {
    logState.paused = true;
    clearTimeout(logState.reconnect);
    if (logState.es) { logState.es.close(); logState.es = null; }
    $("log-pause").textContent = "继续";
    $("log-state").textContent = "已暂停";
  }
});

$("log-clear").addEventListener("click", () => { $("log-view").textContent = ""; });

// ---------- 日志文件 ----------

let logfileSel = null;

async function loadLogFileList() {
  const ul = $("logfile-list");
  try {
    const { files } = await api("/api/logs/files");
    ul.textContent = "";
    if (!files.length) { ul.innerHTML = '<li class="hint">暂无日志文件</li>'; return; }
    for (const f of files) {
      const li = document.createElement("li");
      li.textContent = f.name;
      li.title = f.path;
      li.addEventListener("click", () => {
        logfileSel = f;
        ul.querySelectorAll("li").forEach((x) => x.classList.remove("active"));
        li.classList.add("active");
        $("logfile-name").textContent = f.name;
        loadLogFileContent();
      });
      ul.appendChild(li);
    }
  } catch (e) {
    ul.innerHTML = '<li class="hint">加载失败：' + escapeHtml(errMsg(e)) + "</li>";
  }
}

async function loadLogFileContent() {
  if (!logfileSel) return;
  const view = $("logfile-view");
  view.textContent = "加载中…";
  try {
    const { entries } = await api("/api/logs/content", {
      method: "POST",
      body: { path: logfileSel.path, count: parseInt($("logfile-count").value, 10) },
    });
    view.textContent = "";
    for (const e of entries) appendLog(e);
    if (!entries.length) view.textContent = "（无记录）";
  } catch (e) {
    view.textContent = "加载失败：" + errMsg(e);
  }
}

$("logfile-refresh").addEventListener("click", loadLogFileContent);
$("logfile-count").addEventListener("change", loadLogFileContent);

// ---------- 文件操作日志 ----------

let fileopSel = null;

async function loadFileOpList() {
  const ul = $("fileop-list");
  try {
    const { files } = await api("/api/fileop/files");
    ul.textContent = "";
    if (!files.length) { ul.innerHTML = '<li class="hint">暂无文件操作日志</li>'; return; }
    for (const f of files) {
      const li = document.createElement("li");
      li.textContent = f.name;
      li.title = f.path;
      li.addEventListener("click", () => {
        fileopSel = f;
        ul.querySelectorAll("li").forEach((x) => x.classList.remove("active"));
        li.classList.add("active");
        $("fileop-name").textContent = f.name;
        loadFileOpContent();
      });
      ul.appendChild(li);
    }
  } catch (e) {
    ul.innerHTML = '<li class="hint">加载失败：' + escapeHtml(errMsg(e)) + "</li>";
  }
}

async function loadFileOpContent() {
  if (!fileopSel) return;
  const view = $("fileop-view");
  view.textContent = "加载中…";
  try {
    const { entries } = await api("/api/fileop/content", {
      method: "POST",
      body: { path: fileopSel.path, count: parseInt($("fileop-count").value, 10) },
    });
    view.textContent = "";
    if (!entries.length) { view.textContent = "（无记录）"; return; }
    const table = document.createElement("table");
    table.className = "optable";
    table.innerHTML =
      "<thead><tr><th>时间</th><th>用户</th><th>客户端</th><th>操作</th><th>路径</th>" +
      "<th>大小</th><th>协议</th><th>结果</th><th>消息</th></tr></thead>";
    const tbody = document.createElement("tbody");
    for (const e of entries) {
      const tr = document.createElement("tr");
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
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    view.appendChild(table);
  } catch (e) {
    view.textContent = "加载失败：" + errMsg(e);
  }
}

$("fileop-refresh").addEventListener("click", loadFileOpContent);
$("fileop-count").addEventListener("change", loadFileOpContent);

// ---------- 启动 ----------

armStatusPoll();
showLogin();
