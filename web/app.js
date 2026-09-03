"use strict";

// 后端 API 与前缀。若 kcc server 配置了不同的 web_base，请同步修改此处。
const BASE = "/kcc";

const $ = (id) => document.getElementById(id);
const authHeaders = (extra = {}) => {
  const token = localStorage.getItem("kcc_token");
  return Object.assign({ "Content-Type": "application/json" }, extra, token ? { Authorization: "Bearer " + token } : {});
};

const isTerminal = (s) => s === "completed" || s === "failed" || s === "cancelled";

const redirectIfAuth = async () => {
  try {
    const r = await fetch(BASE + "/api/auth/me", { headers: authHeaders() });
    if (r.ok) {
      const data = await r.json();
      $("me-label").textContent = "你好，" + data.username;
      showMain();
      refreshReports();
      refreshHistory();
    } else {
      showLogin();
    }
  } catch (e) {
    showLogin();
  }
};

const showLogin = () => { $("login-view").hidden = false; $("main-view").hidden = true; };
const showMain = () => { $("login-view").hidden = true; $("main-view").hidden = false; };

async function showErrorInto(selector, msg) {
  const el = $(selector);
  el.textContent = msg;
  el.hidden = msg ? false : true;
}

// ---------- 登录 ----------
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await showErrorInto("login-error", "");
  try {
    const r = await fetch(BASE + "/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: $("login-username").value, password: $("login-password").value }),
    });
    const data = await r.json();
    if (!r.ok) { throw new Error(data.error || "登录失败"); }
    localStorage.setItem("kcc_token", data.token);
    $("me-label").textContent = "你好，" + data.username;
    showMain();
    refreshReports();
    refreshHistory();
  } catch (err) {
    await showErrorInto("login-error", String(err.message || err));
  }
});

$("logout-btn").addEventListener("click", () => {
  localStorage.removeItem("kcc_token");
  showLogin();
});

// ---------- 标签页 ----------
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $("tab-" + tab.dataset.tab.slice(4)).classList.add("active");
    if (tab.dataset.tab === "tab-reports") refreshReports();
    if (tab.dataset.tab === "tab-history") refreshHistory();
  });
});

// ---------- 发起巡检 ----------
let currentJobId = null;
$("inspect-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    types: [$("inspect-type").value],
    namespace: $("inspect-namespace").value || null,
    cluster_name: $("inspect-cluster-name").value || null,
    format: $("inspect-format").value,
    lang: $("inspect-lang").value,
    level: $("inspect-level").value || "warning,critical",
  };
  try {
    const r = await fetch(BASE + "/api/inspect", {
      method: "POST", headers: authHeaders(),
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "启动失败");
    currentJobId = data.inspect_id;
    $("progress-section").hidden = false;
    $("progress-id").textContent = "（ID: " + currentJobId + "）";
    $("logs-box").textContent = "";
    $("download-link").hidden = true;
    startStream(currentJobId);
  } catch (err) {
    alert(err.message || err);
  }
});

let lastLogLine = "";
const MAX_LOG_CHARS = 20000; // 日志区最多保留的字符数，防止长时间巡检把 DOM 撑爆

function resetLogs() {
  lastLogLine = "";
  $("logs-box").textContent = "";
}

function appendLog(line) {
  if (!line) return;
  if (line === lastLogLine) return; // 去重相邻重复行（防止异常状态下刷屏撑爆内存）
  lastLogLine = line;
  const box = $("logs-box");
  box.textContent += line + "\n";
  // 只保留最近 MAX_LOG_CHARS 字符，避免 DOM 无限增长
  if (box.textContent.length > MAX_LOG_CHARS) {
    const all = box.textContent;
    box.textContent = all.slice(all.length - MAX_LOG_CHARS);
  }
  box.scrollTop = box.scrollHeight;
}

// 一次“巡检会话”的生命周期控制：
//   - runController：AbortController，发起新巡检会中止上一次的 SSE / 轮询
//   - statusTimer：自调度 setTimeout（等本轮请求完成后再排下一轮，
//     避免 setInterval 在服务端响应慢时堆积请求、耗尽浏览器内存）
let runController = null;
let statusTimer = null;
let finishedJob = false;
let pollCursor = 0;

function stopCurrentRun() {
  finishedJob = true;
  if (statusTimer) { clearTimeout(statusTimer); statusTimer = null; }
  if (runController) { runController.abort(); runController = null; }
}

// 拉取一次状态并渲染；返回是否已进入终态（completed/failed/cancelled）。
async function updateStatus(id, signal) {
  try {
    const r = await fetch(BASE + "/api/inspect/" + id, { headers: authHeaders(), signal });
    if (r.status === 404) return true; // 任务不存在（已被清理/服务重启），停止轮询
    if (!r.ok) return false;
    const s = await r.json();
    $("progress-meta").textContent = "状态：" + (s.status || "unknown") +
      "　进度：" + Math.round((s.progress || 0)) + "%　模块：" + (s.current || "-") + "/" + (s.total || "-");
    $("progress-bar").style.width = (s.progress || 0) + "%";
    if (typeof s.score === "number") $("progress-score").textContent = "总分：" + s.score.toFixed(1) + "/100";
    if (s.status === "completed" && s.report_id) {
      $("download-link").onclick = (ev) => { ev.preventDefault(); downloadReport(s.report_id, "md"); };
      $("download-link").href = "#";
      $("download-link").hidden = false;
      refreshReports();
    }
    return isTerminal(s.status);
  } catch (e) {
    // 主动中止（新巡检/已完成）视为结束；网络错误则下一轮重试
    return !!(signal && signal.aborted);
  }
}

async function startStream(id) {
  // 中止上一次巡检的轮询 / SSE，防止旧请求堆积
  stopCurrentRun();
  const ctrl = new AbortController();
  runController = ctrl;
  finishedJob = false;
  pollCursor = 0;
  resetLogs();
  $("download-link").hidden = true;
  $("progress-score").textContent = "";

  let sseOk = true; // SSE 不可用时退化为 /logs 游标轮询

  // 统一轮询（自调度，等待本轮请求完成后再排下一轮）：
  //   1) 状态（进度/分数/终态）；2) SSE 不可用时追加 /logs 日志
  (async function pollLoop() {
    if (finishedJob || ctrl.signal.aborted) return;
    const terminal = await updateStatus(id, ctrl.signal);
    if (terminal || ctrl.signal.aborted) { stopCurrentRun(); return; }
    if (!sseOk) {
      try {
        const r = await fetch(BASE + "/api/inspect/" + id + "/logs?cursor=" + pollCursor,
          { headers: authHeaders(), signal: ctrl.signal });
        if (r.ok) {
          const d = await r.json();
          (d.logs || []).forEach(appendLog);
          pollCursor = d.cursor;
        }
      } catch (e) {
        if (ctrl.signal.aborted) return;
      }
    }
    statusTimer = setTimeout(pollLoop, 1500);
  })();

  // 主信道：SSE 实时日志
  try {
    const r = await fetch(BASE + "/api/inspect/" + id + "/stream", { headers: authHeaders(), signal: ctrl.signal });
    if (!r.ok || !r.body) throw new Error("no stream");
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (!finishedJob && !ctrl.signal.aborted) {
      const { done, value } = await reader.read();
      if (done || ctrl.signal.aborted) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
        block.split("\n").forEach((line) => {
          if (line.startsWith("data:")) appendLog(line.slice(5).trim());
        });
      }
    }
  } catch (e) {
    // SSE 不可用 / 中断：退化为 /logs 游标轮询（由上面的 pollLoop 拉取）
    if (!ctrl.signal.aborted) sseOk = false;
  }
}

$("cancel-btn").addEventListener("click", async () => {
  if (!currentJobId) return;
  await fetch(BASE + "/api/inspect/" + currentJobId + "/cancel", { method: "POST", headers: authHeaders() });
});

// 下载报告：用带 Authorization 头的 fetch 取 blob，再触发浏览器下载。
// 不能用普通 <a href> 跳转，否则不会带 token，下载端点会返回 401。
async function downloadReport(id, format) {
  const fmt = format || "html";
  try {
    const r = await fetch(BASE + "/api/reports/" + enc(id) + "/download?format=" + enc(fmt), { headers: authHeaders() });
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || ("下载失败 " + r.status)); }
    const disp = r.headers.get("Content-Disposition") || "";
    let name = "report." + fmt;
    const m = disp.match(/filename="?([^";]+)"?/);
    if (m) name = m[1].replace(/\.\.+/g, ".");
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert(e.message || e);
  }
}

// ---------- 报告列表 ----------
async function refreshReports() {
  const tbody = $("reports-table").querySelector("tbody");
  try {
    const r = await fetch(BASE + "/api/reports", { headers: authHeaders() });
    if (!r.ok) return;
    const data = await r.json();
    const items = data.reports || [];
    tbody.innerHTML = "";
    items.forEach((rep) => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + esc(rep.time || "") + "</td>" +
        "<td>" + esc(rep.cluster || "") + "</td>" +
        "<td>" + esc(rep.score != null ? rep.score.toFixed(1) : "-") + "</td>" +
        "<td>" + esc(rep.format || "") + "</td>" +
        "<td>" + esc(rep.size || "") + "</td>" +
        "<td><button class='btn' onclick='downloadReport(\"" + enc(rep.id) + "\",\"" + enc(rep.format || "html") + "\")'>下载</button> " +
        "<button class='danger' onclick='deleteReport(\"" + enc(rep.id) + "\")'>删除</button></td>";
      tbody.appendChild(tr);
    });
  } catch (e) { /* ignore */ }
}

async function deleteReport(id) {
  await fetch(BASE + "/api/reports/" + id, { method: "DELETE", headers: authHeaders() });
  refreshReports();
}

// ---------- 历史记录 ----------
async function refreshHistory() {
  const tbody = $("history-table").querySelector("tbody");
  try {
    const r = await fetch(BASE + "/api/inspect/history", { headers: authHeaders() });
    if (!r.ok) return;
    const data = await r.json();
    const items = data.runs || [];
    tbody.innerHTML = "";
    items.forEach((h) => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + esc(h.id || "") + "</td>" +
        "<td>" + esc((h.types || []).join(",")) + "</td>" +
        "<td>" + esc(h.started_at || "") + "</td>" +
        "<td>" + esc(h.duration || "") + "</td>" +
        "<td>" + esc(h.status || "") + "</td>";
      tbody.appendChild(tr);
    });
  } catch (e) { /* ignore */ }
}

function esc(s) { const d = document.createElement("div"); d.textContent = String(s ?? ""); return d.innerHTML; }
function enc(s) { return encodeURIComponent(String(s)); }

redirectIfAuth();