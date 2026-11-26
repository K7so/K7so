/* K7so // frontend console */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SEV_LABELS = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
const STATUS_LABELS = { queued: "排队", running: "运行中", completed: "已完成", failed: "失败", cancelled: "已取消" };
const PAGE_TITLES = {
  dashboard: "仪表盘", chat: "智能工作", assets: "资产监管", kits: "K7so工具", scans: "渗透测试",
  findings: "漏洞结果", connectors: "API 中心", paths: "目录配置", capabilities: "模型能力",
  audit: "审计日志", settings: "平台设置",
};
const CATEGORY_ORDER = ["ai", "recon", "intel", "vuln", "tool"];

const state = {
  user: null, page: "dashboard", assets: [], scans: [], findings: [], findingGroups: [], connectors: [],
  settings: null, detail: null, stream: null, activeTab: "overview",
  assetModules: [], kits: [],
  llmKey: "", capabilities: [], capabilityChecked: new Set(), capabilitySwitches: [],
  capabilityWeights: {}, capabilityHints: {},
  chatSessions: [], chatMessages: [], chatSessionId: null, chatBusy: false,
  chatProviders: [], chatProvider: "", chatTyping: false, chatAbort: null, chatStatus: null, chatTypingAt: 0,
  chatPinned: true, chatSelecting: false, chatRenderDirty: false,
};

/* ---------------- utils ---------------- */
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]
  ));
}
function fmtTime(value) {
  if (!value) return "—";
  return String(value).replace("T", " ").slice(0, 16);
}
function inlineMd(text) {
  // text 已经过 HTML 转义，这里只负责行内标记
  return text
    .replace(/`([^`\n]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^_\n]+)__/g, "<strong>$1</strong>");
}

function mdSplitRow(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function mdRender(text) {
  // 先整体转义，再按块级结构重建，保证不会执行任何 HTML/脚本
  const lines = esc(text).split("\n");
  const out = [];
  let i = 0;
  const isTableRow = (line) => /^\s*\|.*\|\s*$/.test(line || "");
  const isDivider = (line) => /^\s*\|[\s:|-]+\|\s*$/.test(line || "");

  while (i < lines.length) {
    const line = lines[i];

    // 代码块：请求包、响应包这类报文必须原样保留换行与缩进，
    // 逐行当正文排会把头部揉成一团，照着复现时根本对不上
    if (/^\s*```/.test(line)) {
      i += 1;
      const body = [];
      while (i < lines.length && !/^\s*```/.test(lines[i])) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1;  // 跳过结束的围栏
      out.push(`<pre class="md-pre">${body.join("\n")}</pre>`);
      continue;
    }

    // 表格：表头 + 分隔行 + 数据行
    if (isTableRow(line) && isDivider(lines[i + 1])) {
      const head = mdSplitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && isTableRow(lines[i])) {
        rows.push(mdSplitRow(lines[i]));
        i += 1;
      }
      const headHtml = head.map((cell) => `<th>${inlineMd(cell)}</th>`).join("");
      const bodyHtml = rows.map((row) => {
        const cells = head.map((_, idx) => `<td>${inlineMd(row[idx] || "")}</td>`).join("");
        return `<tr>${cells}</tr>`;
      }).join("");
      out.push(`<div class="md-table"><table><thead><tr>${headHtml}</tr></thead><tbody>${bodyHtml}</tbody></table></div>`);
      continue;
    }

    // 标题
    const heading = line.match(/^(#{1,5})\s+(.*)$/);
    if (heading) {
      const level = Math.min(heading[1].length + 2, 6);
      out.push(`<h${level}>${inlineMd(heading[2].trim())}</h${level}>`);
      i += 1;
      continue;
    }

    // 分隔线
    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) {
      out.push("<hr>");
      i += 1;
      continue;
    }

    // 无序列表
    if (/^\s*[-*+]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(`<li>${inlineMd(lines[i].replace(/^\s*[-*+]\s+/, ""))}</li>`);
        i += 1;
      }
      out.push(`<ul>${items.join("")}</ul>`);
      continue;
    }

    // 有序列表
    if (/^\s*\d+[.)]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) {
        items.push(`<li>${inlineMd(lines[i].replace(/^\s*\d+[.)]\s+/, ""))}</li>`);
        i += 1;
      }
      out.push(`<ol>${items.join("")}</ol>`);
      continue;
    }

    // 空行
    if (!line.trim()) {
      i += 1;
      continue;
    }

    // 普通段落：连续非空行合并
    const buffer = [];
    while (i < lines.length) {
      const current = lines[i];
      if (
        !current.trim()
        || isTableRow(current)
        || /^\s*```/.test(current)
        || /^(#{1,5})\s+/.test(current)
        || /^\s*[-*+]\s+/.test(current)
        || /^\s*\d+[.)]\s+/.test(current)
        || /^\s*([-*_])\1{2,}\s*$/.test(current)
      ) break;
      buffer.push(inlineMd(current));
      i += 1;
    }
    out.push(`<p>${buffer.join("<br>")}</p>`);
  }
  return out.join("");
}

function mdLite(text) {
  return mdRender(text);
}
function sevBadge(sev) {
  const key = ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info";
  return `<span class="sev sev-${key}">${SEV_LABELS[key]}</span>`;
}
function statusBadge(status) {
  const label = STATUS_LABELS[status] || status || "—";
  return `<span class="status st-${esc(status)}"><span class="dot"></span>${esc(label)}</span>`;
}
function progressBar(value) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0));
  return `<div class="progress"><div class="track"><div class="fill" style="width:${pct}%"></div></div><span>${pct}%</span></div>`;
}
function emptyRow(cols, text = "暂无数据") {
  return `<tr><td colspan="${cols}" class="empty-state">${esc(text)}</td></tr>`;
}
let toastTimer = null;
// 中文业务提示原样展示；英文报错 / HTTP 状态码这类技术信息先翻成人话
function softenError(message) {
  const text = String(message || "").trim();
  if (!text) return "操作没成功，再试一次。";
  const chinese = /[\u4e00-\u9fa5]/.test(text);
  const technical = /\b(4\d\d|5\d\d)\b/.test(text) || (!chinese && /[A-Za-z]{4,}/.test(text));
  return technical ? friendlyChatError(text) : text;
}

function toast(message, type = "") {
  const el = $("#toast");
  el.textContent = type === "error" ? softenError(message) : message;
  el.className = `toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "toast"; }, 3800);
}

async function api(url, options = {}) {
  const opts = { credentials: "same-origin", ...options };
  // raw: true 表示 body 是原始二进制（导入工具 / 文件），不要 JSON 化
  const raw = opts.raw === true;
  if (raw) delete opts.raw;
  if (!raw && opts.body && typeof opts.body !== "string") {
    opts.body = JSON.stringify(opts.body);
    opts.headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  }
  const res = await fetch(url, opts);
  if (res.status === 401) {
    showLogin();
    throw new Error("登录状态已失效");
  }
  let data = null;
  if ((res.headers.get("content-type") || "").includes("application/json")) {
    data = await res.json();
  }
  if (!res.ok) {
    let message = data && data.detail;
    if (Array.isArray(message)) message = message.map((item) => item.msg || JSON.stringify(item)).join("；");
    throw new Error(message || `HTTP ${res.status}`);
  }
  return data;
}

/* ---------------- overlays ---------------- */
function openModal({ title, body, footer = "", wide = false }) {
  const overlay = document.createElement("div");
  overlay.className = "modal-backdrop";
  overlay.style.zIndex = "80";
  overlay.innerHTML = `
    <div class="modal-card ${wide ? "wide" : ""}">
      <div class="modal-head"><h3>${esc(title)}</h3><button class="modal-close" type="button">×</button></div>
      <div class="modal-body">${body}</div>
      ${footer ? `<div class="modal-foot">${footer}</div>` : ""}
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener("click", (event) => { if (event.target === overlay) overlay.remove(); });
  $(".modal-close", overlay).addEventListener("click", () => overlay.remove());
  return overlay;
}

function closeDrawer() {
  stopStream();
  const root = $("#modal-root");
  root.innerHTML = "";
  state.detail = null;
}

function stopStream() {
  if (state.stream) {
    state.stream.close();
    state.stream = null;
  }
}

/* ---------------- auth ---------------- */
const DISCLAIMER_KEY = "mono_disclaimer_ack";

function showLogin() {
  $("#app").classList.add("hidden");
  $("#disclaimer-screen").classList.add("hidden");
  $("#login-screen").classList.remove("hidden");
}
function showApp() {
  $("#login-screen").classList.add("hidden");
  $("#disclaimer-screen").classList.add("hidden");
  $("#app").classList.remove("hidden");
}
function disclaimerAccepted() {
  try { return sessionStorage.getItem(DISCLAIMER_KEY) === "1"; } catch (error) { return false; }
}
function showDisclaimer() {
  $("#app").classList.add("hidden");
  $("#login-screen").classList.add("hidden");
  $("#disclaimer-screen").classList.remove("hidden");
}
function enterConsole() {
  if (!disclaimerAccepted()) {
    showDisclaimer();
    return;
  }
  showApp();
  navigate("dashboard");
}
async function boot() {
  try {
    const me = await api("/api/auth/me");
    state.user = me;
    $("#side-user").textContent = me.username || "admin";
    enterConsole();
  } catch (error) {
    showLogin();
  }
}
$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#login-btn");
  const error = $("#login-error");
  error.textContent = "";
  button.disabled = true;
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: { username: $("#login-user").value.trim(), password: $("#login-pass").value },
    });
    state.user = data;
    $("#side-user").textContent = data.username;
    enterConsole();
  } catch (exc) {
    error.textContent = exc.message;
  } finally {
    button.disabled = false;
  }
});
$("#disclaimer-accept").addEventListener("click", () => {
  try { sessionStorage.setItem(DISCLAIMER_KEY, "1"); } catch (error) { /* 隐私模式下忽略 */ }
  api("/api/auth/disclaimer", { method: "POST" }).catch(() => { /* 留痕失败不阻断进入 */ });
  showApp();
  navigate("dashboard");
});
$("#disclaimer-decline").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch (error) { /* ignore */ }
  try { sessionStorage.removeItem(DISCLAIMER_KEY); } catch (error) { /* ignore */ }
  showLogin();
});
$("#logout-btn").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch (error) { /* ignore */ }
  try { sessionStorage.removeItem(DISCLAIMER_KEY); } catch (error) { /* ignore */ }
  closeDrawer();
  showLogin();
});

/* ---------------- navigation ---------------- */
async function navigate(page) {
  state.page = page;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
  $$(".page").forEach((section) => section.classList.toggle("hidden", section.id !== `page-${page}`));
  // 智能工作要铺满整窗：给 body 挂个标记，让这一页去掉多余的底部留白
  document.body.classList.toggle("chat-page", page === "chat");
  $("#page-title").textContent = PAGE_TITLES[page] || page;
  try {
    if (page === "dashboard") await loadDashboard();
    if (page === "chat") await duoBoot();
    if (page === "chat") await loadAutoSettings();
    if (page === "assets") await loadAssetModules();
    if (page === "kits") await loadKits();
    if (page === "findings") await loadFindings();
    if (page === "connectors") await loadConnectors();
    if (page === "paths") await loadPaths();
    if (page === "capabilities") await loadCapabilities();
    if (page === "audit") await loadAudit();
    if (page === "settings") await loadSettings();
  } catch (error) {
    toast(error.message, "error");
  }
}
$$(".nav-item").forEach((item) => item.addEventListener("click", () => navigate(item.dataset.page)));
document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-goto]");
  if (target) navigate(target.dataset.goto);
});
setInterval(() => {
  const now = new Date();
  $("#clock").textContent = now.toLocaleTimeString("zh-CN", { hour12: false });
  const elapsed = document.querySelector(".chat-typing .typing-elapsed");
  if (elapsed && state.chatTyping) elapsed.textContent = elapsedText();
}, 1000);

/* ---------------- dashboard ---------------- */
async function loadDashboard() {
  const data = await api("/api/dashboard");
  const stats = data.stats;
  $("#dash-stats").innerHTML = [
    ["纳管资产", stats.assets, "ASSETS IN SCOPE"],
    ["渗透测试", stats.scans, `${stats.running} 个进行中`],
    ["待处理风险", stats.open_findings, "OPEN / CONFIRMED"],
    ["风险指数", `${stats.risk_score}<small>/100</small>`, "WEIGHTED SEVERITY"],
    ["连接器健康", `${stats.connectors_healthy}<small>/${stats.connectors}</small>`, `已配置 ${stats.connectors_configured}`],
  ].map(([label, value, meta]) => `
    <div class="stat-card">
      <div class="stat-label">${label}</div>
      <div class="stat-value">${value}</div>
      <div class="stat-meta">${esc(meta)}</div>
    </div>`).join("");

  const trendMax = Math.max(1, ...data.trend.map((row) => Math.max(row.scans, row.findings)));
  $("#dash-trend").innerHTML = data.trend.map((row) => `
    <div class="bar-col" title="${esc(row.day)} 作业 ${row.scans} / 风险 ${row.findings}">
      <div class="bar-val">${row.scans}</div>
      <div class="bar-stack">
        <div class="bar" style="height:${Math.max(2, (row.scans / trendMax) * 100)}%"></div>
        <div class="bar ghost" style="height:${Math.max(2, (row.findings / trendMax) * 100)}%"></div>
      </div>
      <div class="bar-day">${esc(row.day)}</div>
    </div>`).join("");

  const sevMax = Math.max(1, ...Object.values(data.severity));
  $("#dash-severity").innerHTML = Object.entries(data.severity).map(([key, count]) => `
    <div class="sev-row">
      <span class="name">${SEV_LABELS[key]}</span>
      <div class="track"><div class="fill" style="width:${(count / sevMax) * 100}%"></div></div>
      <span class="num">${count}</span>
    </div>`).join("");

  $("#dash-scans").innerHTML = `
    <table><thead><tr><th>作业</th><th>状态</th><th>风险</th></tr></thead><tbody>
    ${data.recent_scans.length ? data.recent_scans.map((scan) => `
      <tr class="clickable" data-scan="${scan.id}">
        <td class="td-title"><strong>${esc(scan.name)}</strong><small>#${scan.id} · ${esc(scan.created_at)}</small></td>
        <td>${statusBadge(scan.status)}</td>
        <td class="mono-cell">${scan.finding_count}</td>
      </tr>`).join("") : emptyRow(3, "还没有渗透测试作业，点击右上角新建渗透测试")}
    </tbody></table>`;
  $$("#dash-scans tr[data-scan]").forEach((row) => row.addEventListener("click", () => openScanDetail(Number(row.dataset.scan))));

  $("#dash-findings").innerHTML = `
    <table><thead><tr><th>等级</th><th>风险</th></tr></thead><tbody>
    ${data.recent_findings.length ? data.recent_findings.map((item) => `
      <tr class="clickable" data-finding="${item.id}">
        <td>${sevBadge(item.severity)}</td>
        <td class="td-title"><strong>${esc(item.title)}</strong><small>${esc(item.target)}</small></td>
      </tr>`).join("") : emptyRow(2, "暂无待处理风险")}
    </tbody></table>`;
  $$("#dash-findings tr[data-finding]").forEach((row) => row.addEventListener("click", () => openFinding(Number(row.dataset.finding))));

  $("#dash-connectors").innerHTML = data.connectors.map((item) => {
    let cls = "unknown", text = item.enabled ? "未检测" : "已停用";
    if (item.enabled && item.ok === 1) { cls = "ok"; text = "正常"; }
    if (item.enabled && item.ok === 0) { cls = "fail"; text = "异常"; }
    return `<span class="health-chip ${cls} ${item.configured ? "configured" : ""}" title="${esc(item.message || "")}">
      <span class="dot"></span>${esc(item.name)}<em style="font-style:normal;color:#7f97ab">${text}</em>
    </span>`;
  }).join("");

  $("#dash-activity").innerHTML = data.activity.length ? data.activity.map((item) => `
    <div class="timeline-item">
      <time>${esc(fmtTime(item.ts).slice(5))}</time>
      <span><b>${esc(item.username || "system")}</b> · ${esc(item.action)}<br>${esc(item.detail || "")}</span>
    </div>`).join("") : `<div class="empty-state">暂无操作记录</div>`;

  const auth = data.authorization || {};
  $("#dash-scope").innerHTML = `
    <span>授权：<strong>登录免责声明已确认</strong> · 点名的目标即为已授权目标</span>
    <span>安全模式 <strong>${auth.safe_mode ? "ON" : "OFF"}</strong></span>
    <span class="muted">AUTHORIZED USE ONLY · 所有操作留痕</span>`;
}

/* ---------------- 通用：选文件 ---------------- */
// 用一个临时 input 触发系统选文件框，避免每页都塞一个 <input type=file>
function pickFiles({ accept = "", multiple = false } = {}) {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = accept;
    input.multiple = multiple;
    input.style.display = "none";
    input.addEventListener("change", () => {
      const files = Array.from(input.files || []);
      input.remove();
      resolve(files);
    });
    document.body.appendChild(input);
    input.click();
  });
}

function humanSize(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/* ---------------- 资产监管 ---------------- */
const SOURCE_LABELS = {
  document: "文件解析",
  dns: "DNS 收集",
  record: "DNS 记录",
  crt: "证书日志",
  manual: "手动添加",
};

async function loadAssetModules() {
  const data = await api("/api/asset-modules");
  state.assetModules = data.items || [];
  $("#asset-module-hint").textContent = `共 ${data.total} 个模块`;
  $("#asset-module-table").innerHTML = `
    <table><thead><tr><th>模块</th><th>建立时间</th><th>资产数</th><th>来源文件</th><th></th></tr></thead>
    <tbody>
    ${state.assetModules.length ? state.assetModules.map((item) => `
      <tr class="clickable" data-module-open="${item.id}">
        <td class="td-title"><strong>${esc(item.name)}</strong><small>#${item.id} · ${esc(item.created_by || "—")}</small></td>
        <td class="mono-cell">${esc(item.created_at)}</td>
        <td class="mono-cell">${item.host_count || 0}</td>
        <td>${(item.sources || []).length
          ? (item.sources || []).map((src) => `<span class="chip" title="${esc(src.name)}">${esc(src.kind || "file")}</span>`).join(" ")
          : `<span class="muted">还没导入文件</span>`}</td>
        <td class="row-actions">
          <button class="btn ghost small" data-module-import="${item.id}">导入</button>
          <button class="btn ghost small" data-module-collect="${item.id}">收集子域</button>
          <button class="btn ghost small" data-module-del="${item.id}">删除</button>
        </td>
      </tr>`).join("") : emptyRow(5, "还没有模块。新建一个，然后把手里的 xlsx / pdf / docx 导进来")}
    </tbody></table>`;

  $$("[data-module-open]").forEach((row) => row.addEventListener("click", (event) => {
    if (event.target.closest("button")) return;
    openModuleDetail(Number(row.dataset.moduleOpen));
  }));
  $$("[data-module-import]").forEach((btn) => btn.addEventListener("click", async (event) => {
    event.stopPropagation();
    await importIntoModule(Number(btn.dataset.moduleImport));
  }));
  $$("[data-module-collect]").forEach((btn) => btn.addEventListener("click", async (event) => {
    event.stopPropagation();
    await collectModule(Number(btn.dataset.moduleCollect), btn);
  }));
  $$("[data-module-del]").forEach((btn) => btn.addEventListener("click", async (event) => {
    event.stopPropagation();
    const moduleId = Number(btn.dataset.moduleDel);
    const target = (state.assetModules || []).find((item) => item.id === moduleId);
    if (!confirm(`确认删除模块「${target ? target.name : moduleId}」及其全部资产？`)) return;
    try {
      await api(`/api/asset-modules/${moduleId}`, { method: "DELETE" });
      toast("模块已删除");
      await loadAssetModules();
    } catch (error) { toast(error.message, "error"); }
  }));
}

function openNewModuleModal() {
  const today = new Date();
  const stamp = `${today.getFullYear()}${String(today.getMonth() + 1).padStart(2, "0")}${String(today.getDate()).padStart(2, "0")}`;
  const overlay = openModal({
    title: "新建资产模块",
    body: `
      <div class="form-grid">
        <label class="field"><span>模块名称</span>
          <input id="m-name" placeholder="例如 客户A-外网资产" value="">
        </label>
        <label class="field"><span>备注（可选）</span>
          <input id="m-note" placeholder="这批资产从哪来、给谁用">
        </label>
        <div class="notice">建好后把 xlsx / txt / pdf / docx / md 导进去，平台会认出域名和 IP，再按 DNS 收集三级子域名。名字里建议带上日期（例如 <code>${stamp}</code>），方便以后对比。</div>
      </div>`,
    footer: `<button class="btn ghost" id="m-cancel">取消</button><button class="btn primary" id="m-save">创建</button>`,
  });
  $("#m-cancel", overlay).addEventListener("click", () => overlay.remove());
  $("#m-save", overlay).addEventListener("click", async () => {
    const name = ($("#m-name", overlay).value || "").trim();
    if (!name) { toast("先给模块起个名字", "error"); return; }
    try {
      await api("/api/asset-modules", {
        method: "POST",
        body: { name, note: ($("#m-note", overlay).value || "").trim() },
      });
      overlay.remove();
      toast("模块已创建");
      await loadAssetModules();
    } catch (error) { toast(error.message, "error"); }
  });
}

async function importIntoModule(moduleId) {
  const files = await pickFiles({ accept: ".xlsx,.xls,.txt,.pdf,.docx,.md,.csv", multiple: true });
  if (!files.length) return;
  const useLlm = confirm("要不要顺带让大模型复核一遍抽取结果？\n\n确定 = 用大模型（慢一些，没接入模型时自动退回正则）\n取消 = 只用正则，最快");
  let okCount = 0, domainCount = 0, ipCount = 0;
  for (const file of files) {
    try {
      const result = await api(
        `/api/asset-modules/${moduleId}/import?use_llm=${useLlm ? "1" : "0"}`,
        {
          method: "POST",
          raw: true,
          body: file,
          headers: { "X-File-Name": encodeURIComponent(file.name) },
        }
      );
      okCount += 1;
      domainCount += result.domains || 0;
      ipCount += result.ips || 0;
      if (result.note) toast(result.note, "error");
    } catch (error) {
      toast(`${file.name}：${error.message}`, "error");
    }
  }
  toast(`导入 ${okCount}/${files.length} 个文件 · 域名 ${domainCount} · IP ${ipCount}`);
  await loadAssetModules();
}

async function collectModule(moduleId, btn = null) {
  if (!confirm(
    "开始收集子域名？\n\n" +
    "三条路一起走：常见前缀逐个解析、DNS 记录（MX/NS/TXT）里的线索、" +
    "证书透明日志（外网不通就自动跳过）。\n通常十几秒到一分钟。"
  )) return;
  const label = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "收集中…"; }
  toast("开始收集，稍等…");
  try {
    const result = await api(`/api/asset-modules/${moduleId}/collect?use_crt=1&guess=1`, { method: "POST" });
    const parts = [`试了 ${result.tried} 个候选`, `解析到 ${result.resolved}`, `新增 ${result.added}`];
    if (result.record) parts.push(`记录线索 ${result.record}`);
    if (result.crt) parts.push(`证书日志 ${result.crt}`);
    toast(`收集完成：${parts.join("，")}`);
    await loadAssetModules();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = label; }
  }
}

async function openModuleDetail(moduleId) {
  const overlay = openModal({
    title: "资产明细",
    wide: true,
    body: `<div class="module-detail"><div class="empty-state">正在加载…</div></div>`,
    footer: `<button class="btn ghost" id="md-import">导入文件</button>
             <button class="btn ghost" id="md-collect">收集子域名</button>
             <button class="btn" id="md-close">关闭</button>`,
  });
  $("#md-close", overlay).addEventListener("click", () => overlay.remove());
  $("#md-import", overlay).addEventListener("click", async () => {
    await importIntoModule(moduleId);
    overlay.remove();
  });
  $("#md-collect", overlay).addEventListener("click", async () => {
    overlay.remove();
    await collectModule(moduleId);
  });
  const paint = async (query = "", kind = "") => {
    const data = await api(
      `/api/asset-modules/${moduleId}/hosts?q=${encodeURIComponent(query)}&kind=${encodeURIComponent(kind)}&limit=800`
    );
    const module = data.module || {};
    $(".module-detail", overlay).innerHTML = `
      <div class="module-head">
        <div>
          <strong>${esc(module.name || "")}</strong>
          <span class="muted">建立于 ${esc(module.created_at || "")} · 共 ${data.total} 条资产</span>
        </div>
        <div class="actions">
          <input class="input" id="md-search" placeholder="搜域名 / IP" value="${esc(query)}" style="width:180px">
          <select class="input" id="md-kind" style="width:110px">
            <option value="">全部</option>
            <option value="domain" ${kind === "domain" ? "selected" : ""}>域名</option>
            <option value="ip" ${kind === "ip" ? "selected" : ""}>IP</option>
          </select>
        </div>
      </div>
      ${(module.sources || []).length ? `<div class="module-sources">${module.sources.map((src) => `
        <span class="chip" title="${esc(src.name)}">${esc(src.name)} · 域名 ${src.domains || 0} / IP ${src.ips || 0}</span>`).join(" ")}</div>` : ""}
      <div class="table-wrap">
        <table><thead><tr><th>资产</th><th>类型</th><th>解析到</th><th>归属主域</th><th>来源</th><th>发现时间</th></tr></thead>
        <tbody>
        ${data.items.length ? data.items.map((row) => `
          <tr>
            <td class="mono-cell">${esc(row.host)}</td>
            <td><span class="chip">${row.kind === "ip" ? "IP" : "域名"}</span></td>
            <td class="mono-cell">${esc(row.ip || "—")}</td>
            <td class="mono-cell">${esc(row.parent || "—")}</td>
            <td>${esc(SOURCE_LABELS[row.source] || row.source || "—")}</td>
            <td class="mono-cell">${esc(row.created_at)}</td>
          </tr>`).join("") : emptyRow(6, "这个模块还没有资产，先导入文件")}
        </tbody></table>
      </div>
      ${data.total > data.items.length ? `<div class="hint">只显示了前 ${data.items.length} 条，用上面的搜索缩小范围</div>` : ""}`;
    $("#md-search", overlay).addEventListener("keydown", (event) => {
      if (event.key === "Enter") paint(event.target.value.trim(), $("#md-kind", overlay).value);
    });
    $("#md-kind", overlay).addEventListener("change", (event) => {
      paint($("#md-search", overlay).value.trim(), event.target.value);
    });
  };

  try {
    await paint();
  } catch (error) {
    $(".module-detail", overlay).innerHTML = `<div class="empty-state">${esc(error.message)}</div>`;
  }
}

async function openCompareModal() {
  const data = await api("/api/asset-modules");
  const items = data.items || [];
  if (items.length < 2) {
    toast("至少要有两个模块才能对比", "error");
    return;
  }
  const options = items.map((item) => `<option value="${item.id}">${esc(item.name)}（${esc(item.created_at)}）</option>`).join("");
  const overlay = openModal({
    title: "对比两个模块",
    wide: true,
    body: `
      <div class="form-grid">
        <div class="grid-2" style="gap:12px">
          <label class="field"><span>较早的模块</span><select id="c-left">${options}</select></label>
          <label class="field"><span>较新的模块</span><select id="c-right">${options}</select></label>
        </div>
        <div class="notice">默认左边选较早的、右边选较新的；结果里的「新增」就是右边比左边多出来的域名。</div>
        <div id="c-result" class="compare-result"><div class="empty-state">点下面的「开始对比」</div></div>
      </div>`,
    footer: `<button class="btn ghost" id="c-close">关闭</button><button class="btn primary" id="c-run">开始对比</button>`,
  });
  const left = $("#c-left", overlay);
  const right = $("#c-right", overlay);
  left.value = String(items[items.length - 1].id);
  right.value = String(items[0].id);
  $("#c-close", overlay).addEventListener("click", () => overlay.remove());
  $("#c-run", overlay).addEventListener("click", async () => {
    try {
      const result = await api(`/api/asset-modules/compare?left=${left.value}&right=${right.value}`);
      const added = result.sample_added || [];
      $("#c-result", overlay).innerHTML = `
        <div class="compare-summary">
          <div><span>新增</span><strong class="up">${result.added.length}</strong></div>
          <div><span>消失</span><strong class="down">${result.removed.length}</strong></div>
          <div><span>两边都有</span><strong>${result.common_count}</strong></div>
          <div><span>左侧总数</span><strong>${result.left_count}</strong></div>
          <div><span>右侧总数</span><strong>${result.right_count}</strong></div>
        </div>
        ${added.length ? `<div class="compare-list"><div class="compare-list-title">新增域名（${result.added.length}）</div>
          ${added.map((host) => `<div class="compare-row"><span class="mono-cell">${esc(host)}</span></div>`).join("")}</div>`
          : `<div class="empty-state">右边没有比左边多出任何域名</div>`}
        ${result.removed.length ? `<div class="compare-list"><div class="compare-list-title">左边有、右边没了（${result.removed.length}）</div>
          ${result.removed.slice(0, 100).map((host) => `<div class="compare-row"><span class="mono-cell">${esc(host)}</span></div>`).join("")}</div>` : ""}`;
    } catch (error) { toast(error.message, "error"); }
  });
}

/* ---------------- K7so工具 ---------------- */
const KIT_LABELS = { python: "Python 脚本", exe: "Windows 程序", jar: "Java 包", go: "Go 程序" };

async function loadKits() {
  const data = await api("/api/kits");
  state.kits = data.items || [];
  $("#kit-hint").textContent = `${data.total} 个工具${data.running ? ` · ${data.running} 个在跑` : ""} · 目录 ${data.dir || ""}`;
  $("#kit-grid").innerHTML = state.kits.length ? state.kits.map((kit) => `
    <div class="kit-card ${kit.running ? "running" : ""}" data-kit="${kit.id}">
      <div class="kit-head">
        <strong>${esc(kit.name)}</strong>
        <span class="chip">${esc(KIT_LABELS[kit.kind] || kit.kind_label || kit.kind)}</span>
      </div>
      <div class="kit-meta">
        <span class="mono-cell">${esc(kit.filename)}</span>
        <span>${humanSize(kit.size)}</span>
      </div>
      ${kit.args ? `<div class="kit-meta dim"><span class="mono-cell">参数：${esc(kit.args)}</span></div>` : ""}
      <div class="kit-actions">
        <button class="btn primary small" data-kit-run="${kit.id}">${kit.running ? "在运行" : "运行"}</button>
        <button class="btn ghost small" data-kit-args="${kit.id}">参数</button>
        <button class="btn ghost small" data-kit-del="${kit.id}">删除</button>
      </div>
      ${kit.exists === false ? `<div class="kit-missing">文件不在了，重新导一次</div>` : ""}
    </div>`).join("") : `
    <div class="empty-state">还没有工具。点右上角「导入工具」把 py / exe / jar 放进来</div>`;

  $$("[data-kit-run]").forEach((btn) => btn.addEventListener("click", (event) => {
    event.stopPropagation();
    runKit(Number(btn.dataset.kitRun));
  }));
  $$("[data-kit-args]").forEach((btn) => btn.addEventListener("click", (event) => {
    event.stopPropagation();
    openKitArgs(Number(btn.dataset.kitArgs));
  }));
  $$("[data-kit-del]").forEach((btn) => btn.addEventListener("click", async (event) => {
    event.stopPropagation();
    const kit = (state.kits || []).find((item) => item.id === Number(btn.dataset.kitDel));
    if (!confirm(`确认删除工具「${kit ? kit.name : ""}」？文件也会一起删掉`)) return;
    try {
      await api(`/api/kits/${btn.dataset.kitDel}`, { method: "DELETE" });
      toast("工具已删除");
      await loadKits();
    } catch (error) { toast(error.message, "error"); }
  }));
}

async function importKits() {
  const files = await pickFiles({ accept: ".py,.exe,.jar", multiple: true });
  if (!files.length) return;
  const kind = $("#kit-kind").value || "";
  let ok = 0;
  for (const file of files) {
    try {
      await api(`/api/kits/upload?kind=${encodeURIComponent(kind)}`, {
        method: "POST",
        raw: true,
        body: file,
        headers: { "X-File-Name": encodeURIComponent(file.name) },
      });
      ok += 1;
    } catch (error) {
      toast(`${file.name}：${error.message}`, "error");
    }
  }
  toast(`已导入 ${ok}/${files.length} 个工具`);
  await loadKits();
}

let kitPollTimer = null;

function renderKitRun(kitName, run) {
  $("#kit-output-panel").classList.remove("hidden");
  $("#kit-output-title").textContent = `运行输出 · ${kitName}`;
  const running = run && run.status === "running";
  $("#kit-output-status").textContent = run
    ? `${running ? "运行中" : "已结束"}${run.returncode === null || run.returncode === undefined ? "" : ` · 退出码 ${run.returncode}`}${run.command ? ` · ${run.command}` : ""}`
    : "还没有运行记录";
  $("#kit-stop").classList.toggle("hidden", !running);
  const output = (run && run.output) || "";
  $("#kit-output").textContent = output || (running ? "（进程已启动，等待输出…）" : "（没有输出）");
}

async function runKit(kitId) {
  const kit = (state.kits || []).find((item) => item.id === kitId);
  try {
    const result = await api(`/api/kits/${kitId}/run`, { method: "POST" });
    toast(`已启动：${kit ? kit.name : kitId}`);
    $("#kit-output-panel").classList.remove("hidden");
    $("#kit-stop").dataset.kit = String(kitId);
    renderKitRun(kit ? kit.name : String(kitId), { status: "running", output: "", command: result.command });
    pollKitRun(result.run_id, kit ? kit.name : String(kitId), 0);
    await loadKits();
  } catch (error) { toast(error.message, "error"); }
}

async function pollKitRun(runId, kitName, tick) {
  if (kitPollTimer) clearTimeout(kitPollTimer);
  try {
    const data = await api(`/api/kits/runs/${runId}`);
    renderKitRun(kitName, data.run);
    if (data.run && data.run.status === "running" && tick < 240) {
      // 前 20 秒看紧一点，之后降频，GUI 程序开着也不至于一直刷接口
      const delay = tick < 20 ? 1000 : 3000;
      kitPollTimer = setTimeout(() => pollKitRun(runId, kitName, tick + 1), delay);
      return;
    }
    if (data.run && data.run.status !== "running") await loadKits();
  } catch (error) {
    // 工具可能瞬间退出、记录还没落库，停一会儿再试一次
    if (tick < 10) {
      kitPollTimer = setTimeout(() => pollKitRun(runId, kitName, tick + 1), 1200);
    }
  }
}

function openKitArgs(kitId) {
  const kit = (state.kits || []).find((item) => item.id === kitId);
  if (!kit) return;
  const overlay = openModal({
    title: "工具参数",
    body: `
      <div class="form-grid">
        <label class="field"><span>显示名称</span><input id="k-name" value="${esc(kit.name)}"></label>
        <label class="field"><span>启动参数（会被原样拼在命令后面）</span>
          <input id="k-args" value="${esc(kit.args || "")}" placeholder="例如 --target example.com -o out.txt">
        </label>
        <label class="field"><span>类型</span>
          <select id="k-kind">
            ${Object.entries(KIT_LABELS).map(([key, label]) => `<option value="${key}" ${kit.kind === key ? "selected" : ""}>${label}</option>`).join("")}
          </select>
        </label>
        <div class="notice">Python 用平台自带解释器跑；JAR 需要机器上有 java；EXE / Go 直接执行。工作目录是工具所在目录。</div>
      </div>`,
    footer: `<button class="btn ghost" id="k-cancel">取消</button><button class="btn primary" id="k-save">保存</button>`,
  });
  $("#k-cancel", overlay).addEventListener("click", () => overlay.remove());
  $("#k-save", overlay).addEventListener("click", async () => {
    try {
      await api(`/api/kits/${kitId}`, {
        method: "PATCH",
        body: {
          name: $("#k-name", overlay).value.trim(),
          args: $("#k-args", overlay).value.trim(),
          kind: $("#k-kind", overlay).value,
        },
      });
      overlay.remove();
      toast("已保存");
      await loadKits();
    } catch (error) { toast(error.message, "error"); }
  });
}

$("#asset-module-new").addEventListener("click", openNewModuleModal);
$("#asset-compare").addEventListener("click", () => openCompareModal().catch((error) => toast(error.message, "error")));
$("#kit-upload").addEventListener("click", () => importKits().catch((error) => toast(error.message, "error")));
$("#kit-stop").addEventListener("click", async () => {
  const kitId = Number($("#kit-stop").dataset.kit || 0);
  if (!kitId) return;
  try {
    await api(`/api/kits/${kitId}/stop`, { method: "POST" });
    toast("已发送停止指令");
    await loadKits();
  } catch (error) { toast(error.message, "error"); }
});
$("#dash-new-scan").addEventListener("click", openNewScanModal);
$("#dash-refresh").addEventListener("click", () => navigate("dashboard"));

/* ---------------- scans ---------------- */
// 「渗透测试」页已经换成 K7so工具页，这里只剩仪表盘还要用的详情弹窗。
// 没有表格元素时直接返回，避免旧入口被误调用时整页脚本崩掉。
async function loadScans() {
  if (!$("#scan-table")) return;
  state.scans = await api("/api/scans");
  $("#scan-table").innerHTML = `
    <table><thead><tr><th>#</th><th>作业</th><th>方式 / 强度</th><th>目标</th><th>状态</th><th>进度</th><th>风险</th><th>创建时间</th><th></th></tr></thead>
    <tbody>
    ${state.scans.length ? state.scans.map((scan) => `
      <tr>
        <td class="mono-cell">${scan.id}</td>
        <td class="td-title"><strong>${esc(scan.name)}</strong><small>${esc(scan.stage || "")}</small></td>
        <td><span class="chip">${esc(modeLabel(scan.mode))}</span> <span class="chip">${esc(profileLabel(scan.profile))}</span></td>
        <td class="mono-cell">${scan.targets.length}</td>
        <td>${statusBadge(scan.status)}</td>
        <td>${progressBar(scan.progress)}</td>
        <td class="mono-cell">${scan.finding_count || 0}</td>
        <td class="mono-cell">${esc(fmtTime(scan.created_at))}</td>
        <td class="row-actions">
          <button class="btn ghost small" data-scan-view="${scan.id}">详情</button>
          ${["queued", "running"].includes(scan.status) ? `<button class="btn ghost small" data-scan-cancel="${scan.id}">取消</button>` : ""}
        </td>
      </tr>`).join("") : emptyRow(9, "暂无渗透测试作业，点击右上角新建渗透测试")}
    </tbody></table>`;
  $$("[data-scan-view]").forEach((btn) => btn.addEventListener("click", () => openScanDetail(Number(btn.dataset.scanView))));
  $$("[data-scan-cancel]").forEach((btn) => btn.addEventListener("click", async () => {
    try {
      await api(`/api/scans/${btn.dataset.scanCancel}/cancel`, { method: "POST" });
      toast("已提交取消请求");
      await loadScans();
    } catch (error) { toast(error.message, "error"); }
  }));
}

async function openNewScanModal() {
  if (!state.assets.length) {
    try {
      state.assets = await api("/api/assets");
    } catch (error) {
      toast(error.message, "error");
      return;
    }
  }
  const overlay = openModal({
    title: "新建渗透测试",
    wide: true,
    body: `
      <div class="form-grid">
        <label class="field"><span>作业名称（可选）</span><input id="f-name" placeholder="例如 外网暴露面测试"></label>
        <div class="grid-2" style="gap:12px">
          <label class="field"><span>模式</span>
            <select id="f-mode">
              <option value="active">完整渗透测试（测绘 + 端口 + 模板 + AI）</option>
              <option value="passive">仅情报测绘（调用已配置的数据源）</option>
            </select>
          </label>
          <label class="field"><span>强度</span>
            <select id="f-profile">
              <option value="quick">快速</option>
              <option value="standard" selected>标准</option>
              <option value="deep">深度</option>
            </select>
          </label>
        </div>
        <label class="field"><span>手动目标（每行一个，可混合域名 / IP / URL）</span>
          <textarea id="f-targets" rows="4" placeholder="example.com&#10;https://app.example.com"></textarea>
        </label>
        <label class="field"><span>从资产台账选择</span>
          <div class="asset-picker" id="f-assets">
            ${state.assets.length ? state.assets.map((asset) => `
              <label class="picker-item"><input type="checkbox" value="${asset.id}">
                <span>${esc(asset.name)}</span><em>${esc(asset.target)}</em></label>`).join("") : `<span class="muted">资产台账为空</span>`}
          </div>
        </label>
        <div class="notice">授权已在登录免责声明中确认，无需填写编号。开始前会执行范围校验：目标需落在「平台设置」的授权域名 / 网段内；平台默认排除 DoS、爆破与侵入型模板。</div>
      </div>`,
    footer: `<button class="btn ghost" id="f-cancel">取消</button><button class="btn primary" id="f-start">开始测试</button>`,
  });
  $("#f-cancel", overlay).addEventListener("click", () => overlay.remove());
  $("#f-start", overlay).addEventListener("click", async () => {
    const assetIds = $$("#f-assets input:checked", overlay).map((input) => Number(input.value));
    const targets = $("#f-targets", overlay).value.split("\n").map((line) => line.trim()).filter(Boolean);
    if (!assetIds.length && !targets.length) { toast("请选择资产或填写目标", "error"); return; }
    try {
      const data = await api("/api/scans", {
        method: "POST",
        body: {
          name: $("#f-name", overlay).value.trim(),
          asset_ids: assetIds,
          targets,
          profile: $("#f-profile", overlay).value,
          mode: $("#f-mode", overlay).value,
        },
      });
      overlay.remove();
      toast(`渗透测试作业 #${data.id} 已加入队列`);
      if (state.page === "scans") await loadScans();
      navigate("scans");
      setTimeout(() => openScanDetail(data.id), 600);
    } catch (error) { toast(error.message, "error"); }
  });
}

async function openScanDetail(scanId) {
  try {
    const detail = await api(`/api/scans/${scanId}`);
    state.detail = detail;
    state.activeTab = "overview";
    renderScanDrawer();
    startStream(scanId);
  } catch (error) { toast(error.message, "error"); }
}

function renderScanDrawer() {
  const detail = state.detail;
  if (!detail) return;
  const root = $("#modal-root");
  const stats = detail.stats || {};
  const recon = stats.recon || {};
  const findings = detail.findings || [];
  const probes = stats.probes || [];
  const ports = stats.ports || [];

  const overview = `
    <div class="kv-grid">
      <div class="kv"><label>目标数量</label><strong>${detail.targets.length}</strong></div>
      <div class="kv"><label>开放端口</label><strong>${ports.length}</strong></div>
      <div class="kv"><label>Nuclei 命中</label><strong>${stats.nuclei || 0}</strong></div>
      <div class="kv"><label>风险项</label><strong>${(detail.severity.critical || 0) + (detail.severity.high || 0) + (detail.severity.medium || 0) + (detail.severity.low || 0) + (detail.severity.info || 0)}</strong></div>
      <div class="kv"><label>AI 研判</label><strong>${stats.ai ? "ON" : "OFF"}</strong></div>
      <div class="kv"><label>耗时</label><strong>${stats.duration ? `${stats.duration}s` : "—"}</strong></div>
    </div>
    <div class="detail-section">
      <label>执行摘要</label>
      <div class="summary-box">${esc(detail.summary || "暂无摘要")}</div>
    </div>
    <div class="detail-section">
      <label>目标列表</label>
      <div class="summary-box">${esc(detail.targets.join("\n"))}</div>
    </div>
    <div class="detail-section">
      <label>资产测绘来源</label>
      <div class="connector-health">
        ${Object.keys(recon.sources || {}).length ? Object.entries(recon.sources).map(([key, count]) => `<span class="health-chip configured"><span class="dot"></span>${esc(key)} · ${count}</span>`).join("") : `<span class="muted">未调用或未配置测绘 API</span>`}
      </div>
    </div>
    <div class="detail-section">
      <label>HTTP 探测（前 30 条）</label>
      <div class="table-wrap"><table><thead><tr><th>URL</th><th>状态</th><th>标题</th><th>Server</th></tr></thead><tbody>
        ${probes.length ? probes.slice(0, 30).map((probe) => `<tr><td class="mono-cell">${esc(probe.url)}</td><td class="mono-cell">${esc(probe.status || probe.error)}</td><td>${esc(probe.title || "")}</td><td class="mono-cell">${esc(probe.server || "")}</td></tr>`).join("") : emptyRow(4, "无探测数据")}
      </tbody></table></div>
    </div>
    <div class="detail-section">
      <label>开放端口（前 40 条）</label>
      <div class="table-wrap"><table><thead><tr><th>主机</th><th>端口</th><th>服务</th></tr></thead><tbody>
        ${ports.length ? ports.slice(0, 40).map((port) => `<tr><td class="mono-cell">${esc(port.host)}</td><td class="mono-cell">${esc(port.port)}</td><td>${esc(port.product || port.service || "")}</td></tr>`).join("") : emptyRow(3, "无开放端口")}
      </tbody></table></div>
    </div>`;

  const logs = `<div class="log" id="detail-log">${(detail.logs || []).map(logLine).join("")}</div>`;
  const findingsHtml = `
    <div class="table-wrap"><table><thead><tr><th>等级</th><th>风险</th><th>来源</th><th>状态</th></tr></thead><tbody>
      ${findings.length ? findings.map((item) => `<tr class="clickable" data-detail-finding="${item.id}">
        <td>${sevBadge(item.severity)}</td>
        <td class="td-title"><strong>${esc(item.title)}</strong><small>${esc(item.target)}</small></td>
        <td class="mono-cell">${esc(item.source)}</td>
        <td><span class="chip">${esc(item.category || "—")}</span></td>
      </tr>`).join("") : emptyRow(4, "暂无风险项")}
    </tbody></table></div>`;

  root.innerHTML = `
    <div class="drawer-backdrop">
      <div class="drawer-panel">
        <div class="drawer-head">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
            <div>
              <h2>${esc(detail.name)}</h2>
              <div class="meta">
                <span>#${detail.id}</span>${statusBadge(detail.status)}
                <span>${esc(modeLabel(detail.mode))} · 强度 ${esc(profileLabel(detail.profile))}</span>
                <span>${esc(fmtTime(detail.created_at))}</span>
                <span>授权依据：${esc(detail.authorization_ref || "登录免责声明")}</span>
              </div>
            </div>
            <button class="modal-close" id="drawer-close">×</button>
          </div>
          <div style="margin-top:14px" id="drawer-progress">${progressBar(detail.progress)}</div>
          <div class="hint" id="drawer-stage" style="margin-top:6px">${esc(detail.stage || "")}</div>
        </div>
        <div class="drawer-body">
          <div class="tabs">
            <button class="tab active" data-tab="overview">概览</button>
            <button class="tab" data-tab="logs">执行日志</button>
            <button class="tab" data-tab="findings">风险项 ${findings.length}</button>
          </div>
          <div id="tab-body"></div>
        </div>
        <div class="drawer-foot">
          <button class="btn ghost" id="drawer-cancel">终止测试</button>
          <button class="btn ghost" id="drawer-json">导出 JSON</button>
          <button class="btn ghost" id="drawer-csv">导出 CSV</button>
        </div>
      </div>
    </div>`;

  const tabBody = $("#tab-body");
  const tabs = { overview, logs, findings: findingsHtml };
  function showTab(name) {
    state.activeTab = name;
    tabBody.innerHTML = tabs[name];
    $$(".tab", root).forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
    if (name === "logs") {
      const logEl = $("#detail-log");
      if (logEl) logEl.scrollTop = logEl.scrollHeight;
    }
    $$("[data-detail-finding]", tabBody).forEach((row) => row.addEventListener("click", () => openFinding(Number(row.dataset.detailFinding))));
  }
  showTab("overview");
  $$(".tab", root).forEach((tab) => tab.addEventListener("click", () => showTab(tab.dataset.tab)));
  $("#drawer-close").addEventListener("click", closeDrawer);
  $(".drawer-backdrop", root).addEventListener("click", (event) => {
    if (event.target.classList.contains("drawer-backdrop")) closeDrawer();
  });
  $("#drawer-cancel").addEventListener("click", async () => {
    try {
      await api(`/api/scans/${detail.id}/cancel`, { method: "POST" });
      toast("已提交取消请求");
    } catch (error) { toast(error.message, "error"); }
  });
  $("#drawer-json").addEventListener("click", () => window.open(`/api/scans/${detail.id}/export?format=json`, "_blank"));
  $("#drawer-csv").addEventListener("click", () => window.open(`/api/scans/${detail.id}/export?format=csv`, "_blank"));
}

function logLine(item) {
  return `<div class="log-line ${esc(item.level || "info")}"><time>${esc((item.ts || "").slice(11))}</time><span class="lv">${esc(item.level || "info")}</span><span class="msg">${esc(item.message)}</span></div>`;
}

function startStream(scanId) {
  stopStream();
  const stream = new EventSource(`/api/scans/${scanId}/stream`);
  state.stream = stream;
  stream.onmessage = (event) => {
    let payload;
    try { payload = JSON.parse(event.data); } catch (error) { return; }
    if (state.detail && state.detail.id !== scanId) return;
    if (payload.type === "log") {
      const logEl = $("#detail-log");
      if (logEl) {
        logEl.insertAdjacentHTML("beforeend", logLine(payload));
        logEl.scrollTop = logEl.scrollHeight;
      }
    } else if (payload.type === "progress" && state.detail) {
      state.detail.progress = payload.progress;
      state.detail.stage = payload.stage;
      const bar = $("#drawer-progress");
      if (bar) bar.innerHTML = progressBar(payload.progress);
      const stage = $("#drawer-stage");
      if (stage) stage.textContent = payload.stage || "";
    } else if (payload.type === "state" && state.detail) {
      state.detail.status = payload.status;
    } else if (payload.type === "done") {
      stream.close();
      state.stream = null;
      if (state.detail && state.detail.id === scanId) {
        setTimeout(async () => {
          try {
            const detail = await api(`/api/scans/${scanId}`);
            state.detail = detail;
            renderScanDrawer();
          } catch (error) { /* ignore */ }
          if (state.page === "scans") loadScans().catch(() => {});
        }, 400);
      }
    }
  };
  stream.onerror = () => { /* EventSource 自动重连 */ };
}

$("#scan-refresh")?.addEventListener("click", () => loadScans().catch((error) => toast(error.message, "error")));

/* ---------------- findings ---------------- */
function findingUrl(item) {
  if (item.url) return item.url;
  const target = item.target || "";
  if (/^https?:\/\//i.test(target)) return target;
  return target || "未标注 URL";
}

function findingExplanation(item) {
  return [item.description, item.evidence]
    .filter((part) => part && part !== "—")
    .join("\n\n") || "—";
}

function domainSevChips(group) {
  return ["critical", "high", "medium", "low", "info"]
    .filter((key) => Number(group[key] || 0) > 0)
    .map((key) => `<span class="domain-sev sev-${key}">${SEV_LABELS[key]} ${group[key]}</span>`)
    .join("");
}

function findingRows(items) {
  return items.map((item, index) => `
        <tr class="clickable finding-row" data-finding="${item.id}">
          <td class="mono-cell">${String(index + 1).padStart(2, "0")}</td>
          <td class="td-title"><strong>${esc(item.title)}</strong></td>
          <td class="mono-cell">${esc(fmtTime(item.created_at))}</td>
          <td>${sevBadge(item.severity)}</td>
        </tr>
        <tr class="finding-expand hidden" data-expand="${item.id}">
          <td colspan="4">
            <div class="finding-expand-body">
              <div class="detail-section"><label>漏洞 URL</label><p class="mono">${esc(findingUrl(item))}</p></div>
              <div class="detail-section"><label>文字解释</label><p>${esc(findingExplanation(item))}</p></div>
              <div class="detail-section"><label>请求包</label><pre class="packet">${esc(item.request_packet || "—")}</pre></div>
              <div class="detail-section"><label>响应包</label><pre class="packet">${esc(item.response_packet || "—")}</pre></div>
            </div>
          </td>
        </tr>`).join("");
}

// 以域名为单位：一个站点一段，先看这家有几个洞、什么等级，再决定展开哪一条
function renderFindingGroups(groups) {
  return groups.map((group, index) => `
    <div class="domain-group" data-domain-group="${esc(group.domain)}">
      <button class="domain-head ${index === 0 ? "open" : ""}" data-domain-toggle>
        <span class="domain-caret">›</span>
        <span class="domain-name mono">${esc(group.domain)}</span>
        <span class="domain-total">${group.total} 条</span>
        <span class="domain-sevs">${domainSevChips(group) || `<span class="domain-sev sev-info">提示 ${group.total}</span>`}</span>
        <span class="domain-latest mono">${group.latest ? esc(fmtTime(group.latest)) : "—"}</span>
      </button>
      <div class="domain-body ${index === 0 ? "" : "hidden"}">
        <table class="finding-list">
          <thead><tr>
            <th class="col-idx">序号</th>
            <th>漏洞标题</th>
            <th class="col-time">输出时间</th>
            <th class="col-sev">危害程度</th>
          </tr></thead>
          <tbody>${findingRows(group.findings || [])}</tbody>
        </table>
      </div>
    </div>`).join("");
}

async function loadFindings(options = {}) {
  const params = new URLSearchParams();
  const severity = $("#finding-severity").value;
  const query = $("#finding-search").value.trim();
  if (severity) params.set("severity", severity);
  if (query) params.set("q", query);
  params.set("source", "ai-agent");
  const groups = (await api(`/api/findings/domains?${params.toString()}`)) || [];
  state.findingGroups = groups;
  state.findings = groups.flatMap((group) => group.findings || []);
  const total = state.findings.length;
  $("#finding-count").textContent = total
    ? `${groups.length} 个域名 · 共 ${total} 条漏洞`
    : "共 0 条漏洞";
  $("#finding-table").innerHTML = groups.length
    ? renderFindingGroups(groups)
    : `<div class="empty-state" style="padding:26px 16px">暂无大模型输出的漏洞</div>`;
  $$("#finding-table [data-domain-toggle]").forEach((head) => head.addEventListener("click", () => {
    const body = head.nextElementSibling;
    if (!body) return;
    body.classList.toggle("hidden");
    head.classList.toggle("open", !body.classList.contains("hidden"));
  }));
  $$("#finding-table tr[data-finding]").forEach((row) => row.addEventListener("click", () => {
    const detail = $(`#finding-table tr[data-expand="${row.dataset.finding}"]`);
    detail.classList.toggle("hidden");
    row.classList.toggle("expanded", !detail.classList.contains("hidden"));
  }));
  if (options.quiet) return;
}

async function openFinding(findingId) {
  try {
    const finding = await api(`/api/findings/${findingId}`);
    const owner = finding.scan_id ? (finding.scan_name || `测试 #${finding.scan_id}`) : "AI 对话归档";
    const overlay = openModal({
      title: `漏洞报告 #${finding.id}`,
      wide: true,
      body: `
        <div class="finding-detail">
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            ${sevBadge(finding.severity)}<span class="chip">${esc(finding.category || "—")}</span>
            <span class="chip">CVSS ${esc(finding.cvss || 0)}</span><span class="chip">${esc(finding.source)}</span>
          </div>
          <h2 style="margin-top:14px">${esc(finding.title)}</h2>
          <div class="kv-grid">
            <div class="kv"><label>漏洞 URL</label><strong style="font-size:11px">${esc(findingUrl(finding))}</strong></div>
            <div class="kv"><label>归属</label><strong style="font-size:11px">${esc(owner)}</strong></div>
            <div class="kv"><label>危害程度</label><strong>${esc(SEV_LABELS[finding.severity] || finding.severity)}</strong></div>
            <div class="kv"><label>测试能力</label><strong style="font-size:11px">${esc(finding.capability || finding.category || "—")}</strong></div>
            <div class="kv"><label>置信度</label><strong>${esc(finding.confidence || "—")}</strong></div>
            <div class="kv"><label>发现时间</label><strong style="font-size:11px">${esc(fmtTime(finding.created_at))}</strong></div>
          </div>
          <div class="detail-section"><label>漏洞描述</label><p>${esc(finding.description || "—")}</p></div>
          <div class="detail-section"><label>验证依据</label><pre>${esc(finding.evidence || "—")}</pre></div>
          <div class="detail-section"><label>复现请求包</label><pre class="packet">${esc(finding.request_packet || "—")}</pre></div>
          <div class="detail-section"><label>复现响应包</label><pre class="packet">${esc(finding.response_packet || "—")}</pre></div>
          <div class="detail-section"><label>修复建议</label><p>${esc(finding.remediation || "—")}</p></div>
        </div>`,
      footer: `<button class="btn ghost" id="finding-close">关闭</button>`,
    });
    $("#finding-close", overlay).addEventListener("click", () => overlay.remove());
  } catch (error) { toast(error.message, "error"); }
}

$("#finding-severity").addEventListener("change", () => loadFindings().catch((e) => toast(e.message, "error")));
$("#finding-search").addEventListener("keydown", (event) => { if (event.key === "Enter") loadFindings().catch((e) => toast(e.message, "error")); });

/* ---------------- connectors ---------------- */
function aiConnectors() {
  return state.connectors.filter((item) => item.category === "ai");
}

async function loadConnectors() {
  state.connectors = await api("/api/connectors");
  const ai = aiConnectors();
  const ready = ai.filter((item) => item.configured && item.enabled).length;
  $("#connector-summary").textContent = `${ready} / ${ai.length} 个大模型可用`;
  renderLlmList(ai);
  initLlmForm(ai);

  const others = state.connectors.filter((item) => item.category !== "ai");
  $("#connector-groups").innerHTML = CATEGORY_ORDER.filter((category) => category !== "ai").map((category) => {
    const items = others.filter((item) => item.category === category);
    if (!items.length) return "";
    return `<div class="group-title">${esc(items[0].category_label || category)}</div>
      <div class="connector-grid">${items.map(connectorCard).join("")}</div>`;
  }).join("");
  $$("[data-conn-test]").forEach((btn) => btn.addEventListener("click", () => testConnector(btn.dataset.connTest, btn)));
  $$("[data-conn-remove]").forEach((btn) => btn.addEventListener("click", async () => {
    const connector = state.connectors.find((item) => item.key === btn.dataset.connRemove);
    const name = connector ? connector.name : "该连接器";
    if (!confirm(`确认移除「${name}」的接入？托管的密钥会被删除，之后要重新填写才能再用。`)) return;
    btn.disabled = true;
    try {
      await api(`/api/connectors/${btn.dataset.connRemove}`, { method: "DELETE" });
      toast("已移除接入");
      await loadConnectors();
    } catch (error) { toast(error.message, "error"); btn.disabled = false; }
  }));
  $$("[data-conn-config]").forEach((btn) => btn.addEventListener("click", () => {
    const connector = state.connectors.find((item) => item.key === btn.dataset.connConfig);
    if (connector) openConnectorModal(connector);
  }));
  $$("[data-conn-doc]").forEach((btn) => btn.addEventListener("click", () => {
    const connector = state.connectors.find((item) => item.key === btn.dataset.connDoc);
    if (connector && connector.docs_url) window.open(connector.docs_url, "_blank");
  }));
}

function initLlmForm(ai) {
  const select = $("#llm-type");
  const options = ai.map((item) => (
    `<option value="${esc(item.key)}">${esc(item.name)}</option>`
  )).join("");
  // 选项内容变了就重建：自定义模型改过「显示名称」后，下拉里也要跟着变
  if (select.dataset.ready !== "1" || select.innerHTML !== options) {
    const keep = select.value || state.llmKey || "";
    select.innerHTML = options;
    if (keep && ai.some((item) => item.key === keep)) select.value = keep;
  }
  if (!select.dataset.ready) {
    select.dataset.ready = "1";
    select.addEventListener("change", () => fillLlmForm());
    $("#llm-save").addEventListener("click", () => saveLlmForm());
    $("#llm-test").addEventListener("click", () => testLlmForm());
  }
  if (state.llmKey && ai.some((item) => item.key === state.llmKey)) select.value = state.llmKey;
  fillLlmForm(ai);
}

function fillLlmForm(ai = aiConnectors()) {
  const key = $("#llm-type").value;
  const connector = ai.find((item) => item.key === key);
  if (!connector) return;
  state.llmKey = key;
  // 「自定义模型」没有预置地址：地址、模型名、显示名称都要用户自己填，内网网关还可以不填 Key
  const custom = key === "custom";
  const labelField = $("#llm-label-field");
  if (labelField) labelField.hidden = !custom;
  if ($("#llm-label")) $("#llm-label").value = custom ? String((connector.config && connector.config.label) || "") : "";
  $("#llm-model").value = (connector.config && connector.config.model) || "";
  $("#llm-model").placeholder = connector.fields.find((field) => field.key === "model")?.placeholder || "";
  $("#llm-base").value = connector.base_url || "";
  $("#llm-base").placeholder = custom
    ? "https://你的网关地址/v1"
    : "https://api.deepseek.com";
  $("#llm-key").value = "";
  $("#llm-key").placeholder = connector.configured
    ? `已配置 ${connector.secret_masked || "已托管"}，留空保持不变`
    : custom ? "内网网关免鉴权可留空" : "请输入 API Key";
  const keyLabel = connector.secret_masked
    ? `KEY ${connector.secret_masked}`
    : connector.secret_required ? "KEY 已托管" : "免密钥";
  $("#llm-status").textContent = [
    connector.configured
      ? `已配置 · ${keyLabel}`
      : custom ? "未配置，填好 Base URL 与模型名称后保存" : "未配置，填写 KEY 后保存",
    connector.last_check_msg || (connector.configured ? "尚未检测" : ""),
  ].filter(Boolean).join(" · ");
  // 免密钥的模型（自定义 / 本地）填完地址就能测，不必等一个 Key
  const noSecret = !connector.secret_required;
  $("#llm-test").disabled = !connector.configured && !noSecret;
}

function llmFormBody() {
  const key = $("#llm-type").value;
  const model = $("#llm-model").value.trim();
  const baseUrl = $("#llm-base").value.trim();
  const secret = $("#llm-key").value.trim();
  if (!key) throw new Error("请先选择大模型类型");
  const body = { enabled: true, config: { model } };
  if (key === "custom") {
    // 自定义模型没有预置值，漏填就会连到空地址：这里先拦住，别等检测时才报「连不上 」
    if (!baseUrl) throw new Error("自定义模型必须填写 Base URL（例如 https://gateway.example.com/v1）");
    if (!model) throw new Error("自定义模型必须填写模型名称（网关里的模型 ID）");
    body.config.label = ($("#llm-label")?.value || "").trim();
  }
  if (baseUrl) body.base_url = baseUrl;
  if (secret) body.secret = secret;
  return { key, body };
}

async function saveLlmForm(ai = aiConnectors()) {
  try {
    const { key, body } = llmFormBody();
    const result = await api(`/api/connectors/${key}`, { method: "PUT", body });
    const connector = (ai || []).find((item) => item.key === key);
    const masked = result && result.secret_masked ? ` · KEY ${result.secret_masked}` : "";
    toast(`${connector ? connector.name : key} 配置已保存${masked}`);
    await loadConnectors();
  } catch (error) { toast(error.message, "error"); }
}

async function testLlmForm(ai = aiConnectors()) {
  const button = $("#llm-test");
  const original = button.textContent;
  try {
    await saveLlmForm(ai);
    const key = $("#llm-type").value;
    button.disabled = true;
    button.textContent = "检测中...";
    const result = await api(`/api/connectors/${key}/test`, { method: "POST" });
    toast(result.message, result.ok ? "" : "error");
    await loadConnectors();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderLlmList(ai) {
  // 列表收「已保存」的：保存过但没检测的自定义模型也要出现，标成「未检测」就行
  const configured = ai.filter((item) => item.saved || item.configured);
  if (!configured.length) {
    $("#llm-list").innerHTML = `<table><tbody>${emptyRow(1, "尚未配置大模型，请在上方填写后保存")}</tbody></table>`;
    return;
  }
  $("#llm-list").innerHTML = `
    <table><thead><tr><th>名称 / 类型</th><th>模型</th><th>Base URL</th><th>API Key</th><th>状态</th><th></th></tr></thead><tbody>
    ${configured.map((item) => {
      let statusText = item.enabled ? "未检测" : "已停用";
      if (item.enabled && item.last_check_ok === 1) statusText = "连接正常";
      if (item.enabled && item.last_check_ok === 0) statusText = "连接失败";
      return `<tr>
        <td class="td-title"><strong>${esc(item.name)}</strong><small>${esc(item.vendor)}</small></td>
        <td class="mono-cell">${esc((item.config && item.config.model) || "—")}</td>
        <td class="mono-cell">${esc(item.base_url || "—")}</td>
        <td class="mono-cell key-cell" title="已脱敏展示，完整密钥只在服务端解密使用">${esc(item.secret_masked || (item.secret_required ? (item.configured ? "已托管" : "—") : "免密钥"))}</td>
        <td><span class="status-dot ${item.last_check_ok === 1 ? "ok" : item.last_check_ok === 0 ? "fail" : "unknown"}"></span>${statusText}</td>
        <td class="row-actions">
          <button class="btn ghost small" data-llm-test="${esc(item.key)}">检测</button>
          <button class="btn ghost small" data-llm-off="${esc(item.key)}">停用</button>
          ${item.configured ? `<button class="btn ghost small danger" data-llm-remove="${esc(item.key)}">移除</button>` : ""}
        </td>
      </tr>`;
    }).join("")}
    </tbody></table>`;
  $$("[data-llm-test]").forEach((btn) => btn.addEventListener("click", async () => {
    const key = btn.dataset.llmTest;
    btn.disabled = true;
    try {
      const result = await api(`/api/connectors/${key}/test`, { method: "POST" });
      toast(result.message, result.ok ? "" : "error");
      await loadConnectors();
    } catch (error) { toast(error.message, "error"); } finally { btn.disabled = false; }
  }));
  $$("[data-llm-off]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("确认停用该大模型？停用后不会出现在对话的模型列表中。")) return;
    try {
      await api(`/api/connectors/${btn.dataset.llmOff}`, { method: "PUT", body: { enabled: false } });
      toast("已停用");
      await loadConnectors();
    } catch (error) { toast(error.message, "error"); }
  }));
  $$("[data-llm-remove]").forEach((btn) => btn.addEventListener("click", async () => {
    if (!confirm("确认移除该大模型的接入？托管的密钥会被删除，之后要重新填写才能再用。")) return;
    try {
      await api(`/api/connectors/${btn.dataset.llmRemove}`, { method: "DELETE" });
      toast("已移除接入");
      await loadConnectors();
    } catch (error) { toast(error.message, "error"); }
  }));
}

function connectorCard(connector) {
  let dotCls = "unknown", statusText = connector.enabled ? "未检测" : "已停用";
  if (connector.enabled && connector.last_check_ok === 1) { dotCls = "ok"; statusText = "连接正常"; }
  if (connector.enabled && connector.last_check_ok === 0) { dotCls = "fail"; statusText = "连接失败"; }
  const meta = [
    `<span class="chip">${esc(connector.category_label)}</span>`,
    `<span class="chip">${esc(connector.auth_type)}</span>`,
    connector.secret_required ? `<span class="chip">${connector.configured ? `密钥 ${esc(connector.secret_masked || "已托管")}` : "未配置密钥"}</span>` : "",
  ].join("");
  return `
    <div class="connector-card ${connector.enabled ? "enabled" : ""}">
      <div class="conn-head">
        <div><strong>${esc(connector.name)}</strong><small>${esc(connector.vendor)}</small></div>
        <span class="conn-status ${dotCls}"><span class="status-dot ${dotCls}"></span>${statusText}</span>
      </div>
      <div class="conn-desc">${esc(connector.description)}</div>
      <div class="conn-meta">${meta}</div>
      <div class="conn-status ${connector.last_check_ok === 1 ? "ok" : ""}">${esc(connector.last_check_msg || "尚未执行连通性检测")}</div>
      <div class="conn-actions">
        <button class="btn ghost small" data-conn-config="${connector.key}">配置</button>
        <button class="btn ghost small" data-conn-test="${connector.key}">检测</button>
        ${connector.configured ? `<button class="btn ghost small danger" data-conn-remove="${connector.key}">移除</button>` : ""}
        ${connector.docs_url ? `<button class="btn ghost small" data-conn-doc="${connector.key}">文档</button>` : ""}
      </div>
    </div>`;
}

async function testConnector(key, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "检测中...";
  try {
    const result = await api(`/api/connectors/${key}/test`, { method: "POST" });
    toast(result.message, result.ok ? "" : "error");
    await loadConnectors();
  } catch (error) {
    toast(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function openConnectorModal(connector) {
  const isCLI = connector.auth_type === "cli";
  const fieldHtml = connector.fields.length ? connector.fields.map((field) => `
    <label class="field"><span>${esc(field.label)}</span>
      <input data-cfg="${esc(field.key)}" value="${esc(connector.config[field.key] ?? field.default ?? "")}" placeholder="${esc(field.placeholder || "")}">
    </label>`).join("") : "";
  const overlay = openModal({
    title: `配置 · ${connector.name}`,
    body: `
      <div class="form-grid">
        <div class="notice">${esc(connector.description)}</div>
        ${isCLI ? "" : `<label class="field"><span>Base URL</span><input id="c-base" value="${esc(connector.base_url)}"></label>`}
        ${fieldHtml}
        ${isCLI ? "" : `<label class="field"><span>${esc(connector.secret_label || "密钥")}</span>
          <input id="c-secret" autocomplete="off" placeholder="${connector.configured ? "已托管，留空保持不变" : "请输入密钥"}">
        </label>`}
        <label class="switch-row"><span>启用该连接器</span><input type="checkbox" id="c-enabled" ${connector.enabled ? "checked" : ""}></label>
      </div>`,
    footer: `<button class="btn ghost" id="c-cancel">取消</button><button class="btn primary" id="c-save">保存</button>`,
  });
  $("#c-cancel", overlay).addEventListener("click", () => overlay.remove());
  $("#c-save", overlay).addEventListener("click", async () => {
    const config = {};
    $$("[data-cfg]", overlay).forEach((input) => { config[input.dataset.cfg] = input.value.trim(); });
    const body = { enabled: $("#c-enabled", overlay).checked, config };
    if (!isCLI) body.base_url = $("#c-base", overlay).value.trim();
    const secret = $("#c-secret", overlay);
    if (secret && secret.value.trim()) body.secret = secret.value.trim();
    try {
      await api(`/api/connectors/${connector.key}`, { method: "PUT", body });
      overlay.remove();
      toast("连接器配置已保存");
      await loadConnectors();
    } catch (error) { toast(error.message, "error"); }
  });
}

/* ---------------- capabilities ---------------- */
// 操作询问的两个平级开关（没有总开关）；授权范围已取消，不再有「跨域请求」这一项。
// 「自动迭代」已下线：它就是对话页的「自动继续」，不再单设开关。
const ASK_KEYS = ["ask_sensitive", "ask_delete"];

function capabilityInputs() {
  return $$("#capability-groups input[type=checkbox]");
}

function switchInputs() {
  return $$("#switch-cards input[type=checkbox]");
}

function renderSwitches() {
  const switches = state.capabilitySwitches || [];
  const subs = switches.filter((item) => item.group === "confirm");
  const mains = switches.filter((item) => item.group !== "confirm");
  // 「操作询问」不再有总开关：三个子开关平级，谁开谁问，各自独立。
  // 它们仍然放在一张卡里，只是这张卡没有开关，只负责分组和说明。
  const cards = mains.map((item) => `
    <div class="auto-panel ${item.enabled ? "on" : ""}" data-switch-card="${esc(item.key)}">
      <div class="auto-head">
        <div class="auto-copy">
          <div class="auto-title">${esc(item.name)}<span class="auto-tag">${esc(item.tag || "")}</span></div>
          <p class="auto-desc">${esc(item.description)}</p>
        </div>
        <label class="auto-switch">
          <input type="checkbox" data-switch-input="${esc(item.key)}" ${item.enabled ? "checked" : ""}>
          <span class="auto-switch-label">${item.enabled ? "已开启" : "已关闭"}</span>
        </label>
      </div>
      ${(item.flags || []).length ? `<div class="auto-flags">${(item.flags || []).map((flag) => `<span>${esc(flag)}</span>`).join("")}</div>` : ""}
    </div>`);
  if (subs.length) {
    cards.push(`
    <div class="auto-panel ask-panel ${subs.some((item) => item.enabled) ? "on" : ""}" data-ask-panel="1">
      <div class="auto-head">
        <div class="auto-copy">
          <div class="auto-title">操作询问<span class="auto-tag">CONFIRM ACTIONS</span></div>
          <p class="auto-desc">两项平级，各自管一类动作，谁开谁问。只有这两类会打断你，其余操作一律直接执行（目标范围不需要授权确认）。</p>
        </div>
        <span class="auto-state" data-ask-state="1"></span>
      </div>
      <div class="auto-sub">
        ${subs.map((sub) => `
        <label class="sub-switch ${sub.enabled ? "on" : ""}">
          <span class="sub-copy">
            <strong>${esc(sub.name)}<span class="sub-tag">${esc(sub.tag || "")}</span></strong>
            <small>${esc(sub.description)}</small>
          </span>
          <span class="auto-switch">
            <input type="checkbox" data-switch-input="${esc(sub.key)}" ${sub.enabled ? "checked" : ""}>
            <span class="auto-switch-label">${sub.enabled ? "已开启" : "已关闭"}</span>
          </span>
        </label>`).join("")}
      </div>
    </div>`);
  }
  $("#switch-cards").innerHTML = cards.join("");
  syncSwitchCards();
}

function syncSwitchCards() {
  switchInputs().forEach((input) => {
    const row = input.closest(".sub-switch");
    if (row) {
      row.classList.toggle("on", input.checked);
      const label = $(".auto-switch-label", row);
      if (label) label.textContent = input.checked ? "已开启" : "已关闭";
      return;
    }
    const card = input.closest(".auto-panel");
    if (!card) return;
    card.classList.toggle("on", input.checked);
    const label = $(".auto-switch-label", card);
    if (label) label.textContent = input.checked ? "已开启" : "已关闭";
  });
  // 「操作询问」卡片只显示两个开关的汇总情况，本身不可点
  const panel = $("[data-ask-panel]");
  if (panel) {
    const on = ASK_KEYS.filter((key) => switchValue(key)).length;
    panel.classList.toggle("on", on > 0);
    const state = $("[data-ask-state]", panel);
    if (state) {
      state.classList.toggle("on", on > 0);
      state.textContent = on ? `${on}/${ASK_KEYS.length} 已开启` : "全部关闭";
    }
  }
}

function switchValue(key) {
  const input = $(`[data-switch-input="${key}"]`);
  return Boolean(input && input.checked);
}

function updateCapabilityStatus() {
  const checked = Array.from(state.capabilityChecked).length;
  const total = state.capabilities.length;
  const hinted = state.capabilities.filter((item) => hintOf(item.key)).length;
  $("#capability-count").textContent =
    `已启用 ${checked} / ${total} 项` + (hinted ? ` · 提示 ${hinted} 项` : "");
  const asks = ASK_KEYS.filter((key) => switchValue(key)).length;
  const auto = switchValue("auto_pentest");
  // 权重最高的几项就是 AI 的开测顺序，直接写出来让人一眼看到自己设的有没有用
  const top = state.capabilities
    .filter((item) => state.capabilityChecked.has(item.key))
    .map((item) => ({ name: item.name, weight: weightOf(item.key) }))
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((item) => `${item.name}(${item.weight})`)
    .join(" → ");
  $("#capability-status").textContent =
    `已启用 ${checked} 项测试能力 · ` +
    `自动渗透${auto ? "开启（清单外也测）" : "关闭（只测清单内）"} · ` +
    `操作询问${asks ? `${asks}/${ASK_KEYS.length} 项开启` : "全部关闭"}` +
    (hinted ? ` · 用户提示 ${hinted} 项` : "") +
    (top ? ` · 优先顺序 ${top}` : "");
  syncSwitchCards();
  capabilityInputs().forEach((input) => {
    input.closest(".capability-item").classList.toggle("checked", input.checked);
  });
  $$("#capability-groups .capability-group").forEach((group) => {
    const boxes = $$("input[type=checkbox]", group);
    const on = boxes.filter((box) => box.checked).length;
    const badge = $(".group-count", group);
    if (badge) badge.textContent = `${on} / ${boxes.length}`;
    group.classList.toggle("all-on", boxes.length > 0 && on === boxes.length);
  });
}

const WEIGHT_DEFAULT = 5;

function weightOf(key) {
  const value = Number((state.capabilityWeights || {})[key]);
  return Number.isFinite(value) && value >= 1 ? Math.min(5, Math.round(value)) : WEIGHT_DEFAULT;
}

// 权重滑块：1-5，原生 range，点哪就是几级、拖动连续调；键盘左右也能微调
// 颜色由 CSS 按「有没有勾选」自动切换，这里不再额外标 hot，避免没启用却高亮
function weightSlider(key, weight, name) {
  return `
    <div class="cap-weight" data-weight-cell="${esc(key)}" style="--fill:${(weight - 1) * 25}%">
      <input type="range" class="cap-slider" min="1" max="5" step="1" value="${weight}"
             data-weight="${esc(key)}" aria-label="${esc(name)} 测试权重（1-5，越大越先测）"
             title="1-5，越大越先测（默认 5）">
      <span class="cap-weight-value" data-weight-value="${esc(key)}">${weight}</span>
    </div>`;
}

function paintWeightCell(key, value) {
  const cell = document.querySelector(`[data-weight-cell="${key}"]`);
  if (!cell) return;
  cell.style.setProperty("--fill", `${(value - 1) * 25}%`);
  const slider = cell.querySelector(".cap-slider");
  if (slider && Number(slider.value) !== value) slider.value = String(value);
  const label = cell.querySelector("[data-weight-value]");
  if (label) label.textContent = String(value);
  const item = state.capabilities.find((entry) => entry.key === key);
  if (item) item.weight = value;
  updateCapabilityStatus();
}

function hintOf(key) {
  return String((state.capabilityHints || {})[key] || "").trim();
}

// 用户提示：默认收起，写了就显示「已写」；展开后是可直接编辑的输入框
function hintBox(item) {
  const hint = hintOf(item.key);
  const label = hint ? "用户提示已写" : "＋ 用户提示";
  return `
    <div class="cap-hint ${hint ? "has" : ""}" data-hint-row="${esc(item.key)}">
      <button type="button" class="cap-hint-btn" data-hint-toggle="${esc(item.key)}"
              aria-expanded="${hint ? "true" : "false"}"
              title="${hint ? esc(hint.slice(0, 120)) : "给这一项写用户提示：模型测这一项之前必须先读完、照着做"}">
        <span class="cap-hint-mark"></span>${label}
      </button>
      <div class="cap-hint-edit ${hint ? "" : "hidden"}" data-hint-edit="${esc(item.key)}">
        <textarea class="input cap-hint-input" data-hint-input="${esc(item.key)}" rows="3" maxlength="600"
                  placeholder="例：只测 /api/order 的越权，必须换别人的订单号验证；不要扫全站、不要碰删除接口。">${esc(hint)}</textarea>
        <span class="cap-hint-tip">模型测这一项前必须先读完这段并照做，漏做就等于没测；改完点「保存能力配置」生效。</span>
      </div>
    </div>`;
}

function renderCapabilities() {
  const query = ($("#capability-search").value || "").trim().toLowerCase();
  const items = state.capabilities.filter((item) => {
    if (!query) return true;
    return [item.name, item.description, item.group, item.key, hintOf(item.key)]
      .join(" ").toLowerCase().includes(query);
  });
  const groups = {};
  items.forEach((item) => {
    if (!groups[item.group]) groups[item.group] = [];
    groups[item.group].push(item);
  });
  $("#capability-hint").textContent = `${state.capabilities.length} 项 · ${Object.keys(groups).length} 组`;
  if (!items.length) {
    $("#capability-groups").innerHTML = `<div class="empty-state">没有匹配「${esc(query)}」的能力</div>`;
    updateCapabilityStatus();
    return;
  }
  $("#capability-groups").innerHTML = Object.entries(groups).map(([group, list]) => `
    <div class="capability-group">
      <div class="group-title capability-group-title">
        <span>${esc(group)}</span>
        <span class="group-count">0 / ${list.length}</span>
        <button class="link group-toggle" data-group="${esc(group)}" type="button">全选本组</button>
      </div>
      <div class="capability-grid">
        ${list.map((item) => {
          const weight = weightOf(item.key);
          return `
          <div class="capability-item ${state.capabilityChecked.has(item.key) ? "checked" : ""}">
            <div class="cap-row">
              <label class="cap-check">
                <input type="checkbox" value="${esc(item.key)}" ${state.capabilityChecked.has(item.key) ? "checked" : ""}>
                <div><strong>${esc(item.name)}</strong><small>${esc(item.description)}</small></div>
              </label>
              ${weightSlider(item.key, weight, item.name)}
            </div>
            ${hintBox(item)}
          </div>`;
        }).join("")}
      </div>
    </div>`).join("");
  updateCapabilityStatus();
}

async function loadCapabilities() {
  const data = await api("/api/capabilities");
  state.capabilities = (data.items || []).filter((item) => item.kind !== "switch");
  state.capabilitySwitches = data.switches || [];
  state.capabilityWeights = { ...(data.weights || {}) };
  state.capabilityHints = { ...(data.hints || {}) };
  state.capabilities.forEach((item) => {
    if (item.user_prompt) state.capabilityHints[item.key] = item.user_prompt;
  });
  state.capabilityChecked = new Set(
    state.capabilities.filter((item) => item.enabled).map((item) => item.key)
  );
  state.capabilitySelected = state.capabilityChecked.size;
  renderSwitches();
  renderCapabilities();
}

$("#capability-groups").addEventListener("change", (event) => {
  if (!event.target.matches("input[type=checkbox]")) return;
  const key = event.target.value;
  if (event.target.checked) state.capabilityChecked.add(key);
  else state.capabilityChecked.delete(key);
  updateCapabilityStatus();
});

$("#switch-cards").addEventListener("change", (event) => {
  if (event.target.matches("[data-switch-input]")) updateCapabilityStatus();
});

$("#capability-groups").addEventListener("click", (event) => {
  const button = event.target.closest(".group-toggle");
  if (!button) return;
  const group = button.dataset.group;
  const node = $$("#capability-groups .capability-group").find(
    (item) => $(".capability-group-title span", item)?.textContent === group
  );
  if (!node) return;
  const inputs = $$("input[type=checkbox]", node);
  const allOn = inputs.length > 0 && inputs.every((input) => input.checked);
  inputs.forEach((input) => {
    input.checked = !allOn;
    if (allOn) state.capabilityChecked.delete(input.value);
    else state.capabilityChecked.add(input.value);
  });
  updateCapabilityStatus();
});

$("#capability-search").addEventListener("input", renderCapabilities);

function applyWeight(key, value) {
  const next = Math.max(1, Math.min(5, Math.round(Number(value) || WEIGHT_DEFAULT)));
  state.capabilityWeights[key] = next;
  paintWeightCell(key, next);
}

// 权重滑块：原生 range，拖动 / 点击 / 方向键都直接给值，不用自己算坐标
$("#capability-groups").addEventListener("input", (event) => {
  const slider = event.target.closest(".cap-slider");
  if (!slider) return;
  applyWeight(slider.dataset.weight, slider.value);
});

// 用户提示：点标题展开/收起，输入即写进 state（保存按钮统一提交）
$("#capability-groups").addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-hint-toggle]");
  if (!toggle) return;
  const key = toggle.dataset.hintToggle;
  const box = document.querySelector(`[data-hint-edit="${key}"]`);
  if (!box) return;
  const open = !box.classList.contains("hidden");
  box.classList.toggle("hidden", open);
  toggle.setAttribute("aria-expanded", open ? "false" : "true");
  if (!open) box.querySelector("textarea")?.focus();
});

$("#capability-groups").addEventListener("input", (event) => {
  const input = event.target.closest("[data-hint-input]");
  if (!input) return;
  const key = input.dataset.hintInput;
  const text = input.value.slice(0, 600);
  if (text.trim()) state.capabilityHints[key] = text;
  else delete state.capabilityHints[key];
  // 收起状态下也要看得出「这项写了提示」：按钮文案跟着变
  const row = input.closest(".cap-hint");
  if (row) {
    row.classList.toggle("has", Boolean(text.trim()));
    const button = row.querySelector(".cap-hint-btn");
    if (button) {
      button.lastChild.textContent = text.trim() ? "用户提示已写" : "＋ 用户提示";
      button.title = text.trim() ? text.trim().slice(0, 120) : "给这一项写用户提示：模型测这一项之前必须先读完、照着做";
    }
  }
});

$("#capability-all").addEventListener("click", () => {
  state.capabilities.forEach((item) => state.capabilityChecked.add(item.key));
  renderCapabilities();
});

$("#capability-none").addEventListener("click", () => {
  state.capabilities.forEach((item) => state.capabilityChecked.delete(item.key));
  renderCapabilities();
});

$("#capability-save").addEventListener("click", async () => {
  const keys = Array.from(state.capabilityChecked);
  const switches = {};
  switchInputs().forEach((input) => { switches[input.dataset.switchInput] = input.checked; });
  const weights = {};
  Object.entries(state.capabilityWeights || {}).forEach(([key, value]) => {
    weights[key] = Math.max(1, Math.min(5, Math.round(Number(value) || WEIGHT_DEFAULT)));
  });
  const hints = {};
  Object.entries(state.capabilityHints || {}).forEach(([key, value]) => {
    const text = String(value || "").trim();
    if (text) hints[key] = text.slice(0, 600);
  });
  try {
    const result = await api("/api/capabilities", { method: "PUT", body: { keys, switches, weights, hints } });
    const asks = ASK_KEYS.filter((key) => switches[key]).length;
    const hintCount = Object.keys(result.hints || hints).length;
    const autoOn = Boolean(switches.auto_pentest);
    toast(
      `已保存：${result.count} 项测试能力 · 自动渗透${autoOn ? "开启（清单外也测）" : "关闭"} · 用户提示 ${hintCount} 项` +
      ` · 操作询问${asks ? `${asks}/${ASK_KEYS.length} 项` : "全部关闭"}`
    );
    await loadCapabilities();
    // 勾选的数量变了，标题右边的方块基数也跟着变（没开会话时也要显示 0/N）
    state.capabilitySelected = Number(result.count || 0);
    updateCovChip();
  } catch (error) { toast(error.message, "error"); }
});

/* ---------------- audit ---------------- */
async function loadAudit() {
  const query = ($("#audit-search").value || "").trim();
  const data = await api(`/api/audit?limit=100${query ? `&q=${encodeURIComponent(query)}` : ""}`);
  $("#audit-total").textContent = `共 ${data.total} 条`;
  $("#audit-table").innerHTML = `
    <table><thead><tr><th>时间</th><th>操作人</th><th>动作</th><th>详情</th><th>来源 IP</th></tr></thead>
    <tbody>
    ${data.items.length ? data.items.map((item) => `
      <tr>
        <td class="mono-cell">${esc(fmtTime(item.ts))}</td>
        <td class="mono-cell">${esc(item.username || "system")}</td>
        <td class="mono-cell">${esc(item.action)}</td>
        <td>${esc(item.detail || "")}</td>
        <td class="mono-cell">${esc(item.ip || "—")}</td>
      </tr>`).join("") : emptyRow(5, "暂无审计记录")}
    </tbody></table>`;
}
$("#audit-search").addEventListener("keydown", (event) => { if (event.key === "Enter") loadAudit().catch((e) => toast(e.message, "error")); });

/* ---------------- settings ---------------- */
async function loadSettings() {
  const settings = await api("/api/settings");
  state.settings = settings;
  $("#s-safe-mode").checked = !!settings.safe_mode;
  $("#s-sensitive-paths").checked = !!settings.sensitive_path_checks;
  $("#s-ai-enabled").checked = !!settings.ai_enabled;
  $("#s-concurrency").value = settings.max_concurrency || 24;
  $("#s-timeout").value = settings.request_timeout || 8;
  $("#s-user-agent").value = settings.user_agent || "";
}

$("#settings-save").addEventListener("click", async () => {
  const body = {
    safe_mode: $("#s-safe-mode").checked,
    sensitive_path_checks: $("#s-sensitive-paths").checked,
    ai_enabled: $("#s-ai-enabled").checked,
    max_concurrency: Number($("#s-concurrency").value),
    request_timeout: Number($("#s-timeout").value),
    user_agent: $("#s-user-agent").value.trim(),
  };
  try {
    await api("/api/settings", { method: "PUT", body });
    toast("设置已保存");
  } catch (error) { toast(error.message, "error"); }
});

$("#password-save").addEventListener("click", async () => {
  const oldPassword = $("#p-old").value;
  const newPassword = $("#p-new").value;
  if (!oldPassword || newPassword.length < 8) { toast("请填写当前口令，新口令至少 8 位", "error"); return; }
  try {
    await api("/api/auth/password", {
      method: "POST",
      body: { old_password: oldPassword, new_password: newPassword },
    });
    $("#p-old").value = "";
    $("#p-new").value = "";
    toast("登录口令已更新");
  } catch (error) { toast(error.message, "error"); }
});

/* ---------------- directory settings ---------------- */
async function loadPaths() {
  const data = await api("/api/settings/paths");
  $("#d-memory-path").value = data.memory_path || "";
  $("#d-work-dir").value = data.work_dir || "";
  const memory = data.memory || {};
  if (!memory.configured) {
    $("#d-memory-status").textContent = "未设置，AI 不会加载记忆";
  } else if (!memory.exists) {
    $("#d-memory-status").textContent = "路径不存在";
  } else if (!(memory.files || []).length) {
    $("#d-memory-status").textContent = "目录可用，暂无记忆文件（把偏好写进 .md 会自动读取）";
  } else {
    $("#d-memory-status").textContent = `已读取 ${memory.files.length} 个文件 · ${memory.chars} 字符`;
  }
  $("#d-memory-preview").textContent = memory.preview || "暂无可读取的记忆内容。把偏好、约定写在这个目录的 .md 文件里即可。";
  const work = data.work || {};
  if (!work.configured) {
    $("#d-work-status").textContent = "未设置，AI 的文件工具不可用";
  } else if (!work.exists) {
    $("#d-work-status").textContent = "目录不可用";
  } else {
    $("#d-work-status").textContent = `目录可用 · 当前 ${work.entries} 项`;
  }
}

$("#paths-save").addEventListener("click", async () => {
  try {
    await api("/api/settings", {
      method: "PUT",
      body: {
        memory_path: $("#d-memory-path").value.trim(),
        work_dir: $("#d-work-dir").value.trim(),
      },
    });
    toast("目录配置已保存");
    await loadPaths();
  } catch (error) { toast(error.message, "error"); }
});

/* ---------------- smart work ---------------- */
const MODE_LABELS = { active: "完整渗透测试", passive: "情报测绘" };
const PROFILE_LABELS = { quick: "快速", standard: "标准", deep: "深度" };
const modeLabel = (mode) => MODE_LABELS[mode] || mode || "—";
const profileLabel = (profile) => PROFILE_LABELS[profile] || profile || "—";

// 把底层报错翻成人话：用户只看到「发生了什么 + 下一步怎么做」，不看到 JSON 与堆栈
function friendlyChatError(raw) {
  const text = String(raw || "").trim();
  const has = (re) => re.test(text);
  if (!text) return "这轮没拿到结果，再发一次我重新处理。";
  if (has(/Failed to fetch|NetworkError|Load failed|network error/i)) {
    return "没连上服务，确认本地平台还在运行（start.bat 的窗口没关），然后再发一次。";
  }
  if (has(/登录状态已失效/)) return "登录状态已过期，重新登录后这条消息还在，再发一次就行。";
  if (has(/api[_-]?key|invalid.{0,8}key|unauthorized|authentication|密钥/i)) return "模型密钥无效或已失效，到「API 中心」重新填一次 Key。";
  if (has(/\b401\b/)) return "模型拒绝了这次请求（401），先到「API 中心」确认 Key 还在有效期内。";
  if (has(/\b402\b|insufficient|余额|积分|quota|额度/i)) return "模型账户额度不足，到服务商后台充值或兑换后再发一次。";
  if (has(/\b403\b/)) return "模型拒绝了这次请求（403），通常是这个 Key 没有该模型的权限。";
  if (has(/\b404\b/)) return "模型名称没对上（404），到「API 中心」核对「模型名称」这一项。";
  if (has(/\b429\b|rate limit|too many/i)) return "请求太频繁被限流（429），等十几秒再发一次。";
  if (has(/\b5\d\d\b/)) return "模型服务商临时故障，稍等一会儿重试即可，平台这边不用改配置。";
  if (has(/timeout|timed out|超时/i)) return "模型响应超时。可以把问题拆小一点，或到「API 中心」换个更快的模型。";
  if (has(/密钥|api[_-]?key|unauthorized|invalid.*key/i)) return "模型密钥无效或已失效，到「API 中心」重新填一次 Key。";
  if (has(/abort/i)) return "已停止本轮生成。";
  // 兜底：去掉 JSON 尾巴、HTML 与过长的英文堆栈，只留一句可读的话
  const cleaned = text
    .replace(/<[^>]{1,200}>/g, "")
    .replace(/\{[\s\S]*\}$/, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
  if (!cleaned || /^[[{"]/.test(cleaned)) return "这一轮出错了，重发一次或换个模型再试。";
  return cleaned;
}

// 这个平台只干一件事：找安全漏洞。所以不再摆场景卡片让人挑，
// 新会话直接给出「丢一个目标进来就能开工」的说明。
const CHAT_EMPTY = `
  <div class="chat-empty">
    <div class="chat-empty-title">智能工作 · SMART WORK</div>
    <p>给它一个域名或 IP，默认就开始找漏洞。</p>
    <p class="chat-empty-foot">资产测绘 → 能力测试 → 逐条归档请求包与响应包。过程我来处理，只在需要你决策时给选项。</p>
  </div>`;

function chatBubble(message, index) {
  const cls = message.error ? "error" : "";
  const cursor = message.streaming ? " streaming" : "";
  // 每条消息都能复制：按钮放在气泡下方，不挡正文、不抢视线
  const copyBtn = message.streaming
    ? ""
    : `<div class="chat-actions"><button class="chat-copy" data-copy-msg="${index}" title="复制这条">复制</button></div>`;
  const text = String(message.content || "");
  // 流式期间先按纯文本铺，写完再整体解析一次 Markdown。
  // 每来一段就重解析整篇，会让文字不停重排——那才是"一闪一闪"的来源。
  const plainLong = message.role !== "user" && message.streaming && text.length > STREAM_PLAIN_LIMIT;
  const body = message.role === "user" ? esc(text) : message.streaming ? esc(text) : mdLite(text);
  const rendered = message.streaming ? ` data-rendered="${text.length}"` : "";
  // 自动继续发出去的那句和手打的一样是用户消息，只是标一个「自动」小签，
  // 回看时能分清哪些是你说的、哪些是平台按你的预设替你发的
  const autoTag = message.auto ? `<span class="chat-auto-tag">自动</span>` : "";
  return `<div class="chat-msg ${message.role}" data-idx="${index}">
    <div class="chat-role">${message.role === "user" ? "你" : "助手"}${autoTag}</div>
    <div class="chat-bubble ${cls}${cursor}${plainLong ? " plain-stream" : ""}"${rendered}>${body}</div>
    ${copyBtn}
  </div>`;
}

// 复制到剪贴板：优先 Clipboard API，非安全上下文（局域网 http）退回 execCommand
async function copyText(text) {
  const value = String(text || "");
  if (!value) return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch (error) { /* 落到兜底方案 */ }
  try {
    const box = document.createElement("textarea");
    box.value = value;
    box.setAttribute("readonly", "");
    box.style.position = "fixed";
    box.style.top = "-1000px";
    box.style.opacity = "0";
    document.body.appendChild(box);
    box.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(box);
    return ok;
  } catch (error) {
    return false;
  }
}

// 把整段对话整理成可粘贴的 Markdown：只留有内容的往来，卡片转成文字
function chatTranscript() {
  const lines = [];
  const title = ($("#chat-title")?.textContent || "").trim();
  if (title) lines.push(`# ${title}`, "");
  (state.chatMessages || []).forEach((message) => {
    const content = String(message.content || "").trim();
    if (message.role === "user" && content) lines.push(`**我**：${content}`, "");
    if (message.role === "assistant" && content) lines.push(`**助手**：${content}`, "");
    if (message.role === "progress" && content) lines.push(`- ${content}`);
    if (message.role === "choice") {
      const picked = message.decision === "chosen" ? message.chosen : "";
      lines.push(`**待选择**：${message.question || ""}${picked ? `\n**已选**：${picked}` : ""}`, "");
    }
    if (message.role === "confirm") {
      lines.push(`**待确认**：${message.summary || ""}（${message.decision === "approved" ? "已确认" : message.decision === "rejected" ? "已跳过" : "待决定"}）`, "");
    }
  });
  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}

async function copyAllChat() {
  const text = chatTranscript();
  if (!text) { toast("这个会话还没有内容", "error"); return; }
  const ok = await copyText(text);
  toast(ok ? "整段对话已复制" : "复制失败，请手动选中", ok ? "" : "error");
}

// 值得用户抬头看的关键节点：书面词、变体说法、口语表达都算。
// 这份清单与后端 engine/agent.py 的 HIGHLIGHT_MARKERS 保持一致。
const HIGHLIGHT_MARKERS = [
  // 突破类
  "关键突破", "重大突破", "有突破", "突破了", "突破性进展", "突破口", "撕开口子", "打开缺口",
  // 发现类
  "重大发现", "新发现", "新的发现", "关键发现", "核心发现", "重要发现", "又发现",
  // 进展类
  "关键进展", "重大进展", "新的进展", "新进展", "有进展", "又有进展", "往前推了一步",
  // 确认 / 证明类
  "确认存在", "已确认存在", "确认可行", "已经证明", "已证明", "证实了", "实锤",
  "验证成功", "成功利用", "可利用", "能利用",
  // 结论 / 证据 / 风险类
  "关键结论", "关键证据", "关键线索", "有力证据", "关键风险", "重大风险",
  "高危确认", "严重风险",
];
// 口语化的说法同样算关键节点：「已经找到漏洞点，可以继续深入」比四个字的书面词更像人话
const HIGHLIGHT_STRONG = [
  "漏洞点", "漏洞入口", "攻击点", "利用点", "有戏", "有料",
  "打得进去", "能打进去", "可以打", "能绕过", "绕过去了",
  "拿到了数据", "能读到数据", "兜出数据", "挖到东西", "挖到线索",
];
const HIGHLIGHT_FINDINGS = [
  "可利用", "未授权", "越权", "口令", "弱口令", "密钥", "令牌", "敏感信息", "敏感数据",
  "高危", "严重", "接口", "入口", "注入点", "后台", "数据库", "堆栈", "身份证", "手机号",
];
const HIGHLIGHT_FOLLOWUP = [
  "继续深入", "往下挖", "继续挖", "深挖", "跟进", "追下去", "继续验证", "接着验",
  "往下试", "扩面", "扩展", "继续测", "追一下",
];
// 否定说法不算突破：「没有突破」「未发现」不能点亮徽标
const HIGHLIGHT_NEGATIVE = ["没", "未", "无", "别", "不", "暂", "尚未"];
const HIGHLIGHT_COLLOQUIAL_LABEL = "值得深入";

// 可变长的关键说法：不写死成四个字。「突破」「关键突破」「关键突破口」
// 「重大安全发现」「已经确认存在」都要认，徽标直接显示模型说的那句原话
const HIGHLIGHT_PATTERNS = [
  /(?:关键|重大|核心|重要|突破性)(?:安全)?(?:突破口|突破|发现|进展|线索|结论|证据|风险)/,
  /(?:已经|已|经)?确认(?:了|出)?(?:确实)?(?:存在|可读|可访问|可绕过|能登|可行|成立)/,
  /(?:已经|已|经)?(?:证明|证实)(?:了)?/,
  /成功(?:利用|登录|绕过|读取|拿到|进入|执行|接管|越权)/,
  /(?:已经能|已能|能|可以)(?:利用|绕过|读到|拿到|进入|接管|越权|读取)/,
  /(?:撕开|打开|找到|发现)(?:了)?(?:口子|缺口|突破口)/,
  /突破口/,
  /(?:新的|新)(?:发现|进展|突破)/,
  /有(?:了)?(?:突破|进展|发现|收获)/,
  /验证成功|实锤/,
  /往前推了(?:一|1)步/,
];

// 模型常写成「**【关键突破】**：…」，判定前先剥掉这些前后缀噪声
function highlightHit(text) {
  const value = String(text || "")
    .replace(/\*/g, "")
    .replace(/^[\s　\-–—·•◆◇■□★☆#>【】[\]「」『』:：]+/, "")
    .trim();
  const head = value.slice(0, 40);
  let best = null;
  for (const pattern of HIGHLIGHT_PATTERNS) {
    const match = pattern.exec(head);
    if (!match) continue;
    const index = match.index;
    const before = head.slice(Math.max(0, index - 3), index);
    if (HIGHLIGHT_NEGATIVE.some((neg) => before.includes(neg))) continue;
    // 同一位置命中多条时取更长的那个：「关键突破口」不能被截成「关键突破」
    if (!best || index < best.index || (index === best.index && match[0].length > best.word.length)) {
      best = { word: match[0], index };
    }
  }
  if (best) return { word: best.word, label: best.word, strip: best.index === 0 };
  const byLength = HIGHLIGHT_MARKERS.slice().sort((a, b) => b.length - a.length);
  let word = byLength.find((item) => value.startsWith(item)) || "";
  if (!word) {
    const tail = value.slice(0, 30);
    for (const item of byLength) {
      const index = tail.indexOf(item);
      if (index < 0) continue;
      const before = tail.slice(Math.max(0, index - 3), index);
      if (HIGHLIGHT_NEGATIVE.some((neg) => before.includes(neg))) continue;
      word = item;
      break;
    }
  }
  if (word) return { word, label: word, strip: value.startsWith(word) };
  const strong = HIGHLIGHT_STRONG.some((item) => value.includes(item));
  const finding = HIGHLIGHT_FINDINGS.some((item) => value.includes(item))
    && HIGHLIGHT_FOLLOWUP.some((item) => value.includes(item));
  if (strong || finding) return { word: "", label: HIGHLIGHT_COLLOQUIAL_LABEL, strip: false };
  return null;
}

function highlightWord(text) {
  const hit = highlightHit(text);
  return hit ? hit.label : "";
}

// 进行中的文案统一用动态省略号收尾：静态的「...」看不出它还在动
const RUNNING_RE = /^(正在|读取中|执行中|处理中|继续)/;
function dotsHtml() {
  return '<em class="dots" aria-hidden="true"><i></i><i></i><i></i></em>';
}
function isRunningText(text) {
  return RUNNING_RE.test(String(text || "").replace(/[.．。…\s]+$/g, "").trim());
}
function htmlWithDots(text) {
  const value = String(text || "").replace(/[.．。…]+$/g, "").trim();
  if (!value) return "";
  return isRunningText(value) ? `${esc(value)}${dotsHtml()}` : esc(value);
}

// 后端已经定过等级就以它为准：冷却期内被降级的关键说法只保留文字，不再放大
function progressIsKey(level, text) {
  if (level === "highlight") return true;
  if (level === "step" || level === "focus" || level === "loading" || level === "info") return false;
  return Boolean(highlightWord(text));
}

function chatProgress(message) {
  const text = String(message.content || "");
  const loading = message.level === "loading" || /^正在读取/.test(text);
  // 后端已经定过等级（info/step/focus 都是普通进展），就按它渲染，不再二次猜高亮。
  // 否则被冷却降级的关键说法，到了前端又被文本规则点亮，等于白降。
  const settled = !loading
    && (message.level === "step" || message.level === "info" || message.level === "focus");
  const hit = loading || settled ? null : highlightHit(text);
  // 进度是单行小字，去掉模型顺手写的 ** 加粗标记，避免露出原始星号
  const stripped = hit && hit.strip
    ? text.replace(/\*/g, "").replace(hit.word, "").replace(/^[\s　【】[\]「」『』:：,，、\-–—]+/, "").trim()
    : text.replace(/\*/g, "").trim();
  const label = hit ? hit.label : "";
  // 四档视觉：key=关键节点（最大最亮）、focus=口语化「值得深入」、loading=正在读记忆、step=普通步骤
  const level = loading
    ? "loading"
    : message.level === "focus"
      ? "focus"
      : hit
        ? (hit.word ? "highlight" : "focus")
        : "step";
  const badgeText = loading
    ? "读取中"
    : level === "focus" && !hit
      ? "值得深入"
      : hit
        ? label
        : progressKind(stripped);
  const badge = `<span class="progress-badge ${level}">${esc(badgeText)}</span>`;
  return `<div class="chat-msg progress ${level}">
    <div class="chat-progress">${badge}<span>${htmlWithDots(stripped)}</span></div>
  </div>`;
}

// 普通步骤也给它一个说得清自己在干什么的徽标，而不是一串光秃秃的「✓」
function progressKind(text) {
  const value = String(text || "");
  if (/^(已读|读到|正在读|看了)/.test(value)) return "读取";
  if (/^(已列|列了|列目录)/.test(value)) return "盘点";
  if (/^(已执行|已跑|跑完|已请求|已调用)/.test(value)) return "执行";
  if (/^(已请求|请求了|探测|扫|验证)/.test(value)) return "探测";
  if (/^(已归档|已记录|登记|写入)/.test(value)) return "归档";
  if (/^(已确认|确认)/.test(value)) return "确认";
  return "进展";
}

const CUSTOM_SENTINELS = new Set(["__custom__", "custom", "other", "自定义", "其他"]);

function chatChoiceCard(message) {
  const decision = message.decision || "pending";
  const options = Array.isArray(message.options) ? message.options : [];
  const buttons = options.map((option, index) => {
    const label = typeof option === "string" ? option : option.label;
    const hint = typeof option === "string" ? "" : option.hint;
    const value = typeof option === "string" ? option : (option.value || option.label);
    const custom = CUSTOM_SENTINELS.has(String(value).trim());
    const primary = index === 0 && !custom ? "primary" : "ghost";
    const attrs = custom
      ? `data-choice-custom-focus="${esc(message.choice_id)}"`
      : `data-choice="${esc(message.choice_id)}" data-value="${esc(value)}"`;
    const badge = index === 0 && !custom ? `<em class="choice-badge">推荐</em>` : "";
    return `<button class="btn ${primary} small choice-btn" ${attrs} ${decision === "pending" ? "" : "disabled"}>
        <strong>${badge}${esc(label)}</strong>${hint ? `<span>${esc(hint)}</span>` : ""}
      </button>`;
  }).join("");
  const hasSentinel = options.some((option) => {
    const value = typeof option === "string" ? option : option.value;
    return CUSTOM_SENTINELS.has(String(value ?? "").trim());
  });
  const custom = decision === "pending" && (message.allow_custom || hasSentinel)
    ? `<div class="choice-custom"><input class="input" id="choice-input-${esc(message.choice_id)}" placeholder="也可以直接输入"><button class="btn ghost small" data-choice-custom="${esc(message.choice_id)}">提交</button></div>`
    : "";
  const stateText = decision === "pending"
    ? ""
    : `<div class="confirm-state ${decision === "chosen" ? "approved" : "rejected"}">${esc(message.chosen || "已选择")}</div>`;
  return `<div class="chat-msg choice">
    <div class="chat-role">请选择 / CHOICE</div>
    <div class="chat-choice ${decision}">
      <div class="choice-question">${mdLite(message.question || "")}</div>
      <div class="choice-options">${buttons}</div>
      ${custom}
      ${stateText}
    </div>
  </div>`;
}

function chatConfirmCard(message) {
  const decision = message.decision || "pending";
  const actions = decision === "pending"
    ? `<div class="confirm-actions">
        <button class="btn primary small" data-decide="approve" data-action="${message.action_id}">确认执行</button>
        <button class="btn ghost small" data-decide="reject" data-action="${message.action_id}">暂不执行</button>
      </div>`
    : `<div class="confirm-state ${decision}">${decision === "approved" ? "已确认并执行" : "已跳过"}</div>`;
  return `<div class="chat-msg confirm">
    <div class="chat-role">待确认事项 / CONFIRM</div>
    <div class="chat-confirm ${decision}">
      <div class="confirm-head">
        <span class="chip">${esc(message.label || "待确认")}</span>
        <strong>${esc(message.summary || "")}</strong>
      </div>
      ${actions}
    </div>
  </div>`;
}

// 思考超过 3 秒就把已用时间显示出来，用户知道它还在干活，而不是卡住了
// 实时漏洞卡：模型一确认并归档，就在对话里就地出现，不用等任务结束再去漏洞结果页刷
function chatFindingCard(message) {
  const card = message.finding || {};
  const sev = ["critical", "high", "medium", "low", "info"].includes(card.severity) ? card.severity : "info";
  const id = Number(card.finding_id || 0);
  const domain = card.domain || "未标注域名";
  const url = card.url || "";
  return `<div class="chat-msg finding">
    <div class="chat-finding hit-${sev}">
      <div class="chat-finding-head">
        ${sevBadge(sev)}
        <strong>${esc(card.title || "未命名漏洞")}</strong>
        ${id ? `<button class="link finding-open" data-open-finding="${id}">看证据 →</button>` : ""}
      </div>
      <div class="chat-finding-meta">
        <span class="chip mono">${esc(domain)}</span>
        ${card.capability ? `<span class="chip">${esc(card.capability)}</span>` : ""}
        <span class="chat-finding-url mono">${esc(url)}</span>
      </div>
    </div>
  </div>`;
}

function elapsedText() {
  if (!state.chatTyping || !state.chatTypingAt) return "";
  const sec = Math.floor((Date.now() - state.chatTypingAt) / 1000);
  if (sec < 3) return "";
  // 快到看门狗阈值时说一句：平台会在 300 秒无进展时自动重开这一步，
  // 免得用户以为它死在这里、一直干等
  const warn = sec >= 240 ? " · 无新进展将自动重开这一步" : "";
  return ` · 已用 ${sec}s${warn}`;
}

function typingText() {
  return String(state.chatTyping || "").replace(/[.．。…]+$/, "").trim();
}

// 等待提示只在文案变化时重建；省略号是 CSS 动画，秒数只改那一小段文字。
// 每秒整块重画会让省略号动画从头开始，看起来就是「一闪一闪」。
function renderTypingIndicator() {
  const base = typingText();
  if (!base) return "";
  if (!state.chatTypingAt) state.chatTypingAt = Date.now();
  return `<div class="chat-typing"><span class="dot"></span><span class="typing-text">${esc(base)}${dotsHtml()}<span class="typing-elapsed">${elapsedText()}</span></span></div>`;
}

// 贴到底：当场贴一次，下一帧再贴一次，稍后再兜底层。
// 字体加载、代码块高亮、进度徽标入场动画都会让内容再长高一点，
// 只贴一次就会停在"差一点点到不了底"的位置。
const CHAT_PIN_TIMERS = new WeakMap();
function nearBottom(box, tolerance) {
  return box.scrollHeight - box.scrollTop - box.clientHeight < (tolerance || 200);
}

/* 对话区里的划词有两个状态，处理方式不一样：

   ① 正在拖（鼠标按住没松）——绝对不能重画、不能贴底。模型在流式输出，进度行一条条往上顶，
      自动贴底会把用户按下的那一行推到上面去；innerHTML 一重建，选中的节点被换掉，
      选区就落到隔壁行。这就是「我选的是下面，结果高亮在上面」的成因。
   ② 已经选好、手松了——照常刷新，但重画前记下选区的字符位置，画完再按位置还原，
      高亮留在原文上，输出也不会因为「你在选中」而停住。 */
function chatDragging() {
  return !!state.chatSelecting;
}

function chatHasSelection(box) {
  if (!box) return false;
  const sel = window.getSelection && window.getSelection();
  if (!sel || !sel.rangeCount || sel.isCollapsed) return false;
  const node = sel.anchorNode;
  if (!node) return false;
  const el = node.nodeType === 1 ? node : node.parentElement;
  return !!(el && box.contains(el));
}

// 只用来判「别动滚动条」：拖选中或者已经选中了，都别把视线拽走
function chatSelectionLocked(box) {
  return chatDragging() || chatHasSelection(box);
}

// 选区在对话区里的字符位置：重画前后靠它把高亮放回原处
function chatTextOffset(box, node, offset) {
  try {
    const range = document.createRange();
    range.selectNodeContents(box);
    range.setEnd(node, offset);
    return range.toString().length;
  } catch (error) {
    return -1;
  }
}

function captureChatSelection(box) {
  const sel = window.getSelection();
  if (!sel || !sel.rangeCount) return null;
  const range = sel.getRangeAt(0);
  if (!box.contains(range.commonAncestorContainer)) return null;
  const start = chatTextOffset(box, range.startContainer, range.startOffset);
  const end = chatTextOffset(box, range.endContainer, range.endOffset);
  if (start < 0 || end < 0) return null;
  return { start, end };
}

function chatPointAt(box, offset) {
  const walker = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
  let seen = 0;
  let node = walker.nextNode();
  while (node) {
    const len = node.nodeValue ? node.nodeValue.length : 0;
    if (seen + len >= offset) return { node, offset: offset - seen };
    seen += len;
    node = walker.nextNode();
  }
  return null;
}

function restoreChatSelection(box, snapshot) {
  if (!snapshot) return;
  const start = chatPointAt(box, snapshot.start);
  const end = chatPointAt(box, snapshot.end);
  if (!start || !end) return;
  const sel = window.getSelection();
  if (!sel) return;
  sel.setBaseAndExtent(start.node, start.offset, end.node, end.offset);
}

// 拖选结束才补画：拖的过程中攒下的新内容，松手后一次画完（并把选区放回去）
function flushChatRender() {
  const box = $("#chat-messages");
  if (!box || chatDragging()) return;
  if (!state.chatRenderDirty) return;
  state.chatRenderDirty = false;
  renderChatMessages(state.chatPinned ? "bottom" : "");
}

// 换会话时旧选区已经没有意义：清掉，否则新会话会被「划词中」挡住不渲染
function clearChatSelection() {
  const box = $("#chat-messages");
  const sel = window.getSelection && window.getSelection();
  if (box && sel && sel.rangeCount) {
    const node = sel.anchorNode;
    const el = node ? (node.nodeType === 1 ? node : node.parentElement) : null;
    if (el && box.contains(el)) sel.removeAllRanges();
  }
  state.chatSelecting = false;
  state.chatRenderDirty = false;
}

function pinChatBottom(box) {
  if (!box || !box.clientHeight) return;
  // 正在划词：一贴底就把选中的那行顶上去，宁可让新内容等一会儿
  if (chatSelectionLocked(box)) return;
  box.scrollTop = box.scrollHeight;
  requestAnimationFrame(() => {
    // 这一帧里用户已经往上翻了就别拽回来；内容只是长高一点就继续贴底
    if (!box.isConnected || !box.clientHeight || !nearBottom(box)) return;
    if (chatSelectionLocked(box)) return;
    box.scrollTop = box.scrollHeight;
  });
  // 流式输出时每帧都会调到这里，兜底定时器只保留最后一个，别堆一堆
  const pending = CHAT_PIN_TIMERS.get(box);
  if (pending) clearTimeout(pending);
  CHAT_PIN_TIMERS.set(box, setTimeout(() => {
    CHAT_PIN_TIMERS.delete(box);
    // 这期间用户主动往上翻了，就别把他拽回来
    if (box.isConnected && box.clientHeight && nearBottom(box) && !chatSelectionLocked(box)) {
      box.scrollTop = box.scrollHeight;
    }
  }, 150));
}

// 出现选择卡/确认卡时，让卡片完整可见。注意要取最后一张卡：
// 取第一张会把用户直接拽回会话最上面（这是"点确认就跳顶"的元凶）
function scrollToLastCard(box) {
  const cards = box.querySelectorAll(".chat-choice, .chat-confirm");
  const card = cards[cards.length - 1];
  if (!card) { pinChatBottom(box); return; }
  const cardRect = card.getBoundingClientRect();
  const boxRect = box.getBoundingClientRect();
  if (!cardRect.height || !boxRect.height) { pinChatBottom(box); return; }
  const cardTop = cardRect.top - boxRect.top + box.scrollTop;
  if (cardRect.height + 24 > box.clientHeight) {
    box.scrollTop = Math.max(0, cardTop - 12);
    return;
  }
  // 卡片后面几乎没内容了（刚点完确认只多一行"正在执行"）就直接贴底，
  // 否则会留出「卡片看得见、底下还缺一截」的空档
  const rest = box.scrollHeight - (cardTop + cardRect.height);
  if (rest < 120) { pinChatBottom(box); return; }
  const top = cardTop + cardRect.height + 14 - box.clientHeight;
  box.scrollTop = Math.max(0, Math.min(top, box.scrollHeight - box.clientHeight));
}

function chatPinned(box) {
  return box.scrollHeight - box.scrollTop - box.clientHeight < 90;
}

/* ---------------- 流式渲染节流 ----------------
   模型一段话可能有几万字（报告、清单）。以前每来一个增量就把整段对话重新渲染一遍，
   字越多越卡，最后标签页直接无响应。现在只重画"正在变的那一条"，并且 60ms 才画一次。 */
let streamPaintTimer = 0;
const STREAM_PAINT_MS = 60;
// 超过这个长度就先按纯文本刷，等写完了再解析一次 Markdown
const STREAM_PLAIN_LIMIT = 6000;

function paintStreamingBubble() {
  const box = $("#chat-messages");
  if (!box) return;
  // 正在拖选：先攒着，等松手再画（这时候追加文字会把按着的那一行顶走）
  if (chatDragging()) { state.chatRenderDirty = true; return; }
  const messages = state.chatMessages || [];
  const last = messages[messages.length - 1];
  if (!last || last.role !== "assistant" || !last.streaming) return;
  const nodes = box.querySelectorAll(".chat-msg.assistant");
  const node = nodes[nodes.length - 1];
  const bubble = node ? node.querySelector(".chat-bubble") : null;
  // DOM 里还没有"正在流式"的气泡（第一条增量刚来）：走一次完整渲染把骨架建起来
  if (!bubble || !bubble.classList.contains("streaming")) { renderChatMessages("bottom"); return; }
  const text = String(last.content || "");
  const render = (bubble.dataset.rendered === undefined) ? -1 : Number(bubble.dataset.rendered);
  if (text.length > STREAM_PLAIN_LIMIT) {
    // 超长回答先按纯文本整块换，避免几万字反复解析
    if (bubble.dataset.plain !== "1") { bubble.dataset.plain = "1"; bubble.classList.add("plain-stream"); }
    if (render !== text.length) { bubble.textContent = text; bubble.dataset.rendered = String(text.length); }
  } else {
    if (bubble.dataset.plain === "1") {
      bubble.dataset.plain = "0";
      bubble.classList.remove("plain-stream");
      bubble.textContent = "";
      bubble.dataset.rendered = "0";
    }
    if (render < 0 || render > text.length) {
      bubble.textContent = "";
      bubble.dataset.rendered = "0";
    }
    const start = Number(bubble.dataset.rendered || 0);
    // 只把新增的那一段接在末尾：不重排、不重解析，也就不会一闪一闪
    if (text.length > start) {
      bubble.appendChild(document.createTextNode(text.slice(start)));
      bubble.dataset.rendered = String(text.length);
    }
  }
  if (state.chatPinned) pinChatBottom(box);
}

function scheduleStreamPaint() {
  if (streamPaintTimer) return;
  streamPaintTimer = setTimeout(() => {
    streamPaintTimer = 0;
    paintStreamingBubble();
  }, STREAM_PAINT_MS);
}

/* 对话区里的提问点列：把本会话问过的每一句排成右侧一点列，
   点一条直接滚到那条消息；鼠标移到点列上，弹出面板列出全部提问。
   会话长了以后往上翻很费劲，这里相当于给对话装了个目录。 */
let outlineSig = "";
let outlineScrollTimer = 0;
let outlineHideTimer = 0;
// 点完一条后短暂锁定高亮：平滑滚动会连发 scroll 事件，
// 不锁的话高亮会被「当前视口顶部那条」抢走，看起来像点错了
let outlineLockUntil = 0;

function chatOutlineItems() {
  return (state.chatMessages || [])
    .map((message, index) => ({ message, index }))
    .filter((item) => item.message.role === "user" && String(item.message.content || "").trim());
}

function outlineLabel(text) {
  const flat = String(text || "").replace(/\s+/g, " ").trim();
  return flat.length > 26 ? `${flat.slice(0, 26)}…` : flat;
}

// 高亮「当前看到的那一条」：以对话区中线为界，最后一条越过中线的就是当前
function markOutlineActive(forced) {
  const list = $("#chat-outline-list");
  const box = $("#chat-messages");
  if (!list || !box) return;
  const buttons = Array.from(list.querySelectorAll("[data-outline]"));
  if (!buttons.length) return;
  const pinned = forced === undefined || forced === null ? null : String(forced);
  if (!pinned && Date.now() < outlineLockUntil) return;
  let active = pinned;
  if (!active) {
    const boxRect = box.getBoundingClientRect();
    if (!boxRect.height) return;
    const line = boxRect.top + boxRect.height * 0.5;
    let best = null;
    let bestTop = Infinity;
    buttons.forEach((btn) => {
      const node = box.querySelector(`.chat-msg[data-idx="${btn.dataset.outline}"]`);
      if (!node) return;
      const top = node.getBoundingClientRect().top;
      if (top < bestTop) { bestTop = top; best = btn.dataset.outline; }
      if (top <= line) active = btn.dataset.outline;
    });
    // 一条都还没过中线（停在最顶上）：把高亮给最近的那条，别让点列空着
    if (!active) active = best;
  }
  buttons.forEach((btn) => {
    const on = btn.dataset.outline === active;
    btn.classList.toggle("active", on);
    if (on) btn.setAttribute("aria-current", "true");
    else btn.removeAttribute("aria-current");
  });
  // 面板里的行跟着一起高亮
  $$("#chat-outline-panel-list [data-outline]").forEach((row) => {
    row.classList.toggle("active", row.dataset.outline === active);
  });
}

function renderChatOutline() {
  const list = $("#chat-outline-list");
  if (!list) return;
  const items = chatOutlineItems();
  const count = $("#chat-outline-count");
  if (count) {
    count.textContent = String(items.length);
    count.title = `本会话提问 ${items.length} 条 · 鼠标移上来列全部，点一下跳过去`;
  }
  const panelCount = $("#chat-outline-panel-count");
  if (panelCount) panelCount.textContent = `${items.length} 条`;
  // 签名没变就不重建：流式输出时对话每秒都在重画，重建侧栏会让高亮闪烁
  const sig = items.map((item) => `${item.index}:${String(item.message.content || "").length}`).join("|");
  if (sig === outlineSig) { markOutlineActive(); return; }
  outlineSig = sig;
  list.innerHTML = items.length
    ? items.map((item) => `
      <button class="chat-outline-item${item.message.auto ? " auto" : ""}" data-outline="${item.index}"
        aria-label="${esc(outlineLabel(item.message.content))}"><i></i></button>`).join("")
    : '<p class="chat-outline-empty">暂无提问</p>';
  const panelList = $("#chat-outline-panel-list");
  if (panelList) {
    panelList.innerHTML = items.length
      ? items.map((item, order) => {
        const text = String(item.message.content || "").replace(/\s+/g, " ").trim();
        return `
        <button class="outline-panel-item" data-outline="${item.index}" title="${esc(text)}">
          <b>${String(order + 1).padStart(2, "0")}</b>
          <span>${item.message.auto ? '<span class="outline-auto">自动</span>' : ""}${esc(text.length > 80 ? `${text.slice(0, 80)}…` : text)}</span>
        </button>`;
      }).join("")
      : '<p class="chat-outline-empty">本会话还没提问</p>';
  }
  markOutlineActive();
}

// 鼠标移到点列上：弹出面板，一次看全本会话所有提问
function showOutlinePanel() {
  clearTimeout(outlineHideTimer);
  const panel = $("#chat-outline-panel");
  if (!panel) return;
  if (!(state.chatMessages || []).some((m) => m.role === "user")) return;
  panel.classList.remove("hidden");
  markOutlineActive();
}

function hideOutlinePanel() {
  clearTimeout(outlineHideTimer);
  // 留一点缓冲：从点列斜着移到面板上，中间会短暂离开点列
  outlineHideTimer = setTimeout(() => {
    $("#chat-outline-panel")?.classList.add("hidden");
  }, 180);
}

function jumpToMessage(index) {
  const box = $("#chat-messages");
  if (!box) return;
  const node = box.querySelector(`.chat-msg[data-idx="${index}"]`);
  if (!node) return;
  // 定位是主动行为：先把「贴底跟随」关掉，否则流式输出会把视线又拽回底部
  state.chatPinned = false;
  const boxRect = box.getBoundingClientRect();
  const nodeRect = node.getBoundingClientRect();
  const target = box.scrollTop + (nodeRect.top - boxRect.top) - Math.max(10, (box.clientHeight - nodeRect.height) / 2);
  const top = Math.max(0, target);
  // 隔得远就直接跳到位：长距离平滑滚动既慢又容易被后续重绘打断，最后停不到目标上
  const near = Math.abs(top - box.scrollTop) <= box.clientHeight * 2;
  box.scrollTo({ top, behavior: near ? "smooth" : "auto" });
  node.classList.remove("flash");
  void node.offsetWidth;  // 强制重排，让动画能重新触发
  node.classList.add("flash");
  setTimeout(() => node.classList.remove("flash"), 1200);
  outlineLockUntil = Date.now() + 800;
  markOutlineActive(index);
}

function renderChatMessages(anchor) {
  const box = $("#chat-messages");
  if (!box) return;
  const messages0 = state.chatMessages || [];
  // 划词期间整页重建会把选中的节点换掉，选区落到隔壁行：先记账，松手后统一重画。
  // 两个例外照画：列表还是空的（第一次进来）、来了新的选择卡/确认卡（要用户拍板的事比选区要紧）。
  const cardSig = messages0
    .filter((item) => item.role === "choice" || item.role === "confirm")
    .map((item) => String(item.choice_id || item.action_id || ""))
    .join(",");
  const shownCards = box.dataset.cards || "";
  if (chatDragging() && box.childElementCount && cardSig === shownCards) {
    state.chatRenderDirty = true;
    return;
  }
  box.dataset.cards = cardSig;
  // 侧栏跟着对话一起更新：条数、当前高亮都要对得上
  renderChatOutline();
  const lastMsg = messages0[messages0.length - 1];
  // 卡片是最后一条时，默认锚到上一条回答：让用户先读到结论，而不是一屏按钮
  const mode = anchor || (lastMsg && (lastMsg.role === "choice" || lastMsg.role === "confirm") ? "answer" : "");
  const prevTop = box.scrollTop;
  // 用户往上翻看历史时不要把他拽回底部；贴底时始终保持跟到最新
  const wasPinned = state.chatPinned === undefined || state.chatPinned === null
    ? true
    : state.chatPinned || chatPinned(box);
  const messages = messages0;
  if (!messages.length && !state.chatTyping) {
    box.innerHTML = CHAT_EMPTY;
    state.chatPinned = true;
    return;
  }
  // 选择题卡片已经展示问题原文时，跳过重复的助手气泡
  const pendingQuestions = new Set(
    messages
      .filter((item) => item.role === "choice")
      .map((item) => String(item.question || "").trim())
  );
  const parts = messages.map((message, index) => {
    // 工具过程只在后台跑，会话里只留对话、进展与需要用户拍板的卡片
    if (message.role === "tool") return "";
    if (message.role === "activity") return "";
    if (message.role === "progress") return chatProgress(message);
    if (message.role === "finding") return chatFindingCard(message);
    if (message.role === "confirm") {
      return chatConfirmCard(message);
    }
    if (message.role === "choice") {
      return chatChoiceCard(message);
    }
    if (message.role === "assistant" && pendingQuestions.has(String(message.content || "").trim())) {
      return "";
    }
    return chatBubble(message, index);
  }).join("");
  const typing = renderTypingIndicator();
  // 手已经松了但文字还选着：重画前记下位置，画完把高亮放回同一段文字上，
  // 这样「继续刷新」和「选中不丢」能同时成立
  const keepSelection = chatHasSelection(box) ? captureChatSelection(box) : null;
  box.innerHTML = parts + typing;
  if (keepSelection) restoreChatSelection(box, keepSelection);
  // 滚动位置在这一帧里才落定，下一帧再算「当前看到哪一条」
  requestAnimationFrame(() => markOutlineActive());
  if (!state.chatTyping) state.chatTypingAt = 0;
  // 聊天页没打开时量不到尺寸，别拿 0 去算（会把滚动条顶到最上面）
  if (!box.clientHeight) return;
  if (mode === "answer") {
    scrollToLastCard(box);
    state.chatPinned = chatPinned(box);
    return;
  }
  if (mode === "bottom" || wasPinned) {
    // 贴底要连贴三次：一帧之内的高度变化很常见，只贴一次总会差那么一点
    pinChatBottom(box);
    state.chatPinned = true;
  } else {
    // 没贴底就停在原处：新内容是往后面追加的，不该把视线推走
    box.scrollTop = prevTop;
    state.chatPinned = chatPinned(box);
  }
}

function renderChatSessions() {
  const list = state.chatSessions || [];
  $("#chat-session-list").innerHTML = list.length
    ? list.map((session) => `
      <div class="chat-session-item ${session.id === state.chatSessionId ? "active" : ""}" data-session="${session.id}">
        <div class="chat-session-main">
          <strong>${esc(session.title || "新会话")}</strong>
          <small>${esc(fmtTime(session.updated_at).slice(5))} · ${session.message_count} 条</small>
        </div>
        <button class="chat-session-del" data-del-session="${session.id}" title="删除会话">×</button>
      </div>`).join("")
    : `<div class="empty-state">暂无会话</div>`;
}

// 没接入模型时不再挂常驻提示条：只在真的点发送时用一条 toast 说明该去哪儿配
function renderChatProviders(status) {
  const select = $("#chat-provider");
  const providers = state.chatProviders || [];
  if (!status.available || !providers.length) {
    select.innerHTML = `<option value="">没有可用模型</option>`;
    select.disabled = true;
    return;
  }
  select.disabled = false;
  select.innerHTML = providers.map((provider) => (
    `<option value="${esc(provider.key)}">${esc(provider.name)}${provider.model ? ` · ${esc(provider.model)}` : ""}</option>`
  )).join("");
  const preferred = state.chatProvider || status.default;
  select.value = preferred && providers.some((p) => p.key === preferred) ? preferred : providers[0].key;
  state.chatProvider = select.value;
}

function setChatBusy(busy) {
  state.chatBusy = busy;
  // 跑着的时候能力方块要跟着涨：模型每报一项就重算一次（5 秒一次，够快也不打扰）
  clearInterval(state.covTimer);
  if (busy) state.covTimer = setInterval(() => { updateCovChip(); }, 5000);
  const send = $("#chat-send");
  const input = $("#chat-input");
  // 忙的时候输入框照常可用，按发送就是把这句话直接交给正在跑的任务，界面上不区分
  if (send) {
    send.disabled = !(state.chatProviders || []).length;
    send.textContent = "发送";
    send.title = "发送";
  }
  if (input) {
    input.disabled = false;
    input.placeholder = "说清你要的结果，例如：把这批资产过一遍，列出必须先修的风险";
  }
  const composeHint = $("#chat-compose-hint");
  if (composeHint) composeHint.textContent = "Enter 发送 · Shift+Enter 换行";
  const stop = $("#chat-stop");
  if (stop) stop.classList.toggle("hidden", !busy);
  if (typeof paintAutoBar === "function") paintAutoBar();
}

async function loadChat() {
  const status = await api("/api/chat/status");
  state.chatProviders = status.providers || [];
  state.chatStatus = status;
  renderChatProviders(status);
  const sessions = (await api("/api/chat/sessions")) || [];
  state.chatSessions = sessions;
  state.chatMessages = state.chatMessages || [];
  if (!state.chatSessionId && sessions.length) {
    await openChatSession(sessions[0].id);
    return;
  }
  renderChatSessions();
  $("#chat-title").textContent = sessions.find((s) => s.id === state.chatSessionId)?.title || "新会话";
  renderChatMessages();
  // 一个会话都还没有时也要把「这一轮要测几项」显示出来（0/N），不能空着
  updateCovChip();
  $("#chat-send").disabled = state.chatBusy || !state.chatProviders.length;
}

async function openChatSession(sessionId) {
  // 单模型会话走原来的布局；双模型那一套交给 duo.js
  if (typeof duoShowSingle === "function") duoShowSingle();
  // 切会话就等于离开上一件事：先把还在跑的那一轮真正停掉，再切过去
  if (state.chatBusy && Number(sessionId) !== state.chatSessionId) haltCurrentRun();
  clearChatSelection();
  state.chatSessionId = Number(sessionId);
  state.chatStopped = false;
  const data = await api(`/api/chat/sessions/${sessionId}`);
  state.chatMessages = (data.messages || [])
    .filter((item) => item.role !== "tool")
    .map((item) => {
      if (item.role === "finding") {
        let card = {};
        try { card = JSON.parse(item.content || "{}"); } catch (error) { card = { title: item.content || "" }; }
        return { role: "finding", finding: card || {} };
      }
      // 回放也要能认出「这句是自动继续替你发的」，和实时看到的一致
      if (item.role === "user" && item.level === "auto") {
        return { ...item, auto: true };
      }
      return item;
    });
  updateCovChip();
  (data.choices || []).forEach((item) => {
    state.chatMessages.push({
      role: "choice",
      choice_id: item.id,
      question: item.question,
      options: item.options || [],
      allow_custom: !!item.allow_custom,
      decision: "pending",
    });
  });
  (data.pending || []).forEach((item) => {
    state.chatMessages.push({
      role: "confirm",
      action_id: item.id,
      tool: item.tool,
      label: item.label,
      summary: item.summary,
      args: item.args || {},
      decision: "pending",
    });
  });
  $("#chat-title").textContent = data.title || "会话";
  state.chatPinned = true;
  renderChatMessages("bottom");
  renderChatSessions();
  // 后台还在跑（刷新页面、切走再切回来）：从现在这条 seq 往后接上，
  // 不重发消息、也不会把已经显示过的内容再渲染一遍
  if (data.running) attachRunningSession(sessionId, Number(data.seq) || 0);
}

// 接上已经在后台跑着的那一批：只收后续事件，界面照常往前长
async function attachRunningSession(sessionId, seq) {
  const controller = new AbortController();
  state.chatAbort = controller;
  state.chatStopped = false;
  state.chatTyping = "这一轮还在后台跑，已接上…";
  state.chatTypingAt = Date.now();
  setChatBusy(true);
  renderChatMessages("bottom");
  try {
    const resumed = await followRun(sessionId, seq, controller);
    if (!resumed.ok && !controller.signal.aborted) {
      state.chatMessages.push({
        role: "progress",
        content: "没接上后台这一轮；它可能已经结束了，发一句话就能看最新状态。",
        level: "step",
      });
    }
  } finally {
    if (state.chatSessionId === sessionId) {
      state.chatAbort = null;
      state.chatTyping = "";
      setChatBusy(false);
      renderChatMessages();
    }
  }
}

async function newChatSession() {
  // 不再拦着不让新建：先停掉当前这一轮，再开新会话。
  // 服务端还会取消这个用户名下所有在跑的轮次，避免"新会话里旧任务还在跑"。
  if (state.chatBusy) haltCurrentRun();
  clearChatSelection();
  const data = await api("/api/chat/sessions", { method: "POST", body: {} });
  state.chatSessions.unshift({ id: data.id, title: data.title, created_at: data.created_at, updated_at: data.created_at, message_count: 0 });
  state.chatSessionId = data.id;
  state.chatMessages = [];
  state.chatPinned = true;
  state.chatStopped = false;
  $("#chat-title").textContent = data.title || "新会话";
  renderChatMessages();
  renderChatSessions();
  // 新会话的能力台账是空的：这里必须重算，否则标题右边还挂着上一个会话的「4/59」
  updateCovChip();
  $("#chat-input").focus();
}

function finalizeStreaming() {
  state.chatMessages.forEach((message) => {
    if (message.streaming) message.streaming = false;
  });
}

// 卡片紧跟在正文后时，去掉正文末尾的「：」等悬空标点
function trimTrailingBubble() {
  const last = state.chatMessages[state.chatMessages.length - 1];
  if (last && last.role === "assistant") {
    last.content = String(last.content || "").replace(/[\s:：,，、;；*]+$/, "");
  }
}

function handleChatEvent(event) {
  if (!event || !event.type) return;
  let anchor = "";
  if (event.type === "status") {
    state.chatTyping = event.message || "思考中…";
  } else if (event.type === "delta") {
    const last = state.chatMessages[state.chatMessages.length - 1];
    if (last && last.role === "assistant" && last.streaming) {
      last.content += event.content || "";
    } else {
      state.chatMessages.push({ role: "assistant", content: event.content || "", streaming: true });
    }
    state.chatTyping = "";
    // 增量只重画这一条气泡，别整页重排（长输出就是这么卡死的）
    scheduleStreamPaint();
    return;
  } else if (event.type === "progress") {
    // 每一步做完都留一条：「已确认…，接下来…」。这些进展累积起来，就是这一轮
    // 到底做了什么的记录，回看靠它——所以不覆盖、不删除，只把「正在读取记忆」
    // 和紧跟着的「已读完记忆」合成一条，免得两行说同一件事。
    finalizeStreaming();
    const text = String(event.content || "").trim();
    const level = event.level || "";
    const isKey = text ? progressIsKey(level, text) : false;
    if (text) {
      const messages = state.chatMessages;
      const last = messages[messages.length - 1];
      const replacing = last && last.role === "progress" && last.level === "loading";
      if (replacing) {
        messages[messages.length - 1] = { role: "progress", content: text, level };
      } else {
        messages.push({ role: "progress", content: text, level });
      }
    }
    state.chatTyping = "继续下一步";
    state.chatTypingAt = Date.now();
    // 关键突破这类节点：一定要让用户看见
    if (isKey) {
      anchor = "bottom";
      state.chatPinned = true;
    }
  } else if (event.type === "finding") {
    // 模型刚归档一条漏洞：立刻就地显示，并把漏洞结果页的列表同步刷掉
    finalizeStreaming();
    state.chatMessages.push({ role: "finding", finding: event.finding || {} });
    state.chatTyping = "继续下一步";
    state.chatTypingAt = Date.now();
    anchor = "bottom";
    state.chatPinned = true;
    if (state.page === "findings") loadFindings({ quiet: true }).catch(() => {});
    if (state.page === "dashboard") loadDashboard().catch(() => {});
  } else if (event.type === "activity") {
    // 旧版本事件：痕迹已并入进展，忽略
  } else if (event.type === "tool") {
    // 兼容旧版事件：过程不展示
    finalizeStreaming();
  } else if (event.type === "message") {
    const text = event.content || "";
    const last = state.chatMessages[state.chatMessages.length - 1];
    if (last && last.role === "assistant" && last.streaming) {
      // 流式已经输出过同样内容，直接收尾，避免重复一段
      if (text) last.content = text;
      last.streaming = false;
    } else {
      state.chatMessages.push({ role: "assistant", content: text });
    }
    state.chatTyping = "";
  } else if (event.type === "confirm") {
    trimTrailingBubble();
    finalizeStreaming();
    state.chatMessages.push({
      role: "confirm",
      action_id: event.action_id,
      tool: event.tool,
      label: event.label,
      args: event.args,
      summary: event.summary,
      decision: "pending",
    });
    state.chatTyping = "";
    anchor = "answer";
  } else if (event.type === "choice") {
    trimTrailingBubble();
    finalizeStreaming();
    state.chatMessages.push({
      role: "choice",
      choice_id: event.choice_id,
      question: event.question,
      options: event.options || [],
      allow_custom: !!event.allow_custom,
      decision: "pending",
    });
    state.chatTyping = "";
    anchor = "answer";
  } else if (event.type === "cancelled") {
    // 后端真的把这一轮停了（循环退出、命令已终止），前端跟着收尾
    finalizeStreaming();
    state.chatTyping = "";
    state.chatStopped = true;
    state.chatMessages.push({
      role: "progress",
      content: event.message || "已按你的要求停止这一轮",
      level: "step",
    });
    setChatBusy(false);
  } else if (event.type === "error") {
    finalizeStreaming();
    const friendly = friendlyChatError(event.message);
    state.chatMessages.push({ role: "assistant", content: friendly, error: true });
    state.chatTyping = "";
    toast(friendly, "error");
  } else if (event.type === "auto_continue") {
    // 平台按你的预设把那句话发出去了：和手打的一样显示成你的消息，带「自动」小签
    finalizeStreaming();
    const text = String(event.text || "继续");
    state.chatMessages.push({ role: "user", content: text, auto: true });
    state.chatMessages.push({
      role: "progress",
      content: `自动继续（第 ${event.round || 2} 轮）：已替你发出「${text}」`,
      level: "step",
    });
    const cov = event.coverage || {};
    if (cov.selected) {
      state.chatMessages.push({
        role: "progress",
        content: `能力台账：已验 ${cov.done}/${cov.selected} 项（${cov.percent}%），还剩 ${cov.pending} 项`,
        level: "step",
      });
    }
    updateCovChip();
    // 把「第几轮、正在跑」写在等待提示上：模型下一轮开口前往往要等几十秒，
    // 只写「自动继续中」会让人以为它停了
    state.chatTyping = `自动继续中 · 第 ${event.round || 2} 轮已开始`;
    state.chatTypingAt = Date.now();
    anchor = "bottom";
    state.chatPinned = true;
  } else if (event.type === "auto_end") {
    // 自动继续停了：把原因说清楚，别让人以为卡住了
    finalizeStreaming();
    state.chatTyping = "";
    state.chatMessages.push({
      role: "progress",
      content: `自动继续结束：${event.reason || "已完成"}（共 ${event.rounds || 1} 轮）`,
      level: "step",
    });
    anchor = "bottom";
  } else if (event.type === "stream_end") {
    // 后台这一批跑完了（收尾由 consumeChatStream 处理），不往对话里塞东西
  } else if (event.type === "done") {
    finalizeStreaming();
    state.chatTyping = "";
    updateCovChip();
    if (state.chatStopped) {
      // 用户主动停的：不要再补一句「这一轮没有产生结论」
      state.chatStopped = false;
      renderChatMessages(anchor);
      return;
    }
    // 这一轮要有"交代"：结论、选择题或确认卡都算，只有进度条不算
    const messages = state.chatMessages || [];
    let lastUser = -1;
    messages.forEach((item, index) => { if (item.role === "user") lastUser = index; });
    const answered = messages.slice(lastUser + 1).some((item) => {
      if (item.role === "choice" || item.role === "confirm") return true;
      return item.role === "assistant" && String(item.content || "").trim() !== "";
    });
    if (!answered) {
      state.chatMessages.push({
        role: "assistant",
        content: "这一轮没有产生结论。换一种说法，或在「API 中心」换一个模型再试一次。",
        error: true,
      });
    }
  }
  renderChatMessages(anchor);
}

// 读一条 SSE 流。每条事件都带 seq：断线重连时把它带上，服务端只补漏掉的那些，
// 既不重复渲染，也不会像以前那样「连接一断，后面几轮全丢」。
// 返回 { ended, lastSeq }：ended 表示这一批执行真的收口了（后台 stream_end / 自动继续结束 / 被停止）。
async function consumeChatStream(response, signal, startSeq = 0) {
  let lastSeq = Number(startSeq) || 0;
  let ended = false;
  if (response.status === 401) { showLogin(); throw new Error("登录状态已失效"); }
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && data.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch (err) { /* 保留默认提示 */ }
    throw new Error(detail);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  while (true) {
    if (signal?.aborted) {
      try { await reader.cancel(); } catch (err) { /* 已取消 */ }
      return { ended, lastSeq };
    }
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let splitIndex;
    while ((splitIndex = buffer.indexOf("\n\n")) >= 0) {
      const chunk = buffer.slice(0, splitIndex);
      buffer = buffer.slice(splitIndex + 2);
      chunk.split("\n").forEach((line) => {
        if (!line.startsWith("data:")) return;
        let event;
        try { event = JSON.parse(line.slice(5).trim()); } catch (err) { return; }
        if (!event || !event.type) return;
        if (Number(event.seq) > lastSeq) lastSeq = Number(event.seq);
        // 后台任务结束时补的终止标记：不是对话内容，只用来收尾
        if (event.type === "stream_end") { ended = true; return; }
        handleChatEvent(event);
        if (event.type === "auto_end" || event.type === "cancelled") ended = true;
      });
    }
  }
  return { ended, lastSeq };
}

// 连接断了就地续上：带 lastSeq 重新订阅，服务端把漏掉的补齐再往下推。
// 断一次不再等于「整条自动继续废掉」，界面上也把「正在重连」说清楚，不装没事。
const RESUME_ROUNDS = 8;
async function followRun(sessionId, lastSeq, controller) {
  let seq = Number(lastSeq) || 0;
  let attempt = 0;
  while (attempt < RESUME_ROUNDS) {
    if (controller.signal.aborted) return { ok: false, lastSeq: seq };
    attempt += 1;
    state.chatTyping = `连接断了，正在重连（第 ${attempt} 次）· 后台还在跑`;
    state.chatTypingAt = Date.now();
    renderChatMessages("bottom");
    await new Promise((resolve) => setTimeout(resolve, Math.min(6000, 700 * attempt)));
    if (controller.signal.aborted) return { ok: false, lastSeq: seq };
    try {
      const response = await fetch(
        `/api/chat/sessions/${sessionId}/stream?after=${seq}`,
        { credentials: "same-origin", signal: controller.signal },
      );
      const out = await consumeChatStream(response, controller.signal, seq);
      seq = out.lastSeq;
      attempt = 0; // 又接上了：重试次数清零，下次再断重新算
      if (out.ended) {
        state.chatTyping = "";
        return { ok: true, lastSeq: seq };
      }
    } catch (error) {
      if (controller.signal.aborted) return { ok: false, lastSeq: seq };
    }
  }
  return { ok: false, lastSeq: seq };
}

async function refreshChatSessions() {
  try {
    state.chatSessions = await api("/api/chat/sessions");
    renderChatSessions();
    const current = state.chatSessions.find((s) => s.id === state.chatSessionId);
    if (current) $("#chat-title").textContent = current.title;
  } catch (error) { /* 忽略刷新失败 */ }
}

async function decideAction(actionId, approve, button) {
  if (state.chatBusy) return;
  const message = state.chatMessages.find(
    (item) => item.role === "confirm" && Number(item.action_id) === Number(actionId)
  );
  if (button) button.disabled = true;
  if (message) message.decision = approve ? "approved" : "rejected";
  setChatBusy(true);
  state.chatStopped = false;
  state.chatTyping = approve ? "正在执行已确认操作…" : "正在整理…";
  // 确认之后马上会有新内容：回到贴底状态，别让答案长在看不见的地方
  state.chatPinned = true;
  renderChatMessages("bottom");
  const controller = new AbortController();
  state.chatAbort = controller;
  try {
    const response = await fetch(`/api/chat/actions/${actionId}/decide`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approve, provider: state.chatProvider }),
      signal: controller.signal,
    });
    const out = await consumeChatStream(response, controller.signal, 0);
    const sessionId = state.chatSessionId;
    if (!out.ended && !controller.signal.aborted && sessionId) {
      await followRun(sessionId, out.lastSeq, controller);
    }
  } catch (error) {
    if (!controller.signal.aborted) {
      const friendly = friendlyChatError(error.message);
      state.chatMessages.push({ role: "assistant", content: friendly, error: true });
      toast(friendly, "error");
    }
  } finally {
    state.chatAbort = null;
    state.chatTyping = "";
    setChatBusy(false);
    renderChatMessages();
    await refreshChatSessions();
  }
}

// 把用户这句话交给正在跑的任务；没送进去返回 false（调用方按新消息发送）
async function interjectChat(text) {
  if (!state.chatSessionId) return false;
  try {
    const response = await fetch(`/api/chat/sessions/${state.chatSessionId}/interject`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: text }),
    });
    if (!response.ok) return false;
    const data = await response.json();
    if (!data || !data.delivered) return false;
    state.chatMessages.push({ role: "user", content: text });
    state.chatTyping = "收到，正在按你说的调整…";
    state.chatTypingAt = Date.now();
    renderChatMessages("bottom");
    return true;
  } catch (error) {
    return false;
  }
}

async function sendChatText(text) {
  const value = String(text || "").trim();
  if (!value) return false;
  if (state.chatBusy) {
    if (await interjectChat(value)) return true;
    // 那一轮刚好收尾：等它落地再当新消息发，别把用户的话弄丢
    for (let i = 0; i < 20 && state.chatBusy; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (state.chatBusy) return false;
  }
  if (!state.chatProviders.length) {
    toast("先在「API 中心」接入大模型，我才能开始工作", "error");
    return false;
  }
  if (!state.chatSessionId) await newChatSession();

  // 点了选项就把这张卡片关掉，避免重复点
  [...state.chatMessages].reverse().forEach((message) => {
    if (message.role === "choice" && message.decision === "pending") {
      message.decision = "chosen";
      message.chosen = value;
    }
  });

  state.chatMessages.push({ role: "user", content: value });
  state.chatTyping = "正在处理…";
  state.chatStopped = false;
  setChatBusy(true);
  renderChatMessages("bottom");

  const controller = new AbortController();
  state.chatAbort = controller;
  const sessionId = state.chatSessionId;
  let failed = false;
  try {
    const response = await fetch(`/api/chat/sessions/${sessionId}/messages`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: value, provider: state.chatProvider }),
      signal: controller.signal,
    });
    const out = await consumeChatStream(response, controller.signal, 0);
    // 流断在半路（后台还在跑）：带着 lastSeq 续上，而不是把界面停在这里
    if (!out.ended && !controller.signal.aborted && state.chatSessionId === sessionId) {
      const resumed = await followRun(sessionId, out.lastSeq, controller);
      if (!resumed.ok && !controller.signal.aborted) {
        state.chatMessages.push({
          role: "progress",
          content: "连接反复断开，这一轮没接上；后台可能仍在执行，重新打开这个会话就能看到后续。",
          level: "step",
        });
      }
    }
  } catch (error) {
    state.chatTyping = "";
    // 已经切到别的会话了：这一轮的结果不该再往新会话里塞
    if (state.chatSessionId === sessionId) {
      if (controller.signal.aborted) {
        state.chatMessages.push({ role: "assistant", content: "已按你的要求停下。需要继续时把目标再说一句就行。", error: true });
      } else {
        const friendly = friendlyChatError(error.message);
        state.chatMessages.push({ role: "assistant", content: friendly, error: true });
        toast(friendly, "error");
      }
    }
    failed = true;
  } finally {
    state.chatAbort = null;
    if (state.chatSessionId === sessionId) {
      state.chatTyping = "";
      setChatBusy(false);
      renderChatMessages();
    }
    await refreshChatSessions();
  }
  return !failed;
}

async function sendChatMessage(event) {
  if (event) event.preventDefault();
  const input = $("#chat-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  const ok = await sendChatText(text);
  // 发失败就把内容放回输入框，别让用户重打一遍
  if (ok === false) {
    input.value = text;
    input.focus();
  }
}

// 停掉当前这一轮：服务端标记取消 + 断开本地流，不动界面（切换会话时会调用）
function haltCurrentRun() {
  const sessionId = state.chatSessionId;
  if (sessionId) {
    fetch(`/api/chat/sessions/${sessionId}/stop`, {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
    }).catch(() => { /* 无网络也要能切走 */ });
  }
  if (state.chatAbort) {
    try { state.chatAbort.abort(); } catch (err) { /* 已断开 */ }
    state.chatAbort = null;
  }
  state.chatTyping = "";
  state.chatStopped = true;
  setChatBusy(false);
}

function stopChat() {
  // 只是关掉前端连接没用：后端循环还在跑，命令也还在后台执行。
  // 必须先让服务端真正停下这一轮（清取消标记 + 杀掉在跑的命令），再断开本地流。
  haltCurrentRun();
  renderChatMessages();
}

// ---------- 自动继续 ----------
// 跑完一轮，平台把这句预设话原样当成用户消息发出去，让模型接着干。
// 次数不设上限；后端的刹车是「连续 3 轮没新动作」和「等你拍板」。
async function loadAutoSettings() {
  try {
    const data = await api("/api/chat/auto");
    state.autoContinue = !!data.enabled;
    state.autoText = data.text || "继续";
    const box = $("#auto-continue");
    const text = $("#auto-text");
    if (box) box.checked = state.autoContinue;
    if (text) text.value = state.autoText;
    paintAutoBar();
  } catch (error) {
    /* 读不到就用默认值，不打扰 */
  }
}

function paintAutoBar() {
  const bar = $("#auto-bar");
  const hint = $("#auto-hint");
  const stop = $("#auto-stop");
  if (bar) bar.classList.toggle("on", !!state.autoContinue);
  if (hint) {
    hint.textContent = state.autoContinue
      ? `每轮跑完自动发「${state.autoText || "继续"}」· 不限次数`
      : "跑完一轮就替你发一句 · 不限次数";
  }
  if (stop) stop.classList.toggle("hidden", !(state.autoContinue && state.chatBusy));
}

let autoSaveTimer = 0;
function saveAuto(enabled, text) {
  state.autoContinue = !!enabled;
  state.autoText = (text || "继续").slice(0, 200) || "继续";
  paintAutoBar();
  clearTimeout(autoSaveTimer);
  autoSaveTimer = setTimeout(async () => {
    try {
      await api("/api/chat/auto", {
        method: "POST",
        body: { enabled: state.autoContinue, text: state.autoText },
      });
    } catch (error) {
      toast(`自动继续设置没保存上：${error.message}`, "error");
    }
  }, 260);
}

async function updateCovChip() {
  const chip = $("#cov-chip");
  if (!chip) return;
  const sid = state.chatSessionId;
  // 切会话/新建会话时可能有多个请求同时在飞：只让最后一次的结果落到界面上，
  // 否则旧会话的 "4/59" 会在新会话里回填上来。
  const seq = (state.covChipSeq = (state.covChipSeq || 0) + 1);
  if (!sid) {
    // 还没开会话（全新装、会话被删光）：也要显示这轮要测几项，不能空着。
    // 勾选数从能力配置里取一次，缓存住，省得每 5 秒轮询都打一遍接口。
    let total = Number(state.capabilitySelected || 0);
    if (!total) {
      try {
        const data = await api("/api/capabilities");
        total = (data.enabled || []).length;
        state.capabilitySelected = total;
      } catch (error) {
        total = 0;
      }
      if (seq !== state.covChipSeq || state.chatSessionId) return;
    }
    if (!total) {
      chip.classList.add("hidden");
      chip.textContent = "";
      return;
    }
    chip.innerHTML = `<b>0/${total}</b><small>还差 ${total}</small>`;
    chip.classList.remove("done");
    chip.title = `能力覆盖台账：已勾选 ${total} 项，这个会话还没开始测`;
    chip.classList.remove("hidden");
    return;
  }
  try {
    const data = await api(`/api/chat/sessions/${sid}/coverage`);
    if (seq !== state.covChipSeq || state.chatSessionId !== sid) return;
    const sum = data.summary || {};
    // 一项都没勾时不占位置；勾了就一定显示——新会话也要显示 0/N，不能留着上一个会话的数
    if (!sum.selected) {
      chip.classList.add("hidden");
      chip.textContent = "";
      return;
    }
    state.capabilitySelected = sum.selected;
    // 方块里只放两个数：已验/已勾、还差几项。看得清、也不占标题的地。
    chip.innerHTML = sum.pending
      ? `<b>${sum.done}/${sum.selected}</b><small>还差 ${sum.pending}</small>`
      : `<b>${sum.done}/${sum.selected}</b><small>已测完</small>`;
    chip.classList.toggle("done", !sum.pending);
    const left = (data.items || [])
      .filter((item) => item.status === "pending" || item.status === "inconclusive")
      .map((item) => item.name);
    chip.title = left.length
      ? `能力覆盖台账：已验 ${sum.done} 项（${sum.percent}%），还差 ${sum.pending} 项\n还没结论：${left.slice(0, 20).join("、")}${left.length > 20 ? " 等" : ""}`
      : `能力覆盖台账：勾选的 ${sum.selected} 项全部有结论`;
    chip.classList.remove("hidden");
  } catch (error) {
    if (seq === state.covChipSeq && state.chatSessionId === sid) chip.classList.add("hidden");
  }
}

$("#auto-continue")?.addEventListener("change", (event) => {
  saveAuto(event.target.checked, $("#auto-text")?.value || "继续");
});
$("#auto-text")?.addEventListener("input", (event) => {
  saveAuto(!!$("#auto-continue")?.checked, event.target.value);
});
$("#auto-stop")?.addEventListener("click", () => {
  stopChat();
  state.autoContinue = false;
  if ($("#auto-continue")) $("#auto-continue").checked = false;
  saveAuto(false, state.autoText || "继续");
  toast("已停止，自动继续已关掉", "ok");
});

$("#chat-form").addEventListener("submit", sendChatMessage);
// 记住用户是不是贴着底部看：手动往上翻过就别再把他拽回来
$("#chat-messages").addEventListener("scroll", () => {
  const box = $("#chat-messages");
  if (!box || !box.clientHeight) return;
  state.chatPinned = chatPinned(box);
});
// 划词期间冻结自动贴底与整页重画：模型还在流式输出，滚动一跟、列表一重建，
// 用户按下的那一行就会被顶到上面去，高亮也跟着错位（「选下面却选中上面」）
$("#chat-messages").addEventListener("mousedown", () => { state.chatSelecting = true; });
document.addEventListener("mouseup", () => {
  if (!state.chatSelecting) return;
  state.chatSelecting = false;
  flushChatRender();
});
// 拖到窗口外松手收不到 mouseup：失焦时兜底解锁，别让渲染一直冻着
window.addEventListener("blur", () => { state.chatSelecting = false; });
// 选区被清掉（点别处、按 Esc）就把攒下的新内容补画上
document.addEventListener("selectionchange", () => {
  const box = $("#chat-messages");
  if (!box || chatSelectionLocked(box)) return;
  flushChatRender();
});
$("#chat-messages").addEventListener("click", (event) => {
  const choiceButton = event.target.closest("[data-choice]");
  if (choiceButton) {
    sendChatText(choiceButton.dataset.value).catch((error) => toast(error.message, "error"));
    return;
  }
  const customButton = event.target.closest("[data-choice-custom]");
  if (customButton) {
    const input = document.getElementById(`choice-input-${customButton.dataset.choiceCustom}`);
    const value = (input?.value || "").trim();
    if (!value) { toast("请先输入内容", "error"); input?.focus(); return; }
    sendChatText(value).catch((error) => toast(error.message, "error"));
    return;
  }
  const focusButton = event.target.closest("[data-choice-custom-focus]");
  if (focusButton) {
    document.getElementById(`choice-input-${focusButton.dataset.choiceCustomFocus}`)?.focus();
    return;
  }
  const copy = event.target.closest("[data-copy-msg]");
  if (copy) {
    const message = state.chatMessages[Number(copy.dataset.copyMsg)];
    const text = String(message?.content || "");
    if (!text) { toast("这条没有可复制的内容", "error"); return; }
    copyText(text).then((ok) => toast(ok ? "已复制" : "复制失败，请手动选中", ok ? "" : "error"));
    return;
  }
  const openFindingBtn = event.target.closest("[data-open-finding]");
  if (openFindingBtn) {
    openFinding(Number(openFindingBtn.dataset.openFinding));
    return;
  }
  const button = event.target.closest("[data-decide]");
  if (!button) return;
  const actionId = Number(button.dataset.action);
  const approve = button.dataset.decide === "approve";
  decideAction(actionId, approve, button).catch((error) => toast(error.message, "error"));
});
$("#chat-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    sendChatMessage();
  }
});
$("#chat-stop")?.addEventListener("click", stopChat);
// 本会话提问：鼠标移到点列上弹出全部提问；点任意一条跳到那条消息。
// 滚动时反过来高亮当前看到的那一条。
$("#chat-outline")?.addEventListener("click", (event) => {
  const item = event.target.closest("[data-outline]");
  if (!item) return;
  hideOutlinePanel();
  jumpToMessage(Number(item.dataset.outline));
});
$("#chat-outline")?.addEventListener("mouseenter", showOutlinePanel);
$("#chat-outline")?.addEventListener("mouseleave", hideOutlinePanel);
$("#chat-outline")?.addEventListener("focusin", showOutlinePanel);
$("#chat-outline")?.addEventListener("focusout", hideOutlinePanel);
$("#chat-outline-panel")?.addEventListener("click", (event) => {
  const item = event.target.closest("[data-outline]");
  if (!item) return;
  hideOutlinePanel();
  jumpToMessage(Number(item.dataset.outline));
});
$("#chat-outline-panel")?.addEventListener("mouseenter", () => clearTimeout(outlineHideTimer));
$("#chat-outline-panel")?.addEventListener("mouseleave", hideOutlinePanel);
$("#chat-messages").addEventListener("scroll", () => {
  if (outlineScrollTimer) return;
  outlineScrollTimer = setTimeout(() => {
    outlineScrollTimer = 0;
    markOutlineActive();
  }, 80);
}, { passive: true });
$("#chat-copy-all")?.addEventListener("click", () => { copyAllChat(); });
$("#chat-new").addEventListener("click", () => newChatSession().catch((error) => toast(error.message, "error")));
$("#chat-provider").addEventListener("change", (event) => { state.chatProvider = event.target.value; });
$("#chat-session-list").addEventListener("click", (event) => {
  const remove = event.target.closest("[data-del-session]");
  if (remove) {
    event.stopPropagation();
    const sessionId = Number(remove.dataset.delSession);
    if (!window.confirm("删除这个会话及其全部记录？")) return;
    api(`/api/chat/sessions/${sessionId}`, { method: "DELETE" })
      .then(async () => {
        state.chatSessions = state.chatSessions.filter((item) => item.id !== sessionId);
        if (state.chatSessionId === sessionId) {
          state.chatSessionId = null;
          state.chatMessages = [];
        }
        renderChatSessions();
        renderChatMessages();
        toast("会话已删除");
      })
      .catch((error) => toast(error.message, "error"));
    return;
  }
  const item = event.target.closest("[data-session]");
  if (item) openChatSession(Number(item.dataset.session)).catch((error) => toast(error.message, "error"));
});

/* ---------------- boot ---------------- */
document.addEventListener("DOMContentLoaded", boot);
