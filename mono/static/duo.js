/* 双模型协同：左右两栏各跑一个模型，中间是它们之间的对话。
 *
 * 这一层不碰单会话那套逻辑（#chat-messages 那套原样留在 #chat-layout 里），
 * 所有状态按栏分开：两栏同时流式输出也不会互相踩。
 */
const DUO = {
  pair: null,
  lanes: { a: null, b: null },
  names: { a: "", b: "" },
  notes: [],
  lastNote: 0,
  timer: 0,
};

function duoEl(key) {
  return document.getElementById(`duo-${key}-messages`);
}

function duoLaneNew(key) {
  return {
    key,
    sessionId: 0,
    provider: "",
    modelName: "",
    messages: [],
    typing: "",
    typingAt: 0,
    seq: 0,
    running: false,
    ctrl: null,
    pinned: true,
    paint: 0,
    dirty: false,
  };
}

function duoBudget(count) {
  const chip = document.getElementById("duo-budget");
  if (!chip) return;
  const left = Number(count || 0);
  chip.classList.remove("hidden");
  chip.textContent = `互相唤醒 ${left} 次`;
  chip.classList.toggle("low", left <= 0);
}

function duoSetState(key) {
  const lane = DUO.lanes[key];
  const chip = document.getElementById(`duo-${key}-state`);
  if (!chip || !lane) return;
  if (!lane.sessionId) {
    chip.textContent = DUO.pair ? "待开工" : "选好就能开始";
    chip.className = "duo-state";
    return;
  }
  chip.textContent = lane.running ? "运行中" : "空闲";
  chip.className = `duo-state${lane.running ? " on" : ""}`;
}

/* 模型下拉：选项来自 API 中心已经配好并检测通过的那些 */
function duoReadyProviders() {
  return state.chatProviders || [];
}

function duoStoredModel(key) {
  try { return localStorage.getItem(`duo.model.${key}`) || ""; } catch (error) { return ""; }
}

function duoStoreModel(key, value) {
  try { localStorage.setItem(`duo.model.${key}`, value || ""); } catch (error) { /* 隐身模式存不了，不影响用 */ }
}

function duoStoredDir() {
  try { return localStorage.getItem("duo.workdir") || ""; } catch (error) { return ""; }
}

function duoStoreDir(value) {
  try { localStorage.setItem("duo.workdir", value || ""); } catch (error) { /* 同上 */ }
}

function duoFillModels() {
  const providers = duoReadyProviders();
  const keys = providers.map((item) => item.key);
  const fallback = [keys[0] || "", keys[1] || keys[0] || ""];
  ["a", "b"].forEach((key, index) => {
    const select = document.getElementById(`duo-${key}-model`);
    if (!select) return;
    const stored = duoStoredModel(key);
    const want = keys.includes(stored) ? stored : fallback[index];
    select.innerHTML = providers.length
      ? providers.map((item) => `<option value="${esc(item.key)}">${esc(item.name)}${item.model ? ` · ${esc(item.model)}` : ""}</option>`).join("")
      : `<option value="">还没有可用的模型</option>`;
    select.disabled = !providers.length;
    if (want) select.value = want;
    const lane = DUO.lanes[key];
    if (lane) {
      lane.provider = select.value;
      lane.modelName = select.selectedOptions[0]?.textContent || select.value;
    }
  });
}

function duoFromDetail(detail) {
  const messages = (detail.messages || [])
    .filter((item) => item.role !== "tool")
    .map((item) => {
      if (item.role === "finding") {
        let card = {};
        try { card = JSON.parse(item.content || "{}"); } catch (error) { card = { title: item.content || "" }; }
        return { role: "finding", finding: card || {} };
      }
      if (item.role === "user" && item.level === "auto") return { ...item, auto: true };
      return item;
    });
  (detail.choices || []).forEach((item) => {
    messages.push({
      role: "choice",
      choice_id: item.id,
      question: item.question,
      options: item.options || [],
      allow_custom: !!item.allow_custom,
      decision: "pending",
    });
  });
  (detail.pending || []).forEach((item) => {
    messages.push({
      role: "confirm",
      action_id: item.id,
      tool: item.tool,
      label: item.label,
      summary: item.summary,
      args: item.args || {},
      decision: "pending",
    });
  });
  return messages;
}

function duoTypingHtml(lane) {
  if (!lane.typing) return "";
  return `<div class="chat-typing duo-typing"><span class="dot"></span><span class="typing-text">${esc(lane.typing)}</span></div>`;
}

function duoBubble(message, index, role) {
  const text = String(message.content || "");
  const streaming = !!message.streaming;
  const body = message.role === "user" || streaming ? esc(text) : mdLite(text);
  const autoTag = message.auto ? `<span class="chat-auto-tag">自动</span>` : "";
  const copyBtn = streaming
    ? ""
    : `<div class="chat-actions"><button class="chat-copy" data-duo-copy="${index}" title="复制这条">复制</button></div>`;
  return `<div class="chat-msg ${message.role}" data-idx="${index}">
    <div class="chat-role">${message.role === "user" ? "你" : esc(role || "助手")}${autoTag}</div>
    <div class="chat-bubble${message.error ? " error" : ""}${streaming ? " streaming" : ""}">${body}</div>
    ${copyBtn}
  </div>`;
}

function duoRender(key, anchor) {
  const lane = DUO.lanes[key];
  const box = duoEl(key);
  if (!lane || !box) return;
  if (!lane.sessionId) {
    box.innerHTML = duoReadyProviders().length
      ? `<div class="chat-empty duo-empty"><p>${esc(lane.modelName || "这一栏")} 已就位。写一句话就开始，两栏各跑各的，中间会显示它们互相说了什么。</p></div>`
      : `<div class="chat-empty duo-empty"><p>还没有可用的模型。去「API 中心」填一个大模型的密钥并点一次检测，回来这里就能选。</p></div>`;
    return;
  }
  const messages = lane.messages || [];
  // 划词期间别整页重建，松手后由 flush 补画（和单会话里一样的处理）
  const cardSig = messages
    .filter((item) => item.role === "choice" || item.role === "confirm")
    .map((item) => String(item.choice_id || item.action_id || ""))
    .join(",");
  if (chatDragging() && box.childElementCount && cardSig === (box.dataset.cards || "")) {
    lane.dirty = true;
    return;
  }
  box.dataset.cards = cardSig;
  const lastMsg = messages[messages.length - 1];
  const mode = anchor || (lastMsg && (lastMsg.role === "choice" || lastMsg.role === "confirm") ? "answer" : "");
  const prevTop = box.scrollTop;
  const wasPinned = lane.pinned === undefined || lane.pinned === null ? true : lane.pinned || chatPinned(box);
  if (!messages.length && !lane.typing) {
    box.innerHTML = `<div class="chat-empty duo-empty"><p>等一句话就开始。${esc(lane.modelName || "")} 的每一步都会留在这里。</p></div>`;
    lane.pinned = true;
    return;
  }
  const parts = messages.map((message, index) => {
    if (message.role === "tool" || message.role === "activity") return "";
    if (message.role === "progress") return chatProgress(message);
    if (message.role === "finding") return chatFindingCard(message);
    if (message.role === "confirm") return chatConfirmCard(message);
    if (message.role === "choice") return chatChoiceCard(message);
    return duoBubble(message, index, lane.modelName);
  }).join("");
  const keep = chatHasSelection(box) ? captureChatSelection(box) : null;
  box.innerHTML = parts + duoTypingHtml(lane);
  if (keep) restoreChatSelection(box, keep);
  lane.dirty = false;
  if (!box.clientHeight) return;
  if (mode === "answer") {
    scrollToLastCard(box);
    lane.pinned = chatPinned(box);
    return;
  }
  if (mode === "bottom" || wasPinned) {
    pinChatBottom(box);
    lane.pinned = true;
  } else {
    box.scrollTop = prevTop;
    lane.pinned = chatPinned(box);
  }
}

/* 流式增量只改最后一条气泡，不整页重排：两栏同时输出时这是唯一不卡的办法 */
function duoPaint(key) {
  const lane = DUO.lanes[key];
  const box = duoEl(key);
  if (!lane || !box) return;
  const last = lane.messages[lane.messages.length - 1];
  if (!last || last.role !== "assistant" || !last.streaming) return;
  const nodes = box.querySelectorAll(".chat-msg.assistant");
  const node = nodes[nodes.length - 1];
  const bubble = node && node.querySelector(".chat-bubble");
  if (!bubble) {
    duoRender(key, "bottom");
    return;
  }
  bubble.classList.add("streaming");
  bubble.textContent = String(last.content || "");
  if (lane.pinned !== false) pinChatBottom(box);
}

function duoSchedulePaint(key) {
  const lane = DUO.lanes[key];
  if (!lane || lane.paint) return;
  lane.paint = requestAnimationFrame(() => {
    lane.paint = 0;
    duoPaint(key);
  });
}

function duoFinalize(key) {
  const lane = DUO.lanes[key];
  if (!lane) return;
  const last = lane.messages[lane.messages.length - 1];
  if (last && last.role === "assistant" && last.streaming) last.streaming = false;
}

function duoTrim(key) {
  const lane = DUO.lanes[key];
  if (!lane) return;
  const last = lane.messages[lane.messages.length - 1];
  if (last && last.role === "assistant" && !String(last.content || "").trim()) {
    lane.messages.pop();
  }
}

function duoEvent(key, event) {
  const lane = DUO.lanes[key];
  if (!lane || !event || !event.type) return;
  const messages = lane.messages;
  let anchor = "";
  if (event.type === "status") {
    lane.typing = event.message || "思考中…";
    lane.typingAt = Date.now();
  } else if (event.type === "delta") {
    const last = messages[messages.length - 1];
    if (last && last.role === "assistant" && last.streaming) {
      last.content += event.content || "";
    } else {
      messages.push({ role: "assistant", content: event.content || "", streaming: true });
    }
    lane.typing = "";
    duoSchedulePaint(key);
    return;
  } else if (event.type === "progress") {
    duoFinalize(key);
    const text = String(event.content || "").trim();
    const level = event.level || "";
    if (text) {
      const last = messages[messages.length - 1];
      const replacing = last && last.role === "progress" && last.level === "loading";
      if (replacing) messages[messages.length - 1] = { role: "progress", content: text, level };
      else messages.push({ role: "progress", content: text, level });
    }
    lane.typing = "继续下一步";
    lane.typingAt = Date.now();
    if (text && progressIsKey(level, text)) {
      anchor = "bottom";
      lane.pinned = true;
    }
  } else if (event.type === "finding") {
    duoFinalize(key);
    messages.push({ role: "finding", finding: event.finding || {} });
    lane.typing = "继续下一步";
    lane.typingAt = Date.now();
    anchor = "bottom";
    lane.pinned = true;
    if (state.page === "findings") loadFindings({ quiet: true }).catch(() => {});
    if (state.page === "dashboard") loadDashboard().catch(() => {});
  } else if (event.type === "activity" || event.type === "tool") {
    duoFinalize(key);
  } else if (event.type === "message") {
    const text = event.content || "";
    const last = messages[messages.length - 1];
    if (last && last.role === "assistant" && last.streaming) {
      if (text) last.content = text;
      last.streaming = false;
    } else {
      messages.push({ role: "assistant", content: text });
    }
    lane.typing = "";
  } else if (event.type === "confirm") {
    duoTrim(key);
    duoFinalize(key);
    messages.push({
      role: "confirm",
      action_id: event.action_id,
      tool: event.tool,
      label: event.label,
      args: event.args,
      summary: event.summary,
      decision: "pending",
    });
    lane.typing = "";
    anchor = "answer";
  } else if (event.type === "choice") {
    duoTrim(key);
    duoFinalize(key);
    messages.push({
      role: "choice",
      choice_id: event.choice_id,
      question: event.question,
      options: event.options || [],
      allow_custom: !!event.allow_custom,
      decision: "pending",
    });
    lane.typing = "";
    anchor = "answer";
  } else if (event.type === "cancelled") {
    duoFinalize(key);
    lane.typing = "";
    lane.running = false;
    messages.push({ role: "progress", content: event.message || "已按你的要求停止这一轮", level: "step" });
    duoSetState(key);
  } else if (event.type === "error") {
    duoFinalize(key);
    const friendly = friendlyChatError(event.message);
    messages.push({ role: "assistant", content: friendly, error: true });
    lane.typing = "";
    toast(`${DUO.names[key] || key.toUpperCase()}：${friendly}`, "error");
  } else if (event.type === "auto_continue") {
    duoFinalize(key);
    const text = String(event.text || "继续");
    messages.push({ role: "user", content: text, auto: true });
    messages.push({ role: "progress", content: `自动继续（第 ${event.round || 2} 轮）：已替你发出「${text}」`, level: "step" });
    const cov = event.coverage || {};
    if (cov.selected) {
      messages.push({
        role: "progress",
        content: `能力台账：已验 ${cov.done}/${cov.selected} 项（${cov.percent}%），还剩 ${cov.pending} 项`,
        level: "step",
      });
    }
    lane.typing = `自动继续中 · 第 ${event.round || 2} 轮已开始`;
    lane.typingAt = Date.now();
    anchor = "bottom";
    lane.pinned = true;
  } else if (event.type === "auto_end") {
    duoFinalize(key);
    lane.typing = "";
    messages.push({ role: "progress", content: `自动继续结束：${event.reason || "已完成"}（共 ${event.rounds || 1} 轮）`, level: "step" });
    anchor = "bottom";
  } else if (event.type === "done") {
    duoFinalize(key);
    lane.typing = "";
    let lastUser = -1;
    messages.forEach((item, index) => { if (item.role === "user") lastUser = index; });
    const answered = messages.slice(lastUser + 1).some((item) => {
      if (item.role === "choice" || item.role === "confirm") return true;
      return item.role === "assistant" && String(item.content || "").trim() !== "";
    });
    if (!answered) {
      messages.push({ role: "assistant", content: "这一轮没有产生结论。换一种说法，或在「API 中心」换一个模型再试一次。", error: true });
    }
  }
  duoRender(key, anchor);
}

async function duoConsume(key, response, signal, startSeq) {
  let lastSeq = Number(startSeq) || 0;
  let ended = false;
  if (response.status === 401) { showLogin(); throw new Error("登录状态已失效"); }
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data && data.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch (error) { /* 保留默认提示 */ }
    throw new Error(detail);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  while (true) {
    if (signal?.aborted) {
      try { await reader.cancel(); } catch (error) { /* 已取消 */ }
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
        try { event = JSON.parse(line.slice(5).trim()); } catch (error) { return; }
        if (!event || !event.type) return;
        if (Number(event.seq) > lastSeq) lastSeq = Number(event.seq);
        if (event.type === "stream_end") { ended = true; return; }
        duoEvent(key, event);
        if (event.type === "auto_end" || event.type === "cancelled") ended = true;
      });
    }
  }
  return { ended, lastSeq };
}

/* 跟一条栏的执行流：断了带 seq 续上，收口后把会话重新拉一遍对齐 */
async function duoAttach(key) {
  const lane = DUO.lanes[key];
  if (!lane || !lane.sessionId) return;
  if (lane.ctrl) lane.ctrl.abort();
  const ctrl = new AbortController();
  lane.ctrl = ctrl;
  lane.running = true;
  duoSetState(key);
  let attempt = 0;
  while (attempt <= 6) {
    if (ctrl.signal.aborted) break;
    try {
      const response = await fetch(
        `/api/chat/sessions/${lane.sessionId}/stream?after=${lane.seq}`,
        { credentials: "same-origin", signal: ctrl.signal },
      );
      const out = await duoConsume(key, response, ctrl.signal, lane.seq);
      lane.seq = out.lastSeq;
      attempt = 0;
      if (out.ended) break;
    } catch (error) {
      if (ctrl.signal.aborted) break;
      lane.typing = `连接断了，正在重连（第 ${attempt + 1} 次）`;
      duoRender(key, "");
      attempt += 1;
      await new Promise((resolve) => setTimeout(resolve, Math.min(6000, 700 * attempt)));
      continue;
    }
    if (ctrl.signal.aborted) break;
    // 流关了但没收到收口标记：后台可能还在跑，再连一次；连三次没动静就当结束
    attempt += 1;
    if (attempt > 3) break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  if (lane.ctrl === ctrl) lane.ctrl = null;
  lane.running = false;
  lane.typing = "";
  duoSetState(key);
  duoRender(key, "");
  duoReload(key, true).catch(() => {});
}

/* 以库里的内容为准重画一栏：卡片状态、待确认、刷新后的对齐都靠它 */
async function duoReload(key, quiet) {
  const lane = DUO.lanes[key];
  if (!lane || !lane.sessionId) return;
  const detail = await api(`/api/chat/sessions/${lane.sessionId}`);
  if (DUO.lanes[key] !== lane) return;
  lane.messages = duoFromDetail(detail);
  lane.seq = Math.max(lane.seq, Number(detail.seq || 0));
  if (!quiet) duoRender(key, "bottom");
  else duoRender(key, "");
}

/* 草稿态：还没建配对，但界面照样是两栏，选好模型写一句话就自动建 */
function duoDraft() {
  DUO.pair = null;
  DUO.notes = [];
  DUO.lastNote = 0;
  const title = document.getElementById("duo-title");
  if (title) title.textContent = "双模型协同";
  document.getElementById("duo-budget")?.classList.add("hidden");
  duoFillModels();
  ["a", "b"].forEach((key) => {
    const lane = duoLaneNew(key);
    const select = document.getElementById(`duo-${key}-model`);
    lane.provider = select ? select.value : "";
    lane.modelName = select?.selectedOptions[0]?.textContent || "";
    DUO.lanes[key] = lane;
    duoSetState(key);
    duoRender(key, "");
  });
  const dir = document.getElementById("duo-workdir");
  if (dir) dir.value = duoStoredDir();
  duoRenderNotes([]);
  duoRenderFiles([]);
}

/* 第一次下发时把配对建出来：左右模型就按界面上选的来，不用先进弹窗 */
async function duoEnsurePair(text) {
  if (DUO.pair) return DUO.pair;
  if (!duoReadyProviders().length) {
    throw new Error("还没有可用的模型：去「API 中心」填一个密钥并检测一下");
  }
  const a = document.getElementById("duo-a-model")?.value || "";
  const b = document.getElementById("duo-b-model")?.value || "";
  if (!a || !b) throw new Error("左右两栏都要选一个模型");
  const dir = document.getElementById("duo-workdir")?.value.trim() || "";
  const pair = await api("/api/chat/pairs", {
    method: "POST",
    body: { title: String(text || "").slice(0, 24), provider_a: a, provider_b: b, workdir: dir },
  });
  await duoOpenPair(pair.id);
  return DUO.pair;
}

async function duoSay(keys, text) {
  const content = String(text || "").trim();
  if (!content) return;
  try {
    await duoEnsurePair(content);
  } catch (error) {
    toast(error.message, "error");
    return;
  }
  const pair = DUO.pair;
  if (!pair) return;
  const lane = keys.length === 2 ? "both" : keys[0];
  const res = await api(`/api/chat/pairs/${pair.id}/say`, {
    method: "POST",
    body: { lane, content },
  });
  keys.forEach((key) => {
    const item = DUO.lanes[key];
    if (!item) return;
    item.messages.push({ role: "user", content });
    item.typing = "已下发，等它接话";
    item.typingAt = Date.now();
    item.pinned = true;
    // 新一轮的事件序号是从 1 重新数的，不重置就会把重连游标停在上一轮末尾
    item.seq = 0;
    duoRender(key, "bottom");
    duoAttach(key).catch(() => {});
  });
  auditHint(res);
}

function auditHint(res) {
  if (res && res.pair) {
    DUO.pair = res.pair;
    duoBudget(res.pair.peer_budget);
  }
}

async function duoDecide(key, actionId, approve, button) {
  const lane = DUO.lanes[key];
  if (!lane || !lane.sessionId) return;
  if (button) button.disabled = true;
  lane.messages.forEach((item) => {
    if (item.role === "confirm" && Number(item.action_id) === Number(actionId)) {
      item.decision = approve ? "approved" : "rejected";
    }
  });
  duoRender(key, "");
  if (lane.ctrl) lane.ctrl.abort();
  const ctrl = new AbortController();
  lane.ctrl = ctrl;
  lane.running = true;
  lane.seq = 0;
  duoSetState(key);
  try {
    const response = await fetch(`/api/chat/actions/${actionId}/decide`, {
      method: "POST",
      credentials: "same-origin",
      signal: ctrl.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approve, provider: lane.provider || "" }),
    });
    const out = await duoConsume(key, response, ctrl.signal, 0);
    lane.seq = out.lastSeq;
  } catch (error) {
    if (!ctrl.signal.aborted) toast(error.message, "error");
  } finally {
    if (lane.ctrl === ctrl) lane.ctrl = null;
    lane.running = false;
    lane.typing = "";
    duoSetState(key);
    duoRender(key, "");
    duoReload(key, true).catch(() => {});
  }
}

async function duoStopAll() {
  if (!DUO.pair) return;
  await api(`/api/chat/pairs/${DUO.pair.id}/stop`, { method: "POST" });
  ["a", "b"].forEach((key) => {
    const lane = DUO.lanes[key];
    if (!lane) return;
    if (lane.ctrl) { lane.ctrl.abort(); lane.ctrl = null; }
    lane.running = false;
    lane.typing = "";
    duoSetState(key);
    duoRender(key, "");
  });
  toast("两栏都已停止");
}

/* 共享目录的实时清单：两个模型写出来的东西都在这条里，每 1.5 秒刷一次 */
function duoRenderFiles(files) {
  const box = document.getElementById("duo-files");
  if (!box) return;
  const list = files || [];
  if (!list.length) {
    box.innerHTML = `<span class="duo-files-empty">目录还是空的，模型写出文件后会出现在这里</span>`;
    return;
  }
  box.innerHTML = list.slice(0, 10).map((item) => (
    `<span class="duo-file" title="${esc(item.name)} · ${esc(item.mtime)} · ${esc(humanSize(item.size))}">
      ${esc(item.name)}<em>${esc(humanSize(item.size))}</em>
    </span>`
  )).join("");
}

function duoRenderNotes() {  const list = document.getElementById("duo-peer-list");
  const count = document.getElementById("duo-peer-count");
  if (!list) return;
  const items = DUO.notes || [];
  if (count) count.textContent = `${items.length} 条`;
  if (!items.length) {
    list.innerHTML = `<p class="duo-peer-empty">两个模型互相交代的事会出现在这里：谁让谁去做什么、对方接没接。</p>`;
    return;
  }
  list.innerHTML = items.map((note) => {
    const from = note.from_lane === "a" ? (DUO.names.a || "左栏") : (DUO.names.b || "右栏");
    const to = note.to_lane === "a" ? (DUO.names.a || "左栏") : (DUO.names.b || "右栏");
    const status = note.status === "read" ? "已读" : note.status === "delivered" ? "已送达" : "待接收";
    return `<div class="duo-note from-${esc(note.from_lane || "a")}">
      <div class="duo-note-head">
        <span class="duo-note-from">${esc(from)}</span>
        <span class="duo-note-arrow">→</span>
        <span class="duo-note-to">${esc(to)}</span>
        <span class="duo-note-st ${esc(note.status || "")}">${status}</span>
      </div>
      <div class="duo-note-body">${esc(note.content || "")}</div>
      <div class="duo-note-time">${esc(fmtTime(note.created_at))}</div>
    </div>`;
  }).join("");
  list.scrollTop = list.scrollHeight;
}

async function duoPollNotes() {
  if (!DUO.pair) return;
  try {
    const data = await api(`/api/chat/pairs/${DUO.pair.id}/notes?after=${DUO.lastNote}`);
    if (data.notes && data.notes.length) {
      DUO.notes = DUO.notes.concat(data.notes);
      DUO.lastNote = Number(data.last || DUO.lastNote);
      duoRenderNotes();
    }
    if (typeof data.budget === "number") duoBudget(data.budget);
    if (Array.isArray(data.files)) duoRenderFiles(data.files);
    ["a", "b"].forEach((key) => {
      const lane = DUO.lanes[key];
      if (!lane || lane.ctrl) return;
      const running = !!(data.running && data.running[key]);
      if (running !== lane.running) {
        lane.running = running;
        duoSetState(key);
      }
      if (running && !lane.ctrl) duoAttach(key).catch(() => {});
    });
  } catch (error) { /* 轮询失败不打扰 */ }
}

function duoShowDuo() {
  document.getElementById("duo-view")?.classList.remove("hidden");
  document.getElementById("chat-layout")?.classList.add("hidden");
}

function duoShowSingle() {
  document.getElementById("duo-view")?.classList.add("hidden");
  const layout = document.getElementById("chat-layout");
  if (!layout) return;
  layout.classList.remove("hidden");
  // 单会话页要用到模型下拉和会话列表：进这一页时补一次，别让发送按钮是灰的
  if (typeof renderChatProviders === "function") renderChatProviders(state.chatStatus || {});
  if (typeof renderChatSessions === "function") renderChatSessions();
  const send = document.getElementById("chat-send");
  if (send) send.disabled = !!state.chatBusy || !((state.chatProviders || []).length);
}

function duoOpenHistory(open) {
  const drawer = document.getElementById("history-drawer");
  if (!drawer) return;
  const show = open === undefined ? drawer.classList.contains("hidden") : !!open;
  drawer.classList.toggle("hidden", !show);
}

async function duoRefreshHistory() {
  const [pairs, sessions] = await Promise.all([
    api("/api/chat/pairs").catch(() => []),
    api("/api/chat/sessions").catch(() => []),
  ]);
  if (state) state.chatSessions = sessions || [];
  renderChatSessions();
  const list = document.getElementById("history-list");
  if (!list) return;
  const pairRows = (pairs || []).map((item) => `
    <div class="history-row">
      <button class="history-item ${DUO.pair && DUO.pair.id === item.id ? "active" : ""}" data-pair="${item.id}">
        <span class="history-kind duo">协同</span>
        <span class="history-main">
          <strong>${esc(item.title || "双模型协同")}</strong>
          <small>${esc(fmtTime(item.updated_at).slice(5))} · ${item.note_count || 0} 条协同 · ${item.message_count || 0} 条对话</small>
        </span>
      </button>
      <button class="history-del" data-del-pair="${item.id}" title="删除这条协同记录">×</button>
    </div>`).join("");
  const singleRows = (sessions || []).map((item) => `
    <button class="history-item" data-single="${item.id}">
      <span class="history-kind">单模型</span>
      <span class="history-main">
        <strong>${esc(item.title || "新会话")}</strong>
        <small>${esc(fmtTime(item.updated_at).slice(5))} · ${item.message_count || 0} 条</small>
      </span>
    </button>`).join("");
  if (!pairRows && !singleRows) {
    list.innerHTML = `<p class="hint" style="padding:14px">还没有记录</p>`;
    return;
  }
  list.innerHTML =
    (pairRows ? `<div class="history-group">协同会话</div>${pairRows}` : "") +
    (singleRows ? `<div class="history-group">单模型会话</div>${singleRows}` : "");
}

async function duoOpenPair(pairId) {
  const data = await api(`/api/chat/pairs/${pairId}`);
  DUO.pair = data.pair;
  DUO.names = data.names || { a: "", b: "" };
  DUO.notes = data.notes || [];
  DUO.lastNote = DUO.notes.length ? Number(DUO.notes[DUO.notes.length - 1].id) : 0;
  duoShowDuo();
  document.getElementById("duo-title").textContent = data.pair.title || "双模型协同";
  document.getElementById("duo-workdir").value = data.pair.workdir || "";
  duoFillModels();
  duoBudget(data.budget);
  ["a", "b"].forEach((key) => {
    const lane = duoLaneNew(key);
    const detail = (data.lanes && data.lanes[key]) || {};
    lane.sessionId = Number(detail.id || 0);
    // 这一栏用哪个模型，以配对记录为准：建的时候选的、后来换的，都在这里
    lane.provider = String((key === "a" ? data.pair.model_a : data.pair.model_b) || detail.provider || "");
    lane.modelName = (data.names && data.names[key]) || lane.provider || key.toUpperCase();
    lane.messages = duoFromDetail(detail);
    lane.seq = Number(detail.seq || 0);
    lane.running = !!detail.running;
    DUO.lanes[key] = lane;
    const select = document.getElementById(`duo-${key}-model`);
    if (select && lane.provider) select.value = lane.provider;
    duoStoreModel(key, lane.provider);
    duoRender(key, "bottom");
    duoSetState(key);
    if (lane.running) duoAttach(key).catch(() => {});
  });
  duoRenderNotes();
  duoRenderFiles([]);
  duoOpenHistory(false);
  if (!DUO.timer) DUO.timer = setInterval(duoPollNotes, 1500);
  duoPollNotes().catch(() => {});
  duoRefreshHistory().catch(() => {});
}

/* 新开一组：界面清空回到草稿态，上一组留在历史里，随时能点回去 */
async function duoNewDraft() {
  if (DUO.pair && (DUO.lanes.a?.running || DUO.lanes.b?.running)) {
    await duoStopAll().catch(() => {});
  }
  if (DUO.pair?.workdir) duoStoreDir(DUO.pair.workdir);
  duoDraft();
  await duoRefreshHistory().catch(() => {});
  document.getElementById("duo-a-input")?.focus();
}

async function duoSaveWorkdir() {
  const value = document.getElementById("duo-workdir").value.trim();
  duoStoreDir(value);
  if (!DUO.pair) {
    toast(value ? "目录已记下，第一次下发时就落在那里" : "已记下用平台默认目录");
    return;
  }
  try {
    const pair = await api(`/api/chat/pairs/${DUO.pair.id}`, { method: "PATCH", body: { workdir: value } });
    DUO.pair = pair;
    document.getElementById("duo-workdir").value = pair.workdir || "";
    toast(pair.workdir ? "共享目录已保存，下一轮就落在新目录" : "已改为使用平台默认目录");
  } catch (error) {
    toast(error.message, "error");
  }
}

/* 进对话页：默认就是两栏，接着上次那组；没有就停在草稿态，写一句就自动建 */
async function duoBoot() {
  const status = await api("/api/chat/status");
  state.chatProviders = status.providers || [];
  state.chatStatus = status;
  duoShowDuo();
  duoFillModels();
  const pairs = await api("/api/chat/pairs").catch(() => []);
  const target = DUO.pair && (pairs || []).some((item) => item.id === DUO.pair.id)
    ? DUO.pair.id
    : (pairs && pairs.length ? pairs[0].id : 0);
  if (target) {
    await duoOpenPair(target);
  } else {
    duoDraft();
  }
  await duoRefreshHistory();
}

/* ---------------- 事件接线 ---------------- */
document.addEventListener("DOMContentLoaded", () => {
  // 双栏里的按钮：卡片、选择题、复制都在这里处理，走各自那一栏的会话
  const body = document.getElementById("duo-body");
  if (!body) return;
  body.addEventListener("click", (event) => {
    const laneEl = event.target.closest("[data-lane]");
    const key = laneEl ? laneEl.dataset.lane : "";
    const lane = DUO.lanes[key];
    if (!lane) return;
    const copy = event.target.closest("[data-duo-copy]");
    if (copy) {
      const message = lane.messages[Number(copy.dataset.duoCopy)];
      const text = String(message?.content || "");
      if (!text) { toast("这条没有可复制的内容", "error"); event.stopPropagation(); return; }
      copyText(text).then((ok) => toast(ok ? "已复制" : "复制失败，请手动选中", ok ? "" : "error"));
      event.stopPropagation();
      return;
    }
    const decide = event.target.closest("[data-decide]");
    if (decide) {
      duoDecide(key, Number(decide.dataset.action), decide.dataset.decide === "approve", decide);
      event.stopPropagation();
      return;
    }
    const choice = event.target.closest("[data-choice]");
    if (choice) {
      duoSay([key], choice.dataset.value).catch((error) => toast(error.message, "error"));
      event.stopPropagation();
      return;
    }
    const custom = event.target.closest("[data-choice-custom]");
    if (custom) {
      const input = document.getElementById(`choice-input-${custom.dataset.choiceCustom}`);
      const value = (input?.value || "").trim();
      if (!value) { toast("请先输入内容", "error"); input?.focus(); event.stopPropagation(); return; }
      duoSay([key], value).catch((error) => toast(error.message, "error"));
      event.stopPropagation();
      return;
    }
    const focus = event.target.closest("[data-choice-custom-focus]");
    if (focus) {
      document.getElementById(`choice-input-${focus.dataset.choiceCustomFocus}`)?.focus();
      event.stopPropagation();
    }
  });

  ["a", "b"].forEach((key) => {
    const form = document.getElementById(`duo-${key}-form`);
    const input = document.getElementById(`duo-${key}-input`);
    if (!form || !input) return;
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      duoSay([key], input.value).then(() => { input.value = ""; }).catch((error) => toast(error.message, "error"));
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        form.requestSubmit();
      }
    });
    const select = document.getElementById(`duo-${key}-model`);
    select.addEventListener("change", () => {
      const lane = DUO.lanes[key];
      const label = select.selectedOptions[0]?.textContent || select.value;
      if (lane) { lane.provider = select.value; lane.modelName = label; }
      duoStoreModel(key, select.value);
      duoRender(key, "");
      if (!DUO.pair) return;  // 草稿态：选好就记着，建配对时按这个来
      const body = key === "a" ? { provider_a: select.value } : { provider_b: select.value };
      api(`/api/chat/pairs/${DUO.pair.id}`, { method: "PATCH", body })
        .then((pair) => { if (pair) { DUO.pair = pair; DUO.names[key] = label; } })
        .catch((error) => {
          toast(error.message, "error");
          duoOpenPair(DUO.pair.id).catch(() => {});
        });
    });
  });

  const bothForm = document.getElementById("duo-both-form");
  const bothInput = document.getElementById("duo-both-input");
  if (bothForm && bothInput) {
    bothForm.addEventListener("submit", (event) => {
      event.preventDefault();
      duoSay(["a", "b"], bothInput.value).then(() => { bothInput.value = ""; }).catch((error) => toast(error.message, "error"));
    });
    bothInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        bothForm.requestSubmit();
      }
    });
  }

  document.getElementById("duo-new").addEventListener("click", () => {
    duoNewDraft().catch((error) => toast(error.message, "error"));
  });
  document.getElementById("duo-stop").addEventListener("click", () => {
    duoStopAll().catch((error) => toast(error.message, "error"));
  });
  document.getElementById("duo-save-dir").addEventListener("click", duoSaveWorkdir);
  document.getElementById("duo-history").addEventListener("click", () => {
    duoRefreshHistory().then(() => duoOpenHistory()).catch(() => duoOpenHistory());
  });
  document.getElementById("history-close").addEventListener("click", () => duoOpenHistory(false));
  document.getElementById("history-list").addEventListener("click", (event) => {
    const del = event.target.closest("[data-del-pair]");
    if (del) {
      event.stopPropagation();
      const id = Number(del.dataset.delPair);
      if (!window.confirm("删除这条协同记录？两栏的对话和协同记录都会一起删除。")) return;
      api(`/api/chat/pairs/${id}`, { method: "DELETE" })
        .then(async () => {
          if (DUO.pair && DUO.pair.id === id) DUO.pair = null;
          const pairs = await api("/api/chat/pairs").catch(() => []);
          if (pairs && pairs.length) await duoOpenPair(pairs[0].id);
          else {
            duoDraft();
            await duoRefreshHistory();
          }
          toast("已删除");
        })
        .catch((error) => toast(error.message, "error"));
      return;
    }
    const pair = event.target.closest("[data-pair]");
    if (pair) {
      duoOpenPair(Number(pair.dataset.pair)).catch((error) => toast(error.message, "error"));
      return;
    }
    const single = event.target.closest("[data-single]");
    if (single) {
      duoOpenHistory(false);
      duoShowSingle();
      openChatSession(Number(single.dataset.single)).catch((error) => toast(error.message, "error"));
    }
  });
  const back = document.getElementById("chat-back-duo");
  if (back) back.addEventListener("click", () => { duoShowDuo(); duoRefreshHistory().catch(() => {}); });
});
