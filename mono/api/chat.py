"""智能工作：会话管理、状态检测与流式对话接口。"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..db import db, get_settings, now_iso, set_settings
from ..engine import coverage
from ..engine.agent import (
    BIG_RESULT_TOOLS,
    LARGE_RESULT_CHARS,
    agent_busy,
    agent_running,
    auto_stopped,
    cancel_agent,
    clear_auto_stop,
    clear_auto_stops,
    confirm_label,
    decide_action,
    decide_choice,
    dispatch_tool,
    forget_session_findings,
    get_action,
    pending_actions,
    pending_choices,
    progress_level,
    CONFIRM_LABELS,
    mask_sensitive,
    pick_llm,
    provider_setup,
    push_interjection,
    ready_providers,
    run_agent,
    set_tool_session,
    tool_session,
)
from .deps import get_current_user

router = APIRouter(prefix="/api/chat", tags=["chat"])


class SessionIn(BaseModel):
    title: str = ""


class MessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    provider: str = ""


class DecideIn(BaseModel):
    approve: bool = True
    provider: str = ""


class AutoIn(BaseModel):
    enabled: bool = False
    text: str = ""


# SSE 心跳间隔：模型久不出字时靠它把连接活着（代理默认 60s 就断）
SSE_HEARTBEAT_SECONDS = 15
AUTO_TEXT_DEFAULT = "继续"
AUTO_TEXT_MAX = 200
# 连续这么多轮「没有实质动作」才停：用户要的是不限次数，但不能无限烧钱。
# 判据是「有没有动手」，不是「有没有归档」——探测一轮常常还没到归档那一步；
# 而且长任务里模型常常连着两三轮回一段很长的分析文字，阈值给到 6 才不会误杀。
AUTO_IDLE_LIMIT = 6
# 勾了能力但还没验完时：用户定死了「所有能力测完才能结束」，所以空转不再是收手理由，
# 只有连续这么多轮**一点动作都没有**才暂停（并明确写「任务未完成」，别让人误以为测完了）。
AUTO_IDLE_LIMIT = 6
# 勾了能力、还没验完的时候：用户定死「任务没做完就不许停」，所以空转不再有上限。
# 0 = 不收手：一轮没动作就再推一轮，把提醒加重，直到验完或用户自己按停止。
# 真正剩下的人为刹车只有三条：用户点停止、有件事等他拍板、页面断了两分钟以上（人已离开）。
AUTO_IDLE_LIMIT_WITH_COVERAGE = 0
# 单轮偶发失败（429 / 5xx / 读超时）先原地重试几次，别让整条链断在这里
AUTO_RETRY_LIMIT = 1
AUTO_RETRY_DELAY = 3
# 页面断开超过这么久（没有任何订阅者）就不再往下接龙：人已经走了，接着跑纯烧额度。
# 阈值给得宽：正常重连是秒级，只有休眠 / 关页面才会空这么久。
AUTO_OFFLINE_PAUSE = 120
# 这些工具只是「看一眼」，不改变任何东西；整轮只有它们时按「只查不干」对待
QUERY_ONLY_TOOLS = {
    "list_capabilities",
    "platform_overview",
    "list_assets",
    "list_scans",
    "get_scan",
    "list_findings",
    "list_connectors",
    "list_dir",
    "read_file",
    "read_memory",
    "search_memory",
}


class _Run:
    """一个会话当前这一批执行（可能是很多轮自动继续）。

    关键点：它**不挂在 HTTP 请求上**。请求只是订阅者之一，浏览器断了、
    代理超时了、笔记本合上了，后台该跑的轮次照跑；重新连上来接上 `after`
    就能把漏掉的事件补齐。以前把执行塞在请求生成器里，请求一断就
    `worker.cancel()`，表现出来就是「自动继续只跑一轮就没了」。
    """

    __slots__ = ("session_id", "events", "seq", "subs", "task", "done", "empty_since")

    def __init__(self, session_id: int):
        self.session_id = int(session_id)
        self.events: list[dict[str, Any]] = []
        self.seq = 0
        self.subs: set[asyncio.Queue] = set()
        self.task: asyncio.Task | None = None
        self.done = False
        # 最后一个订阅者走掉的时间：用来判断「人是不是已经离开很久了」
        self.empty_since: float | None = None


_RUNS: dict[int, _Run] = {}
_RUN_END = object()
# 事件缓冲上限：一次长测可能上千条，留够回放又不至于吃内存
RUN_BUFFER_MAX = 6000


def _publish(run: _Run, event: Any) -> None:
    if not isinstance(event, dict):
        return
    run.seq += 1
    item = dict(event)
    item["seq"] = run.seq
    run.events.append(item)
    if len(run.events) > RUN_BUFFER_MAX:
        del run.events[: RUN_BUFFER_MAX // 3]
    for queue in list(run.subs):
        try:
            queue.put_nowait(item)
        except asyncio.QueueFull:  # 订阅者自己太慢，丢这一条不影响别人
            pass


def _finish_run(run: _Run) -> None:
    run.done = True
    for queue in list(run.subs):
        try:
            queue.put_nowait(_RUN_END)
        except asyncio.QueueFull:
            pass


def start_run(session_id: int, events) -> _Run:
    """把一段事件流放到后台跑，返回可反复订阅的运行对象。"""
    old = _RUNS.get(int(session_id))
    if old and old.task and not old.task.done():
        # 同一会话不允许两批并行：先真的停掉上一批（含后台命令）
        old.task.cancel()
        cancel_agent(session_id, "已开始新一轮执行")
        # 这是平台自己打断，不是用户点的「停止」——别让自动继续因此收手
        clear_auto_stop(session_id)

    run = _Run(session_id)
    _RUNS[int(session_id)] = run

    async def pump() -> None:
        try:
            async for event in events:
                _publish(run, event)
        except asyncio.CancelledError:
            _publish(run, {"type": "cancelled", "message": "已停止这一轮执行"})
            raise
        except Exception as exc:  # 任何异常都要让订阅者收到一句话，不能静默
            _publish(
                run, {"type": "error", "message": f"助手执行异常：{type(exc).__name__}: {exc}"}
            )
        finally:
            _finish_run(run)

    run.task = asyncio.create_task(pump())
    return run


async def run_events(run: _Run, after: int = 0):
    """订阅一次运行：先补齐 after 之后的历史事件，再跟着往后推。

    产出 `None` 表示该发心跳了（模型久不出字时防止代理掐连接）。
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=2048)
    run.subs.add(queue)
    run.empty_since = None
    try:
        for item in list(run.events):
            if int(item.get("seq") or 0) > after:
                yield item
        if run.done:
            yield {"type": "stream_end", "seq": run.seq}
            return
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=SSE_HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                yield None
                continue
            if item is _RUN_END:
                yield {"type": "stream_end", "seq": run.seq}
                return
            if int(item.get("seq") or 0) <= after:
                continue
            yield item
    finally:
        run.subs.discard(queue)
        if not run.subs:
            run.empty_since = time.monotonic()


def _sse_stream(run: _Run, after: int = 0):
    async def body():
        async for item in run_events(run, after):
            if item is None:
                yield ": ping\n\n"
                continue
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        body(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def auto_settings() -> tuple[bool, str]:
    data = get_settings()
    enabled = str(data.get("auto_continue") or "false").lower() in ("1", "true", "yes", "on")
    text = str(data.get("auto_continue_text") or AUTO_TEXT_DEFAULT).strip() or AUTO_TEXT_DEFAULT
    return enabled, text[:AUTO_TEXT_MAX]


@router.get("/auto")
async def read_auto(user=Depends(get_current_user)):
    enabled, text = auto_settings()
    return {"enabled": enabled, "text": text, "max_rounds": 0, "idle_limit": AUTO_IDLE_LIMIT}


@router.post("/auto")
async def save_auto(payload: AutoIn, user=Depends(get_current_user)):
    """自动继续：跑完一轮就把这句预设话当成用户消息发出去，让模型接着干。

    次数不设上限（用户明确要求），但有两个刹车：连续 3 轮没有任何新动作就停；
    出现待确认的操作或选择题时先停下等用户拍板。
    """
    text = (payload.text or "").strip()[:AUTO_TEXT_MAX] or AUTO_TEXT_DEFAULT
    set_settings({"auto_continue": "true" if payload.enabled else "false", "auto_continue_text": text})
    if payload.enabled:
        # 重新打开开关 = 他愿意让它接着跑：之前点过「停止」留下的标记要一并作废，
        # 否则第一轮结束就收手，表现出来就是「开了自动继续却只跑一次」。
        clear_auto_stops()
    return {"ok": True, "enabled": payload.enabled, "text": text}


def _session(session_id: int, username: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM chat_sessions WHERE id=?", (session_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="会话不存在")
    if row["username"] and row["username"] != username:
        raise HTTPException(status_code=403, detail="无权访问该会话")
    return row


@router.get("/status")
async def chat_status():
    providers = ready_providers()
    setup = provider_setup()
    llm = pick_llm()
    if not llm:
        return {"available": False, "provider": "", "model": "", "providers": [], "setup": setup}
    return {
        "available": True,
        "provider": llm.name,
        "model": llm.model,
        "key": llm.key,
        "default": llm.key,
        "providers": providers,
        "setup": setup,
    }


@router.get("/sessions")
async def list_sessions(user=Depends(get_current_user)):
    username = user.get("u", "")
    with db() as conn:
        rows = conn.execute(
            """SELECT s.id, s.title, s.created_at, s.updated_at,
                      (SELECT COUNT(*) FROM chat_messages m
                        WHERE m.session_id=s.id AND m.role IN ('user','assistant')) AS message_count
               FROM chat_sessions s WHERE s.username=? ORDER BY s.updated_at DESC, s.id DESC LIMIT 50""",
            (username,),
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("/sessions")
async def create_session(payload: SessionIn, user=Depends(get_current_user)):
    title = payload.title.strip()[:60] or "新会话"
    ts = now_iso()
    username = user.get("u", "")
    # 换会话就等于离开上一件事：把他名下还在跑的轮次真正停掉，
    # 否则新会话里显示"空闲"，旧会话的命令还在后台跑（用户看到的就是"原来的任务还在执行"）
    cancelled = _cancel_user_runs(username)
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO chat_sessions (title, username, created_at, updated_at) VALUES (?,?,?,?)",
            (title, username, ts, ts),
        )
        session_id = cursor.lastrowid
    return {"id": session_id, "title": title, "created_at": ts, "cancelled": cancelled}


def _cancel_user_runs(username: str) -> list[int]:
    """停掉这个用户名下所有还在跑的会话，返回被停掉的会话 id。"""
    if not username:
        return []
    with db() as conn:
        rows = conn.execute(
            "SELECT id FROM chat_sessions WHERE username=?", (username,)
        ).fetchall()
    stopped: list[int] = []
    for row in rows:
        session_id = int(row["id"])
        if agent_running(session_id) and cancel_agent(session_id, "已切换到新会话，上一轮执行已停止"):
            stopped.append(session_id)
        run = _RUNS.get(session_id)
        if run and run.task and not run.task.done():
            run.task.cancel()
            if session_id not in stopped:
                stopped.append(session_id)
    return stopped


@router.post("/sessions/{session_id}/stop")
async def stop_session(session_id: int, user=Depends(get_current_user)):
    """真正停止一轮执行：不只是断开前端连接，还停掉循环与后台命令。

    执行已经不在请求上了，所以这里必须同时把后台 task 叫停——
    否则用户点了停止，界面停了、后台还在跑（甚至跑完还发「继续」）。
    """
    _session(session_id, user.get("u", ""))
    stopped = cancel_agent(session_id)
    run = _RUNS.get(int(session_id))
    if run and run.task and not run.task.done():
        run.task.cancel()
        stopped = True
    return {"ok": True, "stopped": stopped}


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: int, user=Depends(get_current_user)):
    _session(session_id, user.get("u", ""))
    run = _RUNS.pop(int(session_id), None)
    if run and run.task and not run.task.done():
        run.task.cancel()
    with db() as conn:
        conn.execute("DELETE FROM chat_messages WHERE session_id=?", (session_id,))
        conn.execute("DELETE FROM chat_sessions WHERE id=?", (session_id,))
    forget_session_findings(session_id)
    return {"ok": True}


READ_ONLY_TOOLS = {
    "read_file",
    "read_memory",
    "search_memory",
    "list_findings",
    "get_scan",
    "list_assets",
    "list_scans",
    "platform_overview",
    "list_connectors",
}


def _action_label(item: dict) -> str:
    """确认卡片上的中文标签：看敏感原文的、删除的、写入的，其他按工具归类。"""
    if (item.get("args") or {}).get("__reveal_sensitive"):
        return "查看敏感内容"
    summary = str(item.get("summary") or "")
    return confirm_label(item.get("tool_name", ""), summary)


def _progress_item_level(item: dict) -> str:
    """优先用落库时记下的等级：冷却期内被降级的关键说法，回放时也要保持普通样式。"""
    stored = str(item.get("level") or "")
    if stored:
        return stored
    # 老数据没有 level 列：读记忆那句「正在读取记忆」按进行中处理，回放时才不会留成两条
    content = str(item.get("content") or "")
    if content.startswith("正在读取"):
        return "loading"
    return progress_level(content)


def _collapse_progress(messages: list[dict]) -> list[dict]:
    """回放与实时完全一致：每一步的进展都留下。

    进展本身就是用户回看「模型做了什么」的唯一凭据，所以一条都不删；只把同一件事
    的「正在做」和「做完了」合掉一条（读记忆时会出现），避免两行说同一件事。
    旧版本留下的 role='tool' 痕迹不再展示。
    """
    out: list[dict] = []
    for item in messages:
        role = item.get("role")
        if role == "tool":
            continue
        if role == "progress":
            level = _progress_item_level(item)
            item["level"] = level
            prev = out[-1] if out else None
            prev_is_progress = bool(prev) and prev.get("role") == "progress"
            # 只有一种合并：「正在读取记忆」等它读完后，被紧跟的那条结果顶掉。
            # 反过来（结果已经出来、又来了条 loading）不能顶——那会把上一条真进展吃掉，
            # 回放就比实时少了几行，用户看到的就是「刷新之后过程不见了」。
            if prev_is_progress and prev.get("level") == "loading" and level != "loading":
                out[-1] = item
                continue
            out.append(item)
            continue
        out.append(item)
    return out


@router.get("/sessions/{session_id}")
async def get_session(session_id: int, user=Depends(get_current_user)):
    row = _session(session_id, user.get("u", ""))
    with db() as conn:
        messages = conn.execute(
            """SELECT id, role, content, level, created_at
               FROM chat_messages
               WHERE session_id=? AND role IN ('user','assistant','progress','finding')
               ORDER BY id""",
            (session_id,),
        ).fetchall()
    pending = pending_actions(session_id)
    # 同一件事只给一张卡（历史上可能残留重复的待确认记录）
    seen: set[str] = set()
    unique_pending: list[dict] = []
    for item in pending:
        key = json.dumps(
            [item.get("tool_name"), item.get("args") or {}], ensure_ascii=False, sort_keys=True, default=str
        )
        if key in seen:
            continue
        seen.add(key)
        unique_pending.append(item)
    run = _RUNS.get(int(session_id))
    return {
        "id": row["id"],
        "title": row["title"],
        # 切走再切回来 / 刷新页面：这一批还在后台跑的话，前端直接接上，不用重发消息
        "running": bool(run and run.task and not run.task.done()),
        "seq": run.seq if run else 0,
        "messages": _collapse_progress([dict(r) for r in messages]),
        "pending": [
            {
                "id": item["id"],
                "tool": item["tool_name"],
                "summary": item["summary"],
                "label": _action_label(item),
                "args": item.get("args") or {},
            }
            for item in unique_pending
        ],
        "choices": [
            {
                "id": item["id"],
                "question": item["question"],
                "options": item["options"],
                "allow_custom": item["allow_custom"],
            }
            for item in pending_choices(session_id)
        ],
    }


@router.get("/sessions/{session_id}/coverage")
async def session_coverage(session_id: int, user=Depends(get_current_user)):
    """这个会话的能力覆盖情况：勾了几项、验了几项、还剩哪些。"""
    _session(session_id, user.get("u", ""))
    return {
        "summary": coverage.summary(session_id),
        "items": coverage.plan(session_id),
    }


@router.post("/sessions/{session_id}/interject")
async def interject_message(session_id: int, payload: MessageIn, user=Depends(get_current_user)):
    """AI 正在思考时用户的补充输入：不下发新任务，只把话插进当前这一轮。

    返回 delivered=True 表示已送进正在运行的任务（会优先于原任务执行）；
    False 表示当前没有在跑的轮次，调用方应退回普通发送流程。
    """
    row = _session(session_id, user.get("u", ""))
    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="消息不能为空")

    if not push_interjection(session_id, content):
        return {"delivered": False, "busy": False}

    ts = now_iso()
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
            (session_id, "user", content, ts),
        )
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE session_id=? AND role='user'",
            (session_id,),
        ).fetchone()["c"]
        if count == 1 and row["title"] in ("", "新会话"):
            conn.execute(
                "UPDATE chat_sessions SET title=?, updated_at=? WHERE id=?",
                (content[:24], ts, session_id),
            )
        else:
            conn.execute("UPDATE chat_sessions SET updated_at=? WHERE id=?", (ts, session_id))
    return {"delivered": True, "busy": agent_busy(session_id)}


@router.post("/sessions/{session_id}/messages")
async def post_message(session_id: int, payload: MessageIn, user=Depends(get_current_user)):
    row = _session(session_id, user.get("u", ""))
    username = user.get("u", "")
    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="消息不能为空")

    # 用户自己发话了：自动继续的「已停止」标记作废，该接着跑就接着跑
    clear_auto_stop(session_id)
    ts = now_iso()
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
            (session_id, "user", content, ts),
        )
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE session_id=? AND role='user'",
            (session_id,),
        ).fetchone()["c"]
        if count == 1 and row["title"] in ("", "新会话"):
            conn.execute(
                "UPDATE chat_sessions SET title=?, updated_at=? WHERE id=?",
                (content[:24], ts, session_id),
            )
        else:
            conn.execute("UPDATE chat_sessions SET updated_at=? WHERE id=?", (ts, session_id))

    # 用户回答了选择题：把待选状态关掉，避免刷新后重复出现
    for item in pending_choices(session_id):
        decide_choice(int(item["id"]), content)

    # 有待确认的敏感操作时，直接回「确认 / 取消」也能生效
    pending = pending_actions(session_id)
    if pending:
        latest = get_action(int(pending[-1]["id"])) or {}
        if _is_affirmative(content):
            return _sse_stream(start_run(session_id, _decide_events(latest, True, payload.provider, username)))
        if any(hint in content.strip().lower() for hint in NEGATIVE_HINTS) and len(content.strip()) <= 12:
            return _sse_stream(start_run(session_id, _decide_events(latest, False, payload.provider, username)))

    # 这段执行放进后台跑：请求断掉（浏览器切后台、代理超时、网络抖一下）
    # 只是少了一个订阅者，轮次照跑，重连上来还能把漏掉的补齐。
    run = start_run(session_id, _auto_loop(session_id, username, payload.provider))
    return _sse_stream(run, 0)


@router.get("/sessions/{session_id}/stream")
async def resume_stream(session_id: int, after: int = 0, user=Depends(get_current_user)):
    """续传：把 after 之后的事件补齐，然后继续跟随。

    前端连接断了就带着自己的 lastSeq 重新连这里，不用重发消息、也不会重复跑。
    """
    _session(session_id, user.get("u", ""))
    run = _RUNS.get(int(session_id))
    if not run:
        async def closed():
            yield f"data: {json.dumps({'type': 'stream_end', 'reason': 'no_run'}, ensure_ascii=False)}\n\n"

        return StreamingResponse(
            closed(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    return _sse_stream(run, max(0, int(after or 0)))


def _activity(session_id: int) -> tuple[int, int, int]:
    """这一轮到底有没有往前走。

    看三样「落地的东西」：新归档了几条漏洞、新上报了几项能力结论，
    以及审计里新增了几条动作——AI 发过包（`http_request`）、跑过命令、
    写过文件都会落一条，这些才算真干活。
    不数进展条数——进展每轮都会多几句，拿它判「有进展」等于永远判有，
    空转保护就形同虚设。
    """
    with db() as conn:
        findings = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE source='ai-agent'"
        ).fetchone()["c"]
        actions = conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()["c"]
    return int(findings), coverage.summary(session_id)["done"], int(actions)


def _append_user_message(session_id: int, text: str, level: str = "auto") -> None:
    """自动继续发出去的那句话：和手打的一样入库，只多一个 level=auto 的标记。

    标记落在库里，刷新回放时还能认出「这句是平台替你发的」，不会和你说的话混在一起。
    """
    ts = now_iso()
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, level, created_at) VALUES (?,?,?,?,?)",
            (session_id, "user", text, level, ts),
        )
        conn.execute("UPDATE chat_sessions SET updated_at=? WHERE id=?", (ts, session_id))


def _append_progress(session_id: int, text: str, level: str = "step") -> None:
    """把平台自己的结论也落库：刷新、换设备回看时，「为什么停」不能凭空消失。"""
    ts = now_iso()
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, level, created_at) VALUES (?,?,?,?,?)",
            (session_id, "progress", text, level, ts),
        )
        conn.execute("UPDATE chat_sessions SET updated_at=? WHERE id=?", (ts, session_id))


def _auto_end(session_id: int, reason: str, rounds: int) -> dict[str, Any]:
    """自动继续收口：事件 + 落库各一份，界面和回放都看得到原因。"""
    _append_progress(session_id, f"自动继续结束：{reason}（共 {rounds} 轮）")
    return {"type": "auto_end", "reason": reason, "rounds": rounds}


def _idle_cap(ledger_open: bool) -> int:
    """空转多少轮才收手；返回 0 表示「不收手」。

    用户的要求是「自动继续不会停」：只要勾选的能力还有没验完的，空转多少轮都接着发，
    只把提醒一次次加重。全部验完之后才回到普通的 6 轮空转保护。
    """
    return AUTO_IDLE_LIMIT_WITH_COVERAGE if ledger_open else AUTO_IDLE_LIMIT


async def _auto_loop(session_id: int, username: str, provider: str):
    """一条用户消息进来后可能连着跑很多轮——这就是「自动继续」。

    每轮结束按顺序判断：开关还开着吗、用户停过吗、有没有等他拍板的事、
    这一轮到底往前走没有。都通过就把预设提示词**原样当成用户消息**发出去
    （所以对话里会看到这条气泡，和手打的一模一样），并把「能力台账还剩哪几项」
    作为平台提示一并交下去。

    次数不设上限（用户要的就是这个），刹车只有三个：
    1. 出现待确认操作 / 选择题 / 用户点过停止 → 立刻停，等他拍板；
    2. 台账已清空、且连续 6 轮没有任何落地动作（没发包、没跑命令、没写文件、没归档、没上报能力）→ 停，并说明停在哪；
    3. 自动继续被关掉、或这一轮被取消 / 报错 → 收手。
    **台账没清空时第 2 条不生效**：勾了能力没验完，空转多少轮都接着发下一轮——
    以前到这里就按「连续 20 轮空转」收手，用户看到的正是「只自动继续了一两次就不动了」。
    只要这一轮真动过手，就接着发下一轮——不再因为「这一轮没新归档」而提前收口。
    """
    round_index = 0
    idle = 0
    note = ""
    retried = 0
    while True:
        round_index += 1
        before = _activity(session_id)
        cancelled = False
        failed = False
        # 这一轮到底动了几次手：由引擎回填，比只在库里找痕迹可靠
        # （有些工具不落审计，只看库会把「刚测完一轮」误判成空转）
        stats: dict[str, Any] = {"tool_calls": 0, "test_actions": 0, "tools": []}
        try:
            async for event in run_agent(
                session_id, username, provider, resume_note=note, stats=stats
            ):
                kind = event.get("type")
                if kind in ("cancelled", "stopped"):
                    cancelled = True
                elif kind == "error":
                    failed = True
                yield event
        except asyncio.CancelledError:
            # 用户点了停止 / 平台要开新一批：这是主动打断，不能当成「接口报错」去重试
            raise
        except Exception as exc:
            # 引擎外面兜底：模型连接直接抛异常（502、DNS、超时）时，
            # 以前这个异常会穿透整个循环，整条自动继续当场断掉、连重试都没有。
            # 现在按「这一轮失败」处理，交给下面的重试分支。
            failed = True
            yield {"type": "error", "message": f"这一轮执行中断：{type(exc).__name__}: {exc}"}
        note = ""
        calls = int(stats.get("tool_calls") or 0)
        used = {str(name) for name in (stats.get("tools") or [])}

        enabled, text = auto_settings()
        if not enabled:
            if round_index > 1:
                yield _auto_end(session_id, "自动继续已关闭", round_index)
            return
        if cancelled:
            # 以前这里是静默 return：用户只看到「自动继续了一次就不动了」，
            # 连一句为什么都没有。现在每一处退出都留话。
            yield _auto_end(session_id, "这一轮被停止了，自动继续不再接龙", round_index)
            return
        if failed:
            # 429 / 5xx / 读超时这类偶发失败不该把整条链断在这里：
            # 原地重试一次，成功了接着跑，仍失败才收手并说清原因。
            if retried < AUTO_RETRY_LIMIT:
                retried += 1
                round_index -= 1  # 重试不算新的一轮
                yield {
                    "type": "status",
                    "message": f"这一轮模型接口报错，正在第 {retried} 次重试（不算新一轮）…",
                }
                note = "【平台提示】上一轮模型请求失败，请从中断处继续，不要重复已经完成的工作。"
                await asyncio.sleep(AUTO_RETRY_DELAY)
                continue
            yield _auto_end(session_id, "模型接口连续报错，自动继续先停下；重新发一句话就能接着跑", round_index)
            return
        retried = 0
        if auto_stopped(session_id):
            yield _auto_end(session_id, "你点了停止，自动继续已关掉", round_index)
            return
        # 人已经离开很久（关页面 / 休眠）：这一轮跑完就不再接龙，别在后台空烧额度
        run = _RUNS.get(int(session_id))
        if (
            run
            and not run.subs
            and run.empty_since
            and time.monotonic() - run.empty_since > AUTO_OFFLINE_PAUSE
        ):
            yield _auto_end(
                session_id,
                "页面已经断开两分钟，自动继续先暂停（不替你白烧额度）；重新打开会话就能接着跑",
                round_index,
            )
            return
        # 等你拍板的事不能替你做主
        if pending_actions(session_id) or pending_choices(session_id):
            yield _auto_end(session_id, "有一件事等你确认，自动继续先停下", round_index)
            return

        after = _activity(session_id)
        # 「往前走」的判据放宽到三条，命中一条就算在干活：
        #   ① 归档了新漏洞 / 上报了新能力结论；② 审计里多了动作（发包、命令、写文件）；
        #   ③ 这一轮调用过真正干活的工具（发包、跑命令、写文件、改状态……）。
        # 以前只认 ①②，结果「整轮都在发包但还没归档」的轮次被判空转，
        # 连续几轮就自动停了：用户看到的就是「自动发了两次就不动了」。
        landed = after != before
        query_only = bool(used) and used.issubset(QUERY_ONLY_TOOLS)
        moved = landed or (calls > 0 and not query_only)
        summary_now = coverage.summary(session_id)
        ledger_open = bool(summary_now["selected"]) and summary_now["pending"] > 0
        cap = _idle_cap(ledger_open)
        idle = 0 if moved else idle + 1
        if cap and idle >= cap:
            reason = f"连续 {idle} 轮没有实质动作（只查不干或干脆没调工具），先停下"
            if summary_now["pending"]:
                reason += f"（能力台账里还剩 {summary_now['pending']} 项没验）"
            yield _auto_end(session_id, reason, round_index)
            return

        _append_user_message(session_id, text)
        # 先把「马上接着跑」这件事说出来：模型下一轮开口前往往要等几十秒，
        # 没有这句提示，用户会以为自动继续已经停了。
        yield {
            "type": "status",
            "message": (
                f"第 {round_index} 轮结束（本轮动手 {calls} 次），正在发「{text}」开始第 "
                f"{round_index + 1} 轮…"
            ),
        }
        yield {
            "type": "auto_continue",
            "text": text,
            "round": round_index + 1,
            "coverage": coverage.summary(session_id),
        }
        # 下一轮的「继续」不只是两个字：把台账里剩的那几项点名交下去；
        # 上一轮要是没动手，就把「这一轮直接开打」顶到它面前，别让它接着写分析
        note = coverage.next_batch_prompt(session_id)
        # 自动继续开着的时候，别再拿选择题来「请示方向」——那会让整条链条停在这里等用户点，
        # 表现出来就是「跑两轮就停了」。方向按能力权重自己定，只有破坏性操作才停。
        steer = (
            "【自动继续进行中】不要再抛选择题（ask_choice）问「接下来测哪个 / 要不要继续」，"
            "也不要只写一段总结就结束：按能力权重自己决定下一项，直接动手。"
            "只有遇到必须用户拍板的破坏性操作时才停下来问。"
        )
        note = f"{steer}\n\n{note}" if note else steer
        if idle > 0:
            nudge = (
                f"【平台提示·第 {idle + 1} 次】上一轮没有实际动作（没发请求、没跑命令、没归档）。"
                "这一轮不要先总结、不要先复述计划，直接开始动手：第一个工具调用就是发请求或跑命令。"
                "打不通就按工具结果里的 retry_hint 改包重试，试到能说出「为什么这条路走不通」为止。"
            )
            note = f"{nudge}\n\n{note}" if note else nudge


AFFIRMATIVE_HINTS = ("确认", "确定", "同意", "执行", "可以", "好的", "好", "继续", "允许", "ok", "okay", "yes", "go")
NEGATIVE_HINTS = ("不", "别", "取消", "拒绝", "停", "no", "cancel")


def _is_affirmative(text: str) -> bool:
    value = text.strip().lower()
    if not value or len(value) > 30:
        return False
    if any(hint in value for hint in NEGATIVE_HINTS):
        return False
    return any(hint in value for hint in AFFIRMATIVE_HINTS)


async def _decide_events(action: dict, approve: bool, provider: str, username: str):
    """执行/拒绝一个待确认动作，并把结果交回模型继续对话。产出 dict 事件。"""
    session_id = int(action["session_id"])
    tool = action["tool_name"]
    args = action.get("args") or {}
    summary = action.get("summary") or tool
    if approve:
        decide_action(int(action["id"]), "approved")
        try:
            with tool_session(session_id):
                # 用户点过确认：这个动作里的内部标记算可信，看敏感原文的标记才会生效
                result = await dispatch_tool(tool, args, username, trusted=True)
        except Exception as exc:  # 工具异常也要把结果交回模型
            result = {"ok": False, "error": f"工具执行异常：{type(exc).__name__}: {exc}"}
        # 文件、记忆、命令、请求这类结果本身就很长，截太狠等于没执行
        cap = LARGE_RESULT_CHARS if tool in BIG_RESULT_TOOLS else 3000
        note = (
            f"【用户已确认】{summary} 已由平台执行，工具 {tool} 返回："
            f"{json.dumps(result, ensure_ascii=False)[:cap]}\n"
            "请基于该结果继续，不要重复调用同一个工具；关键结论用 **加粗** 标出。"
        )
    else:
        decide_action(int(action["id"]), "rejected")
        note = (
            f"【用户拒绝】用户拒绝执行：{summary}。"
            "不要重试，也不要换参数绕过；改为说明风险、给出只读替代方案或询问下一步。"
        )
        if args.get("__reveal_sensitive") and tool in READ_ONLY_TOOLS:
            # 拒绝查看原文：给模型一份脱敏结果，够它继续分析
            base_args = {k: v for k, v in args.items() if k != "__reveal_sensitive"}
            try:
                with tool_session(session_id):
                    again = await dispatch_tool(tool, base_args, username)
                masked = mask_sensitive(again)
                note += "\n用户只允许使用脱敏内容，以下是脱敏后的结果：" + str(masked)[:2000]
            except Exception as exc:
                note += f"\n（脱敏结果获取失败：{type(exc).__name__}）"

    yield {"type": "status", "message": "正在整理结果…"}
    try:
        async for event in run_agent(session_id, username, provider, resume_note=note):
            yield event
    except Exception as exc:
        yield {"type": "error", "message": f"助手执行异常：{type(exc).__name__}: {exc}"}


@router.post("/actions/{action_id}/decide")
async def decide_pending_action(
    action_id: int, payload: DecideIn, user=Depends(get_current_user)
):
    """确认或拒绝一次敏感操作；确认后立即执行，并把结果交回模型继续。"""
    username = user.get("u", "")
    action = get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="待确认操作不存在")
    if action.get("username") and action["username"] != username:
        raise HTTPException(status_code=403, detail="无权处理该操作")
    if action.get("status") != "pending":
        raise HTTPException(status_code=409, detail="该操作已被处理")

    session_id = int(action["session_id"])
    run = start_run(session_id, _decide_events(action, payload.approve, payload.provider, username))
    return _sse_stream(run, 0)
