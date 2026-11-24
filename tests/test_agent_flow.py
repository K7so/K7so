"""智能工作循环的回归测试：不需要真实大模型，用脚本化的假模型跑全部边界场景。

用法：
    python tests/test_agent_flow.py
退出码 0 表示全部通过。
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-test-")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.db import db, init_db, now_iso, set_settings  # noqa: E402
import mono.engine.agent as agent  # noqa: E402
from mono.engine.capabilities import (  # noqa: E402
    enabled_keys,
    get_switches,
    save_enabled,
    set_switches,
)

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


# ---------------- 假模型 ----------------


def reply(text: str, finish: str = "stop") -> dict:
    return {"message": {"role": "assistant", "content": text}, "finish_reason": finish}


def tool_call(name: str, args: dict | None = None, call_id: str = "call_1") -> dict:
    return {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(args or {}, ensure_ascii=False)},
                }
            ],
        },
        "finish_reason": "tool_calls",
    }


def failure(message: str) -> dict:
    return {"error": message}


class FakeLLM:
    name = "Fake"
    model = "fake-1"
    key = "fake"

    def __init__(self, script: list[dict]):
        self.script = script
        self.index = 0
        self.seen_messages: list[list[dict]] = []
        self.seen_tools: list[list[str]] = []

    def _next(self) -> dict:
        if self.index >= len(self.script):
            return reply("（脚本已耗尽，用兜底回复收尾）")
        item = self.script[self.index]
        self.index += 1
        return item

    async def stream_complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=180):
        self.seen_messages.append([dict(m) for m in messages])
        self.seen_tools.append([(spec.get("function") or {}).get("name", "") for spec in (tools or [])])
        item = self._next()
        if "error" in item:
            yield ("error", item["error"])
            return
        text = str(item["message"].get("content") or "")
        for start in range(0, len(text), 8):
            yield ("text", text[start : start + 8])
        yield ("final", {"message": item["message"], "finish_reason": item.get("finish_reason", "stop")})

    async def complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=120):
        self.seen_messages.append([dict(m) for m in messages])
        self.seen_tools.append([(spec.get("function") or {}).get("name", "") for spec in (tools or [])])
        item = self._next()
        from mono.connectors.base import ConnectorResult

        if "error" in item:
            return ConnectorResult(False, item["error"])
        return ConnectorResult(
            True, "ok", {"message": item["message"], "finish_reason": item.get("finish_reason", "stop")}
        )


def use(llm: FakeLLM) -> None:
    agent.pick_llm = lambda provider="": llm  # type: ignore[assignment]


def new_session(title: str = "t") -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO chat_sessions (title, username, created_at, updated_at) VALUES (?,?,?,?)",
            (title, "admin", now_iso(), now_iso()),
        )
        return int(cur.lastrowid)


def say(session_id: int, text: str, role: str = "user") -> None:
    """直接往会话里写一条记录，用来构造「前面已经干过活」的上下文。"""
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
            (session_id, role, text, now_iso()),
        )


async def run(script: list[dict], session_id: int | None = None) -> list[dict]:
    llm = FakeLLM(script)
    use(llm)
    sid = session_id or new_session()
    events = []
    async for event in agent.run_agent(sid, "admin"):
        events.append(event)
    events.append({"type": "_llm_messages", "data": llm.seen_messages})
    events.append({"type": "_llm_tools", "data": llm.seen_tools})
    return events


def kinds(events: list[dict]) -> list[str]:
    return [e["type"] for e in events]


def find(events: list[dict], kind: str) -> list[dict]:
    return [e for e in events if e["type"] == kind]


# ---------------- 用例 ----------------


async def test_quiet_tool_hidden() -> None:
    sid = new_session("quiet")
    events = await run([tool_call("list_capabilities"), reply("平台一切正常。")], sid)
    tool_events = [e for e in find(events, "tool") if e["name"] == "list_capabilities"]
    check("预检工具不推卡片", not tool_events, f"仍有 {len(tool_events)} 个事件")
    with db() as conn:
        rows = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE session_id=? AND tool_name='list_capabilities'",
            (sid,),
        ).fetchone()["c"]
    check("预检工具不落库", rows == 0, f"落库 {rows} 条")
    check("正常拿到回复", any(e.get("content") == "平台一切正常。" for e in find(events, "message")))


async def test_many_tools_no_hard_stop() -> None:
    script = [tool_call("platform_overview") for _ in range(12)] + [reply("连查 12 轮后给出结论。")]
    events = await run(script)
    errors = find(events, "error")
    check("连续 12 轮工具不再报错中断", not errors, str(errors)[:200])
    check("最后有正文收尾", any("结论" in str(e.get("content")) for e in find(events, "message")))


async def test_budget_exhausted_graceful() -> None:
    budget = agent.step_budget()
    script = [tool_call("platform_overview") for _ in range(budget)] + [reply("汇总：目前没有资产。")]
    events = await run(script)
    errors = find(events, "error")
    check("轮次耗尽不抛 error", not errors, str(errors)[:200])
    messages = [str(e.get("content") or "") for e in find(events, "message")]
    check("轮次耗尽后强行收口出正文", any("汇总" in m or "做到这里" in m for m in messages), str(messages)[:200])


async def test_length_continuation() -> None:
    events = await run([reply("前半段内容。", "length"), reply("后半段内容。", "stop")])
    content = "".join(str(e.get("content") or "") for e in find(events, "message"))
    check("截断后自动续写并拼接", "前半段内容。" in content and "后半段内容。" in content, content[:120])
    check("截断不再报错", not find(events, "error"))


async def test_stream_fallback() -> None:
    """流式通道故障时应自动回落非流式，用户无感拿到完整回答。"""
    events = await run([failure("请求异常: ProxyError: 502 Bad Gateway"), reply("回落非流式后成功。")])
    check("流式故障自动回落", any("回落非流式后成功" in str(e.get("content")) for e in find(events, "message")))
    check("回落过程不报错给用户", not find(events, "error"))


async def test_transient_retry() -> None:
    """流式与非流式都遇到瞬时故障时，应重试并给出提示。"""
    events = await run(
        [
            failure("请求异常: ProxyError: 502 Bad Gateway"),
            failure("请求异常: ProxyError: 502 Bad Gateway"),
            reply("重试后成功。"),
        ]
    )
    check("两次 502 后重试成功", any("重试后成功" in str(e.get("content")) for e in find(events, "message")))
    check("重试有状态提示", any("重试" in str(e.get("message")) for e in find(events, "status")))


async def test_auth_error_not_retried() -> None:
    events = await run([failure("HTTP 401: invalid api key")])
    errors = find(events, "error")
    check("鉴权失败直接报错不重试", len(errors) == 1 and "401" in str(errors[0].get("message")))


async def test_ask_choice() -> None:
    script = [
        tool_call(
            "ask_choice",
            {
                "question": "先做哪一步？",
                "options": [
                    {"label": "配置授权范围", "hint": "解决无目标可扫", "value": "配置授权范围"},
                    {"label": "安装工具", "value": "安装工具"},
                ],
            },
        )
    ]
    sid = new_session("choice")
    events = await run(script, sid)
    choice_events = find(events, "choice")
    check("产出选择题事件", len(choice_events) == 1, str(kinds(events)))
    with db() as conn:
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_choices WHERE session_id=? AND status='pending'", (sid,)
        ).fetchone()["c"]
    check("选择题入库待答", pending == 1, f"pending={pending}")


async def test_in_scope_scan_no_confirm() -> None:
    """目标直接开跑，不再打断用户。"""
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    events = await run([tool_call("start_scan", {"targets": ["https://demo.example.com"], "mode": "passive"})])
    check("发起评估不弹确认", not find(events, "confirm"), str(kinds(events)))
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    check("评估已建任务", after == before + 1, f"{before} -> {after}")


async def test_out_of_scope_confirm() -> None:
    """以前会被判「越界」的目标，现在直接建任务——授权范围这层已经取消。"""
    sid = new_session("oos")
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    events = await run([tool_call("start_scan", {"targets": ["https://any-other-site.test"], "mode": "passive"})], sid)
    confirm = find(events, "confirm")
    check("任意目标都不弹确认", len(confirm) == 0, str(kinds(events)))
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        row = conn.execute("SELECT authorization_ref FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    check("任务真的建了", after == before + 1, f"{before} -> {after}")
    check("授权依据记为免责声明", "免责声明" in str(row["authorization_ref"] if row else ""), str(row)[:160])


async def test_sensitive_file_confirm() -> None:
    """读取可能含凭据的文件前要问一次。"""
    set_settings({"work_dir": str(Path(TMP) / "ws"), "memory_path": ""})
    ws = Path(TMP) / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / ".env").write_text("TOKEN=abc", encoding="utf-8")
    events = await run([tool_call("read_file", {"path": ".env"})])
    confirm = find(events, "confirm")
    check("读敏感文件先弹确认", len(confirm) == 1, str(kinds(events)))
    check("确认卡标为读取敏感文件", str(confirm[0].get("label") if confirm else "") == "读取敏感文件")


async def test_sensitive_content_confirm() -> None:
    """敏感信息不止文件：普通文件里出现凭据，也要先问用户。"""
    ws = Path(TMP) / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "app.conf").write_text("db_password=SuperSecret123", encoding="utf-8")
    events = await run([tool_call("read_file", {"path": "app.conf"})])
    confirm = find(events, "confirm")
    check("结果含凭据先弹确认", len(confirm) == 1, str(kinds(events)))
    check("确认卡标为查看敏感内容", str(confirm[0].get("label") if confirm else "") == "查看敏感内容")
    with db() as conn:
        stored = conn.execute("SELECT args_json FROM chat_actions ORDER BY id DESC LIMIT 1").fetchone()
    check("确认后带查看原文标记", "__reveal_sensitive" in str(stored["args_json"] if stored else ""))


def test_mask_helpers() -> None:
    check("识别私钥", "私钥" in agent.sensitive_kinds("-----BEGIN RSA PRIVATE KEY-----"))
    check("识别云密钥", agent.sensitive_kinds({"k": "AKIAABCDEFGHIJKLMNOP"}) == ["云访问密钥"])
    masked = agent.mask_sensitive({"password": "abcd1234efgh"})
    check("凭据被脱敏", "abcd1234efgh" not in str(masked), str(masked))
    check("普通内容不误报", not agent.sensitive_kinds({"content": "hello world"}))
    # 脚本里写 json.dumps 不该被当成 .dump 备份文件，否则每写一次脚本就弹一次「凭据」确认
    check("json.dumps 不算敏感文件", not agent._looks_sensitive("json.dumps"), "json.dumps")
    check("真的备份文件仍算敏感", agent._looks_sensitive("db.dump") and agent._looks_sensitive("backup.sql"))
    check(".env 仍算敏感", agent._looks_sensitive("app/.env") and agent._looks_sensitive(".env.local"))


async def test_normal_file_no_confirm() -> None:
    """普通文件、登记资产这类日常动作不打扰用户。"""
    ws = Path(TMP) / "ws"
    (ws / "notes.txt").write_text("hello", encoding="utf-8")
    events = await run([tool_call("read_file", {"path": "notes.txt"})])
    check("读普通文件不弹确认", not find(events, "confirm"), str(kinds(events)))


async def test_create_asset_without_confirm() -> None:
    """登记资产属于日常动作，直接落库，不打断用户。"""
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
    events = await run([tool_call("create_asset", {"target": "https://demo.example.com", "name": "演示站"})])
    check("登记资产不弹确认", not find(events, "confirm"), str(kinds(events)))
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
    check("登记资产已落库", after == before + 1, f"{before} -> {after}")


async def test_progress_keeps_history() -> None:
    """进展不覆盖：一轮做三步就留三条，回看时才看得到每一步做了什么。"""
    ws = Path(TMP) / "trace_ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "n0.txt").write_text("row 0\n", encoding="utf-8")
    (ws / "n1.txt").write_text("row 1\n", encoding="utf-8")
    old = agent.get_settings().get("work_dir")
    set_settings({"work_dir": str(ws)})
    try:
        sid = new_session("trace")
        events = await run(
            [
                tool_call("read_file", {"path": "n0.txt"}, "c1"),
                tool_call("read_file", {"path": "n1.txt"}, "c2"),
                tool_call("platform_overview", {}, "c3"),
                reply("都看过了。"),
            ],
            sid,
        )
    finally:
        set_settings({"work_dir": old or ""})
    raw_steps = [str(e.get("content") or "") for e in find(events, "progress")]
    # 正式收尾前平台会插一条「已完成收尾核对」，那是自检不是工作步骤，单独算
    steps = [s for s in raw_steps if "收尾核对" not in s]
    check("收尾前做了自检", any("收尾核对" in s for s in raw_steps), str(raw_steps)[:300])
    check("三步各留一条进展", len(steps) == 3, str(steps))
    check("第一条写清动了哪个文件", bool(steps) and "n0.txt" in steps[0], str(steps))
    check("第二条写清动了哪个文件", len(steps) > 1 and "n1.txt" in steps[1], str(steps))
    check("每条都交代下一步", all("下一步" in s or "接下来" in s for s in steps), str(steps))
    check("不再单独推执行痕迹", not find(events, "activity"), str(kinds(events)))

    from mono.api.chat import _collapse_progress

    with db() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT id, role, content, level FROM chat_messages WHERE session_id=? ORDER BY id", (sid,)
            ).fetchall()
        ]
    folded = _collapse_progress(rows)
    replay = [m["content"] for m in folded if m["role"] == "progress"]
    check("回放里三步都在", len([s for s in replay if "收尾核对" not in s]) == 3, str(replay))
    check("回放也带自检那条", any("收尾核对" in s for s in replay), str(replay)[:200])
    check("回放不掺痕迹块", not [m for m in folded if m["role"] == "activity"], str(folded)[:200])
    check("回放文字与实时一致", replay == raw_steps, str(replay)[:200])


async def test_loading_merged() -> None:
    """「正在读取记忆」被「已读完记忆」覆盖成一条：同一件事不留两行。"""
    sid = new_session("loading")
    events = await run([tool_call("read_memory", {}), reply("记忆看过了。")], sid)
    steps = [str(e.get("content") or "") for e in find(events, "progress")]
    check("先播「正在读取记忆」", bool(steps) and steps[0] == "正在读取记忆", str(steps))
    check("随后播一条完成结论", len(steps) == 2 and "记忆" in steps[1], str(steps))
    from mono.api.chat import _collapse_progress

    with db() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT id, role, content, level FROM chat_messages WHERE session_id=? ORDER BY id", (sid,)
            ).fetchall()
        ]
    replay = [m["content"] for m in _collapse_progress(rows) if m["role"] == "progress"]
    check("回放把同一件事合成一条", len(replay) == 1 and replay[0] == steps[1], str(replay))


async def test_no_tool_feed() -> None:
    """工具过程不推卡片、不落技术痕迹：对话里只留一句人话进展。"""
    sid = new_session("quiet")
    events = await run([tool_call("platform_overview"), reply("现状已掌握。")], sid)
    check("不推送工具卡片", not find(events, "tool"), str(kinds(events)))
    check("过程有进度提示", any("核对" in str(e.get("message")) for e in find(events, "status")))
    with db() as conn:
        rows = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE session_id=? AND role='tool'", (sid,)
        ).fetchone()["c"]
    check("不写技术痕迹行", rows == 0, f"rows={rows}")
    steps = [str(e.get("content") or "") for e in find(events, "progress")]
    check("留一条人话进展", len(steps) == 1 and "已盘点" in steps[0], str(steps))


async def test_process_narration_dropped() -> None:
    """模型调工具前写的"我先查看…"属于过程独白，不能出现在对话里。"""
    script = [
        {
            "message": {
                "role": "assistant",
                "content": "我先查看平台概览，再回答你。",
                "tool_calls": [
                    {
                        "id": "call_x",
                        "type": "function",
                        "function": {"name": "platform_overview", "arguments": "{}"},
                    }
                ],
            },
            "finish_reason": "tool_calls",
        },
        reply("结论：平台一切正常。"),
    ]
    events = await run(script)
    texts = " ".join(str(e.get("content") or "") for e in find(events, "message"))
    check("过程独白被丢弃", "我先查看" not in texts, texts[:80])
    check("结论正常输出", "一切正常" in texts)


async def test_choice_keeps_conclusion() -> None:
    """选择题前必须先给结论，只有重复的问句被裁掉。"""
    script = [
        {
            "message": {
                "role": "assistant",
                "content": "**关键结论**：当前无待处理风险。下一步先补哪块？",
                "tool_calls": [
                    {
                        "id": "call_c",
                        "type": "function",
                        "function": {
                            "name": "ask_choice",
                            "arguments": json.dumps(
                                {
                                    "question": "下一步先做哪项？",
                                    "options": [{"label": "补连接器"}, {"label": "跑评估"}],
                                },
                                ensure_ascii=False,
                            ),
                        },
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ]
    events = await run(script)
    texts = " ".join(str(e.get("content") or "") for e in find(events, "message"))
    check("选择题前保留结论", "关键结论" in texts, texts[:80])
    check("重复问句被裁掉", "下一步先补哪块" not in texts, texts[:80])
    check("选择题照常产出", len(find(events, "choice")) == 1)


def test_lead_in_stripped() -> None:
    """选择题前只留「下一步建议」这种悬空标题时，标题要一并裁掉。"""
    check("悬空引导标题被裁掉", agent._strip_trailing_lead_in("结论：没风险。\n\n**下一步建议**") == "结论：没风险。")
    kept = agent._strip_trailing_lead_in("结论。\n\n下一步建议先补工具")
    check("有内容的建议行不误删", kept.endswith("下一步建议先补工具"), kept)


async def test_open_question_trimmed_without_card() -> None:
    """模型没给选择卡却用问句收尾：平台裁掉问句，不让用户替它做决定。"""
    script = [reply("风险集中在登录接口，另有两条中危。\n\n要我现在跑一次评估吗？")]
    events = await run(script)
    texts = " ".join(str(e.get("content") or "") for e in find(events, "message"))
    check("问句结尾被裁掉", "现在跑一次评估吗" not in texts, texts[:80])
    check("结论仍然保留", "风险集中在登录接口" in texts, texts[:80])


def test_prompt_contract() -> None:
    """提示与工具规格要与"免责声明即授权"一致，且不再索要编号。"""
    check("提示禁止索要授权编号", "绝不要再索要授权编号" in agent.SYSTEM_PROMPT)
    check("提示禁止播报操作过程", "不要向用户播报" in agent.SYSTEM_PROMPT)
    spec = next(t for t in agent.TOOL_SPECS if t["function"]["name"] == "start_scan")
    check("发起评估不再强制授权编号", spec["function"]["parameters"]["required"] == [])
    check(
        "确认只剩敏感文件与删除两类",
        set(agent.CONFIRM_LABELS) == {"read_file", "run_shell", "run_python"},
        str(agent.CONFIRM_LABELS),
    )
    check("提示说明只有两件事要确认", "只有两件事会让用户点头" in agent.SYSTEM_PROMPT)
    check("提示说明不再校验授权范围", "不需要任何范围确认" in agent.SYSTEM_PROMPT)
    check("提示要求先读前端代码", "先读前端代码，再按权重排测试顺序" in agent.SYSTEM_PROMPT)
    check("提示要求先给结论", "第一句就给判断或结论" in agent.SYSTEM_PROMPT)
    check("提示规定「继续」即授权执行", "视为授权你按推荐方案直接执行到底" in agent.SYSTEM_PROMPT)
    check("提示禁止重复追问", "同一个问题在一次会话里只问一次" in agent.SYSTEM_PROMPT)
    check("提示统一「渗透测试」措辞", "这件事叫「渗透测试」" in agent.SYSTEM_PROMPT)
    check("提示声明有命令执行能力", "不要回答\"我没有命令执行能力\"" in agent.SYSTEM_PROMPT)
    check("提示要求每步给进展", "每一步做完都要给一句进展" in agent.SYSTEM_PROMPT)
    check("提示说明进展会累积", "不断累积" in agent.SYSTEM_PROMPT)
    check("提示要求记忆读全", "记忆必须读全" in agent.SYSTEM_PROMPT)
    # 能力清单里没有的项目（CORS、TLS、主机头…）不该再被"顺手测一下"
    check("提示禁止测清单外能力", "清单之外的一律不测" in agent.SYSTEM_PROMPT)
    check(
        "下架能力在提示里点名",
        all(word in agent.SYSTEM_PROMPT for word in ("CORS", "TLS", "主机头", "请求走私", "验证码绕过")),
    )
    check(
        "提示禁止用广度动作凑数",
        "端口扫描、目录爆破、子域枚举" in agent.SYSTEM_PROMPT,
    )
    # 三个方向是硬指标：提示词和推回提示都要写死
    check(
        "提示写明三个方向",
        all(word in agent.SYSTEM_PROMPT for word in ("高敏感信息泄露", "控制权限", "可造成实际危害")),
    )
    check(
        "推回提示也带三个方向",
        all(word in agent.NEXT_ROUND_PROMPT for word in ("高敏感信息泄露", "控制权限", "可造成实际危害")),
    )
    names = {t["function"]["name"] for t in agent.TOOL_SPECS}
    check(
        "命令/脚本/请求三类工具已注册",
        {"run_shell", "run_python", "http_request"} <= names,
        str(sorted(names)),
    )
    check("记忆检索工具已注册", {"read_memory", "search_memory"} <= names)


async def test_duplicate_tool_not_repeated() -> None:
    """同名同参工具被模型重复调用时，平台仍应正常处理（不崩、不重复写库）。"""
    script = [tool_call("platform_overview"), tool_call("platform_overview"), reply("已拿到概览。")]
    events = await run(script)
    check("重复调用不崩溃", not find(events, "error"))
    check("重复调用只回一次结论", any("概览" in str(e.get("content")) for e in find(events, "message")))


async def test_duplicate_batch_call_deduped() -> None:
    """批量检测连点多次时只真正执行一次，避免模型绕圈浪费轮次。"""
    script = [
        tool_call("test_all_connectors"),
        tool_call("test_all_connectors", {"category": "ai"}),
        reply("连接器情况已汇总。"),
    ]
    events = await run(script)
    running = [e for e in find(events, "status") if "能力接入" in str(e.get("message"))]
    check("重复批量检测只执行一次", len(running) == 1, f"执行 {len(running)} 次")
    check("去重后仍能收尾", any("连接器" in str(e.get("content")) for e in find(events, "message")))


async def test_shrink_tool_history() -> None:
    messages = [{"role": "system", "content": "s"}]
    for i in range(12):
        messages.append({"role": "tool", "content": "x" * 6000, "tool_call_id": f"c{i}"})
    agent._shrink_tool_history(messages)
    total = sum(len(str(m.get("content") or "")) for m in messages)
    check("上下文压缩生效", total <= agent.CONTEXT_CHAR_BUDGET, f"total={total}")
    intact = sum(1 for m in messages[-4:] if len(str(m.get("content") or "")) > 5000)
    check("最近 4 条工具结果保持完整", intact == 4, f"intact={intact}")


async def test_history_char_budget() -> None:
    sid = new_session("history")
    with db() as conn:
        for i in range(30):
            conn.execute(
                "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
                (sid, "user" if i % 2 == 0 else "assistant", "长" * 2000, now_iso()),
            )
    history = agent._history(sid)
    total = sum(len(item["content"]) for item in history)
    check("历史按字数预算裁剪", total <= agent.HISTORY_CHAR_BUDGET + 2000, f"total={total}")
    check("历史保留最近对话", history and history[-1]["content"].startswith("长"))


async def test_context_grows_slowly() -> None:
    """20 轮对话后送进模型的上下文仍应可控。"""
    script = []
    for _ in range(10):
        script.append(tool_call("platform_overview"))
        script.append(reply("第 N 轮说明。" * 40))
    script.append(reply("收尾。"))
    events = await run(script)
    payload = find(events, "_llm_messages")[0]["data"]
    biggest = max(sum(len(str(m.get("content") or "")) for m in turn) for turn in payload)
    check("多轮后上下文未爆", biggest < agent.CONTEXT_CHAR_BUDGET * 3, f"biggest={biggest}")


async def test_no_model_configured() -> None:
    agent.pick_llm = lambda provider="": None  # type: ignore[assignment]
    events = []
    async for event in agent.run_agent(new_session("nomodel"), "admin"):
        events.append(event)
    check("未配置模型给出明确提示", len(find(events, "error")) == 1)


def test_memory_tools() -> None:
    """记忆目录与工作目录都能被读到；目录外拒绝；写入仍只允许工作目录。"""
    root = Path(TMP)
    memory = root / "memory"
    work = root / "workspace"
    memory.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    (memory / "MEMORY.md").write_text("# 偏好\n- 报告用 Markdown\n", encoding="utf-8")
    (work / "note.md").write_text("工作目录内容\n", encoding="utf-8")
    set_settings({"memory_path": str(memory), "work_dir": str(work)})

    listed = agent._tool_list_dir({"scope": "memory"}, "admin")
    names = [item["name"] for item in listed.get("entries") or []]
    check("记忆目录可列目录", bool(listed.get("ok")) and "MEMORY.md" in names, str(listed)[:200])

    rel = agent._tool_read_file({"path": "MEMORY.md"}, "admin")
    check("按文件名读到记忆", bool(rel.get("ok")) and "报告用 Markdown" in rel.get("content", ""), str(rel)[:200])

    absolute = agent._tool_read_file({"path": str(memory / "MEMORY.md")}, "admin")
    check("按绝对路径读到记忆", bool(absolute.get("ok")) and absolute.get("scope") == "记忆目录", str(absolute)[:200])

    allmem = agent._tool_read_memory({}, "admin")
    check("read_memory 一次取全文", bool(allmem.get("ok")) and "报告用 Markdown" in allmem.get("content", ""), str(allmem)[:200])

    outside = agent._tool_read_file({"path": str(root / "mono.db")}, "admin")
    check("配置目录之外读取被拒", outside.get("ok") is False and "拒绝" in str(outside.get("error")), str(outside)[:200])

    denied = agent._tool_write_file({"path": str(memory / "MEMORY.md"), "content": "篡改"}, "admin")
    check("不能改写记忆文件", denied.get("ok") is False, str(denied)[:200])

    (memory / "README.md").write_text("目录说明，不是用户记忆", encoding="utf-8")
    names_now = [item.name for item in agent.memory_files()]
    check("记忆目录里每个文件都算记忆", "README.md" in names_now and "MEMORY.md" in names_now, str(names_now))

    # 记忆路径配成单个文件时，只暴露这个文件，不带出同目录的其他内容
    set_settings({"memory_path": str(memory / "MEMORY.md")})
    only = agent._tool_read_file({"path": "MEMORY.md"}, "admin")
    check("记忆配单文件可读", bool(only.get("ok")) and only.get("scope") == "记忆目录", str(only)[:160])
    sibling = agent._tool_read_file({"path": str(memory / "README.md")}, "admin")
    check("单文件模式不带出同目录文件", sibling.get("ok") is False, str(sibling)[:160])
    set_settings({"memory_path": str(memory)})

    ctx = agent._workspace_context()
    check("上下文写明记忆目录与读法", "记忆目录" in ctx and "read_memory" in ctx, ctx[:200])
    check("上下文预载记忆内容", "报告用 Markdown" in ctx, ctx[:200])


async def test_interjection_priority() -> None:
    """AI 思考中用户插话：当前轮作废，插话作为最高优先级指令进入下一轮。"""
    sid = new_session("interject")
    state = {"round": 0}

    class InterruptLLM(FakeLLM):
        async def stream_complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=180):
            self.seen_messages.append([dict(m) for m in messages])
            state["round"] += 1
            if state["round"] == 1:
                agent.push_interjection(sid, "改成只看高危")
                for _ in range(4):
                    yield ("text", "正在盘点")
                yield ("final", {"message": {"role": "assistant", "content": "正在盘点"}, "finish_reason": "stop"})
                return
            for part in ["已按你的补充", "，只看高危。"]:
                yield ("text", part)
            yield (
                "final",
                {"message": {"role": "assistant", "content": "已按你的补充，只看高危。"}, "finish_reason": "stop"},
            )

    llm = InterruptLLM([])
    use(llm)
    events = []
    async for event in agent.run_agent(sid, "admin"):
        events.append(event)

    joined = json.dumps(llm.seen_messages[-1], ensure_ascii=False)
    check("插话进入下一轮上下文", "改成只看高危" in joined)
    check("插话标注为最高优先级", "优先级高于原任务" in joined)
    check("插话后给出新结论", any(e.get("type") == "message" and "只看高危" in e.get("content", "") for e in events))
    check("插话不产生报错", not find(events, "error"))
    check("任务结束后不再登记为忙碌", agent.agent_busy(sid) is False)


def test_interjection_queue() -> None:
    """没有在跑的任务时不接受插话，避免消息被静默吞掉。"""
    sid = new_session("idle")
    check("空闲时插话不入队", agent.push_interjection(sid, "随便说一句") is False)
    agent._ACTIVE_SESSIONS.add(sid)
    check("运行中插话可入队", agent.push_interjection(sid, "补充一句") is True)
    check("插话可取回", agent.take_interjections(sid) == ["补充一句"])
    agent._ACTIVE_SESSIONS.discard(sid)


async def test_interjection_after_answer() -> None:
    """正文已经推给用户之后才插话：也要补一轮，不能把用户最后那句话吞掉。"""
    sid = new_session("tail")
    llm = FakeLLM([reply("第一版结论。"), reply("补充后的结论。")])
    use(llm)
    events = []
    async for event in agent.run_agent(sid, "admin"):
        events.append(event)
        if event.get("type") == "message" and "第一版" in event.get("content", ""):
            agent.push_interjection(sid, "再补一条风险提示")

    messages = [e for e in events if e.get("type") == "message"]
    check("收尾插话会补一轮", len(messages) == 2 and "补充后的结论" in messages[-1].get("content", ""), str(messages)[:200])
    joined = json.dumps(llm.seen_messages[-1], ensure_ascii=False)
    check("补的那轮带上插话", "再补一条风险提示" in joined)
    check("补完只发一次 done", len(find(events, "done")) == 1)


async def test_progress_each_step() -> None:
    """每一步做完都要给结论：模型写的那句话原样变成进度条，且落库可回放。"""
    sid = new_session("progress")
    stepped = {
        "message": {
            "role": "assistant",
            "content": "已拿到 12 个 JS 文件，接下来批量找接口。",
            "tool_calls": [
                {
                    "id": "call_p1",
                    "type": "function",
                    "function": {"name": "platform_overview", "arguments": "{}"},
                }
            ],
        },
        "finish_reason": "tool_calls",
    }
    events = await run([stepped, reply("结论：接口清单已理出。")], sid)
    progress = find(events, "progress")
    check("每步产出进度事件", len(progress) == 1, str(kinds(events)))
    text = str(progress[0].get("content") if progress else "")
    check("进度就是那句结论", "已拿到 12 个 JS 文件" in text and len(text) <= 70, text)
    with db() as conn:
        rows = conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='progress'", (sid,)
        ).fetchall()
    check("进度落库可回放", len(rows) == 1 and "接下来说" not in str(rows[0]), str([r["content"] for r in rows])[:120])
    check("进度不影响最终结论", any("接口清单已理出" in str(e.get("content")) for e in find(events, "message")))


async def test_progress_fallback() -> None:
    """模型没写"已…接下来…"时，平台自己拼一句，不能让用户只看到沉默。"""
    events = await run([tool_call("platform_overview"), reply("结论：一切正常。")])
    progress = find(events, "progress")
    check("无独白也有进度", len(progress) == 1, str(kinds(events)))
    check("兜底进度说得清做了什么", "已盘点平台现状" in str(progress[0].get("content") if progress else ""), str(progress)[:160])


def test_clean_progress() -> None:
    """进度文案清洗：去掉列表符号与重复标点，长句截断。"""
    check("去掉列表符号", agent._clean_progress("- 已拿到 3 个域名") == "已拿到 3 个域名")
    check("只取第一句", agent._clean_progress("已跑完第一轮。接下来扫接口。") == "已跑完第一轮。")
    long_line = agent._clean_progress("已" + "很长的结论" * 30)
    check("过长会截断", len(long_line) <= agent.PROGRESS_MAX_CHARS, str(len(long_line)))
    # "我先去看看"是意图，不是结论：不能当成这一步的结果播报出去
    intent = agent._progress_event("我先把平台现状和你的习惯取回来。", [{"tool": "platform_overview", "args": {}, "result": {}}])
    check("意图句不当作结论", intent.startswith("已盘点平台现状"), intent)
    done = agent._progress_event("已拿到 12 个 JS 文件，接下来批量找接口。", [{"tool": "platform_overview", "args": {}, "result": {}}])
    check("结论句优先用模型原话", done.startswith("已拿到 12 个 JS"), done)


async def test_shell_and_python() -> None:
    """真有命令执行能力：shell 与 Python 都能跑，输出与退出码都拿得到。"""
    ws = Path(TMP) / "exec"
    ws.mkdir(parents=True, exist_ok=True)
    set_settings({"work_dir": str(ws), "memory_path": ""})

    shell = agent._tool_run_shell({"command": "echo mono-ok"}, "admin")
    check("run_shell 能执行", bool(shell.get("ok")) and "mono-ok" in str(shell.get("stdout")), str(shell)[:200])
    check("run_shell 带退出码", shell.get("exit_code") == 0, str(shell.get("exit_code")))

    fail = agent._tool_run_shell({"command": "exit 3"}, "admin")
    check("非零退出码如实上报", fail.get("ok") is False and fail.get("exit_code") == 3, str(fail)[:160])

    py = agent._tool_run_python({"code": "print(6*7)"}, "admin")
    check("run_python 能执行", bool(py.get("ok")) and "42" in str(py.get("stdout")), str(py)[:200])

    bad_py = agent._tool_run_python({"code": "raise SystemExit('boom')"}, "admin")
    check("脚本报错带回 stderr", bad_py.get("ok") is False and "boom" in str(bad_py.get("stderr")), str(bad_py)[:200])

    blocked = agent._tool_run_shell({"command": "rm -rf /"}, "admin")
    check("破坏性命令直接拒绝", blocked.get("ok") is False and "不可逆" in str(blocked.get("error")), str(blocked)[:160])

    no_cmd = agent._tool_run_shell({"command": ""}, "admin")
    check("空命令被拒", no_cmd.get("ok") is False)


async def test_http_request_tool() -> None:
    """http_request 等价 curl：拿到状态码、响应体，还给出可归档的请求包/响应包。"""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"ok":true,"echo":"mono"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self.send_response(201)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):  # 静音，别把测试输出刷满
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # 这里测的是 HTTP 客户端本身：任何目标都直接发，不再有范围拦截
        got = agent._tool_http_request({"url": f"http://127.0.0.1:{port}/api/status"}, "admin")
        check("http_request 正常返回", got.get("status") == 200 and "mono" in str(got.get("body")), str(got)[:200])
        check("带请求包", "GET /api/status HTTP/1.1" in str(got.get("request_packet")), str(got.get("request_packet"))[:160])
        check("带响应包", "HTTP/1.1 200" in str(got.get("response_packet")), str(got.get("response_packet"))[:160])

        posted = agent._tool_http_request(
            {
                "url": f"http://127.0.0.1:{port}/submit",
                "method": "POST",
                "body": '{"a":1}',
                "raw_body_is_json": True,
            },
            "admin",
        )
        check("POST 正常返回", posted.get("status") == 201, str(posted)[:200])

        dead = agent._tool_http_request({"url": "http://127.0.0.1:1/none"}, "admin")
        check("连不上给出错误不抛异常", dead.get("ok") is False and "失败" in str(dead.get("error")), str(dead)[:160])
    finally:
        server.shutdown()


async def test_http_out_of_scope_confirm() -> None:
    """任意域名的请求都直接发，不再问「这个域名有没有授权」。"""
    sid = new_session("oos-http")
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM chat_actions").fetchone()["c"]
    events = await run([tool_call("http_request", {"url": "https://any-other-site.test/login"})], sid)
    check("任意域名请求都不弹确认", not find(events, "confirm"), str(kinds(events)))
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS c FROM chat_actions").fetchone()["c"]
    check("没有生成确认卡记录", after == before, f"{before} -> {after}")


async def test_shell_sensitive_confirm() -> None:
    """命令要读凭据文件时，和 read_file 一样先问一次。"""
    sid = new_session("shell-env")
    events = await run([tool_call("run_shell", {"command": "type .env"})], sid)
    confirm = find(events, "confirm")
    check("读凭据文件的命令先确认", len(confirm) == 1, str(kinds(events)))
    check("确认卡标为读取敏感文件", str(confirm[0].get("label") if confirm else "") == "读取敏感文件")


async def test_shell_out_of_scope_confirm() -> None:
    """命令里带的域名同样不拦——授权已由免责声明覆盖，只留删除类确认。"""
    sid = new_session("shell-oos")
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM chat_actions").fetchone()["c"]
    events = await run([tool_call("run_shell", {"command": "curl -s https://any-other-site.test/login"})], sid)
    check("命令访问站外域名不弹确认", not find(events, "confirm"), str(kinds(events)))
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS c FROM chat_actions").fetchone()["c"]
    check("没有生成确认卡记录", after == before, f"{before} -> {after}")

    sid2 = new_session("shell-in")
    events2 = await run([tool_call("run_shell", {"command": "echo hello"})], sid2)
    check("普通只读命令直接执行", not find(events2, "confirm"), str(kinds(events2)))


def test_delete_and_ask_switches() -> None:
    """删除操作要问；执行命令本身不问；两个询问开关平级、各自独立，没有总开关。"""
    from mono.engine.capabilities import (
        ASK_DELETE_KEY,
        ASK_SENSITIVE_KEY,
        set_switches,
    )

    set_switches({ASK_DELETE_KEY: True, ASK_SENSITIVE_KEY: True})

    reason = agent.confirmation_reason("run_shell", {"command": "rm notes.txt"})
    check("删除命令要确认", "删除" in reason, reason)
    check("删除命令标为删除操作", agent.confirm_label("run_shell", reason) == "删除操作", reason)
    check("普通命令不确认", agent.confirmation_reason("run_shell", {"command": "ls -la"}) == "")
    check(
        "Python 删目录也要确认",
        "删除" in agent.confirmation_reason("run_python", {"code": "import shutil; shutil.rmtree('tmp')"}),
    )
    check("Python 普通代码不确认", agent.confirmation_reason("run_python", {"code": "print(sum([1,2]))"}) == "")
    drop = agent.confirmation_reason("run_shell", {"command": "psql -c 'drop table users'"})
    check("删库语句也要确认", "删" in drop, drop)
    check("删库语句标为删除操作", agent.confirm_label("run_shell", drop) == "删除操作", drop)
    check("变量 del 不算删除文件", agent.confirmation_reason("run_python", {"code": "data = [1]\ndel data[0]"}) == "")

    set_switches({ASK_DELETE_KEY: False})
    check("关掉删除开关就不问", agent.confirmation_reason("run_shell", {"command": "rm notes.txt"}) == "")
    set_switches({ASK_DELETE_KEY: True})

    check(
        "站外请求不再要确认",
        agent.confirmation_reason("http_request", {"url": "https://any-other-site.test/"}) == "",
    )
    check(
        "站外命令也不再要确认",
        agent.confirmation_reason("run_shell", {"command": "curl -s https://any-other-site.test/"}) == "",
    )

    check("读凭据文件要确认", "凭据" in agent.confirmation_reason("read_file", {"path": ".env"}))
    set_switches({ASK_SENSITIVE_KEY: False})
    check("关掉敏感开关就不问", agent.confirmation_reason("read_file", {"path": ".env"}) == "")
    set_switches({ASK_SENSITIVE_KEY: True})

    set_switches({ASK_SENSITIVE_KEY: False, ASK_DELETE_KEY: False})
    check("两个开关都关了就一律不问", agent.confirmation_reason("read_file", {"path": ".env"}) == "")
    check(
        "两个开关都关了删除也不问",
        agent.confirmation_reason("run_shell", {"command": "rm notes.txt"}) == "",
    )
    set_switches({ASK_SENSITIVE_KEY: True, ASK_DELETE_KEY: True})


def test_progress_highlight() -> None:
    """关键节点要能被识别、不被压缩，归档高危漏洞时自动升级成关键突破。"""
    check("关键突破被识别", agent.progress_level("关键突破：登录接口未授权") == "highlight")
    # 十种提醒词都要认，别只认「关键突破」一种
    for word in (
        "重大突破", "关键线索", "关键发现", "重大发现",
        "关键结论", "关键风险", "重大风险", "核心发现", "关键证据",
    ):
        check(f"{word}被识别", agent.progress_level(f"{word}：发现一条可利用路径") == "highlight")
    check("方括号写法也认", agent.progress_level("【重大发现】订单接口无鉴权") == "highlight")
    check("加粗星号写法也认", agent.progress_level("**关键证据**：日志里留了口令") == "highlight")
    # 口语化表达同样算关键节点，格式不必硬套四个字的书面词
    check("口语化：找到漏洞点", agent.progress_level("已经找到漏洞点，可以继续深入") == "focus")
    check("口语化：还能往下挖", agent.progress_level("这个接口还能往下挖，接着验") == "focus")
    check("口语化：有突破口", agent.progress_level("这里有个突破口，我顺着往下走") == "highlight")
    check("口语化：高危可继续查", agent.progress_level("确认是高危，继续深入看看能不能拿到数据") == "focus")
    check("普通进度是 info", agent.progress_level("已拿到 3 个接口") == "info")
    line = agent._progress_event("关键突破：发现未授权访问，可直接读取他人订单", [])
    check("关键结论保留完整", line.startswith("关键突破") and "未授权访问" in line, line)
    check("关键结论不被截成半句", not line.endswith("…"), line)
    results = [
        {
            "tool": "record_finding",
            "args": {"title": "登录接口未授权访问漏洞", "severity": "high"},
            "result": {"ok": True},
        }
    ]
    line2 = agent._progress_event("已归档一条结论", results)
    check("归档高危自动升级为关键突破", line2.startswith("关键突破"), line2)
    low = agent._progress_event(
        "已归档一条结论",
        [{"tool": "record_finding", "args": {"title": "缺少安全响应头", "severity": "low"}, "result": {"ok": True}}],
    )
    check("低危用关键结论而不是突破", low.startswith("关键结论"), low)


async def test_progress_highlight_event() -> None:
    """高亮进度要以 level=highlight 推给前端，并落库供刷新后回放。"""
    item = tool_call("platform_overview")
    item["message"]["content"] = "关键突破：平台侧发现一个未授权接口"
    sid = new_session("highlight")
    events = await run([item, reply("已核实并归档。")], sid)
    prog = find(events, "progress")
    check("进度事件带 level", bool(prog) and prog[0].get("level") == "highlight", str(prog)[:200])
    with db() as conn:
        row = conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='progress' ORDER BY id DESC LIMIT 1",
            (sid,),
        ).fetchone()
    check("高亮进度落库", bool(row) and "关键突破" in str(row["content"]))


def test_domain_normalization() -> None:
    """漏洞按域名归组：协议、路径、查询串都丢掉，端口只在非默认时保留。"""
    from mono.netutil import host_of

    check("取主机名", host_of("https://A.example.com/x?y=1") == "a.example.com", host_of("https://A.example.com/x?y=1"))
    check("80 端口不写出来", host_of("http://a.example.com:80/x") == "a.example.com")
    check("非默认端口保留", host_of("https://a.example.com:8443/x") == "a.example.com:8443")
    check("省略协议的写法也认", host_of("a.example.com/login") == "a.example.com")
    check("IP 带端口", host_of("10.0.0.5:8080/admin") == "10.0.0.5:8080")
    check("IPv6 归一", host_of("http://[::1]:9000/x") == "[::1]:9000")
    check("空值给占位", host_of("") == "未标注域名")


async def test_finding_realtime() -> None:
    """归档即输出：模型一确认漏洞，卡片当场推给前端并落库，回放还在。"""
    sid = new_session("finding-live")
    record = tool_call(
        "record_finding",
        {
            "url": "https://demo.example.com/api/users?id=1",
            "title": "用户资料未授权访问",
            "severity": "high",
        },
    )
    events = await run([record, reply("已归档，继续下一步。")], sid)
    cards = find(events, "finding")
    check("归档后立刻推出漏洞卡片", len(cards) == 1, str(cards)[:200])
    card = (cards[0].get("finding") or {}) if cards else {}
    check("卡片带漏洞标题", card.get("title") == "用户资料未授权访问", str(card))
    check("卡片带危害等级", card.get("severity") == "high" and card.get("severity_label") == "高危", str(card))
    check("卡片带归属域名", card.get("domain") == "demo.example.com", str(card))
    check("卡片带完整 URL", str(card.get("url") or "").endswith("/api/users?id=1"), str(card))
    with db() as conn:
        rows = conn.execute(
            "SELECT role, level, content FROM chat_messages WHERE session_id=? AND role='finding'", (sid,)
        ).fetchall()
    check("漏洞卡片落库", len(rows) == 1, str(len(rows)))
    check("落库带危害等级", bool(rows) and rows[0]["level"] == "high", str(rows)[:160])
    check("落库内容可解析", bool(rows) and json.loads(rows[0]["content"]).get("domain") == "demo.example.com")
    # 卡片已经把「发现了什么」说清楚了，别再补一句同样的进度
    lines = [str(e.get("content") or "") for e in find(events, "progress")]
    check("卡片不再重复一句进度", not any("已确认并归档「用户资料未授权访问」" in line for line in lines), str(lines)[:200])


def test_memory_full_read() -> None:
    """记忆再大也要读完：分页游标覆盖到最后一段，末尾内容能拿到。"""
    memory = Path(TMP) / "big-memory"
    (memory / "sub").mkdir(parents=True, exist_ok=True)
    first = "# 偏好\n" + ("按时汇报进度。\n" * 1200)
    second = "# 历史\n" + ("上一轮评估结论：接口鉴权缺失。\n" * 900)
    (memory / "MEMORY.md").write_text(first, encoding="utf-8")
    (memory / "sub" / "HISTORY.md").write_text(second, encoding="utf-8")
    (memory / "校验码.txt").write_text("结尾标记：MONO-TAIL-9Z\n", encoding="utf-8")
    set_settings({"memory_path": str(memory)})

    total = sum(item["chars"] for item in agent.memory_manifest())
    check("记忆目录递归统计", len(agent.memory_manifest()) == 3, str(agent.memory_manifest()))

    cursor = 0
    pieces: list[str] = []
    rounds = 0
    while True:
        data = agent._tool_read_memory({"cursor": cursor}, "admin")
        pieces.append(str(data.get("content") or ""))
        rounds += 1
        if not data.get("has_more"):
            break
        cursor = int(data.get("next_cursor") or 0)
        if rounds > 40:  # 防御：绝不能死循环
            break
    joined = "".join(pieces)
    check("分页读到 has_more=false", rounds > 1 and not data.get("has_more"), f"rounds={rounds}")
    check("末尾内容能读到", "MONO-TAIL-9Z" in joined, joined[-120:])
    check("分页拼起来没有缺字", len(joined) == int(data.get("total_chars") or 0), f"{len(joined)} vs {data.get('total_chars')}")
    check("全文长度与清单一致", abs(len(joined) - total) < 400, f"{len(joined)} vs {total}")

    single = agent._tool_read_memory({"only": "校验码.txt"}, "admin")
    check("可按单个文件读", "MONO-TAIL-9Z" in str(single.get("content")), str(single)[:160])
    check("单文件读仍报总量", int(single.get("total_chars") or 0) > 0)

    found = agent._tool_search_memory({"keyword": "MONO-TAIL"}, "admin")
    check("记忆可检索", found.get("count") == 1 and "校验码.txt" in str(found.get("matches")), str(found)[:200])

    ctx = agent._workspace_context()
    check("上下文标出记忆总量", "合计约" in ctx or "全部约" in ctx, ctx[:200])
    check("上下文提示未读完要续读", "记忆未读完" in ctx or "read_memory" in ctx, ctx[:200])

    pages = agent.memory_chunk(cursor=0, limit=2000)
    check("分块大小可控", len(pages["content"]) == 2000 and pages["has_more"] is True, str(len(pages["content"])))

    # 分块大小必须小于工具结果预算，否则 JSON 被截断，模型以为读到了其实少了尾巴
    biggest = agent._tool_read_memory({"limit": 999999}, "admin")
    compact = agent._compact(biggest, "read_memory")
    check("大分块不会被压缩器截断", "内容已截断" not in compact, compact[-80:])
    check("返回的正文与 chars 一致", len(biggest.get("content") or "") == int(biggest.get("chars") or -1), str(biggest.get("chars")))
    check("分块上限受预算约束", int(biggest.get("chars") or 0) <= agent.READ_CHUNK_MAX, f"{biggest.get('chars')} vs {agent.READ_CHUNK_MAX}")

    agent._tool_write_file({"path": "x.txt", "content": "1"}, "admin")
    denied = agent._tool_write_file({"path": str(memory / "MEMORY.md"), "content": "改"}, "admin")
    check("记忆仍不可写", denied.get("ok") is False, str(denied)[:120])


def test_grant_once_and_target_skip() -> None:
    """同一处信息只问一次；目标侧的敏感信息不问，我自己的才问。"""
    sid = new_session("grant")
    reason = agent.confirmation_reason("read_file", {"path": ".env"}, sid)
    check("第一次读自己的凭据要问", "凭据" in reason, reason)
    agent.remember_grant(sid, agent.grant_key("read_file", {"path": ".env"}), "approved")
    check("同一处信息第二次不再问", agent.confirmation_reason("read_file", {"path": ".env"}, sid) == "")

    other = new_session("grant2")
    check("换个会话仍要问一次", "凭据" in agent.confirmation_reason("read_file", {"path": ".env"}, other))

    target_env = str(agent.WORKSPACE_DIR / "target" / ".env")
    check("目标侧 .env 不问", agent.confirmation_reason("read_file", {"path": target_env}, sid) == "")
    check("目标侧命令也不问", agent.confirmation_reason("run_shell", {"command": f"cat {target_env}"}, sid) == "")
    check("我自己的凭据命令仍要问", "凭据" in agent.confirmation_reason("run_shell", {"command": "cat ~/.ssh/id_rsa"}, sid))

    # 走一次真实的"确认卡 → 用户点确认"，确认过的信息自动记账，第二次不再问
    action = agent.create_action(sid, "admin", "read_file", {"path": ".env"}, "读凭据")
    agent.decide_action(int(action["id"]), "approved")
    check("点过确认后自动记住这处信息", agent.confirmation_reason("read_file", {"path": ".env"}, sid) == "")


async def test_interjection_acknowledged() -> None:
    """用户插话：先回一句「收到，我这么处理」，再继续动手，不能闷头干活。"""
    sid = new_session("ack")
    state = {"round": 0}

    class AckLLM(FakeLLM):
        async def stream_complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=180):
            self.seen_messages.append([dict(m) for m in messages])
            state["round"] += 1
            if state["round"] == 1:
                agent.push_interjection(sid, "停止探测，保留现有结论")
                yield ("text", "正在验第三个接口")
                yield (
                    "final",
                    {"message": {"role": "assistant", "content": "正在验第三个接口"}, "finish_reason": "stop"},
                )
                return
            if state["round"] == 2:
                ack = "收到，已归档的 3 条结论保留，剩下的不再探测，我直接出报告。"
                message = {
                    "role": "assistant",
                    "content": ack,
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": "list_findings", "arguments": "{}"},
                        }
                    ],
                }
                yield ("final", {"message": message, "finish_reason": "tool_calls"})
                return
            yield ("text", "报告已按现有 3 条结论生成。")
            yield (
                "final",
                {"message": {"role": "assistant", "content": "报告已按现有 3 条结论生成。"}, "finish_reason": "stop"},
            )

    use(AckLLM([]))
    events = []
    async for event in agent.run_agent(sid, "admin"):
        events.append(event)

    texts = [str(e.get("content") or "") for e in events if e["type"] == "message"]
    ack_index = next((i for i, t in enumerate(texts) if "收到" in t and "3 条" in t), -1)
    final_index = next((i for i, t in enumerate(texts) if "报告已按现有" in t), -1)
    check("插话后先回应用户", ack_index >= 0, str(texts)[:200])
    check("回应出现在动手之前", 0 <= ack_index < final_index, str(texts)[:200])
    check("插话回应不重复", sum(1 for t in texts if "收到" in t and "3 条" in t) == 1, str(texts)[:200])


async def test_long_output_batched() -> None:
    """两万字的回答不能按 24 字一个事件推，否则浏览器必卡；内容还得完整。"""
    text = "".join(f"第 {i} 行：这是一段用来验证长输出分块的内容，字段齐全。\n" for i in range(700))
    events = await run([reply(text)])
    deltas = find(events, "delta")
    joined = "".join(str(e.get("content") or "") for e in deltas)
    check("长输出内容完整", joined == text, f"{len(joined)} vs {len(text)}")
    check("长输出事件数受控", len(deltas) <= 80, f"{len(deltas)} 个事件")


async def test_sync_tool_off_event_loop() -> None:
    """同步工具（起命令、发请求、出报告）必须在线程里跑，不能把事件循环卡住。"""
    import time

    def slow_tool(args, username):
        time.sleep(0.2)
        return {"ok": True}

    agent._HANDLERS["__slow_probe"] = slow_tool
    ticks = {"n": 0}

    async def ticker():
        for _ in range(5):
            await asyncio.sleep(0.03)
            ticks["n"] += 1

    try:
        task = asyncio.create_task(ticker())
        result = await agent.dispatch_tool("__slow_probe", {}, "admin")
        await task
    finally:
        agent._HANDLERS.pop("__slow_probe", None)
    check("同步工具照常返回", result.get("ok") is True, str(result))
    check("执行期间事件循环仍在转", ticks["n"] >= 4, f"tick={ticks['n']}")


def test_ack_text() -> None:
    check("回应只取第一句", agent._ack_text("收到，先停下。剩下的我来处理。") == "收到，先停下。")
    check("空回应为空串", agent._ack_text("") == "")
    check("回应有长度上限", len(agent._ack_text("这是一句很长的话" * 30)) <= 110)


# ---------------- 本轮新增：停止、去重、措辞、记忆播报 ----------------


async def test_cancel_stops_run() -> None:
    """用户点停止：循环要真的退出（不是只断开前端），并推 cancelled 事件。"""
    import time

    def slow_tool(args, username):
        time.sleep(0.12)
        return {"ok": True}

    agent._HANDLERS["__slow_cancel"] = slow_tool
    sid = new_session("cancel")
    use(FakeLLM([tool_call("__slow_cancel", {"i": i}) for i in range(20)]))
    events: list[dict] = []

    async def consume() -> None:
        async for event in agent.run_agent(sid, "admin"):
            events.append(event)

    try:
        task = asyncio.create_task(consume())
        for _ in range(60):
            await asyncio.sleep(0.02)
            if agent.agent_busy(sid):
                break
        await asyncio.sleep(0.2)
        stopped = agent.cancel_agent(sid)
        await asyncio.wait_for(task, timeout=15)
    finally:
        agent._HANDLERS.pop("__slow_cancel", None)
    check("停止时确实有任务在跑", stopped, str(stopped))
    check("停止推出 cancelled 事件", "cancelled" in kinds(events), str(kinds(events))[:200])
    check("停止后不再登记为运行中", not agent.agent_busy(sid))
    await asyncio.sleep(0.3)
    after = len(events)
    await asyncio.sleep(0.3)
    check("停止后没有后续事件", len(events) == after, f"{after} → {len(events)}")


def test_action_dedupe() -> None:
    """同一件事只留一张待确认卡，避免「同一句话弹好几次」。"""
    sid = new_session("dedupe")
    first = agent.create_action(sid, "admin", "read_file", {"path": ".env"}, "读凭据")
    again = agent.create_action(sid, "admin", "read_file", {"path": ".env"}, "读凭据")
    check("同样的待确认只留一张卡", first["id"] == again["id"], f"{first['id']} vs {again['id']}")
    other = agent.create_action(sid, "admin", "read_file", {"path": ".ssh/id_rsa"}, "读私钥")
    check("不同目标仍是两张卡", other["id"] != first["id"])


async def test_confirm_only_once() -> None:
    """同一处信息：第一次问一次，确认之后再读不再问，也不再追问「查看原文」。"""
    ws = Path(TMP) / "ws_once"
    ws.mkdir(exist_ok=True)
    (ws / ".env").write_text("API_KEY=abcdefgh12345678\n", encoding="utf-8")
    set_settings({"work_dir": str(ws)})
    sid = new_session("once")
    events1 = await run([tool_call("read_file", {"path": ".env"}), reply("需要你先确认。")], sid)
    cards = find(events1, "confirm")
    check("第一次读自己的凭据弹一张卡", len(cards) == 1, str(kinds(events1))[:200])
    if cards:
        agent.decide_action(int(cards[0]["action_id"]), "approved")
    events2 = await run([tool_call("read_file", {"path": ".env"}), reply("读到了。")], sid)
    check("确认过之后再读同一个文件不弹卡", not find(events2, "confirm"), str(kinds(events2))[:200])


def test_highlight_vocabulary() -> None:
    """用户点名的说法都要点亮，不能只认那十个词。"""
    words = [
        "有突破", "有关键突破", "重大发现", "新发现", "新的进展",
        "确认存在", "已经证明", "关键线索", "成功利用", "实锤",
        "已确认存在", "验证成功", "能利用", "有进展",
    ]
    for word in words:
        check(f"「{word}」被高亮", agent.progress_level(f"{word}：订单接口可以越权读") == "highlight")
    check("句中命中同样高亮", agent.progress_level("这个接口已经证明存在越权") == "highlight")
    check("否定说法不点亮", agent.progress_level("没有突破，还是 401") == "info")
    check("未发现不算高亮", agent.progress_level("未发现可利用的入口") == "info")
    check("普通进度仍是 info", agent.progress_level("已拿到 3 个接口，接下来逐个验") == "info")


def test_highlight_cooldown_rule() -> None:
    """关键节点要稀有：刚点亮过，紧跟着几步的关键说法降级成普通进度。"""
    check("开局的第一个关键说法点亮", agent.highlight_allowed(0, -99))
    check("隔了两步仍不点亮", not agent.highlight_allowed(2, 0))
    check("刚好够冷却步数才点亮", agent.highlight_allowed(agent.HIGHLIGHT_COOLDOWN_STEPS, 0))
    check("冷却步数不少于 3 步", agent.HIGHLIGHT_COOLDOWN_STEPS >= 3, str(agent.HIGHLIGHT_COOLDOWN_STEPS))
    # 降级只影响外观，文字本身照样认得出来
    check("关键说法本身仍被识别", agent.progress_level("关键突破：订单接口可以越权读") == "highlight")


async def test_highlight_cooldown_flow() -> None:
    """一轮里连着几步都说「关键突破」，只有第一条点亮，后面几条降级。"""
    ws = Path(TMP) / "cooldown_ws"
    ws.mkdir(parents=True, exist_ok=True)
    for i in range(4):
        (ws / f"note{i}.txt").write_text(f"接口 {i} 返回 200\n", encoding="utf-8")
    old = agent.get_settings().get("work_dir")
    set_settings({"work_dir": str(ws)})
    phrases = [
        "关键突破：登录接口未授权，可直接读他人资料",
        "重大发现：订单接口也能越权读取",
        "关键证据：回显里出现了他人手机号",
        "确认存在：鉴权中间件整段缺失",
    ]
    try:
        script = []
        for i, text in enumerate(phrases):
            item = tool_call("read_file", {"path": f"note{i}.txt"}, call_id=f"call_{i}")
            item["message"]["content"] = text
            script.append(item)
        script.append(reply("四条都已核实，正在整理报告。"))
        sid = new_session("cooldown")
        events = await run(script, sid)
    finally:
        set_settings({"work_dir": old or ""})
    prog = [
        e
        for e in find(events, "progress")
        if "收尾核对" not in str(e.get("content") or "")
    ]
    levels = [e.get("level") for e in prog]
    check("四条关键说法都播了", len(prog) == 4, str(prog)[:300])
    if len(prog) == 4:
        check("第一条点亮", levels[0] == "highlight", str(levels))
        check("紧跟着的两条降级", levels[1] == "step" and levels[2] == "step", str(levels))
        check("间隔够了再点亮一次", levels[3] == "highlight", str(levels))
        # 降级的不只是字号：行首的「关键/重大」帽子也摘掉，否则普通小字写着「关键证据」自相矛盾
        second = str(prog[1].get("content") or "")
        third = str(prog[2].get("content") or "")
        check("降级的说法摘掉了关键帽子",
              not second.startswith(("关键", "重大", "核心", "重要")) and "订单接口也能越权读取" in second,
              second)
        check("降级的说法内容还在", "回显里出现了他人手机号" in third, third)
        check("点亮的那条仍带原话", str(prog[0].get("content") or "").startswith("关键突破"), str(prog[0])[:120])
    with db() as conn:
        rows = conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='progress'", (sid,)
        ).fetchall()
    texts = [str(r["content"]) for r in rows]
    check("降级后的说法照样落库", any("订单接口也能越权读取" in t for t in texts), str(texts)[:300])


def test_evidence_progress() -> None:
    """回显里出现真凭实据：提一句让人知道往哪查，但不点亮，也不机械复读。"""
    payload = [
        {
            "tool": "http_request",
            "args": {"url": "https://t/api"},
            "result": {"ok": True, "status": 200, "body": "user=admin 未授权访问"},
        }
    ]
    seen: set[str] = set()
    hit = agent._evidence_progress(payload, seen)
    check("回显命中未授权时提一句", "未授权" in hit, hit)
    check(
        "这句不点亮关键节点",
        agent.progress_level(hit) == "info",
        f"{hit} -> {agent.progress_level(hit)}",
    )
    check("同一类证据只提一次", agent._evidence_progress(payload, seen) == "", "重复命中")
    quiet = agent._evidence_progress(
        [{"tool": "http_request", "args": {"url": "https://t/"}, "result": {"ok": True, "status": 200, "body": "hello world"}}]
    )
    check("没有证据时不硬造", quiet == "", quiet)


async def test_memory_read_progress() -> None:
    """读记忆前后各播一条：正在读取记忆 / 已完成记忆读取。"""
    root = Path(TMP) / "mem_phase"
    root.mkdir(exist_ok=True)
    (root / "偏好.md").write_text("报告用 Markdown，结论放最前。\n", encoding="utf-8")
    old = agent.get_settings().get("memory_path")
    set_settings({"memory_path": str(root)})
    try:
        events = await run([tool_call("read_memory", {}), reply("记忆读完了。")])
    finally:
        set_settings({"memory_path": old or ""})
    progress = find(events, "progress")
    lines = [str(item.get("content") or "") for item in progress]
    levels = [item.get("level") for item in progress]
    check("读之前播报正在读取记忆", any(line.startswith("正在读取记忆") for line in lines), str(lines)[:220])
    check("读完播报已完成记忆读取", any("已完成记忆读取" in line for line in lines), str(lines)[:220])
    check("读取中用 loading 档", "loading" in levels, str(levels))


def test_memory_reads_any_file() -> None:
    """记忆目录里什么文件都当记忆：文本、子目录、Word 文档。"""
    import zipfile

    root = Path(TMP) / "mem_any"
    (root / "deep").mkdir(parents=True, exist_ok=True)
    (root / "a.txt").write_text("纯文本记忆", encoding="utf-8")
    (root / "deep" / "b.md").write_text("子目录里的记忆", encoding="utf-8")
    with zipfile.ZipFile(root / "c.docx", "w") as bundle:
        bundle.writestr(
            "word/document.xml",
            "<w:document><w:body><w:p><w:r><w:t>Word 里的约定</w:t></w:r></w:p></w:body></w:document>",
        )
    old = agent.get_settings().get("memory_path")
    set_settings({"memory_path": str(root)})
    try:
        names = [item["name"] for item in agent.memory_manifest()]
        text = agent.read_memory()
    finally:
        set_settings({"memory_path": old or ""})
    check("文本与子目录都读到", "a.txt" in names and "deep/b.md" in names, str(names))
    check("docx 也抽成文本", "Word 里的约定" in text, text[:160])
    check("子目录内容进正文", "子目录里的记忆" in text)


async def test_progress_on_later_turns() -> None:
    """第二轮、第三轮同样要有结论播报，不能只在第一次对话里有。"""
    sid = new_session("turns")
    first = await run([tool_call("platform_overview"), reply("第一轮结束。")], sid)
    second = await run([tool_call("platform_overview"), reply("第二轮结束。")], sid)
    check("第一轮有进度", any("已盘点平台现状" in str(e.get("content")) for e in find(first, "progress")))
    check("第二轮同样有进度", any("已盘点平台现状" in str(e.get("content")) for e in find(second, "progress")))
    tracer = find(second, "_llm_messages")
    joined = json.dumps(tracer[0].get("data") if tracer else [], ensure_ascii=False)
    check("后续轮次提示词里重申播报要求", "播报要求不变" in joined, joined[:160])


def test_question_turn_vocabulary() -> None:
    """用户问「你测过吗」是提问，不是继续派活。"""
    asking = [
        "你的意思是你测试过了未授权管理接口、SQL 注入、反射型 XSS、开放重定向、路径穿越、"
        "默认凭据绕过、文件读取及严重接管链，但是没有发现是吗",
        "SQL 注入你测了吗",
        "那你有没有发现开放重定向",
        "结论是什么",
        "刚才测了哪几类？",
    ]
    for text in asking:
        check(f"问句识别：{text[:14]}", agent.question_turn(text), text)

    working = [
        "继续测 SQL 注入",
        "帮我看看有没有未授权接口",
        "再跑一遍那个脚本",
        "确认一下 /login?url= 是不是开放重定向",
        "你验一下这个接口是不是未授权",
        "那你测一下 XSS",
    ]
    for text in working:
        check(f"派活不误判：{text[:14]}", not agent.question_turn(text), text)


def test_work_digest_survives_history_budget() -> None:
    """历史会被字数预算裁掉，但「做过什么」必须还在——否则模型会当成新任务重跑。"""
    sid = new_session("digest")
    say(sid, "帮我测一下这个站")
    say(sid, "关键突破：/api/user 未授权可读 2000 条", "progress")
    for _ in range(24):
        say(sid, "填充内容" * 380, "assistant")
    digest = agent._work_digest(sid)
    history = agent._history(sid)
    check("台账留住早期关键结论", "关键突破" in digest, digest[:160])
    check("历史确实已经被裁掉", not any("关键突破" in str(m["content"]) for m in history))
    check("台账把进度写成分步记录", "已执行的步骤" in digest, digest[:80])


async def test_question_mode_answers_without_rerun() -> None:
    """用户提问时：可以核对结论，但不能重新执行（跑脚本 / 发包 / 重扫）。"""
    sid = new_session("ask")
    say(sid, "帮我测一下这个站")
    say(sid, "已确认管理接口全部 302 到登录页，接下来逐项实测注入", "progress")
    say(sid, "你测过 SQL 注入了吗？")
    events = await run([reply("没测。目前只确认了管理接口 302，注入、XSS、跳转都还没验。")], sid)

    tools = find(events, "_llm_tools")
    allowed = set(tools[0]["data"][0]) if tools and tools[0]["data"] else set()
    check("提问轮次不给执行类工具", not (allowed & {"run_shell", "run_python", "http_request"}), str(allowed))
    check("提问轮次仍可核对结论", "list_findings" in allowed, str(allowed))
    messages = [str(e.get("content") or "") for e in find(events, "message")]
    check("直接回答了问题", any("没测" in m for m in messages), str(messages)[:160])
    tracer = find(events, "_llm_messages")
    joined = json.dumps(tracer[0]["data"] if tracer else [], ensure_ascii=False)
    check("台账进了上下文", "302 到登录页" in joined, joined[:160])
    check("提问轮次不推执行类进度", not any("继续下一步" in str(e.get("content")) for e in find(events, "progress")))


async def test_question_progress_report_retried() -> None:
    """模型拿「已…，接下来…」当回答时，要再问一次，把答案要出来。"""
    sid = new_session("ask2")
    say(sid, "帮我测一下这个站")
    say(sid, "XSS 你测了吗？")
    events = await run(
        [
            reply("已盘点平台现状，接下来继续验证注入与 XSS。"),
            reply("没测。只做了接口盘点，XSS 这一项还没开始。"),
        ],
        sid,
    )
    messages = [str(e.get("content") or "") for e in find(events, "message")]
    check("进度句没被当成答案", not any("继续验证注入与 XSS" in m for m in messages), str(messages)[:160])
    check("重问后给出真答案", any("没测" in m for m in messages), str(messages)[:160])


def test_interjection_question_note() -> None:
    """干活途中被问「测过没有」：要让他先答一句，而不是当成换任务。"""
    note = agent._interjection_note(["你测过 SQL 注入了吗？"])
    check("插话问句要求先回答", "在问结果" in note, note[-120:])
    plain = agent._interjection_note(["顺便把报告也写出来"])
    check("派活式插话不加问句要求", "在问结果" not in plain)


async def test_question_mode_blocks_forced_tool() -> None:
    """模型无视工具清单硬发 run_python 时也要挡住，不能又跑一遍。"""
    sid = new_session("ask3")
    say(sid, "帮我测一下这个站")
    say(sid, "你测过 SQL 注入了吗？")
    events = await run(
        [
            tool_call("run_python", {"code": "print('re-test')"}),
            reply("没测。SQL 注入还没验，当前只做过接口盘点。"),
        ],
        sid,
    )
    executed = [e for e in find(events, "progress") if "脚本跑完" in str(e.get("content"))]
    check("提问轮次不执行硬塞的工具", not executed, str(executed)[:160])
    messages = [str(e.get("content") or "") for e in find(events, "message")]
    check("挡住后仍给出答案", any("没测" in m for m in messages), str(messages)[:160])


async def test_parallel_tools() -> None:
    """同一条消息里的多个只读工具并发跑：两个都先发出去，再各自等。

    这里不拿墙钟当判据：机器一忙（后台还在跑别的测试、浏览器没关），0.3 秒的
    sleep 也会被拉长，墙钟断言就会假红。改成记下两次调用「发起」的时刻——
    并发时两者几乎同时开始，串行则必然隔着一个 sleep。
    """
    original = agent.dispatch_tool
    starts: list[float] = []

    async def slow(name, args, username):
        starts.append(time.perf_counter())
        await asyncio.sleep(0.3)
        return {"ok": True, "tool": name}

    agent.dispatch_tool = slow  # type: ignore[assignment]
    try:
        batch = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "list_assets", "arguments": "{}"}},
                    {"id": "c2", "type": "function", "function": {"name": "list_scans", "arguments": "{}"}},
                ],
            },
            "finish_reason": "tool_calls",
        }
        started = time.perf_counter()
        events = await run([batch, reply("两个都拿到了。")])
        elapsed = time.perf_counter() - started
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]

    gap = (starts[1] - starts[0]) if len(starts) >= 2 else 99.0
    check("多个只读工具并发执行", len(starts) == 2 and gap < 0.12,
          f"两个工具发起间隔 {gap:.3f}s（串行会隔 0.3s 以上），总耗时 {elapsed:.2f}s")
    tracer = find(events, "_llm_messages")
    seen = json.dumps(tracer[0]["data"][1] if tracer and len(tracer[0]["data"]) > 1 else [], ensure_ascii=False)
    check("两个工具结果都回给了模型", "list_assets" in seen and "list_scans" in seen, seen[-200:])


def test_memory_loading_plain() -> None:
    """「正在读取记忆」只保留这一句：不带括号、不带游标和文件名。"""
    for args in ({}, {"cursor": 9000}, {"only": "偏好.md"}):
        line = agent._memory_loading_line(args)
        check(f"读记忆文案干净 {args}", line == "正在读取记忆", line)


async def test_findings_digest_written_out() -> None:
    """收尾必须在控制台把每个漏洞的标题、请求包、响应包摊开写出来。

    模型只说一句「已归档」时，平台要自己把三条东西补齐——用户不该为了
    核对一条漏洞再去翻另一个页面。
    """
    sid = new_session("digest")
    say(sid, "看一下 https://shop.example.com 的订单接口有没有越权读取")
    packet = "GET /api/order/9001 HTTP/1.1\nHost: shop.example.com\nCookie: sid=me"
    body = 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"orderId":9001,"phone":"138****"}'
    events = await run(
        [
            tool_call(
                "record_finding",
                {
                    "url": "https://shop.example.com/api/order/9001",
                    "title": "订单越权导致信息泄露",
                    "severity": "high",
                    "description": "普通用户改 orderId 可读他人订单，正常页面只展示自己的",
                    "request_packet": packet,
                    "response_packet": body,
                },
                call_id="c1",
            ),
            reply("结论：已确认订单越权，漏洞已归档到漏洞结果。"),
        ],
        sid,
    )
    final = ""
    for item in find(events, "message"):
        if item.get("role") == "assistant":
            final = str(item.get("content") or "")
    check("收尾结论补上了漏洞清单", "【漏洞清单·逐条复核】" in final, final[:200])
    check("清单里有标题", "订单越权导致信息泄露" in final)
    check("清单里有请求包原文", "GET /api/order/9001 HTTP/1.1" in final and "Host: shop.example.com" in final)
    check("清单里有响应包原文", '"orderId":9001' in final)
    check("报文用代码块包着", final.count("```http") == 2, str(final.count("```http")))

    # 模型自己写全了：不重复追一遍
    sid2 = new_session("digest-full")
    say(sid2, "看一下 https://shop.example.com 的订单接口有没有越权读取")
    full = (
        "结论：订单越权导致信息泄露（高危）。\n\n"
        f"请求包：\n```http\n{packet}\n```\n\n响应包：\n```http\n{body}\n```"
    )
    events2 = await run(
        [
            tool_call(
                "record_finding",
                {
                    "url": "https://shop.example.com/api/order/9001",
                    "title": "订单越权导致信息泄露",
                    "severity": "high",
                    "description": "普通用户改 orderId 可读他人订单，正常页面只展示自己的",
                    "request_packet": packet,
                    "response_packet": body,
                },
                call_id="c1",
            ),
            reply(full),
        ],
        sid2,
    )
    final2 = ""
    for item in find(events2, "message"):
        if item.get("role") == "assistant":
            final2 = str(item.get("content") or "")
    check("自己写全了就不重复追一遍", "【漏洞清单·逐条复核】" not in final2, final2[:160])


async def test_digest_on_every_round_exit() -> None:
    """每一轮工作完成都要摊开三件套——轮次跑满被迫收口的那条路也不能漏。

    真实场景里一轮常常是把 50 个工具轮次用完才收口；以前只有「正常收尾」那条路
    会补清单，轮次跑满的场次恰好最容易漏，用户拿到的就是一句「已归档」。
    """
    sid = new_session("digest-budget")
    say(sid, "看一下 https://shop.example.com 的订单接口有没有越权读取")
    packet = "GET /api/order/9001 HTTP/1.1\nHost: shop.example.com\nCookie: sid=me"
    body = 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"orderId":9001}'
    old_budget = agent.step_budget
    agent.step_budget = lambda: 2  # 两步就把预算用完，逼它走「轮次用尽」的收口路径
    try:
        events = await run(
            [
                tool_call(
                    "record_finding",
                    {
                        "url": "https://shop.example.com/api/order/9001",
                        "title": "订单越权导致信息泄露",
                        "severity": "high",
                        "description": "普通用户改 orderId 可读他人订单，正常页面只展示自己的",
                        "request_packet": packet,
                        "response_packet": body,
                    },
                    call_id="c1",
                ),
                tool_call("list_assets", {}, call_id="c2"),
                reply("这一轮先做到这里。"),
            ],
            sid,
        )
    finally:
        agent.step_budget = old_budget

    final = ""
    for item in find(events, "message"):
        if item.get("role") == "assistant":
            final = str(item.get("content") or "")
    check("轮次跑满收口也带上漏洞清单", "【漏洞清单·逐条复核】" in final, final[:200])
    check("轮次跑满收口带标题", "订单越权导致信息泄露" in final)
    check("轮次跑满收口带请求包", "GET /api/order/9001 HTTP/1.1" in final)
    check("轮次跑满收口带响应包", '"orderId":9001' in final)
    check("清单只算这一轮（跑完就清）", sid not in agent._SESSION_FINDINGS)


async def test_digest_per_domain_scope() -> None:
    """清单按域名给，不按轮给：同一个域名要列全，同一条不重复列举。

    用户定死的口径：这一轮测的是一个域名，就列该域名在本次测试里出现过的所有漏洞；
    这一轮测了几个域名，就每个域名各列一份。所以第二轮要能看到第一轮同域名的漏洞，
    换域名之后只列新域名，不能把旧域名的漏洞混进来。
    """
    sid = new_session("digest-per-domain")
    say(sid, "先测 https://shop.example.com 的订单接口")

    def archived(call_id: str, url: str, title: str, status: str = "200 OK") -> tuple[dict, str, str]:
        parts = url.split("/", 3)
        path = "/" + (parts[3] if len(parts) > 3 else "")
        packet = f"GET {path} HTTP/1.1\nHost: {parts[2]}"
        body = f"HTTP/1.1 {status}\nContent-Type: application/json\n\n{{\"path\":\"{path}\"}}"
        return (
            tool_call(
                "record_finding",
                {
                    "url": url,
                    "title": title,
                    "severity": "high",
                    "description": "普通用户可读他人数据，正常页面只展示自己的",
                    "request_packet": packet,
                    "response_packet": body,
                },
                call_id=call_id,
            ),
            packet,
            body,
        )

    def final_text(events: list[dict]) -> str:
        text = ""
        for item in find(events, "message"):
            if item.get("role") == "assistant":
                text = str(item.get("content") or "")
        return text

    a_call, a_req, _ = archived("r1", "https://shop.example.com/api/order/9001", "订单越权导致信息泄露")
    b_call, b_req, _ = archived(
        "r2", "https://shop.example.com/api/user/88", "用户资料越权读取", "201 Created"
    )
    text1 = final_text(await run([a_call, b_call, reply("第一轮结论：已归档。")], sid))
    check(
        "第一轮列全了该域名当轮的漏洞",
        "订单越权导致信息泄露" in text1 and "用户资料越权读取" in text1 and a_req in text1 and b_req in text1,
        text1[:200],
    )
    check("第一轮按域名分组", "域名 shop.example.com（2 条）" in text1, text1[:240])

    # 第二轮继续测同一个域名：清单要把该域名本次测试的全部漏洞列全，不只这一轮新发现的
    c_call, c_req, _ = archived("r3", "https://shop.example.com/api/admin/1", "后台接口未授权访问")
    text2 = final_text(await run([c_call, reply("第二轮结论：已归档。")], sid))
    check(
        "第二轮把同域名前几轮的漏洞也列全了",
        all(t in text2 for t in ("订单越权导致信息泄露", "用户资料越权读取", "后台接口未授权访问")),
        text2[:240],
    )
    check("第二轮带上了前几轮的请求包", a_req in text2 and c_req in text2, text2[:240])
    check("同一条漏洞只列一次", text2.count("订单越权导致信息泄露") == 1, str(text2.count("订单越权导致信息泄露")))
    check("第二轮清单条数是该域名累计 3 条", "域名 shop.example.com（3 条）" in text2, text2[:240])
    check("标出本轮新增的那条", "后台接口未授权访问" in text2 and "（本轮新增）" in text2, text2[:240])

    # 换一个域名测：只列这一轮测的域名，旧域名的漏洞不混进来
    d_call, _, _ = archived("r4", "https://api.other.com/api/user/1", "另一个域名的越权")
    text3 = final_text(await run([d_call, reply("第三轮结论：已归档。")], sid))
    check(
        "换域名后只列这一轮测的域名",
        "另一个域名的越权" in text3 and "订单越权导致信息泄露" not in text3,
        text3[:240],
    )
    check("换域名后分组只算该域名", "域名 api.other.com（1 条）" in text3, text3[:240])

    # 一轮里测两个域名：每个域名各列一份
    e_call, _, _ = archived("r5", "https://shop.example.com/api/export", "导出接口未授权")
    f_call, _, _ = archived("r6", "https://api.other.com/api/pay", "支付回调越权")
    text4 = final_text(await run([e_call, f_call, reply("第四轮结论：已归档。")], sid))
    check(
        "多域名一轮各列一份",
        "域名 shop.example.com（4 条）" in text4 and "域名 api.other.com（2 条）" in text4,
        text4[:300],
    )
    check(
        "多域名清单覆盖两边",
        "导出接口未授权" in text4 and "支付回调越权" in text4,
        text4[:300],
    )


async def test_digest_dedupe() -> None:
    """同一条漏洞归档两次（同域名、同标题、同 URL）只列一条，保留最新。"""
    rows = [
        {"id": 1, "title": "订单越权", "url": "https://a.example.com/x", "severity": "high"},
        {"id": 2, "title": "订单越权", "url": "https://a.example.com/x", "severity": "high"},
        {"id": 3, "title": "订单越权", "url": "https://a.example.com/y", "severity": "low"},
        {"id": 4, "title": "导出越权", "url": "https://www.a.example.com/z", "severity": "critical"},
    ]
    deduped = agent._dedupe_rows(rows)
    check(
        "同域名同标题同 URL 只留最新一条",
        [row["id"] for row in deduped] == [4, 2, 3],
        str([row["id"] for row in deduped]),
    )
    check("www 前缀算同一家", agent._same_domain("www.a.example.com", "a.example.com"))


async def test_digest_steps() -> None:
    """硬性要求：结论要写清漏洞是怎么一步步打出来的，每一步都带自己的请求包与响应包。

    用户原话：「Agent 输出时要写清楚是如何一步一步实现漏洞的，让用户看明白」
    「最好是每一个步骤的请求包和响应包都给我」。所以测四件事：
    平台记下的真实步骤能按顺序摊开、每步报文不串；模型自己写的步骤原样保留；
    只有最后一对报文没写步骤也算漏；一条步骤都没有时当场提醒补。
    """
    sid = new_session("digest-steps")
    original = agent.shell_http_request

    def fake_request(url, method="GET", headers=None, body="", **kwargs):
        path = url.replace("https://steps.example.com", "").split("?")[0]
        ok = "order" in url
        status = 200 if ok else 403
        return {
            "ok": ok,
            "status": status,
            "reason": "OK" if ok else "Forbidden",
            "url": url,
            "method": method,
            "request_packet": f"{method} {path} HTTP/1.1\nHost: steps.example.com",
            "response_packet": f"HTTP/1.1 {status} {'OK' if ok else 'Forbidden'}\n\n{{\"order\": 9001}}",
        }

    agent.shell_http_request = fake_request  # type: ignore[assignment]
    token = agent.set_tool_session(sid)
    try:
        await agent.dispatch_tool(
            "http_request",
            {"url": "https://steps.example.com/api/order/9001", "note": "不带 token 直接取订单，看是否校验归属"},
            "admin",
        )
        await agent.dispatch_tool(
            "http_request",
            {"url": "https://steps.example.com/api/user/88", "note": "换成别人的用户 id，确认能读到对方资料"},
            "admin",
        )
        recorded = await agent.dispatch_tool(
            "record_finding",
            {
                "url": "https://steps.example.com/api/order/9001",
                "title": "订单越权导致信息泄露",
                "severity": "high",
                "description": "普通用户改 orderId 可读他人订单，正常页面只展示自己的",
                "remediation": "订单查询按登录用户过滤 owner_id",
            },
            "admin",
        )
        steps_given = await agent.dispatch_tool(
            "record_finding",
            {
                "url": "https://steps.example.com/api/user/88",
                "title": "用户资料越权读取",
                "severity": "high",
                "description": "普通用户可读他人资料，正常页面只展示自己的",
                "request_packet": "GET /api/user/88 HTTP/1.1\nHost: steps.example.com",
                "response_packet": "HTTP/1.1 200 OK\n\n{\"name\": \"alice\"}",
                "steps": [
                    {
                        "action": "先不带 token 请求 /api/user/1",
                        "result": "返回 200 与 alice 的昵称",
                        "why": "未登录也能读，说明接口没校验登录态",
                    },
                    {
                        "action": "再换成 bob 的 token 请求 /api/user/1",
                        "result": "仍返回 alice 的数据",
                        "why": "登录用户能读他人资料，是越权而不是公开信息",
                    },
                ],
            },
            "admin",
        )
        bare = await agent.dispatch_tool(
            "record_finding",
            {
                "url": "https://other.example.net/api/x",
                "title": "另一个站点的未授权访问",
                "severity": "medium",
                "description": "无需登录即可读取配置页",
                "request_packet": "GET /api/x HTTP/1.1\nHost: other.example.net",
                "response_packet": "HTTP/1.1 200 OK\n\n{}",
            },
            "admin",
        )
    finally:
        agent._TOOL_SESSION.reset(token)
        agent.shell_http_request = original  # type: ignore[assignment]

    check("归档结果带上步骤数", recorded.get("steps") == 2, str(recorded)[:200])
    text = agent.findings_digest(sid, "已归档，去漏洞结果页看。")
    check("清单按步骤展开", "复现步骤：" in text and "步骤1：" in text and "步骤2：" in text, text[-400:])
    check(
        "每一步都有自己的请求包与响应包",
        all(f"请求包{n}：" in text and f"响应包{n}：" in text for n in (1, 2)),
        text[-400:],
    )
    check(
        "第一步的报文没有被第二步覆盖",
        "不带 token 直接取订单" in text and "换成别人的用户 id" in text and "请求包2：" in text,
        text[-400:],
    )
    check("步骤里带出成因与影响", "成因与影响：" in text, text[-400:])
    check("清单末尾给修复方案", "修复方案：" in text and "owner_id" in text, text[-200:])
    check("模型自己写的步骤原样保留", "先不带 token 请求 /api/user/1" in text and "未登录也能读" in text, text[-400:])
    check("模型没写 why 的步骤不会被编造", "由此判断：未登录也能读" in text, text[-400:])
    check("一条步骤都没有时当场提醒补", "step_gap" in bare and "steps" in str(bare.get("step_gap")), str(bare)[:200])

    # 只贴了最后一对报文、没写过程：也要补
    body = (
        "漏洞清单：订单越权导致信息泄露\n"
        "GET /api/order/9001 HTTP/1.1\n"
        "HTTP/1.1 200 OK"
    )
    filled = agent.findings_digest(sid, body)
    check("只贴报文没写步骤也算漏，照样补", "复现步骤：" in filled and "步骤1：" in filled, filled[-300:])

    # 响应包太大：只留关键几行，并写明这是节选（用户要求「只写一小部分即可」）
    huge_sid = new_session("digest-huge")
    token = agent.set_tool_session(huge_sid)
    try:
        await agent.dispatch_tool(
            "record_finding",
            {
                "url": "https://big.example.com/list",
                "title": "列表接口未授权访问",
                "severity": "medium",
                "description": "未登录可直接拉取全量用户列表，正常页面只展示自己的",
                "request_packet": "GET /list HTTP/1.1\nHost: big.example.com",
                "response_packet": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n" + ("<tr><td>alice</td></tr>" * 3000),
            },
            "admin",
        )
    finally:
        agent._TOOL_SESSION.reset(token)
    huge_text = agent.findings_digest(huge_sid, "")
    check("超长响应包只留节选", len(huge_text) < 4000, str(len(huge_text)))
    check(
        "节选写明了是截断",
        "节选" in huge_text and "完整内容见漏洞结果页" in huge_text,
        huge_text[-260:],
    )


async def test_packet_gap_is_flagged() -> None:
    """归档时缺报文要当场告诉模型：收尾要交三件套，缺哪份现在补。"""
    sid = new_session("packet-gap")
    token = agent.set_tool_session(sid)
    try:
        result = await agent.dispatch_tool(
            "record_finding",
            {
                "url": "https://shop.example.com/api/order/9001",
                "title": "订单越权导致信息泄露",
                "severity": "high",
                "description": "普通用户改 orderId 可读他人订单，正常页面只展示自己的",
            },
            "admin",
        )
    finally:
        agent._TOOL_SESSION.reset(token)
    gap = str(result.get("packet_gap") or "")
    check("缺报文时归档结果里带提醒", "请求包" in gap and "响应包" in gap, gap[:120])
    check("提醒写清了怎么补", "http_request" in gap and "request_packet" in gap, gap[:160])

    thin = agent.findings_digest(sid, "已归档。")
    check("缺报文的条目在清单里写明要补测", "归档时没记录请求包" in thin and "无法复现" in thin, thin[-200:])


async def test_tool_result_pairing() -> None:
    """每个 tool_call 都要有一条对应的 tool 结果，顺序一致、中间不夹别的角色。

    线上真实的 400「tool call result does not follow tool call」就是这里坏的：
    同一批里被去重跳过的那条没补结果，或者中间插了一条 system 提示。
    """
    original = agent.dispatch_tool
    calls: list[str] = []

    async def stub(name, args, username):
        calls.append(str((args or {}).get("url") or name))
        return {"ok": True, "status": 200, "body": "hello"}

    agent.dispatch_tool = stub  # type: ignore[assignment]
    batch = {
        "message": {
            "role": "assistant",
            "content": "一起发三个请求",
            "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "http_request", "arguments": json.dumps({"url": "https://t.example/a"})}},
                {"id": "c2", "type": "function", "function": {"name": "http_request", "arguments": json.dumps({"url": "https://t.example/a"})}},
                {"id": "c3", "type": "function", "function": {"name": "http_request", "arguments": json.dumps({"url": "https://t.example/b"})}},
            ],
        },
        "finish_reason": "tool_calls",
    }
    try:
        events = await run([batch, reply("三个都回来了。")])
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]

    check("同参数的重复调用只真跑一次", len(calls) == 2, str(calls))
    tracer = find(events, "_llm_messages")
    second = tracer[0]["data"][1] if tracer and len(tracer[0]["data"]) > 1 else []
    idx = next(
        (i for i, m in enumerate(second) if m.get("role") == "assistant" and m.get("tool_calls")),
        None,
    )
    check("第二轮请求里带上了那条 assistant 调用", idx is not None, str(second)[-200:])
    if idx is not None:
        follow = second[idx + 1 : idx + 4]
        check("三个调用都有结果", [m.get("role") for m in follow] == ["tool", "tool", "tool"], str([m.get("role") for m in follow]))
        check("结果顺序与调用一致", [m.get("tool_call_id") for m in follow] == ["c1", "c2", "c3"], str([m.get("tool_call_id") for m in follow]))
        check(
            "结果之间没有夹 system 提示",
            all(m.get("role") == "tool" for m in follow),
            str([m.get("role") for m in follow]),
        )
    check(
        "去重提示改成整批之后再说",
        any(
            ("已经执行过相同的调用" in str(m.get("content") or ""))
            or ("已经只执行了一次" in str(m.get("content") or ""))
            for m in second
            if m.get("role") == "system"
        ),
        str([m.get("role") for m in second])[-120:],
    )


async def test_early_finish_pushed_back() -> None:
    """只做了侦察就写「尚未逐项验证」：平台把它推回去补测，而不是当成交付。"""
    original = agent.dispatch_tool
    hits: list[str] = []

    async def stub(name, args, username):
        hits.append(name)
        return {"ok": True, "status": 200, "body": "ok", "url": (args or {}).get("url")}

    agent.dispatch_tool = stub  # type: ignore[assignment]
    try:
        half = "结论：本轮仅完成资产登记与前端侦察，尚未逐项验证，不能判断是否存在漏洞。"
        script = [
            tool_call("http_request", {"url": "https://t.example/"}, call_id="c1"),
            reply(half),
            tool_call("http_request", {"url": "https://t.example/api/users"}, call_id="c2"),
            reply("继续补测：未授权访问已验完，接着验越权。"),
        ]
        sid = new_session("early-finish")
        say(sid, "测试 https://t.example/ 有没有漏洞")
        events = await run(script, sid)
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]

    pushed = [
        e for e in find(events, "progress") if "还没验完" in str(e.get("content") or "")
    ]
    check("半成品结论被推回去", bool(pushed), str(find(events, "progress"))[:300])
    tracer = find(events, "_llm_messages")
    prompts = "\n".join(
        str(m.get("content") or "")
        for batch in (tracer[0]["data"] if tracer else [])
        for m in batch
        if m.get("role") == "system"
    )
    check("推回时明确说不能收口", "这一轮还没做完" in prompts, prompts[-400:])
    check("推回时给出补测顺序", "未授权访问" in prompts and "1." in prompts, prompts[-400:])
    check("推回后确实继续动手", len(hits) >= 2, str(hits))
    check("最后仍有正式答复", bool(find(events, "message")), str(kinds(events))[:200])

    # 反过来：用户只是让「看一眼」，不能被当成评估没做够而强行推回去
    agent.dispatch_tool = stub  # type: ignore[assignment]
    try:
        quick = new_session("quick-look")
        say(quick, "看一下 https://t.example/ 首页能不能打开")
        events2 = await run(
            [tool_call("http_request", {"url": "https://t.example/"}, call_id="q1"), reply("能打开，返回 200。")],
            quick,
        )
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]
    check(
        "看一眼的活不被推回去",
        not any("还没验完" in str(e.get("content") or "") for e in find(events2, "progress")),
        str(find(events2, "progress"))[:200],
    )


async def test_autonomy_choice_auto_decided() -> None:
    """用户说过「全测、你自己决定」：模型再抛选择题，平台直接替它拍板继续。"""
    sid = new_session("autonomy")
    say(sid, "全测啊，你自己决定先测哪个，总之不能漏")
    try:
        ask = tool_call(
            "ask_choice",
            {
                "question": "接下来优先补测哪一类？",
                "options": [
                    {"label": "先补未授权访问", "description": "命中率最高"},
                    {"label": "按顺序全补测", "description": "覆盖面最广"},
                ],
            },
            call_id="c1",
        )
        events = await run([ask, reply("按顺序全补测，先跑未授权访问。")], sid)
    finally:
        pass

    check("不再把选择权丢回给用户", not find(events, "choice"), str(kinds(events))[:200])
    prog = [str(e.get("content") or "") for e in find(events, "progress")]
    check("播报里说明是平台自己定的", any("已按你的授权自己定" in p for p in prog), str(prog)[:300])
    tracer = find(events, "_llm_messages")
    second = tracer[0]["data"][1] if tracer and len(tracer[0]["data"]) > 1 else []
    tool_payload = "".join(str(m.get("content") or "") for m in second if m.get("role") == "tool")
    check("拍板结果回给了模型", "按顺序全补测" in tool_payload, tool_payload[:300])


async def test_finding_must_be_archived() -> None:
    """结论里报了高危却一条没归档：先逼它写进漏洞结果，再允许收尾。"""
    sid = new_session("archive-gate")
    say(sid, "测试 https://t.example/login 有没有默认口令问题")
    claim = "结论：确认存在 1 个高危问题——默认口令可直接登录后台，已用 admin/admin123 验证成功。"
    events = await run(
        [
            reply(claim),
            tool_call(
                "record_finding",
                {
                    "url": "https://t.example/login",
                    "title": "默认口令可直接登录后台",
                    "severity": "high",
                    "description": "使用默认账号可直接进入管理后台。",
                    "remediation": "首次启动强制改密并禁用默认账户。",
                    "request_packet": "POST /api/auth/login HTTP/1.1",
                    "response_packet": "HTTP/1.1 200 OK",
                },
                call_id="c1",
            ),
            reply("已写入漏洞结果。"),
        ],
        sid,
    )
    prog = [str(e.get("content") or "") for e in find(events, "progress")]
    check("报了问题却不归档会被推回去", any("逐条归档" in p for p in prog), str(prog)[:300])
    tracer = find(events, "_llm_messages")
    prompts = "\n".join(
        str(m.get("content") or "")
        for batch in (tracer[0]["data"] if tracer else [])
        for m in batch
        if m.get("role") == "system"
    )
    check("推回时说明漏洞结果页还是空的", "一条都没进漏洞结果页" in prompts, prompts[-300:])
    check("推回后真的归档了", bool(find(events, "finding")), str(kinds(events))[:200])
    # 反面：明确说「没有发现」的结论不该被当成「有漏洞没归档」
    check("没有发现时不误判", not agent._claims_findings("本轮没有发现高危问题"))
    check("复盘类表述不误判", not agent._claims_findings("共 0 条漏洞，未发现可复现问题"))


async def test_stall_archives_before_stop() -> None:
    """原地打转要收口时，如果已经确认了问题却没归档，先补一轮归档再停。"""
    original = agent.dispatch_tool
    seen: list[str] = []

    async def stub(name, args, username):
        seen.append(name)
        return {"ok": True, "output": "1"}

    agent.dispatch_tool = stub  # type: ignore[assignment]
    loop_call = tool_call("run_python", {"code": "print(1)"}, call_id="loop")
    claim = dict(loop_call)
    claim["message"] = {
        "role": "assistant",
        "content": "确认存在：默认口令可直接登录后台（高危）。",
        "tool_calls": loop_call["message"]["tool_calls"],
    }
    finding = tool_call(
        "record_finding",
        {"url": "https://t.example/login", "title": "默认口令可直接登录后台", "severity": "high"},
        call_id="fix1",
    )
    try:
        # 空转阈值是连续 5 步没有新结果：第 1 步会真跑一次，之后连续 5 步都在重复同一个调用，
        # 第 6 步（claim）既是空转又带着「已确认问题」的说法，正好触发「先归档再收口」
        events = await run(
            [loop_call, loop_call, loop_call, loop_call, loop_call, claim, finding, reply("已归档。")]
        )
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]
    prog = [str(e.get("content") or "") for e in find(events, "progress")]
    check("空转到收口前先补归档", any("逐条归档" in p for p in prog), str(prog)[-300:])
    check("补归档时确实调了归档工具", "record_finding" in seen, str(seen))
    check("归档产生了漏洞卡片", bool(find(events, "finding")), str(kinds(events))[:200])


async def test_axes_gate() -> None:
    """三个方向是硬指标：动作次数够、但结论只写一句「未发现明显问题」，同样不算做完。"""
    original = agent.dispatch_tool

    async def stub(name, args, username):
        return {"ok": True, "status": 200, "body": "ok"}

    agent.dispatch_tool = stub  # type: ignore[assignment]
    sid = new_session("axes-gate")
    say(sid, "测一下 https://t.example/ 的安全性，重点看数据泄露、控制权限和实际危害")
    calls = [
        {
            "id": f"a{index}",
            "type": "function",
            "function": {"name": "http_request", "arguments": json.dumps({"url": f"https://t.example/p{index}"})},
        }
        for index in range(20)
    ]
    batch = {"message": {"role": "assistant", "content": "", "tool_calls": calls}, "finish_reason": "tool_calls"}
    try:
        events = await run(
            [
                batch,
                reply("未发现明显问题。"),
                reply("泄露：没看到凭据或源码；权限：接口都要登录，没能越权；危害：没有可写入的接口。"),
            ],
            sid,
        )
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]

    prog = [str(e.get("content") or "") for e in find(events, "progress")]
    check("三方向没交代会被推回", any("三个方向还没各有结论" in item for item in prog), str(prog)[-300:])
    tracer = find(events, "_llm_messages")
    prompts = "\n".join(
        str(m.get("content") or "")
        for data in (tracer[0]["data"] if tracer else [])
        for m in data
        if m.get("role") == "system"
    )
    check(
        "推回时把三个方向摊开讲",
        all(word in prompts for word in ("高敏感信息泄露", "控制权限", "可造成实际危害")),
        prompts[-400:],
    )
    # 三方向判定本身
    check("空结论三个方向全缺", len(agent.missing_axes("")) == 3)
    check(
        "逐个方向交代后不缺",
        agent.missing_axes("泄露：无；权限：无；危害：无") == [],
        str(agent.missing_axes("泄露：无；权限：无；危害：无")),
    )
    check("一句话糊过去仍算缺", len(agent.missing_axes("未发现明显问题")) == 3)


async def test_capability_ledger() -> None:
    """能力台账：只有 report_capability 记过的才算验过，归档漏洞自动记「有漏洞」。"""
    from mono.engine import coverage

    prev = enabled_keys()
    keys = ["idor", "unauthorized", "file_download"]
    save_enabled(keys)
    sid = new_session("ledger")
    try:
        data = coverage.summary(sid)
        check("台账：勾几项记几项", data["selected"] == 3, str(data))
        check("台账：一次没报都算没验", data["done"] == 0, str(data))

        with agent.tool_session(sid):
            ok = await agent.dispatch_tool(
                "report_capability",
                {"capability": "idor", "status": "clean", "note": "GET /api/user?id=2 返回 403"},
                "admin",
            )
        check("上报一项就记账", bool(ok.get("ok")) and ok.get("status") == "clean", str(ok))
        check("剩余项跟着减", coverage.summary(sid)["pending"] == 2, str(coverage.summary(sid)))

        with agent.tool_session(sid):
            bad = await agent.dispatch_tool(
                "report_capability", {"capability": "根本不存在的项", "status": "clean", "note": "x"}, "admin"
            )
        check("认不出的能力拒收", not bad.get("ok"), str(bad))

        with agent.tool_session(sid):
            await agent.dispatch_tool(
                "record_finding",
                {
                    "url": "https://t.example/api/user?id=2",
                    "title": "未授权读取他人资料",
                    "severity": "high",
                    "capability": "unauthorized",
                    "description": "未登录即可读取他人资料",
                    "remediation": "接口补鉴权",
                },
                "admin",
            )
        marks = coverage.marks(sid)
        check(
            "归档漏洞自动记「有漏洞」",
            marks.get("unauthorized", {}).get("status") == "vulnerable",
            str(marks),
        )

        prompt = coverage.next_batch_prompt(sid)
        check("推下一批时点名剩余项", "任意文件读取" in prompt, prompt[:200])
        check("还有没验的就不算做完", not coverage.all_done(sid))
        coverage.mark(sid, "file_download", "blocked", "整站统一 403")
        check("每项都有结论才算完", coverage.all_done(sid), str(coverage.plan(sid)))
    finally:
        save_enabled(prev)


async def test_capability_user_prompt() -> None:
    """用户提示：写进上下文、催测时一并交下去，上报前必须先读到才记账。"""
    from mono.engine import capabilities, coverage

    prev_keys = enabled_keys()
    prev_hints = capabilities.get_hints()
    save_enabled(["idor", "unauthorized"])
    capabilities.save_hints(
        {"idor": "只测 /api/order?id=2，必须换别人的订单号；不要扫全站、不要碰删除接口。"}
    )
    sid = new_session("hint")
    try:
        text = capabilities.context_text()
        check("能力上下文带出用户提示原文", "只测 /api/order?id=2" in text, text[:300])
        check("上下文写明这是硬性要求", "用户提示 · 硬性要求" in text, text[:300])
        check("上下文要求提示逐条有结果", "note 里要写清提示里每处要求" in text or "各自的结果" in text, text[:400])
        check("没写提示的项不会被硬塞提示", text.count("【用户提示 · 硬性要求】") == 1, str(text.count("【用户提示 · 硬性要求】")))

        with agent.tool_session(sid):
            first = await agent.dispatch_tool(
                "report_capability",
                {"capability": "idor", "status": "clean", "note": "测了 /api/order?id=2 返回自己的订单"},
                "admin",
            )
        check("第一次上报先返回提示原文", bool(first.get("hint_required")), str(first)[:200])
        check("返回里带用户提示内容", "只测 /api/order?id=2" in str(first.get("user_prompt") or ""), str(first)[:200])
        check("提示没读完不记账", coverage.summary(sid)["done"] == 0, str(coverage.summary(sid)))
        check("返回里说明「不是失败」", "不是测试失败" in str(first.get("next") or ""), str(first.get("next"))[:160])

        with agent.tool_session(sid):
            second = await agent.dispatch_tool(
                "report_capability",
                {"capability": "idor", "status": "clean", "note": "按提示只测了 /api/order?id=2，返回 403"},
                "admin",
            )
        check("读完再报就记账", bool(second.get("ok")) and coverage.summary(sid)["done"] == 1, str(second)[:200])

        # 没写提示的项不受这条门槛影响：一次就记账
        with agent.tool_session(sid):
            plain = await agent.dispatch_tool(
                "report_capability",
                {"capability": "unauthorized", "status": "blocked", "note": "整站 /api 未登录统一 401"},
                "admin",
            )
        check("没写提示的项一次就记账", bool(plain.get("ok")), str(plain)[:200])

        prompt = coverage.next_batch_prompt(sid)
        check("催下一批时跳过已验项", "越权访问" not in prompt or "未授权访问" in prompt, prompt[:300])

        coverage.mark(sid, "idor", "inconclusive", "证据不足，需要再补一次")
        prompt2 = coverage.next_batch_prompt(sid)
        check("还剩项被点名时带上用户提示", "只测 /api/order?id=2" in prompt2, prompt2[:400])

        with agent.tool_session(sid):
            listed = await agent.dispatch_tool("list_capabilities", {}, "admin")
        check(
            "查能力清单时带出用户提示",
            any(item.get("user_prompt") for item in listed.get("capabilities") or []),
            str(listed.get("user_prompts"))[:160],
        )

        # 清空提示后门槛解除
        capabilities.save_hints({})
        check("提示可以清空", capabilities.get_hints() == {}, str(capabilities.get_hints()))
        with agent.tool_session(sid):
            cleared = await agent.dispatch_tool(
                "report_capability",
                {"capability": "idor", "status": "clean", "note": "清空提示后直接上报"},
                "admin",
            )
        check("清空提示后不再要求先读", bool(cleared.get("ok")), str(cleared)[:200])
    finally:
        capabilities.save_hints(prev_hints)
        save_enabled(prev_keys)


async def test_coverage_blocks_finish() -> None:
    """能力没验完就不许收口：推回次数不受 8 次上限限制，结论末尾强制标「任务未完成」。"""
    from mono.engine import coverage

    original = agent.dispatch_tool

    async def stub(name, args, username):
        return {"ok": True, "status": 200, "body": "ok"}

    agent.dispatch_tool = stub  # type: ignore[assignment]
    prev = enabled_keys()
    save_enabled(["idor", "unauthorized"])
    sid = new_session("cov-block")
    say(sid, "测一下 https://t.example/ 的安全性，重点看数据泄露、控制权限和实际危害")
    calls = [
        {
            "id": f"c{index}",
            "type": "function",
            "function": {"name": "http_request", "arguments": json.dumps({"url": f"https://t.example/a{index}"})},
        }
        for index in range(10)
    ]
    batch = {"message": {"role": "assistant", "content": "", "tool_calls": calls}, "finish_reason": "tool_calls"}
    script = [batch] + [reply("泄露：没看到；权限：没越权；危害：没有可写入的口。") for _ in range(12)]
    try:
        events = await run(script, sid)

        tracer = find(events, "_llm_messages")
        calls_made = len(tracer[0]["data"]) if tracer else 0
        check("台账没满时不按推回次数放弃", calls_made > agent.MAX_COVERAGE_PUSHES + 2, f"只调了 {calls_made} 次")
        contents = [str(e.get("content") or "") for e in find(events, "message")]
        body = contents[-1] if contents else ""
        check("结论末尾强制标注任务未完成", "任务未完成" in body, body[-400:])
        check("写清还差几项", "还差 2 项" in body, body[-400:])
        prompts = "\n".join(
            str(m.get("content") or "")
            for data in (tracer[0]["data"] if tracer else [])
            for m in data
            if m.get("role") == "system"
        )
        check("推回时点明「不要写总结直接开工」", "直接调用 http_request" in prompts, prompts[-300:])

        # 全部有结论时，结论里换成「可以交付」，不再挂未完成横幅
        coverage.mark(sid, "idor", "clean", "测过")
        coverage.mark(sid, "unauthorized", "blocked", "整站 401")
        line = coverage.gate_line(sid)
        check("全部有结论时给交付结论", "全部有结论" in line and "任务未完成" not in line, line)
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]
        save_enabled(prev)


async def test_coverage_gate() -> None:
    """勾了能力却一次都没上报：三方向写全了、动作也够，照样推回去继续测。"""
    original = agent.dispatch_tool

    async def stub(name, args, username):
        return {"ok": True, "status": 200, "body": "ok"}

    agent.dispatch_tool = stub  # type: ignore[assignment]
    prev = enabled_keys()
    save_enabled(["idor", "unauthorized"])
    sid = new_session("cov-gate")
    say(sid, "测一下 https://t.example/ 的安全性，重点看数据泄露、控制权限和实际危害")
    calls = [
        {
            "id": f"c{index}",
            "type": "function",
            "function": {"name": "http_request", "arguments": json.dumps({"url": f"https://t.example/a{index}"})},
        }
        for index in range(20)
    ]
    batch = {"message": {"role": "assistant", "content": "", "tool_calls": calls}, "finish_reason": "tool_calls"}
    try:
        events = await run(
            [
                batch,
                reply(
                    "泄露：没看到凭据或源码；权限：接口都要登录，没能越权；危害：没有可写入的接口。"
                ),
                reply("按台账继续：接着测越权那一项。"),
            ],
            sid,
        )
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]
        save_enabled(prev)

    tracer = find(events, "_llm_messages")
    prompts = "\n".join(
        str(m.get("content") or "")
        for data in (tracer[0]["data"] if tracer else [])
        for m in data
        if m.get("role") == "system"
    )
    check("没上报能力会被推回补测", "能力清单还没验完" in prompts, prompts[-400:])
    check("推回时点名下一批能力", "越权" in prompts or "未授权访问" in prompts, prompts[-300:])
    check("推回时说明还剩几项", "还剩" in prompts, prompts[-300:])

    # 自动迭代关着也照推：勾了能力就说明要按清单验，不能靠用户每轮催
    async def stub_again(name, args, username):
        return {"ok": True, "status": 200, "body": "ok"}

    agent.dispatch_tool = stub_again  # type: ignore[assignment]
    save_enabled(["idor", "unauthorized"])
    side = new_session("cov-gate-off")
    say(side, "测一下 https://t.example/ 的安全性，重点看数据泄露、控制权限和实际危害")
    batch2 = {
        "message": {"role": "assistant", "content": "", "tool_calls": calls},
        "finish_reason": "tool_calls",
    }
    try:
        events2 = await run(
            [
                batch2,
                reply("泄露：没看到凭据或源码；权限：接口都要登录，没能越权；危害：没有可写入的接口。"),
                reply("按台账继续测越权。"),
            ],
            side,
        )
    finally:
        agent.dispatch_tool = original  # type: ignore[assignment]
        save_enabled(prev)
    tracer2 = find(events2, "_llm_messages")
    prompts2 = "\n".join(
        str(m.get("content") or "")
        for data in (tracer2[0]["data"] if tracer2 else [])
        for m in data
        if m.get("role") == "system"
    )
    check("自动迭代关了，勾了能力也照样推", "能力清单还没验完" in prompts2, prompts2[-300:])


def test_output_budget() -> None:
    """输出上限与上下文预算已放大，且模型不认大 max_tokens 时能自动降档。"""
    check("输出上限已放大到 16000", agent.MAX_OUTPUT_TOKENS >= 16000, str(agent.MAX_OUTPUT_TOKENS))
    check("续写段数不少于 4", agent.CONTINUE_ROUNDS >= 4, str(agent.CONTINUE_ROUNDS))
    check("上下文预算已放大", agent.CONTEXT_CHAR_BUDGET >= 80000, str(agent.CONTEXT_CHAR_BUDGET))
    check("历史预算已放大", agent.HISTORY_CHAR_BUDGET >= 24000, str(agent.HISTORY_CHAR_BUDGET))
    check("单条工具结果放宽", agent.TOOL_RESULT_CHARS >= 5000, str(agent.TOOL_RESULT_CHARS))
    check(
        "识别 max_tokens 过大",
        agent._token_limit_error("HTTP 400: max_tokens is too large, maximum is 8192"),
    )
    check("鉴权错误不当成参数问题", not agent._token_limit_error("HTTP 401: invalid api key"))
    check("普通网络错误不当成参数问题", not agent._token_limit_error("请求异常: ConnectError"))


async def test_irreversible_write_blocked() -> None:
    """改口令、删账号、清表一律拦下：验证危害只能用只读证据，不能真把目标改坏。"""
    check(
        "改密请求被识别",
        agent.irreversible_write_reason("http://t/api/auth/password\n{\"new_password\":\"x\"}", "POST") == "修改口令",
    )
    check(
        "登录请求不误伤",
        agent.irreversible_write_reason('http://t/api/auth/login\n{"password":"admin123"}', "POST") == "",
    )
    check(
        "读请求里的敏感字段不误伤",
        agent.irreversible_write_reason("http://t/app.js?x=new_password", "GET") == "",
    )
    check(
        "清表语句被识别",
        agent.irreversible_write_reason('http://t/api/query\n{"sql":"drop table users"}', "POST") == "清空数据表",
    )
    check(
        "脚本里的改密被识别",
        agent._script_write_reason('import requests; requests.post(u, json={"new_password": "x"})') == "修改口令",
    )
    check("脚本只读源码不误伤", agent._script_write_reason('print(open("app.js").read().find("new_password"))') == "")
    # 平台自身的连接器/设置是用户配置，不是被测对象：模型不能借「测 SSRF」把地址改掉
    check(
        "改平台连接器配置被拦",
        agent.irreversible_write_reason("http://127.0.0.1:8014/api/connectors/deepseek", "PUT") == "修改平台自身配置",
    )
    check(
        "改平台设置被拦",
        agent.irreversible_write_reason("http://127.0.0.1:8014/api/settings", "PUT") == "修改平台自身配置",
    )
    check(
        "读平台设置不拦",
        agent.irreversible_write_reason("http://127.0.0.1:8014/api/settings", "GET") == "",
    )
    check(
        "外部目标的同名接口不拦",
        agent.irreversible_write_reason("http://target.example/api/settings", "PUT") == "",
    )

    blocked = await agent.dispatch_tool(
        "http_request",
        {
            "url": "http://127.0.0.1:9/api/auth/password",
            "method": "POST",
            "body": '{"old_password":"admin123","new_password":"Xyz123456"}',
            "timeout": 3,
        },
        "admin",
    )
    check("改密请求直接拒绝", blocked.get("ok") is False and blocked.get("blocked") is True, str(blocked)[:200])
    check("拒绝时说明改用只读证据", "只读的等价证据" in str(blocked.get("error")), str(blocked.get("error"))[:200])
    script = await agent.dispatch_tool(
        "run_python",
        {"code": 'import requests\nrequests.post("http://127.0.0.1:9/p", json={"new_password": "x"})'},
        "admin",
    )
    check("脚本改密同样拒绝", script.get("ok") is False and script.get("blocked") is True, str(script)[:200])


async def main() -> int:
    init_db()
    save_enabled([])
    await test_quiet_tool_hidden()
    await test_many_tools_no_hard_stop()
    await test_budget_exhausted_graceful()
    await test_length_continuation()
    test_output_budget()
    await test_stream_fallback()
    await test_transient_retry()
    await test_auth_error_not_retried()
    await test_ask_choice()
    await test_choice_keeps_conclusion()
    await test_open_question_trimmed_without_card()
    test_lead_in_stripped()
    await test_process_narration_dropped()
    test_prompt_contract()
    await test_create_asset_without_confirm()
    await test_progress_keeps_history()
    await test_loading_merged()
    await test_no_tool_feed()
    await test_in_scope_scan_no_confirm()
    await test_out_of_scope_confirm()
    await test_sensitive_file_confirm()
    await test_sensitive_content_confirm()
    test_mask_helpers()
    await test_irreversible_write_blocked()
    await test_normal_file_no_confirm()
    await test_duplicate_tool_not_repeated()
    await test_duplicate_batch_call_deduped()
    await test_shrink_tool_history()
    await test_history_char_budget()
    await test_context_grows_slowly()
    await test_no_model_configured()
    test_memory_tools()
    await test_interjection_priority()
    await test_interjection_after_answer()
    test_interjection_queue()
    await test_progress_each_step()
    await test_progress_fallback()
    test_clean_progress()

    # 命令执行能力（真跑命令 / 真发请求），放在最后，避免影响前面的会话计数
    await test_shell_and_python()
    await test_http_request_tool()
    await test_http_out_of_scope_confirm()
    await test_shell_sensitive_confirm()
    await test_shell_out_of_scope_confirm()
    test_delete_and_ask_switches()
    test_progress_highlight()
    await test_progress_highlight_event()
    test_domain_normalization()
    await test_finding_realtime()
    test_memory_full_read()
    test_grant_once_and_target_skip()
    await test_interjection_acknowledged()
    await test_long_output_batched()
    await test_sync_tool_off_event_loop()
    test_ack_text()
    await test_cancel_stops_run()
    test_action_dedupe()
    await test_confirm_only_once()
    test_highlight_vocabulary()
    test_highlight_cooldown_rule()
    await test_highlight_cooldown_flow()
    test_evidence_progress()
    await test_memory_read_progress()
    test_memory_reads_any_file()
    await test_progress_on_later_turns()
    test_question_turn_vocabulary()
    test_work_digest_survives_history_budget()
    await test_question_mode_answers_without_rerun()
    await test_question_progress_report_retried()
    await test_question_mode_blocks_forced_tool()
    test_interjection_question_note()
    await test_parallel_tools()
    await test_tool_result_pairing()
    await test_early_finish_pushed_back()
    await test_axes_gate()
    await test_capability_ledger()
    await test_capability_user_prompt()
    await test_coverage_gate()
    await test_coverage_blocks_finish()
    await test_autonomy_choice_auto_decided()
    await test_finding_must_be_archived()
    await test_stall_archives_before_stop()
    test_memory_loading_plain()
    await test_findings_digest_written_out()
    await test_digest_on_every_round_exit()
    await test_digest_per_domain_scope()
    await test_digest_dedupe()
    await test_digest_steps()
    await test_packet_gap_is_flagged()

    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
