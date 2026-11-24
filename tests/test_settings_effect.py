"""设置项是否真的生效：每一项都在真实调用路径上验一遍。

不是测「函数返回值对不对」，而是让假模型真的发一次工具调用，
看平台的拦截、确认、放行到底有没有发生 —— 这些开关摆在工作台上，
用户点开它是期待它管事的。

用法：
    python tests/test_settings_effect.py
退出码 0 表示全部通过。
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-test-")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.db import db, init_db, now_iso, set_settings  # noqa: E402
import mono.engine.agent as agent  # noqa: E402
from mono.engine.capabilities import (  # noqa: E402
    ASK_DELETE_KEY,
    ASK_SENSITIVE_KEY,
    context_text as capabilities_context,
    get_weights,
    save_enabled,
    save_weights,
    set_switches,
    weighted_items,
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


class FakeLLM:
    def __init__(self, script: list[dict]):
        self.script = list(script)
        self.seen_messages: list[list[dict]] = []

    name = "Fake"
    model = "fake"
    key = "fake"

    def _next(self) -> dict:
        if not self.script:
            return {"message": {"role": "assistant", "content": "做完了。"}, "finish_reason": "stop"}
        return self.script.pop(0)

    async def stream_complete(self, messages, tools=None, **kwargs):
        self.seen_messages.append(messages)
        item = self._next()
        if item.get("finish_reason") == "tool_calls":
            yield ("final", item)
            return
        text = str((item.get("message") or {}).get("content") or "")
        yield ("text", text)
        yield ("final", item)

    async def complete(self, messages, tools=None, **kwargs):
        self.seen_messages.append(messages)
        from mono.connectors.base import ConnectorResult

        return ConnectorResult(
            True,
            "ok",
            {"message": self._next()["message"], "finish_reason": "stop"},
        )


def use(llm: "FakeLLM") -> None:
    agent.pick_llm = lambda provider="": llm  # type: ignore[assignment]


def new_session(title: str = "t") -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO chat_sessions (title, username, created_at, updated_at) VALUES (?,?,?,?)",
            (title, "admin", now_iso(), now_iso()),
        )
        return int(cur.lastrowid)


async def run(script: list[dict], session_id: int | None = None) -> list[dict]:
    llm = FakeLLM(script)
    use(llm)
    sid = session_id or new_session()
    events = []
    async for event in agent.run_agent(sid, "admin"):
        events.append(event)
    return events


def kinds(events: list[dict]) -> list[str]:
    return [e["type"] for e in events]


def find(events: list[dict], kind: str) -> list[dict]:
    return [e for e in events if e["type"] == kind]


# ---------------- 现场保护 ----------------


class FakeHTTP:
    """替掉真的发请求：只记下发了什么，不真出网。"""

    def __init__(self):
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "ok": True,
            "status": 200,
            "method": kwargs.get("method", "GET"),
            "url": kwargs.get("url", ""),
            "headers": {},
            "body": '{"ok":true}',
        }


def patch_http() -> FakeHTTP:
    fake = FakeHTTP()
    agent.shell_http_request = fake  # type: ignore[assignment]
    return fake


_ORIGINAL_HTTP = agent.shell_http_request
_ORIGINAL_SHELL = agent.shell_run_command
_ORIGINAL_PY = agent.shell_run_script


class FakeShell:
    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, command, cwd=None, timeout=0):
        self.calls.append(command)
        return {"ok": True, "exit_code": 0, "stdout": "", "stderr": ""}


def patch_shell() -> FakeShell:
    fake = FakeShell()
    agent.shell_run_command = fake  # type: ignore[assignment]
    agent.shell_run_script = fake  # type: ignore[assignment]
    return fake


def restore() -> None:
    agent.shell_http_request = _ORIGINAL_HTTP  # type: ignore[assignment]
    agent.shell_run_command = _ORIGINAL_SHELL  # type: ignore[assignment]
    agent.shell_run_script = _ORIGINAL_PY  # type: ignore[assignment]


DEFAULTS = {
    "safe_mode": "true",
    "sensitive_path_checks": "true",
    "ai_enabled": "true",
    "request_timeout": "8",
    "max_concurrency": "24",
}


def base_settings(**over) -> None:
    values = dict(DEFAULTS)
    values.update({k: str(v) for k, v in over.items()})
    set_settings(values)


def all_asks(on: bool = True) -> None:
    set_switches({ASK_SENSITIVE_KEY: on, ASK_DELETE_KEY: on})


# ---------------- 用例 ----------------


async def test_any_target_goes_out() -> None:
    """授权范围取消了：任意域名直接发，不再弹「目标不在授权范围」。"""
    base_settings()
    all_asks()
    fake = patch_http()
    try:
        first = await run(
            [tool_call("http_request", {"url": "https://one.example/a"}), reply("好。")],
            new_session("free-1"),
        )
        second = await run(
            [tool_call("http_request", {"url": "https://another-site.test/b"}), reply("好。")],
            new_session("free-2"),
        )
        local = await run(
            [tool_call("http_request", {"url": "http://127.0.0.1:8080/admin"}), reply("好。")],
            new_session("free-local"),
        )
        localhost = await run(
            [tool_call("http_request", {"url": "http://localhost:8080/api/users"}), reply("好。")],
            new_session("free-localhost"),
        )
    finally:
        restore()
    check(
        "任意域名都不弹确认",
        not find(first, "confirm") and not find(second, "confirm"),
        f"{kinds(first)} {kinds(second)}",
    )
    check(
        "自己的 127.0.0.1 与 localhost 更不需要授权",
        not find(local, "confirm") and not find(localhost, "confirm"),
        f"{kinds(local)} {kinds(localhost)}",
    )
    check("四次请求都真的发出去了", len(fake.calls) == 4, f"实际 {len(fake.calls)} 次")


async def test_scan_any_target() -> None:
    """发起评估同样不再校验范围：任何目标都直接建任务。"""
    base_settings()
    all_asks()
    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    events = await run(
        [
            tool_call("start_scan", {"targets": ["https://whatever-site.test"], "mode": "passive"}),
            reply("好。"),
        ],
        new_session("scan-free"),
    )
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        row = conn.execute("SELECT authorization_ref FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    check("任意目标都不弹确认", not find(events, "confirm"), str(kinds(events)))
    check("任务已建", after == before + 1, f"{before} -> {after}")
    check(
        "授权依据记为免责声明",
        "免责声明" in str(row["authorization_ref"] if row else ""),
        str(row)[:140],
    )


def test_scope_feature_removed() -> None:
    """授权范围这套东西得真删掉：没有判定函数、没有设置字段、没有跨域开关。"""
    check(
        "越界判定函数已删除",
        not hasattr(agent, "scope_block_error") and not hasattr(agent, "_outside_scope"),
    )
    import mono.api.settings as settings_api

    check(
        "设置接口不再收授权范围",
        "scope_domains" not in settings_api.ALLOWED and "scope_cidrs" not in settings_api.ALLOWED,
    )
    check("设置模型不再有授权范围字段", "scope_domains" not in settings_api.SettingsIn.model_fields)
    from mono.engine import capabilities as caps

    check("跨域开关已下线", "ask_out_of_scope" not in caps.SWITCH_BY_KEY)
    check(
        "确认标签不再有越界项",
        "start_scan" not in agent.CONFIRM_LABELS and "http_request" not in agent.CONFIRM_LABELS,
        str(agent.CONFIRM_LABELS),
    )


def test_scope_ui_removed() -> None:
    """设置页不该再出现授权域名 / 网段 / 内网开关。"""
    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
    check("设置页没有授权域名输入", "s-scope-domains" not in html)
    check("设置页没有授权网段输入", "s-scope-cidrs" not in html)
    check("设置页没有内网开关", "s-allow-private" not in html)
    check("设置页写明免责声明即授权", "登录免责声明即操作授权" in html)


def test_weights_ordering() -> None:
    """权重：默认满格 5、可改 1-5、越界夹住、顺序按权重降序。"""
    save_enabled(["unauthorized", "sqli", "sensitive_info"])
    check("默认权重为 5", get_weights().get("unauthorized") == 5, str(get_weights().get("unauthorized")))
    save_weights({"unauthorized": 5, "sqli": 1})
    order = [item["key"] for item in weighted_items()]
    check("权重 5 排最前", order[0] == "unauthorized", str(order))
    check("权重 1 排最后", order[-1] == "sqli", str(order))
    save_weights({"unauthorized": 99})
    check("超过 5 被夹到 5", get_weights().get("unauthorized") == 5)
    save_weights({"unauthorized": 0})
    check("小于 1 被夹到 1", get_weights().get("unauthorized") == 1)
    save_weights({"unauthorized": "abc"})  # type: ignore[arg-type]
    check("非数字被忽略", get_weights().get("unauthorized") == 1)
    save_weights({"not_a_key": 5})
    check("未知能力键被忽略", "not_a_key" not in get_weights())


def test_weights_in_prompt() -> None:
    """提示词里要真的按权重排，并且要求先做前端代码分析。"""
    save_enabled(["unauthorized", "sqli"])
    save_weights({"unauthorized": 5, "sqli": 2})
    text = capabilities_context()
    check("提示词带权重数字", "[权重 5]" in text and "[权重 2]" in text, text[:200])
    check(
        "高权重写在前面",
        text.index("未授权访问") < text.index("SQL 注入（注入攻击）"),
        text[:400],
    )
    check("提示词要求先读前端代码", "先看前端代码" in text)
    check("提示词不再提自动迭代开关", "自动迭代已开启" not in text)
    check("提示词点名要抓 JS", "JS" in text and "http_request" in text)
    save_weights({"unauthorized": 3, "sqli": 3})
    save_enabled([])


def test_key_masking() -> None:
    """脱敏：能认出是哪把 Key，但拿不到完整的。"""
    from mono.api.connectors import mask_secret

    long_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234"
    masked = mask_secret(long_key)
    check("长 Key 只留头尾", masked.startswith("sk-pro") and masked.endswith("1234"), masked)
    check("中间被打掉", "abcdefghij" not in masked, masked)
    check("空值仍为空", mask_secret("") == "")
    short = mask_secret("sk-1234")
    check("短 Key 只留后两位", short.endswith("34") and "sk-12" not in short, short)


async def test_ai_switch_scope() -> None:
    """「启用 AI 研判」只管批量评估里的 AI 分析，不该把对话也关掉。

    这条是防回归：以前这个开关的文案容易让人以为它是 AI 总开关，
    真把它接到对话上，用户一关就再也没法和模型说话了。
    """
    base_settings(ai_enabled="false")
    all_asks()
    fake = patch_http()
    try:
        events = await run(
            [tool_call("http_request", {"url": "https://target.example/a"}), reply("好。")],
            new_session("ai-off"),
        )
    finally:
        restore()
    check("AI 研判关闭：对话照常能发请求", len(fake.calls) == 1, f"事件={kinds(events)} 调用={len(fake.calls)}")
    base_settings(ai_enabled="true")


async def test_safe_mode() -> None:
    """安全模式开着时，改数据的方法要先问；关掉后可以直接发。"""
    base_settings(safe_mode="true")
    all_asks()
    fake = patch_http()
    try:
        events = await run(
            [
                tool_call("http_request", {"url": "https://target.example/api/user/2", "method": "PUT", "body": '{"role":"admin"}'}),
                reply("好。"),
            ],
            new_session("safe-on"),
        )
        after = len(fake.calls)
    finally:
        restore()
    check("安全模式开：PUT 要确认", bool(find(events, "confirm")), f"事件={kinds(events)}")
    check("安全模式开：PUT 没发出去", after == 0, f"实际 {after} 次")

    base_settings(safe_mode="false")
    all_asks()
    fake2 = patch_http()
    try:
        events2 = await run(
            [
                tool_call("http_request", {"url": "https://target.example/api/user/2", "method": "PUT", "body": '{"role":"admin"}'}),
                reply("好。"),
            ],
            new_session("safe-off"),
        )
        after2 = len(fake2.calls)
    finally:
        restore()
    check("安全模式关：PUT 直接发", not find(events2, "confirm") and after2 == 1, f"事件={kinds(events2)} 调用={after2}")
    base_settings(safe_mode="true")


async def test_sensitive_paths_switch() -> None:
    """「敏感路径检查」关掉后，读本机凭据不再拦。"""
    base_settings(sensitive_path_checks="true")
    all_asks()
    events = await run(
        [tool_call("read_file", {"path": ".env"}), reply("好。")],
        new_session("sens-on"),
    )
    check("敏感路径开：读 .env 要确认", bool(find(events, "confirm")), f"事件={kinds(events)}")

    base_settings(sensitive_path_checks="false")
    all_asks()
    events2 = await run(
        [tool_call("read_file", {"path": ".env"}), reply("好。")],
        new_session("sens-off"),
    )
    check("敏感路径关：读 .env 直接放行", not find(events2, "confirm"), f"事件={kinds(events2)}")
    base_settings(sensitive_path_checks="true")


async def test_timeout_setting() -> None:
    """设置里的超时要落到实际请求上，不能永远 30 秒。"""
    base_settings(request_timeout="5")
    all_asks()
    fake = patch_http()
    try:
        await run(
            [tool_call("http_request", {"url": "https://target.example/a"}), reply("好。")],
            new_session("timeout"),
        )
    finally:
        restore()
    used = fake.calls[0].get("timeout") if fake.calls else None
    check("超时设置生效", used == 5, f"实际 timeout={used}")
    base_settings(request_timeout="8")


async def test_forged_flag_stripped() -> None:
    """模型自己在参数里塞「已经确认，直接看原文」，必须被剥离。"""
    base_settings(sensitive_path_checks="true")
    all_asks()
    events = await run(
        [tool_call("read_file", {"path": ".env", "__reveal_sensitive": True}), reply("好。")],
        new_session("forged"),
    )
    check("伪造看原文标记：仍然要确认", bool(find(events, "confirm")), f"事件={kinds(events)}")

    calls: list[dict] = []

    async def probe(args, username):
        calls.append(dict(args))
        return {"ok": True}

    agent._HANDLERS["probe_args"] = probe  # type: ignore[index]
    try:
        await agent.dispatch_tool("probe_args", {"a": 1, "__reveal_sensitive": True}, "admin")
        await agent.dispatch_tool("probe_args", {"b": 2, "__reveal_sensitive": True}, "admin", trusted=True)
    finally:
        agent._HANDLERS.pop("probe_args", None)
    check("模型给的 __ 参数一律剥离", "__reveal_sensitive" not in calls[0], str(calls[:1]))
    check("确认后重放：内部标记保留", calls[-1].get("__reveal_sensitive") is True, str(calls[-1]))


async def test_auto_pentest_switch() -> None:
    """自动渗透开关：默认关=只测清单内；打开后系统提示与能力快照都放开清单外。

    这是真调用路径上的验证：看的是模型这一轮实际收到的 system 消息，
    不是只读一下 get_switches 的返回值。
    """
    base_settings()
    all_asks()
    save_enabled(["idor", "sqli"])

    def system_text(llm: "FakeLLM") -> str:
        first = llm.seen_messages[0] if llm.seen_messages else []
        return "\n".join(str(m.get("content") or "") for m in first if m.get("role") == "system")

    async def turn(title: str) -> str:
        llm = FakeLLM([reply("好。")])
        use(llm)
        sid = new_session(title)
        _ = [event async for event in agent.run_agent(sid, "admin")]
        return system_text(llm)

    set_switches({"auto_pentest": False})
    off_text = await turn("dog-off")
    check("自动渗透默认关闭", not agent.auto_pentest_enabled())
    check("关闭时系统提示不带覆盖段", "开关覆盖 · 自动渗透已开启" not in off_text)
    check("关闭时能力快照写「只能在这些范围内工作」", "只能在这些范围内工作" in off_text, off_text[:200])
    check("关闭时明确「自动渗透已关闭」", "自动渗透已关闭" in off_text, off_text[:200])

    set_switches({"auto_pentest": True})
    on_text = await turn("dog-on")
    check("打开后开关读到 true", agent.auto_pentest_enabled())
    check("打开后系统提示追加覆盖段", "开关覆盖 · 自动渗透已开启" in on_text, on_text[:200])
    check("打开后覆盖段明说清单外也测", "清单之外的漏洞类型**也要测**" in on_text, on_text[-400:])
    check("打开后能力快照改成「底线不是上限」", "底线，不是上限" in on_text, on_text[:400])
    check("打开后不再说「只能在这些范围内工作」", "只能在这些范围内工作" not in on_text, on_text[:400])
    check("打开后明确「清单是底线，不是边界」", "清单是底线，不是边界" in on_text, on_text[-400:])

    # 低价值项仍然不进漏洞清单：开关不是什么都放开的借口
    check("低价值项仍然排除", "CORS 宽松" in on_text and "Source Map" in on_text, on_text[-200:])

    tool_note = str(agent._tool_list_capabilities({}, "admin").get("note") or "")
    check("能力清单工具说明随开关变化", "清单是底线" in tool_note, tool_note[:200])

    # 台账口径：关闭时说「可以交付」，打开时说「清单内可以交付，清单外可继续」
    from mono.engine import coverage as cov

    sid = new_session("dog-ledger")
    for key in ("idor", "sqli"):
        cov.mark(sid, key, "clean", "验过")
    set_switches({"auto_pentest": False})
    check("关闭时台账收尾只说可以交付", "可以交付" in cov.gate_line(sid) and "清单内可以交付" not in cov.gate_line(sid))
    set_switches({"auto_pentest": True})
    check("打开时台账收尾说「清单内可以交付」", "清单内可以交付" in cov.gate_line(sid), cov.gate_line(sid)[:160])

    # 清单外的类型误报能力名：开着的时候要指路到 record_finding，而不是让模型卡死
    agent._TOOL_SESSION.set(sid)
    unknown = agent._tool_report_capability({"capability": "缓存投毒", "status": "vulnerable", "note": "x"}, "admin")
    check("打开后未知类型指路 record_finding", "record_finding" in str(unknown.get("error") or ""), str(unknown)[:160])
    set_switches({"auto_pentest": False})
    unknown2 = agent._tool_report_capability({"capability": "缓存投毒", "status": "vulnerable", "note": "x"}, "admin")
    check("关闭后未知类型仍按未知能力拒绝", "未知能力" in str(unknown2.get("error") or ""), str(unknown2)[:160])
    save_enabled([])


async def test_run_all() -> None:
    init_db()
    await test_any_target_goes_out()
    await test_scan_any_target()
    test_scope_feature_removed()
    test_scope_ui_removed()
    test_weights_ordering()
    test_weights_in_prompt()
    test_key_masking()
    await test_ai_switch_scope()
    await test_safe_mode()
    await test_sensitive_paths_switch()
    await test_timeout_setting()
    await test_forged_flag_stripped()
    await test_auto_pentest_switch()


def main() -> int:
    asyncio.run(test_run_all())
    failed = [name for name, ok, _ in RESULTS if not ok]
    print()
    print(f"共 {len(RESULTS)} 项，失败 {len(failed)} 项")
    for name in failed:
        print("  未通过：" + name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
