"""承上摘要与「不重复上一轮」的回归测试。

覆盖三件事：
1. 每轮开工前，平台把「已经知道的」收成一份交给模型（台账、已归档漏洞、做过的动作、
   上一轮写过的小节），并明确禁止它再抄一遍；
2. 与之前轮次一字不差的长段落会被去掉，报文与代码块不动，提问的轮次不动；
3. 自定义模型（custom）能接进来：目录、注册表、可用判定、对话页模型列表都认它。

用法：
    python tests/test_round_brief.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-brief-")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.catalog import CATALOG_BY_KEY  # noqa: E402
from mono.connectors import load_connector, REGISTRY  # noqa: E402
from mono.db import db, init_db, now_iso  # noqa: E402
import mono.engine.agent as agent  # noqa: E402
from mono.engine.capabilities import save_enabled  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


# ---------------- 假模型 ----------------


class FakeLLM:
    name = "Fake"
    model = "fake-1"
    key = "fake"

    def __init__(self, texts: list[str]):
        self.texts = texts
        self.index = 0
        self.seen: list[list[dict]] = []

    def _next(self) -> str:
        # 一轮里模型可能被叫很多次（自检、被台账推回）：脚本用完后一直重复最后一句，
        # 这样「最终正文」永远是脚本里那段，断言才稳定
        if not self.texts:
            return "（没有脚本内容）"
        if self.index >= len(self.texts):
            return self.texts[-1]
        text = self.texts[self.index]
        self.index += 1
        return text

    async def stream_complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=180):
        self.seen.append([dict(m) for m in messages])
        text = self._next()
        for start in range(0, len(text), 12):
            yield ("text", text[start : start + 12])
        yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

    async def complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=120):
        self.seen.append([dict(m) for m in messages])
        text = self._next()
        from mono.connectors.base import ConnectorResult

        return ConnectorResult(True, "ok", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})


def use(llm: FakeLLM) -> None:
    agent.pick_llm = lambda provider="": llm  # type: ignore[assignment]


def new_session(title: str = "brief") -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO chat_sessions (title, username, created_at, updated_at) VALUES (?,?,?,?)",
            (title, "admin", now_iso(), now_iso()),
        )
        return int(cur.lastrowid)


def say(session_id: int, text: str, role: str = "user", level: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, level, created_at) VALUES (?,?,?,?,?)",
            (session_id, role, text, level, now_iso()),
        )


def add_finding(session_id: int, title: str = "订单接口未授权读取", target: str = "http://shop.test") -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO findings (scan_id, target, title, severity, category, source, description,
                                     evidence, status, created_at, url, request_packet, response_packet, dedupe_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (0, target, title, "high", "unauthorized", "manual", "不带头就能读到别人的订单", "",
             "open", now_iso(), f"{target}/api/order/1001",
             "GET /api/order/1001 HTTP/1.1\nHost: shop.test", "HTTP/1.1 200 OK\n\n{}",
             f"{target}|{title}|/api/order/1001"),
        )


async def run_round(session_id: int, script: list[str]) -> tuple[list[dict], FakeLLM]:
    llm = FakeLLM(script)
    use(llm)
    events: list[dict] = []
    async for event in agent.run_agent(session_id, "admin"):
        events.append(event)
    return events, llm


def system_text(llm_messages: list[dict]) -> str:
    return "\n".join(str(item.get("content") or "") for item in llm_messages if item.get("role") == "system")


LONG = (
    "已确认管理后台的登录接口在未携带 Cookie 时直接返回 200 和用户列表，"
    "这一条属于典型的未授权访问，危害程度按高危计；受影响的是 /api/admin/users 这个入口，"
    "返回体里包含用户名、手机号与最近登录时间，复现只需要一次 GET。"
)


# ---------------- 承上摘要 ----------------


def test_brief_content() -> None:
    sid = new_session("brief-content")
    save_enabled(["unauthorized", "sqli_char"])
    say(sid, "把目标过一遍，先看有哪些入口")
    say(sid, "已确认 /api/admin/users 不带头返回 200，接下来看写接口", role="progress", level="step")
    say(sid, "## 已测入口\n\n登录接口未带 Cookie 返回 200。\n\n## 待测\n\n写接口。", role="assistant")
    add_finding(sid)

    brief = agent._round_brief(sid)
    check("承上摘要带能力台账", "能力台账" in brief, brief[:80])
    check("承上摘要带已归档漏洞条数", "已归档漏洞 1 条" in brief, brief[:120])
    check("承上摘要带漏洞标题", "订单接口未授权读取" in brief)
    check("承上摘要带做过的动作", "/api/admin/users 不带头返回 200" in brief)
    check("承上摘要带上一轮结论", "上一轮结尾说的" in brief)
    check("承上摘要列出上一轮写过的小节", "已测入口" in brief and "不要换个说法再写一遍" in brief)
    check("承上摘要不含空话", "暂无" not in brief)

    short = agent._round_brief_line(sid)
    check("界面版承上是一行", "\n" not in short and short.startswith("承上："), short)
    check("界面版承上带已验数量", "已验 0/2 项能力" in short, short)
    check("界面版承上带归档条数", "已归档 1 条漏洞" in short, short)

    # 漏洞表是全局的（跟 _work_digest 一个口径）：先清空，才看得出「还没有归档」
    with db() as conn:
        conn.execute("DELETE FROM findings")
    save_enabled([])
    empty = new_session("brief-empty")
    text = agent._round_brief(empty)
    check("空会话也能给出承上（说明还没有归档）", "还没有" in text, text[:80])
    check("空会话没有界面摘要", agent._round_brief_line(empty) == "")
    save_enabled(["unauthorized", "sqli_char"])


async def test_brief_injected_each_round() -> None:
    sid = new_session("brief-round2")
    say(sid, "把目标过一遍")
    say(sid, "已确认 /login 存在，接下来看接口", role="progress", level="step")
    say(sid, LONG, role="assistant")

    events, llm = await run_round(sid, ["这一轮去测 /api/admin/users 的鉴权。\n\n结果：未授权可读。"])
    joined = system_text(llm.seen[0])
    check("第二轮开工前塞了承上摘要", "【本轮开工前" in joined, joined[:60])
    check("承上摘要写进了已知内容", "已确认 /login 存在" in joined, joined[:400])
    check("明令不许重抄清单", "不要把上面这份清单再抄一遍" in joined)
    check("明令不许重复上一轮段落", "都不要重复" in joined)
    check("给了「同上」的替代写法", "（同上）" in joined)

    progress = [e for e in events if e["type"] == "progress" and str(e.get("content", "")).startswith("承上：")]
    check("界面上也播了一条承上", len(progress) == 1, str(progress)[:120])

    with db() as conn:
        rows = [str(r["content"]) for r in conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='progress'", (sid,)
        ).fetchall()]
    check("承上摘要落库可见", any(line.startswith("承上：") for line in rows), str(rows)[:160])

    # 第一轮（没有历史）不该塞承上：那是还没发生的事
    fresh = new_session("brief-round1")
    events1, llm1 = await run_round(fresh, ["先把首页抓下来看看。"])
    check("第一轮不塞承上", "【本轮开工前" not in system_text(llm1.seen[0]))
    check("第一轮不播承上", not [e for e in events1 if str(e.get("content", "")).startswith("承上：")])


async def test_question_turn_has_no_brief() -> None:
    sid = new_session("brief-ask")
    say(sid, "把目标过一遍")
    say(sid, LONG, role="assistant")
    say(sid, "你测过 SQL 注入吗？")

    events, llm = await run_round(sid, ["你测过 SQL 注入吗？"])
    joined = system_text(llm.seen[0])
    check("提问轮次不塞承上", "【本轮开工前" not in joined)
    check("提问轮次不播承上", not [e for e in events if str(e.get("content", "")).startswith("承上：")])


# ---------------- 不重复上一轮 ----------------


def test_strip_repeated() -> None:
    sid = new_session("strip")
    say(sid, "第一轮问题")
    say(sid, LONG, role="assistant")
    baseline = agent._max_message_id(sid)

    fresh_text = LONG + "\n\n这一轮新测的是写接口：删除商品不需要二次确认，已归档。"
    out, dropped = agent._strip_repeated_paragraphs(sid, fresh_text, baseline)
    check("一字不差的长段落被去掉", dropped == 1, str(dropped))
    check("重复段不再出现", "受影响的是 /api/admin/users 这个入口" not in out)
    check("这一轮的新结论保留", "删除商品不需要二次确认" in out)
    check("说明省略了几段", "与前面轮次一字不差" in out, out[-40:])

    short = "未发现注入。"
    kept, n = agent._strip_repeated_paragraphs(sid, short, baseline)
    check("短段落不按重复处理", n == 0 and short in kept, str(n))

    packet = "POST /api/order HTTP/1.1\nHost: shop.test\n\n{\"id\":1}"
    say(sid, packet, role="assistant")
    base2 = agent._max_message_id(sid)
    kept2, n2 = agent._strip_repeated_paragraphs(sid, packet, base2)
    check("报文段落一律不动", n2 == 0 and "POST /api/order" in kept2, str(n2))

    # 本轮自己刚写的不能被当成「上一轮」删掉：baseline 取在它之前
    sid3 = new_session("strip-baseline")
    say(sid3, "第一轮问题")
    base3 = agent._max_message_id(sid3)
    say(sid3, LONG, role="assistant")
    kept3, n3 = agent._strip_repeated_paragraphs(sid3, LONG, base3)
    check("本轮刚写的内容不误删", n3 == 0 and LONG in kept3, str(n3))

    kept4, n4 = agent._strip_repeated_paragraphs(sid3, LONG, 0)
    check("历史里有的段落照样能识别", n4 == 1, str(n4))


async def test_no_repeat_end_to_end() -> None:
    sid = new_session("strip-round")
    say(sid, "继续把日志里没测过的接口测一遍")
    say(sid, LONG, role="assistant")

    # 一轮里模型会被叫好几次（自检、收口），每一句都给同一段，确保最终正文是它
    events, llm = await run_round(sid, [LONG] * 6)
    final = [e for e in events if e["type"] == "message" and e.get("role") == "assistant"]
    check("整段重复被换成一句说明", final and "与前面轮次一字不差" in str(final[-1]["content"]),
          str(final[-1]["content"])[:80] if final else "没有最终消息")
    with db() as conn:
        saved = conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='assistant' ORDER BY id DESC LIMIT 1",
            (sid,),
        ).fetchone()
    check("落库的也是去掉重复之后的版本", "与前面轮次一字不差" in str(saved["content"]))

    # 提问轮次不裁剪：用户就是要看原来的结论
    sid2 = new_session("strip-ask")
    say(sid2, "第一轮")
    say(sid2, LONG, role="assistant")
    say(sid2, "把刚才那段结论再发我一遍？")
    events2, _ = await run_round(sid2, [LONG] * 6)
    final2 = [e for e in events2 if e["type"] == "message" and e.get("role") == "assistant"]
    body2 = str(final2[-1]["content"]) if final2 else ""
    check("提问轮次原文照发", "受影响的是 /api/admin/users 这个入口" in body2, body2[:60])


# ---------------- 自定义模型 ----------------


def test_custom_model_catalog() -> None:
    custom = CATALOG_BY_KEY.get("custom") or {}
    check("目录里有自定义模型", custom.get("name") == "自定义模型", str(custom.get("name")))
    check("自定义模型归在大模型类", custom.get("category") == "ai")
    check("自定义模型允许不填密钥", custom.get("secret_required") is False)
    fields = {item["key"] for item in custom.get("fields", [])}
    check("可填模型名与显示名称", fields == {"model", "label"}, str(fields))
    check("注册表里有 custom", REGISTRY.get("custom") is not None)
    check("注册表 key 对得上", getattr(REGISTRY.get("custom"), "key", "") == "custom")
    check("自定义模型排在 ollama 之前被优先选中", agent.AI_PROVIDER_ORDER.index("custom") < agent.AI_PROVIDER_ORDER.index("ollama"))


def test_custom_model_ready() -> None:
    from mono.db import set_settings  # noqa: F401

    with db() as conn:
        conn.execute(
            "UPDATE connectors SET enabled=1, base_url=?, config_json=?, secret_enc='', last_check_ok=NULL WHERE key='custom'",
            ("http://10.1.1.9:8000/v1", '{"model": "qwen2.5-72b-instruct", "label": "内网千问"}'),
        )
    connector = load_connector("custom")
    check("没检测过不算可用", not agent.is_ready(connector), str(agent.is_ready(connector)))
    with db() as conn:
        conn.execute("UPDATE connectors SET last_check_ok=1 WHERE key='custom'")
    connector = load_connector("custom")
    check("免密钥也能算可用", agent.is_ready(connector) is True)

    providers = {item["key"]: item for item in agent.ready_providers()}
    check("对话页模型列表里有自定义模型", "custom" in providers, str(list(providers)))
    check("列表里显示自定义的名字", providers.get("custom", {}).get("name") == "内网千问", str(providers.get("custom")))
    check("列表里带模型 ID", providers.get("custom", {}).get("model") == "qwen2.5-72b-instruct")

    problem = connector.config_problem()
    check("填好地址和模型后没有配置问题", problem is None, str(problem))

    with db() as conn:
        conn.execute("UPDATE connectors SET base_url='', config_json='{}' WHERE key='custom'")
    empty = load_connector("custom")
    check("没填地址先提示补地址", "Base URL" in empty.config_problem().message)
    with db() as conn:
        conn.execute("UPDATE connectors SET base_url='https://gw.test/v1' WHERE key='custom'")
    nomodel = load_connector("custom")
    check("只填地址没填模型也提示", "模型名称" in nomodel.config_problem().message)


# ---------------- 前端接线（细节由浏览器验证，这里守住不被改回去） ----------------


def test_frontend_wiring() -> None:
    js = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")
    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")

    check("划词状态有独立字段", "chatSelecting: false" in js and "chatRenderDirty: false" in js)
    check("有「正在划词」的判定函数", "function chatSelectionLocked(" in js)
    check("贴底前先看有没有在划词", "if (chatSelectionLocked(box)) return;" in js)
    check("重建列表前先看有没有在划词", "state.chatRenderDirty = true;\n    return;" in js)
    check("划词结束后补画", "function flushChatRender(" in js and "flushChatRender();" in js)
    check("按下鼠标进划词态", 'addEventListener("mousedown", () => { state.chatSelecting = true; })' in js)
    check("松手后退出划词态", 'document.addEventListener("mouseup", () => {' in js)
    check("选区清掉后补画", 'document.addEventListener("selectionchange", () => {' in js)
    check("切会话时清掉旧选区", "clearChatSelection();" in js)
    check("拖到窗口外也能解锁", 'window.addEventListener("blur"' in js)
    check("卡片的紧急程度高于选区", "cardSig" in js and 'box.dataset.cards' in js)
    check("拖选中和已选中分开判", "function chatDragging(" in js and "function chatHasSelection(" in js)
    check("重画前记住选区位置", "captureChatSelection(box)" in js and "restoreChatSelection(box, keepSelection)" in js)
    check("拖选中不重画（只有拖的时候冻住）", "if (chatDragging() && box.childElementCount" in js)
    check("贴底仍然避让选区", "return chatDragging() || chatHasSelection(box);" in js)

    check("自定义模型有显示名称输入", 'id="llm-label-field"' in html and 'id="llm-label"' in html)
    check("显示名称平时收起", 'id="llm-label-field" hidden' in html)
    check("自定义模型可切出显示名称", 'labelField.hidden = !custom' in js)
    check("自定义模型必须填地址", "自定义模型必须填写 Base URL" in js)
    check("自定义模型必须填模型名", "自定义模型必须填写模型名称" in js)
    check("免密钥的模型也能直接检测", "const noSecret = !connector.secret_required;" in js)
    check("静态资源换了版本号", "?v=20261126g" in html)
    check("接入列表名称与类型分两行", 'class="td-title"><strong>${esc(item.name)}</strong><small>' in js)
    check("接入列表表头说清两列", "名称 / 类型" in js)



def main() -> int:
    init_db()
    test_brief_content()
    asyncio.run(test_brief_injected_each_round())
    asyncio.run(test_question_turn_has_no_brief())
    test_strip_repeated()
    asyncio.run(test_no_repeat_end_to_end())
    test_custom_model_catalog()
    test_custom_model_ready()
    test_frontend_wiring()

    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
