"""两条硬要求的回归测试。

1. 泄露的信息，正常用户看不到的才算泄露——公开可见的信息归档时要被降级；
2. 对话界面右侧能列出本会话的每一句提问，点一条直接定位到那条消息。

用法：
    python tests/test_leak_and_outline.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-leak-")
WORK = Path(TMP) / "work"
WORK.mkdir(parents=True, exist_ok=True)
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

import mono.engine.agent as agent  # noqa: E402
from mono.db import db, init_db, set_settings  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


async def record(title: str, severity: str, description: str = "", evidence: str = "") -> dict:
    return await agent.dispatch_tool(
        "record_finding",
        {"url": "https://shop.example.com/api/user", "title": title, "severity": severity,
         "description": description, "evidence": evidence},
        "admin",
    )


def db_row(title: str) -> dict:
    with db() as conn:
        row = conn.execute(
            "SELECT severity, evidence FROM findings WHERE title=? ORDER BY id DESC LIMIT 1", (title,)
        ).fetchone()
    return dict(row) if row else {}


def test_gate() -> None:
    # 标题像泄露、标了高危，但说明里只有「返回了手机号」——没证明正常用户看不到
    sev, note = agent.leak_gate(
        "用户手机号信息泄露", "high", "接口返回了用户手机号与邮箱", "HTTP 200，响应含 phone/mail 字段"
    )
    check("公开可见的「泄露」被降到中危", sev == "medium", sev)
    check("降级时说明原因", "正常用户看不到" in note, note)

    # 写清了对照：未登录也能拿到别人的数据
    sev2, note2 = agent.leak_gate(
        "用户手机号信息泄露",
        "high",
        "未登录直接请求该接口可拿到他人账号的手机号与邮箱，正常页面只有本人登录后才显示自己的",
        "GET /api/user?id=1002 未带凭证返回 200",
    )
    check("给了对照证据就保持高危", sev2 == "high" and note2 == "", f"{sev2} {note2}")

    # 页面上本来就公开的信息，且声称严重
    sev3, _ = agent.leak_gate("源码备份文件泄露", "critical", "首页 JS 里能看到接口地址", "")
    check("严重级泄露无对照时降到高危", sev3 == "high", sev3)

    # 不是泄露类的结论不受影响
    sev4, note4 = agent.leak_gate("SQL 注入", "critical", "id 参数可注入", "sleep(3) 生效")
    check("非泄露类结论不变", sev4 == "critical" and note4 == "", sev4)

    # 中危的泄露不做过严校验：门槛只拦「往高危上吹」的
    sev5, note5 = agent.leak_gate("邮箱泄露", "medium", "接口返回邮箱", "")
    check("中危泄露不降级", sev5 == "medium" and note5 == "", sev5)


def test_archive() -> None:
    async def main() -> None:
        init_db()
        set_settings({"work_dir": str(WORK), "memory_path": "", "scope_domains": "example.com"})

        low = await record("配置文件信息泄露", "high", "页面注释里写着数据库地址", "响应体含 db host")
        check("归档时自动降级", low.get("severity") == "medium", str(low)[:160])
        check("返回里提示补什么证据", "正常用户看不到" in str(low.get("severity_note") or ""), str(low)[:160])
        row = db_row("配置文件信息泄露")
        check("库里记的是降级后的等级", row.get("severity") == "medium", str(row)[:160])
        check("证据里留下降级说明", "平台按判定门槛降级" in str(row.get("evidence") or ""), str(row)[:160])

        # 补上对照证据再归档一次：应该覆盖成高危
        up = await record(
            "配置文件信息泄露",
            "high",
            "未登录访问 /static/app.js 可读到内部数据库地址与内部接口，正常页面不展示这些字段",
            "GET /static/app.js 无凭证 200，命中 internal-db 主机名",
        )
        check("补齐对照后可升回高危", up.get("severity") == "high", str(up)[:160])
        row2 = db_row("配置文件信息泄露")
        check("库里同步升级", row2.get("severity") == "high", str(row2)[:160])

        ok = await record(
            "订单越权访问导致信息泄露",
            "high",
            "普通用户改 orderId 即可读取他人订单，含收货人与手机号；正常页面只展示自己的订单",
            "GET /api/order/9001 携带本人 Cookie 返回他人订单",
        )
        check("正常泄露结论照常归档为高危", ok.get("severity") == "high", str(ok)[:160])

    asyncio.run(main())


def test_digest() -> None:
    """收尾必须在控制台逐条写出标题 + 请求包 + 响应包。"""

    async def main() -> None:
        init_db()
        set_settings({"work_dir": str(WORK), "memory_path": "", "scope_domains": "example.com"})
        sid = 9001
        agent._SESSION_FINDINGS[sid] = []
        token = agent.set_tool_session(sid)
        try:
            await agent.dispatch_tool(
                "record_finding",
                {
                    "url": "https://shop.example.com/api/order/9001",
                    "title": "订单越权导致信息泄露",
                    "severity": "high",
                    "description": "普通用户改 orderId 可读他人订单，正常页面只展示自己的",
                    "evidence": "GET /api/order/9001 携带本人 Cookie 返回他人订单",
                    "request_packet": "GET /api/order/9001 HTTP/1.1\nHost: shop.example.com\nCookie: sid=me",
                    "response_packet": 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"orderId":9001,"phone":"138****"}',
                },
                "admin",
            )
        finally:
            agent._TOOL_SESSION.reset(token)

        ids = agent._SESSION_FINDINGS.get(sid) or []
        check("归档后记进本轮清单", len(ids) == 1, str(ids))

        thin = "已归档 1 条漏洞，去漏洞结果页查看。"
        out = agent.findings_digest(sid, thin)
        check("结论没写报文时自动补上", "【漏洞清单·逐条复核】" in out, out[:120])
        check("补的是标题", "订单越权导致信息泄露" in out)
        check("补了请求包原文", "GET /api/order/9001 HTTP/1.1" in out and "Host: shop.example.com" in out)
        check("补了响应包原文", "HTTP/1.1 200 OK" in out and '"orderId":9001' in out)
        check("报文用代码块包着", out.count("```http") == 2, str(out.count("```http")))

        full = (
            "本轮结论：订单越权导致信息泄露（高危）。\n\n"
            "请求包：\n```http\nGET /api/order/9001 HTTP/1.1\nHost: shop.example.com\n```\n\n"
            "响应包：\n```http\nHTTP/1.1 200 OK\n\n{}\n```"
        )
        same = agent.findings_digest(sid, full)
        check("自己写全了就不重复追一遍", "【漏洞清单·逐条复核】" not in same, same[-120:])

        # 只写了标题 + 请求包、少一份响应包，同样算没写全：三样缺一不可
        half = (
            "本轮结论：订单越权导致信息泄露（高危）。\n\n"
            "请求包：\n```http\nGET /api/order/9001 HTTP/1.1\nHost: shop.example.com\n```"
        )
        half_out = agent.findings_digest(sid, half)
        check("少了响应包也要补上", "【漏洞清单·逐条复核】" in half_out and "HTTP/1.1 200 OK" in half_out, half_out[-160:])

        empty = agent.findings_digest(9002, "没有发现问题的结论")
        check("没有归档就不动结论", empty == "没有发现问题的结论", empty)

    asyncio.run(main())


def test_prompts() -> None:
    check("主提示词写明判定门槛", "正常用户看不到" in agent.SYSTEM_PROMPT)
    check("主提示词点明公开信息不算泄露", "不算泄露" in agent.SYSTEM_PROMPT)
    check(
        "主提示词要求按域名逐条写出标题与报文",
        "请求包" in agent.SYSTEM_PROMPT
        and "该域名在本次测试里出现过的全部漏洞" in agent.SYSTEM_PROMPT
        and "不要重复列举" in agent.SYSTEM_PROMPT,
    )
    check(
        "硬性要求写的是「每一轮工作完成之后」",
        "每一轮工作完成之后" in agent.SYSTEM_PROMPT
        and "自动继续接龙的每一轮收尾都要写" in agent.SYSTEM_PROMPT,
    )
    check("深度轮提示词已随自动迭代下线", not hasattr(agent, "DEEP_ROUND_PROMPT"))
    check("催办提示词带上门槛", "正常用户看不到" in agent.NEXT_ROUND_PROMPT)
    check("收尾自检要查泄露门槛", "正常用户看不到" in agent.SELF_CHECK_PROMPT)
    check("收尾自检要查报文有没有写全", "请求包" in agent.SELF_CHECK_PROMPT and "响应包" in agent.SELF_CHECK_PROMPT)
    check(
        "主提示词要求写清一步步的复现过程",
        "怎么一步步打出来的" in agent.SYSTEM_PROMPT
        and "步骤1：做了什么" in agent.SYSTEM_PROMPT
        and "一步一对" in agent.SYSTEM_PROMPT,
    )
    check(
        "主提示词要求每步各自配对报文",
        "请求包N / 响应包N" in agent.SYSTEM_PROMPT
        and "不能代替前面几步" in agent.SYSTEM_PROMPT,
    )
    check(
        "主提示词要求报文别整页贴、太长就节选",
        "报文别整页贴" in agent.SYSTEM_PROMPT and "以下为节选" in agent.SYSTEM_PROMPT,
    )
    check(
        "收尾自检也查每一步的报文",
        "每一步自己的请求包N与响应包N" in agent.SELF_CHECK_PROMPT,
    )
    record_spec = next(
        item["function"] for item in agent.TOOL_SPECS if item["function"]["name"] == "record_finding"
    )
    check("归档工具支持 steps 入参", "steps" in record_spec["parameters"]["properties"])
    http_spec = next(
        item["function"] for item in agent.TOOL_SPECS if item["function"]["name"] == "http_request"
    )
    check(
        "发包工具支持 note 说明这一步的目的",
        "note" in http_spec["parameters"]["properties"]
        and "复现步骤" in http_spec["parameters"]["properties"]["note"]["description"],
    )
    desc = next(
        item["function"]["description"]
        for item in agent.TOOL_SPECS
        if item["function"]["name"] == "record_finding"
    )
    check("归档工具描述提醒写对照", "正常用户看不到" in desc)


def test_capability_ui() -> None:
    """能力页：权重是滑块不是格子；每项可写用户提示，保存时一起提交。"""
    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
    js = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")
    css = (ROOT / "mono/static/style.css").read_text(encoding="utf-8")

    check("能力页文案改成滑块", "右侧滑块" in html and "方块" not in html)
    check("能力页说明用户提示的作用", "用户提示" in html and "必须读完" in html)
    check("权重控件是原生 range", 'type="range" class="cap-slider"' in js)
    check("滑块带 1-5 与默认值", 'min="1" max="5" step="1"' in js and "WEIGHT_DEFAULT = 5" in js)
    check("旧的方块控件已彻底移除", "weight-block" not in js and "weight-block" not in css and "weight-steps" not in js)
    check("不再自己算坐标拖拽", "weightFromPoint" not in js and "weightDragKey" not in js)
    check("滑块拖动实时生效", '.cap-slider' in js and 'addEventListener("input"' in js and "applyWeight" in js)
    check("滑块有样式", ".cap-slider {" in css and "::-webkit-slider-thumb" in css)
    check("每项都有用户提示入口", 'data-hint-input="${esc(item.key)}"' in js and "function hintBox(" in js)
    check("提示默认收起、点开编辑", "data-hint-toggle" in js and 'class="cap-hint-edit' in js)
    check("提示输入实时写进 state", "state.capabilityHints[key] = text" in js)
    check("提示随能力配置一起保存", "body: { keys, switches, weights, hints }" in js)
    check("提示有输入框样式", ".cap-hint-input {" in css and ".cap-hint.has" in css)
    check("搜索也能搜到提示内容", "hintOf(item.key)" in js)
    check("能力徽标显示还差几项", "还差 ${sum.pending}" in js and "已测完" in js)


def test_outline_ui() -> None:
    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
    js = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")
    css = (ROOT / "mono/static/style.css").read_text(encoding="utf-8")

    check("对话页有提问点列容器", 'id="chat-outline-list"' in html)
    check("导航有计数", 'id="chat-outline-count"' in html)
    check("点列放进对话区（不再单独占一栏）",
          'class="chat-stream"' in html and html.index('id="chat-messages"') < html.index('id="chat-outline"'))
    check("对话布局是两栏（会话记录 / 对话）", "244px minmax(0, 1fr)" in css and "1fr) 58px" not in css)
    check("点列绝对定位在对话区右缘", ".chat-outline {" in css and "position: absolute" in css)
    check("整页铺满窗口", "body.chat-page .main { padding: 0; }" in css and "height: 100vh" in css)
    check("发送与输入框同一行", 'class="chat-compose-row"' in html and ".chat-compose-row { display: flex" in css)
    check("自动继续与停止生成同一行", 'class="auto-row"' in html and 'id="chat-stop"' in html and 'id="auto-stop"' in html)
    check(
        "自动继续挪到会话记录下方",
        html.index('id="chat-session-list"') < html.index('id="auto-bar"'),
    )
    check("提问导航是一列短横", "chat-outline-item" in js and "<i></i>" in js and ".chat-outline-item i" in css)
    check(
        "悬停弹出全部提问面板",
        "function showOutlinePanel(" in js and 'id="chat-outline-panel"' in html
        and "chat-outline-panel" in css and 'addEventListener("mouseenter", showOutlinePanel)' in js,
    )
    check("面板逐条列出本会话提问", "outline-panel-item" in js and "chatOutlineItems()" in js)
    check("面板里点一条也能跳", 'closest("[data-outline]")' in js and "jumpToMessage(" in js)
    check("有定位函数", "function jumpToMessage(" in js)
    check("点击条目触发定位", 'closest("[data-outline]")' in js)
    check("消息节点带索引", 'data-idx="${index}"' in js)
    check("滚动时高亮当前提问", "markOutlineActive" in js and "addEventListener(\"scroll\"" in js)
    check("跳过去会闪一下", "chat-msg.flash" in css)
    check("窄屏收起点列与面板", ".chat-outline, .chat-outline-panel { display: none; }" in css)
    check("对话能渲染报文代码块", "md-pre" in js and "```" in js and ".chat-bubble .md-pre" in css)
    # 断线续传：一轮可能跑几分钟，浏览器切后台/代理超时都会断。
    # 断了要自己带 seq 接上，界面也得说清「在重连」，不能装作已经结束。
    check("每条事件带 seq 并记录 lastSeq", "if (Number(event.seq) > lastSeq) lastSeq = Number(event.seq);" in js)
    check("断线后自动续传", "function followRun(" in js and "/stream?after=${seq}" in js)
    check("续传期间界面说明在重连", "正在重连" in js and "后台还在跑" in js)
    check("正常收尾认 stream_end 标记", '"stream_end"' in js and "ended = true" in js)
    check("打开会话能接上后台在跑的批次", "function attachRunningSession(" in js and "data.running" in js)
    check("续传有上限，不会无限重试", "const RESUME_ROUNDS" in js)


def main() -> int:
    test_gate()
    test_archive()
    test_digest()
    test_prompts()
    test_capability_ui()
    test_outline_ui()
    failed = [item for item in RESULTS if not item[1]]
    total = len(RESULTS)
    print("-" * 66)
    print(f"共 {total} 项，通过 {total - len(failed)} 项，失败 {len(failed)} 项")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
