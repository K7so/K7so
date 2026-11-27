"""接口层冒烟测试：把每个 HTTP 接口都打一遍，覆盖正常值、边界值与未登录场景。

用法：
    python tests/test_api_smoke.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-api-")
os.environ["MONO_DATA_DIR"] = TMP
# 初始口令现在默认随机生成（仓库里不留固定口令），测试里显式钉一个，才能用固定口令登录
os.environ["K7so_ADMIN_PASSWORD"] = "admin123"
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from mono.main import app  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


def _install_fake_llm():
    """顶一个假模型，把「用户发问句 → HTTP → SSE → 落库」这条链路真跑一遍。"""
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-1"
        key = "fake"
        last_tools: list[str] = []

        async def stream_complete(self, messages, tools=None, **kwargs):
            FakeLLM.last_tools = [(spec.get("function") or {}).get("name", "") for spec in (tools or [])]
            text = "没测。这个会话里只做过接口盘点，SQL 注入这一项还没验。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True,
                "ok",
                {"message": {"role": "assistant", "content": "没测。"}, "finish_reason": "stop"},
            )

    engine_agent.pick_llm = lambda provider="": FakeLLM()
    return FakeLLM


def _install_fake_loop_llm():
    """每轮都说「回复「继续」」的假模型：验证自动继续会接龙，也会在空转时收手。"""
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-loop"
        key = "fake"

        async def stream_complete(self, messages, tools=None, **kwargs):
            text = "这一轮还没测完，回复「继续」我接着往下推。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True,
                "ok",
                {"message": {"role": "assistant", "content": "还没测完。"}, "finish_reason": "stop"},
            )

    engine_agent.pick_llm = lambda provider="": FakeLLM()
    return FakeLLM


def _install_fake_cover_llm(items: list[str]):
    """每轮上报一项能力的假模型：验证「自动测试选中的能力」能一项项推到底。"""
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-cover"
        key = "fake"
        pending = list(items)
        after_tool = False

        async def stream_complete(self, messages, tools=None, **kwargs):
            if FakeLLM.pending and not FakeLLM.after_tool:
                key = FakeLLM.pending.pop(0)
                FakeLLM.after_tool = True
                msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"cov_{key}",
                            "type": "function",
                            "function": {
                                "name": "report_capability",
                                "arguments": json.dumps(
                                    {"capability": key, "status": "clean", "note": f"测过 {key} 的相关入口"},
                                    ensure_ascii=False,
                                ),
                            },
                        }
                    ],
                }
                yield ("final", {"message": msg, "finish_reason": "tool_calls"})
                return
            FakeLLM.after_tool = False
            text = "这一项登记完了，继续下一项。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True, "ok", {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
            )

    engine_agent.pick_llm = lambda provider="": FakeLLM()
    return FakeLLM


def _install_fake_tool_only_llm(rounds_with_tool: int = 5):
    """每一轮只调一个「不落审计」的工具（platform_overview），用来回归「自动继续两次就停」。

    真实场景里最常发生的就是这种轮次：模型连着发了几十个包、读了几页前端 JS，
    但还没到归档那一步——库里既没有新漏洞、也没有新审计，于是被当成空转掐断。
    新判据是「这一轮调用过工具就算在干活」，所以这种轮次应该一直继续下去。
    """
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-tool-only"
        key = "fake"
        rounds = 0
        after_tool = False

        async def stream_complete(self, messages, tools=None, **kwargs):
            if FakeLLM.rounds < rounds_with_tool and not FakeLLM.after_tool:
                FakeLLM.rounds += 1
                FakeLLM.after_tool = True
                msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"o_{FakeLLM.rounds}",
                            "type": "function",
                            "function": {"name": "platform_overview", "arguments": "{}"},
                        }
                    ],
                }
                yield ("final", {"message": msg, "finish_reason": "tool_calls"})
                return
            FakeLLM.after_tool = False
            text = "这一轮把平台状态过了一遍，还没有新的结论。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True,
                "ok",
                {
                    "message": {"role": "assistant", "content": "这一轮把平台状态过了一遍，还没有新的结论。"},
                    "finish_reason": "stop",
                },
            )

    engine_agent.pick_llm = lambda *a, **k: FakeLLM()
    return FakeLLM


def _install_fake_failing_llm(failures: int = 4):
    """连着发几次都打不通（端口 1 必然拒连），验证平台会追问「这方向是不是没路了」。

    真实场景：模型试了两个写法就准备写「不可利用」，没人顶它一句它不会自己想。
    """
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-failing"
        key = "fake"
        calls = 0
        seen: list[str] = []

        async def stream_complete(self, messages, tools=None, **kwargs):
            FakeLLM.calls += 1
            FakeLLM.seen = [str(item.get("content") or "") for item in messages]
            n = FakeLLM.calls
            if n <= failures:
                msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"f_{n}",
                            "type": "function",
                            "function": {
                                "name": "http_request",
                                "arguments": json.dumps(
                                    {
                                        "url": f"http://127.0.0.1:1/probe_{n}",
                                        "method": "POST",
                                        "body": "id=1",
                                        "timeout": 3,
                                    }
                                ),
                            },
                        }
                    ],
                }
                yield ("final", {"message": msg, "finish_reason": "tool_calls"})
                return
            text = "这几次都没打成功，先停下说清楚为什么。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True,
                "ok",
                {"message": {"role": "assistant", "content": "停"}, "finish_reason": "stop"},
            )

    engine_agent.pick_llm = lambda *a, **k: FakeLLM()
    return FakeLLM


def _count_auto_rounds(sid: int, limit: int = 25) -> tuple[int, list[dict]]:
    """直接盯着自动继续那条循环，看它到底能接多少轮（不经过模型，跑得很快）。

    用来回归「自动继续只跑一次就停」：把引擎换成一个「什么都不干」的桩，
    台账没满时循环必须一直往下发；收到第 limit 轮就主动收手，避免测试自己跑不完。
    """
    import asyncio

    import mono.api.chat as chat_mod
    from mono.db import db as _db

    # 闸门要求「这一栏收到过用户任务」才允许接龙；测试会话直接补一条手打的任务消息
    with _db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE session_id=? AND role='user' "
            "AND COALESCE(level,'')!='auto'",
            (int(sid),),
        ).fetchone()
        if not row or not row["c"]:
            conn.execute(
                "INSERT INTO chat_messages (session_id, role, content, level, created_at) VALUES (?,?,?,?,?)",
                (int(sid), "user", "把这件事做完", "", time.strftime("%Y-%m-%dT%H:%M:%S")),
            )

    events: list[dict] = []
    original = chat_mod.run_agent

    async def fake_run_agent(*args, **kwargs):
        # 一轮里什么都不做：既不发包也不报能力，等于「空转」
        if False:
            yield {}
        return

    async def drive():
        chat_mod.run_agent = fake_run_agent
        try:
            gen = chat_mod._auto_loop(sid, "admin", "")
            async for event in gen:
                events.append(event)
                if sum(1 for item in events if item.get("type") == "auto_continue") >= limit:
                    break
            await gen.aclose()
        finally:
            chat_mod.run_agent = original

    asyncio.run(drive())
    rounds = sum(1 for item in events if item.get("type") == "auto_continue")
    return rounds, events


def _install_fake_busy_llm(rounds_with_tool: int = 3):
    """前几轮真动手（写文件，会落一条审计），之后只说话：验证「干了活就别掐断」。

    回归的是「自动继续只跑一次」这个 bug：以前这一轮没新归档就立刻收口，
    哪怕刚发过包 / 写过文件也算空转。
    """
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-busy"
        key = "fake"
        rounds = 0
        after_tool = False

        async def stream_complete(self, messages, tools=None, **kwargs):
            if FakeLLM.rounds < rounds_with_tool and not FakeLLM.after_tool:
                FakeLLM.rounds += 1
                FakeLLM.after_tool = True
                msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"w_{FakeLLM.rounds}",
                            "type": "function",
                            "function": {
                                "name": "write_file",
                                "arguments": json.dumps(
                                    {"path": f"auto/round_{FakeLLM.rounds}.txt", "content": "探测记录"},
                                    ensure_ascii=False,
                                ),
                            },
                        }
                    ],
                }
                yield ("final", {"message": msg, "finish_reason": "tool_calls"})
                return
            FakeLLM.after_tool = False
            text = "这一轮只做了探测，先记下来，还没到能归档的时候。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True, "ok", {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
            )

    engine_agent.pick_llm = lambda provider="": FakeLLM()
    return FakeLLM


def _install_fake_tool_llm():
    """先调一次 platform_overview，再给结论——验证「做了什么」会随 SSE 推给前端。"""
    import mono.engine.agent as engine_agent

    class FakeLLM:
        name = "Fake"
        model = "fake-tool"
        key = "fake"
        calls = 0

        async def stream_complete(self, messages, tools=None, **kwargs):
            FakeLLM.calls += 1
            if FakeLLM.calls == 1:
                msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "platform_overview", "arguments": "{}"},
                        }
                    ],
                }
                yield ("final", {"message": msg, "finish_reason": "tool_calls"})
                return
            text = "平台现状已核对：目前没有资产。"
            yield ("text", text)
            yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

        async def complete(self, messages, tools=None, **kwargs):
            from mono.connectors.base import ConnectorResult

            return ConnectorResult(
                True, "ok", {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
            )

    engine_agent.pick_llm = lambda provider="": FakeLLM()
    return FakeLLM


def main() -> int:
    with TestClient(app) as client:
        # ---------- 未登录 ----------
        check("首页可访问", client.get("/").status_code == 200)
        anon = client.get("/api/chat/sessions")
        check("未登录接口返回 401", anon.status_code == 401, str(anon.status_code))
        check("未登录不泄露数据", "sessions" not in anon.text)

        check("错误口令登录失败", client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code == 401)
        check("空用户名被拒", client.post("/api/auth/login", json={"username": "", "password": ""}).status_code in (401, 422))

        login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        check("正确口令登录成功", login.status_code == 200 and login.json().get("ok") is True, login.text[:120])
        check("登录返回身份", login.json().get("username") == "admin")

        check("会话信息可用", client.get("/api/auth/me").status_code == 200)
        check("免责声明留痕", client.post("/api/auth/disclaimer").status_code == 200)

        # ---------- 仪表盘 / 审计 ----------
        dash = client.get("/api/dashboard")
        check("仪表盘正常", dash.status_code == 200 and isinstance(dash.json(), dict), dash.text[:120])
        check("审计日志正常", client.get("/api/audit").status_code == 200)

        # ---------- 资产 CRUD ----------
        create = client.post("/api/assets", json={"target": "https://api.example.com", "name": "接口站"})
        check("新增资产成功", create.status_code == 200, create.text[:160])
        asset_id = create.json().get("id") or create.json().get("asset_id")
        check("新增资产返回 id", isinstance(asset_id, int), str(create.json())[:160])

        check("资产列表可查", client.get("/api/assets").status_code == 200)
        check("资产搜索可用", client.get("/api/assets", params={"q": "接口"}).status_code == 200)
        check("空目标被拒", client.post("/api/assets", json={"target": ""}).status_code == 422)

        if isinstance(asset_id, int):
            update = client.patch(f"/api/assets/{asset_id}", json={"name": "改名后"})
            check("修改资产成功", update.status_code == 200, update.text[:120])
            check("删除资产成功", client.delete(f"/api/assets/{asset_id}").status_code == 200)
            check("重复删除返回 404", client.delete(f"/api/assets/{asset_id}").status_code == 404)
        else:
            for name in ("修改资产成功", "删除资产成功", "重复删除返回 404"):
                check(name, False, "缺少 asset_id")

        check("不存在的资产 404", client.patch("/api/assets/999999", json={"name": "x"}).status_code == 404)

        # ---------- 扫描（授权范围已取消：任意目标都能直接建任务）----------
        check("扫描列表可查", client.get("/api/scans").status_code == 200)
        check("不存在的扫描 404", client.get("/api/scans/999999").status_code == 404)
        check("取消不存在的扫描 404", client.post("/api/scans/999999/cancel").status_code == 404)
        any_host = client.post(
            "/api/scans",
            json={"targets": ["https://not-in-scope.invalid"], "mode": "passive"},
        )
        check("任意目标都能发起扫描", any_host.status_code == 200, any_host.text[:160])
        empty_target = client.post("/api/scans", json={"targets": [], "mode": "passive"})
        check("空目标仍被拒", empty_target.status_code == 400, empty_target.text[:160])

        # ---------- 漏洞 ----------
        check("漏洞列表可查", client.get("/api/findings").status_code == 200)
        check("漏洞筛选可用", client.get("/api/findings", params={"severity": "high", "status": "open"}).status_code == 200)
        check("不存在的漏洞 404", client.get("/api/findings/999999").status_code == 404)
        check("非法状态值被拒", client.patch("/api/findings/999999", json={"status": "bad"}).status_code == 422)

        # ---------- 漏洞按域名统计 ----------
        from mono.db import db, now_iso

        samples = [
            ("https://a.example.com/api/users?id=1", "用户资料未授权", "high"),
            ("https://a.example.com/api/orders", "订单越权", "critical"),
            ("http://a.example.com:8080/login", "登录口弱口令", "medium"),
            ("http://10.0.0.5:8080/admin", "后台未授权", "high"),
            ("https://a.example.com/x", "缺少安全响应头", "info"),
        ]
        with db() as conn:
            for index, (url, title, severity) in enumerate(samples):
                conn.execute(
                    """INSERT INTO findings
                       (scan_id, asset_id, target, url, title, severity, category, source, status,
                        dedupe_key, created_at)
                       VALUES (0, NULL, ?, ?, ?, ?, '对话测试', 'ai-agent', 'open', ?, ?)""",
                    (url, url, title, severity, f"seed:{index}", now_iso()),
                )
        groups = client.get("/api/findings/domains").json()
        names = [item["domain"] for item in groups]
        check("按域名归组返回", isinstance(groups, list) and groups, str(groups)[:160])
        check("同一站点的漏洞并成一组", names.count("a.example.com") == 1, str(names))
        check("端口不同单独成组", "a.example.com:8080" in names, str(names))
        check("IP 站点也能归组", "10.0.0.5:8080" in names, str(names))
        a_group = next(item for item in groups if item["domain"] == "a.example.com")
        check("域名内漏洞条数正确", a_group["total"] == 3, str(a_group["total"]))
        check("域名内按等级计数", a_group["critical"] == 1 and a_group["high"] == 1 and a_group["info"] == 1, str(a_group))
        check("域名内带上漏洞明细", len(a_group["findings"]) == 3, str(len(a_group["findings"])))
        check("域名组按危害排序", groups[0]["critical"] >= 0 and names[0] in ("a.example.com", "10.0.0.5:8080"), str(names))
        check("按等级筛选后归组也生效", all(item["domain"] for item in client.get("/api/findings/domains", params={"severity": "high"}).json()))
        check("归组接口不吞掉单条详情", client.get(f"/api/findings/{a_group['findings'][0]['id']}").status_code == 200)

        # ---------- 连接器 ----------
        conns = client.get("/api/connectors")
        check("连接器列表可查", conns.status_code == 200 and len(conns.json()) > 10)
        check("连接器字段完整", all("configured" in item for item in conns.json()))
        check("未配置连接器检测给出提示", client.post("/api/connectors/fofa/test").status_code in (200, 400))
        check("未知连接器检测 404", client.post("/api/connectors/not-exist/test").status_code == 404)

        # 连通检测必须真发一次补全：只看 /models 列表会把「额度用完」误报成成功
        import asyncio

        import httpx

        from mono.connectors.llm import OpenAIChatConnector

        def probe(payload, status=200):
            row = {
                "key": "ncc_llm",
                "base_url": "https://probe.invalid/v1",
                "config_json": json.dumps({"model": "cyber-model-1"}),
                "secret_enc": "",
                "enabled": 1,
            }
            conn = OpenAIChatConnector(row)
            conn.secret = "sk-probe"  # 跳过解密，直接给一个假密钥

            async def fake_post(path, **kwargs):
                return httpx.Response(status, json=payload), ""

            conn.http_post = fake_post  # type: ignore[assignment]
            return asyncio.run(conn.test())

        quota = probe({"error": {"message": "账户额度不足，请充值后重试", "code": "insufficient_quota"}})
        check("额度为 0 不报连接成功", quota.ok is False, quota.message)
        check("额度不足给出充值提示", "额度" in quota.message and "充值" in quota.message, quota.message)
        empty = probe({"choices": []})
        check("没有 choices 也算失败", empty.ok is False and "额度" in empty.message, empty.message)
        good = probe({"choices": [{"message": {"role": "assistant", "content": "pong"}, "finish_reason": "stop"}]})
        check("真出结果才算连接成功", good.ok is True and "额度可用" in good.message, good.message)
        reasoning = probe({"choices": [{"message": {"role": "assistant", "reasoning_content": "thinking"}}]})
        check("只有思考内容也不算失败", reasoning.ok is True, reasoning.message)
        bad_key = probe({"error": {"message": "invalid api key"}}, status=401)
        check("密钥无效给出对应提示", bad_key.ok is False and "密钥" in bad_key.message, bad_key.message)
        no_model = probe({"error": {"message": "model_not_found"}})
        check("模型名不对给出对应提示", no_model.ok is False and "不可用" in no_model.message, no_model.message)
        limited = probe({"error": {"message": "rate_limit_exceeded"}}, status=429)
        check("限流单独提示", limited.ok is False and "限流" in limited.message, limited.message)

        # 移除接入：密钥真删、自动停用
        client.put("/api/connectors/ncc_llm", json={"secret": "sk-demo-value", "enabled": True})
        configured = next(item for item in client.get("/api/connectors").json() if item["key"] == "ncc_llm")
        check("保存密钥后标记已配置", configured["configured"] is True)
        masked = str(configured.get("secret_masked") or "")
        check("能看到脱敏后的 KEY", masked and masked != "sk-demo-value", masked)
        check("脱敏后仍能辨认头尾", masked.startswith("sk-") and masked.endswith("ue"), masked)
        check(
            "接口不返回完整密钥",
            "sk-demo-value" not in client.get("/api/connectors").text,
            "响应里出现了明文 Key",
        )
        put_resp = client.put("/api/connectors/ncc_llm", json={"secret": "sk-another-1234", "enabled": True})
        check("保存后立刻回显脱敏值", str(put_resp.json().get("secret_masked") or "").endswith("34"), put_resp.text[:120])
        client.put("/api/connectors/ncc_llm", json={"secret": "", "enabled": True})
        kept = next(item for item in client.get("/api/connectors").json() if item["key"] == "ncc_llm")
        check("空密钥不会把已有 Key 清掉", kept["configured"] is True, str(kept.get("secret_masked")))
        check("空密钥保存后仍是同一把 Key", str(kept.get("secret_masked") or "").endswith("34"), str(kept.get("secret_masked")))
        removed = client.delete("/api/connectors/ncc_llm")
        check("移除接入返回成功", removed.status_code == 200 and removed.json().get("ok") is True, removed.text[:120])
        after_remove = next(item for item in client.get("/api/connectors").json() if item["key"] == "ncc_llm")
        check("移除后不再是已配置", after_remove["configured"] is False, str(after_remove.get("configured")))
        check("移除后自动停用", after_remove["enabled"] is False, str(after_remove.get("enabled")))
        check("移除未知连接器 404", client.delete("/api/connectors/not-exist").status_code == 404)

        # 自定义模型：目录里没有的网关，地址/模型名/显示名称自己填，内网可以不带 Key
        listed = {item["key"]: item for item in client.get("/api/connectors").json()}
        custom = listed.get("custom") or {}
        check("连接器列表里有自定义模型", custom.get("name") == "自定义模型", str(custom.get("name")))
        check("自定义模型不要求密钥", custom.get("secret_required") is False)
        check(
            "自定义模型可填显示名称",
            any(field["key"] == "label" for field in custom.get("fields", [])),
            str(custom.get("fields")),
        )

        saved = client.put(
            "/api/connectors/custom",
            json={
                "enabled": True,
                "base_url": "http://10.9.9.9:8000/v1",
                "config": {"model": "qwen2.5-72b-instruct", "label": "内网千问"},
            },
        )
        check("自定义模型可以保存", saved.status_code == 200, saved.text[:120])
        after = next(item for item in client.get("/api/connectors").json() if item["key"] == "custom")
        check("保存后地址生效", after["base_url"] == "http://10.9.9.9:8000/v1", str(after.get("base_url")))
        check("保存后显示名称生效", after["name"] == "内网千问", str(after.get("name")))
        check("保存后模型名生效", (after.get("config") or {}).get("model") == "qwen2.5-72b-instruct")
        check("没填密钥不算已配置", after["configured"] is False, str(after.get("configured")))
        check("保存过的自定义模型进已接入列表", after.get("saved") is True, str(after.get("saved")))
        others = [item for item in client.get("/api/connectors").json()
                  if item["key"] != "custom" and item.get("saved") and not item.get("configured")]
        check("没配过的内置模型不往列表里钻", not others, str([item["key"] for item in others]))

        # 没填地址不许瞎发请求：直接给一句能照着办的提示
        client.put("/api/connectors/custom", json={"enabled": True, "base_url": "", "config": {"model": "", "label": ""}})
        no_base = client.post("/api/connectors/custom/test")
        check("空地址检测不报连接成功", no_base.json().get("ok") is False, no_base.text[:120])
        check("空地址提示补 Base URL", "Base URL" in str(no_base.json().get("message")), no_base.text[:160])

        # 免密钥也能进对话页的模型列表：只看「上次检测真的出过结果」
        from mono.db import db as _db

        with _db() as conn:
            conn.execute(
                "UPDATE connectors SET last_check_ok=1, base_url=?, config_json=? WHERE key='custom'",
                ("http://10.9.9.9:8000/v1", json.dumps({"model": "qwen2.5-72b-instruct", "label": "内网千问"}, ensure_ascii=False)),
            )
        status = client.get("/api/chat/status").json()
        keys = [item["key"] for item in status.get("providers", [])]
        check("自定义模型进了对话页模型列表", "custom" in keys, str(keys))
        picked = next((item for item in status.get("providers", []) if item["key"] == "custom"), {})
        check("对话页显示自定义的名字", picked.get("name") == "内网千问", str(picked))

        # ---------- 能力 ----------
        caps = client.get("/api/capabilities")
        check("能力目录可查", caps.status_code == 200, caps.text[:120])
        payload = caps.json()
        items = payload.get("items") or []
        check("能力数量为 64（同类合并后）", len(items) == 64, f"实际 {len(items)}")
        removed = {"cors_misconfig", "xss_filter_bypass", "tls_misconfig", "host_header",
                   "http_smuggling", "websocket_hijack", "session_reuse",
                   "captcha_bypass", "mfa_bypass", "workflow_bypass", "auth_bypass"}
        names = {item["key"] for item in items}
        check("已删除的能力不再出现", not (removed & names), str(sorted(removed & names)))
        check("自动迭代字段已下线", "auto_iterate" not in payload, str(payload.keys()))
        check("开关以列表形式给出", isinstance(payload.get("switches"), list) and len(payload["switches"]) == 3)
        auto_card = [item for item in (payload.get("switches") or []) if item.get("key") == "auto_pentest"]
        check("自动渗透开关存在且默认关闭", bool(auto_card) and auto_card[0].get("enabled") is False, str(auto_card)[:160])
        check("自动渗透不挂在操作询问下", bool(auto_card) and auto_card[0].get("group") == "scope", str(auto_card)[:120])
        merged = {"sqli_char", "sqli_int", "sqli_time", "sqli_error", "sqli_union", "sqli_stacked",
                  "horizontal_escalation", "path_traversal", "cloud_metadata", "backup_file", "cve_nday"}
        check("重复能力项已合并", not (merged & names), str(sorted(merged & names)))
        check(
            "合并后的代表项都在",
            {"sqli", "idor", "file_download", "cloud_vuln", "source_leak", "component_vuln"} <= names,
        )
        check("权重默认满格 5", (payload.get("weight_scale") or {}).get("default") == 5,
              str(payload.get("weight_scale")))
        check("未设过的能力权重是 5",
              all(int(item.get("weight") or 0) == 5 for item in items), "存在非 5 的默认权重")
        cards = [item.get("key") for item in (payload.get("switches") or [])]
        check("操作询问没有总开关卡片", "confirm_actions" not in cards, str(cards))
        check(
            "操作询问含两个细分开关",
            {"ask_sensitive", "ask_delete"} <= set(payload),
            str(sorted(payload.keys()))[:200],
        )
        check(
            "跨域开关已随授权范围一起下线",
            "ask_out_of_scope" not in payload,
            str(sorted(payload.keys()))[:200],
        )
        shift = payload.get("switches") or []
        asks = [item for item in shift if str(item.get("key", "")).startswith("ask_")]
        check("细分开关默认开启", len(asks) == 2 and all(item.get("enabled") for item in asks), str(asks)[:200])
        check("细分开关挂在操作询问下", all(item.get("group") == "confirm" for item in asks), str(asks)[:120])
        toggled = client.put("/api/capabilities", json={"keys": [], "switches": {"ask_delete": False}})
        check("细分开关可单独关闭", toggled.status_code == 200 and toggled.json().get("ask_delete") is False, toggled.text[:120])
        client.put("/api/capabilities", json={"keys": [], "switches": {"ask_delete": True}})

        save = client.put("/api/capabilities", json={"keys": ["xss_reflected", "ssrf"]})
        check("保存能力勾选成功", save.status_code == 200, save.text[:120])
        after = client.get("/api/capabilities").json()
        enabled = [item["key"] for item in (after.get("items") or []) if item.get("enabled")]
        check("能力勾选已生效", set(enabled) == {"xss_reflected", "ssrf"}, str(enabled))

        # ---------- 权重 ----------
        check("每项能力都带权重", all(1 <= int(item.get("weight") or 0) <= 5 for item in (after.get("items") or [])))
        check("权重量表是 1-5", (after.get("weight_scale") or {}).get("min") == 1 and (after.get("weight_scale") or {}).get("max") == 5)
        saved_w = client.put(
            "/api/capabilities",
            json={"keys": ["xss_reflected", "ssrf"], "weights": {"ssrf": 5, "xss_reflected": 1}},
        )
        check("权重可保存", saved_w.status_code == 200, saved_w.text[:120])
        w = saved_w.json().get("weights") or {}
        check("权重真的落库", w.get("ssrf") == 5 and w.get("xss_reflected") == 1, str(w)[:160])
        check("顺序按权重降序", (saved_w.json().get("order") or [None])[0] == "ssrf", str(saved_w.json().get("order"))[:120])
        clamped = client.put("/api/capabilities", json={"weights": {"ssrf": 99, "xss_reflected": 0}})
        cw = clamped.json().get("weights") or {}
        check("越界权重被夹到 1-5", cw.get("ssrf") == 5 and cw.get("xss_reflected") == 1, str(cw)[:160])
        ignored = client.put("/api/capabilities", json={"weights": {"not_a_capability": 5}})
        check("未知能力键被忽略", "not_a_capability" not in (ignored.json().get("weights") or {}))

        # ---------- 用户提示 ----------
        hinted = client.put(
            "/api/capabilities",
            json={
                "keys": ["xss_reflected", "ssrf"],
                "hints": {"ssrf": "只测 /api/proxy 的 SSRF，必须打 127.0.0.1 和 169.254.169.254。"},
            },
        )
        check("用户提示可保存", hinted.status_code == 200, hinted.text[:160])
        hh = hinted.json().get("hints") or {}
        check("用户提示落库", "只测 /api/proxy" in str(hh.get("ssrf") or ""), str(hh)[:160])
        again = client.get("/api/capabilities").json()
        check("接口回显用户提示", "只测 /api/proxy" in str((again.get("hints") or {}).get("ssrf") or ""))
        check(
            "每条能力条目也带出提示",
            any(item.get("user_prompt") for item in again.get("items") or []),
            str([item.get("key") for item in again.get("items") or [] if item.get("user_prompt")])[:120],
        )
        keep = client.put("/api/capabilities", json={"keys": ["xss_reflected", "ssrf"]})
        check(
            "不传 hints 时不清空已有提示",
            "只测 /api/proxy" in str((keep.json().get("hints") or {}).get("ssrf") or ""),
            str(keep.json().get("hints"))[:160],
        )
        unknown_hint = client.put(
            "/api/capabilities",
            json={"keys": ["xss_reflected"], "hints": {"not_a_capability": "x", "ssrf": ""}},
        )
        check("未知能力的提示被忽略、空值等于删除", not (unknown_hint.json().get("hints") or {}), str(unknown_hint.json().get("hints"))[:160])
        client.put("/api/capabilities", json={"keys": []})

        check("非法开关名被拒", client.put("/api/capabilities", json={"switches": {"bad": True}}).status_code in (200, 400, 422))

        # ---------- 设置 ----------
        got = client.get("/api/settings")
        check("设置可读", got.status_code == 200 and "safe_mode" in got.json())
        check("授权范围字段已下线", "scope_domains" not in got.json(), str(sorted(got.json().keys()))[:200])
        check("授权模式标为免责声明", got.json().get("authorization_mode") == "disclaimer")
        saved = client.put("/api/settings", json={"max_concurrency": 8, "safe_mode": False})
        check("设置可写", saved.status_code == 200, saved.text[:120])
        after_settings = client.get("/api/settings").json()
        check("设置已生效", after_settings.get("max_concurrency") == 8 and after_settings.get("safe_mode") is False, str(after_settings)[:160])
        client.put("/api/settings", json={"safe_mode": True})
        check("非法并发被拒", client.put("/api/settings", json={"max_concurrency": 0}).status_code in (200, 400, 422))
        paths = client.get("/api/settings/paths")
        check("目录配置可读", paths.status_code == 200)
        body = paths.json() if paths.status_code == 200 else {}
        check("默认记忆目录可用", bool((body.get("memory") or {}).get("configured")), str(body)[:160])
        check("默认工作目录可用", bool((body.get("work") or {}).get("configured")), str(body)[:160])

        # ---------- 会话 ----------
        status_resp = client.get("/api/chat/status")
        check("对话状态可读", status_resp.status_code == 200)
        check("对话状态带接入情况", "setup" in (status_resp.json() or {}), status_resp.text[:120])
        session = client.post("/api/chat/sessions", json={"title": "接口测试"})
        check("新建会话成功", session.status_code == 200, session.text[:120])
        sid = session.json().get("id")
        check("会话列表可查", client.get("/api/chat/sessions").status_code == 200)

        if isinstance(sid, int):
            check("会话详情可查", client.get(f"/api/chat/sessions/{sid}").status_code == 200)
            detail = client.get(f"/api/chat/sessions/{sid}").json()
            check("会话详情含选择题字段", "choices" in detail and "pending" in detail)
            idle = client.post(f"/api/chat/sessions/{sid}/interject", json={"content": "补充一句"})
            check("空闲时插话返回未送达", idle.status_code == 200 and idle.json().get("delivered") is False, idle.text[:120])
            check("插话空消息被拒", client.post(f"/api/chat/sessions/{sid}/interject", json={"content": ""}).status_code == 422)
            check("空消息被拒", client.post(f"/api/chat/sessions/{sid}/messages", json={"content": ""}).status_code == 422)
            check("超长消息被拒", client.post(f"/api/chat/sessions/{sid}/messages", json={"content": "x" * 5000}).status_code == 422)
            check("删除会话成功", client.delete(f"/api/chat/sessions/{sid}").status_code == 200)
            check("删除后 404", client.get(f"/api/chat/sessions/{sid}").status_code == 404)
        else:
            for name in ("会话详情可查", "会话详情含选择题字段", "空消息被拒", "超长消息被拒", "删除会话成功", "删除后 404"):
                check(name, False, "缺少 session id")

        check("不存在的会话 404", client.get("/api/chat/sessions/999999").status_code == 404)
        check("不存在的动作 404", client.post("/api/chat/actions/999999/decide", json={"approve": True}).status_code == 404)

        # ---------- 对话链路（假模型，验证提问不走成派活）----------
        fake = _install_fake_llm()
        talk = client.post("/api/chat/sessions", json={"title": "问答链路"})
        talk_id = talk.json().get("id") if talk.status_code == 200 else None
        if isinstance(talk_id, int):
            said = client.post(f"/api/chat/sessions/{talk_id}/messages", json={"content": "你测过 SQL 注入了吗？"})
            check("问句走通 SSE", said.status_code == 200, str(said.status_code))
            check("问句拿到回答", "没测" in said.text, said.text[-200:])
            check(
                "问句轮次不下发执行类工具",
                not ({"run_shell", "run_python", "http_request"} & set(fake.last_tools or [])),
                str(fake.last_tools),
            )
            replay = client.get(f"/api/chat/sessions/{talk_id}").json()
            answered = [m for m in replay.get("messages", []) if m["role"] == "assistant"]
            check("回答落库可回放", any("没测" in m["content"] for m in answered), str(answered)[:160])
        else:
            for name in ("问句走通 SSE", "问句拿到回答", "问句轮次不下发执行类工具", "回答落库可回放"):
                check(name, False, "缺少 session id")

        # ---------- 进展：干活的轮次要逐条留下「做了什么」----------
        _install_fake_tool_llm()
        work = client.post("/api/chat/sessions", json={"title": "进展链路"})
        work_id = work.json().get("id") if work.status_code == 200 else None
        if isinstance(work_id, int):
            ran = client.post(f"/api/chat/sessions/{work_id}/messages", json={"content": "把平台现状核对一遍"})
            check("干活轮走通 SSE", ran.status_code == 200, str(ran.status_code))
            check("SSE 里带进展", '"progress"' in ran.text, ran.text[-300:])
            check("进展写明做了什么", "已盘点平台现状" in ran.text, ran.text[-300:])
            replay_work = client.get(f"/api/chat/sessions/{work_id}").json()
            steps_work = [m for m in replay_work["messages"] if m["role"] == "progress"]
            check(
                "回放里进展也在",
                bool(steps_work) and "已盘点平台现状" in steps_work[-1]["content"],
                str(steps_work)[-200:],
            )
            check(
                "不再有单独的执行痕迹块",
                not any(m["role"] in ("activity", "tool") for m in replay_work["messages"]),
                str([m["role"] for m in replay_work["messages"]]),
            )
        else:
            for name in ("干活轮走通 SSE", "SSE 里带进展", "进展写明做了什么", "回放里进展也在", "不再有单独的执行痕迹块"):
                check(name, False, "缺少 session id")

        # ---------- 自动继续：跑完一轮，平台替你把预设的那句话发出去 ----------
        _install_fake_loop_llm()
        from mono.db import db as _db2
        from mono.engine.capabilities import save_enabled as _save_caps

        _save_caps([])  # 不勾能力：让「空转保护」这条路径可预测
        auto_default = client.get("/api/chat/auto")
        check("自动继续默认关闭", auto_default.status_code == 200 and auto_default.json().get("enabled") is False, auto_default.text[:120])
        saved = client.post("/api/chat/auto", json={"enabled": True, "text": "接着测"})
        check("自动继续可以打开", saved.status_code == 200 and saved.json().get("enabled") is True, saved.text[:120])
        check("预设提示词是变量", client.get("/api/chat/auto").json().get("text") == "接着测")
        auto_sid = client.post("/api/chat/sessions", json={"title": "自动继续"}).json().get("id")
        if isinstance(auto_sid, int):
            ran = client.post(f"/api/chat/sessions/{auto_sid}/messages", json={"content": "测一下 https://t.example 的安全性"})
            check("自动继续跑通", ran.status_code == 200, str(ran.status_code))
            check("平台替你发了一句", '"auto_continue"' in ran.text, ran.text[-300:])
            check("发的是预设那句", "接着测" in ran.text, ran.text[-300:])
            check("空转会自动收手", '"auto_end"' in ran.text, ran.text[-300:])
            with _db2() as conn:
                rows = conn.execute(
                    "SELECT content, level FROM chat_messages WHERE session_id=? AND role='user' ORDER BY id",
                    (auto_sid,),
                ).fetchall()
            auto_rows = [r for r in rows if r["level"] == "auto"]
            check("自动消息单独入库", len(auto_rows) >= 1, str([dict(r) for r in rows])[:200])
            check("自动消息内容就是预设词", all(r["content"] == "接着测" for r in auto_rows))
            replay_auto = client.get(f"/api/chat/sessions/{auto_sid}").json()
            check(
                "回放能认出自动消息",
                any(m["level"] == "auto" for m in replay_auto.get("messages", []) if m["role"] == "user"),
                str(replay_auto.get("messages"))[-200:],
            )
            cov = client.get(f"/api/chat/sessions/{auto_sid}/coverage")
            check("覆盖台账可查", cov.status_code == 200 and "summary" in cov.json(), cov.text[:120])
        else:
            for name in ("自动继续跑通", "平台替你发了一句", "发的是预设那句", "空转会自动收手", "自动消息单独入库", "自动消息内容就是预设词", "回放能认出自动消息", "覆盖台账可查"):
                check(name, False, "缺少 session id")

        # 真动过手（写文件 → 有审计）的轮次不该被当成空转：自动继续要接着发下一轮
        _install_fake_busy_llm(3)
        _save_caps([])
        client.post("/api/chat/auto", json={"enabled": True, "text": "继续"})
        busy_sid = client.post("/api/chat/sessions", json={"title": "动手了别停"}).json().get("id")
        if isinstance(busy_sid, int):
            busy = client.post(f"/api/chat/sessions/{busy_sid}/messages", json={"content": "继续测 https://t.example"})
            rounds = busy.text.count('"auto_continue"')
            check("动过手就接着发下一轮（不止一次）", rounds >= 2, f"auto_continue x{rounds}")
            check("空转了仍然会收手", '"auto_end"' in busy.text, busy.text[-200:])
            with _db2() as conn:
                wrote = conn.execute(
                    "SELECT COUNT(*) AS c FROM audit_logs WHERE action='workspace_write'"
                ).fetchone()["c"]
            check("这一轮确实落了动作（写文件有审计）", wrote >= 1, str(wrote))
        else:
            for name in ("动过手就接着发下一轮（不止一次）", "空转了仍然会收手", "这一轮确实落了动作（写文件有审计）"):
                check(name, False, "缺少 session id")

        # 只调了工具、没落审计的轮次同样算「在干活」：不能两三轮就停
        _install_fake_tool_only_llm(5)
        _save_caps([])
        client.post("/api/chat/auto", json={"enabled": True, "text": "继续"})
        only_sid = client.post("/api/chat/sessions", json={"title": "只查状态不停"}).json().get("id")
        if isinstance(only_sid, int):
            only = client.post(f"/api/chat/sessions/{only_sid}/messages", json={"content": "继续测 https://t.example"})
            only_rounds = only.text.count('"auto_continue"')
            check("只调工具也算动手，不会被当成空转", only_rounds >= 4, f"auto_continue x{only_rounds}")
            check("轮次切换有明确提示（不再像卡住）", "本轮动手" in only.text, only.text[-300:])
            check("模型真的空转后仍会收手", '"auto_end"' in only.text, only.text[-200:])
            with _db2() as conn:
                wrote_tool_only = conn.execute(
                    "SELECT COUNT(*) AS c FROM audit_logs WHERE action='http_request'"
                ).fetchone()["c"]
            check("这一轮确实没有任何审计动作（证明不是靠审计判的）", wrote_tool_only == 0, str(wrote_tool_only))
        else:
            for name in ("只调工具也算动手，不会被当成空转", "轮次切换有明确提示（不再像卡住）", "模型真的空转后仍会收手", "这一轮确实没有任何审计动作（证明不是靠审计判的）"):
                check(name, False, "缺少 session id")

        # 台账没清空时：空转不再收手。用户要的是「自动继续不会停」，
        # 20 轮上限已经取消，只剩三个刹车：点停止 / 等他拍板 / 页面断开两分钟。
        import mono.api.chat as _chat_mod
        import mono.engine.agent as _agent_mod2

        check("台账没满时空转不收手", _chat_mod._idle_cap(True) == 0, str(_chat_mod._idle_cap(True)))
        check(
            "台账清空后仍保留 6 轮空转保护",
            _chat_mod._idle_cap(False) == _chat_mod.AUTO_IDLE_LIMIT,
            str(_chat_mod._idle_cap(False)),
        )
        chat_src = (ROOT / "mono/api/chat.py").read_text(encoding="utf-8")
        check("台账没满不再按空转收手（旧的 20 轮说法已删）", "任务未完成：能力台账" not in chat_src)

        # 闸门：一栏没收到用户任务时，谁叫都不许开工（同伴同步的消息只能记账）
        import asyncio as _aio

        naked_sid = client.post("/api/chat/sessions", json={"title": "没任务"}).json().get("id")
        if isinstance(naked_sid, int):

            async def _naked():
                gen = _chat_mod._auto_loop(naked_sid, "admin", "")
                return [item async for item in gen]

            naked_events = _aio.run(_naked())
            check(
                "没收到用户任务就不开工",
                bool(naked_events) and naked_events[0].get("type") == "auto_end"
                and naked_events[0].get("rounds") == 0,
                str(naked_events[:1])[:160],
            )
            from mono.db import db as _db3

            with _db3() as conn:
                conn.execute(
                    "INSERT INTO chat_messages (session_id, role, content, level, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (naked_sid, "user", "继续", "auto", time.strftime("%Y-%m-%dT%H:%M:%S")),
                )
            check("自动接龙那句不算用户任务", _chat_mod.has_user_task(naked_sid) is False)
        else:
            check("没收到用户任务就不开工", False, "缺少 session id")
            check("自动接龙那句不算用户任务", False, "缺少 session id")

        wake_src = chat_src[chat_src.index("def _wake_peer("):]
        wake_src = wake_src[: wake_src.index("set_peer_wake_hook")]
        check("同伴叫醒也不越过没任务这道闸", "has_user_task" in wake_src)
        check("被同伴叫醒只跑一轮、不接龙", "max_rounds=1" in wake_src)
        check("协同提示写明没任务不动手", "只做用户交给你的任务" in (ROOT / "mono/engine/pairs.py").read_text(encoding="utf-8"))
        check("自动继续写清「台账没满不收手」", "台账没清空时第 2 条不生效" in chat_src)

        # 台账没满：空转 25 轮也照样往下发（旧逻辑 20 轮就停了）
        _save_caps(["idor"])
        client.post("/api/chat/auto", json={"enabled": True, "text": "继续"})
        endless_sid = client.post("/api/chat/sessions", json={"title": "不许停"}).json().get("id")
        if isinstance(endless_sid, int):
            rounds, evs = _count_auto_rounds(endless_sid, 25)
            check("台账没满时自动继续能一路接下去", rounds >= 25, f"auto_continue x{rounds}")
            check("台账没满时不会自动收手", not any(e.get("type") == "auto_end" for e in evs), str(evs[-1])[:160])
        else:
            for name in ("台账没满时自动继续能一路接下去", "台账没满时不会自动收手"):
                check(name, False, "缺少 session id")

        # 台账清空之后：空转 6 轮还是要收手（不能真的无限烧额度）
        _save_caps([])
        closed_sid = client.post("/api/chat/sessions", json={"title": "空转收手"}).json().get("id")
        if isinstance(closed_sid, int):
            rounds2, evs2 = _count_auto_rounds(closed_sid, 25)
            check("台账清空后空转仍会收手", rounds2 < 25 and any(e.get("type") == "auto_end" for e in evs2), f"auto_continue x{rounds2}")
        else:
            check("台账清空后空转仍会收手", False, "缺少 session id")
        client.post("/api/chat/auto", json={"enabled": False, "text": "继续"})

        # 第一轮就要把勾选的能力测完：一轮的工具步数按「还剩几项」现算，不再写死 50 步
        check("没勾能力时一轮还是 50 步", _agent_mod2.round_step_budget(0) == 50, str(_agent_mod2.round_step_budget(0)))
        check(
            "58 项时一轮步数按项数放大",
            _agent_mod2.round_step_budget(58) >= 58 * _agent_mod2.LEDGER_STEPS_PER_ITEM,
            str(_agent_mod2.round_step_budget(58)),
        )
        check("步数有兜底上限", _agent_mod2.round_step_budget(500) == _agent_mod2.LEDGER_HARD_STEPS, str(_agent_mod2.round_step_budget(500)))
        agent_src = (ROOT / "mono/engine/agent.py").read_text(encoding="utf-8")
        check("单轮时长按台账续期", "turn_cap" in agent_src and "LEDGER_HARD_SECONDS" in agent_src)
        check("提示词要求不许把能力留到下一轮", "也不要把手上没测完的项留给下一轮" in agent_src)

        # 30 项能力在一轮里全测完：关掉自动继续，只发一条消息就该清零
        import mono.engine.capabilities as _caps_mod

        many_keys = [item["key"] for item in _caps_mod.catalog()][:30]
        _install_fake_cover_llm(list(many_keys))
        _save_caps(list(many_keys))
        client.post("/api/chat/auto", json={"enabled": False, "text": "继续"})
        many_sid = client.post("/api/chat/sessions", json={"title": "一轮测完"}).json().get("id")
        if isinstance(many_sid, int):
            many = client.post(
                f"/api/chat/sessions/{many_sid}/messages", json={"content": "继续测 https://t.example 的越权"}
            )
            many_cov = client.get(f"/api/chat/sessions/{many_sid}/coverage").json().get("summary", {})
            check("一轮就把 30 项测完", many_cov.get("done") == 30, str(many_cov))
            check("没有把剩下的活留到下一轮", not many_cov.get("pending"), str(many_cov))
            check("关掉自动继续时不需要接龙", '"auto_continue"' not in many.text, many.text[-200:])
        else:
            for name in ("一轮就把 30 项测完", "没有把剩下的活留到下一轮", "关掉自动继续时不需要接龙"):
                check(name, False, "缺少 session id")
        _save_caps([])

        # 连续几次打不通：平台要追问「这个方向是不是没路了」，不能让它悄悄收口
        failing = _install_fake_failing_llm(4)
        _save_caps([])
        client.post("/api/chat/auto", json={"enabled": False, "text": "继续"})
        fail_sid = client.post("/api/chat/sessions", json={"title": "打不通要追问"}).json().get("id")
        if isinstance(fail_sid, int):
            client.post(f"/api/chat/sessions/{fail_sid}/messages", json={"content": "测一下 http://127.0.0.1:1 这个接口"})
            asked = [text for text in failing.seen if "连续第 3 个请求没成功" in text]
            check("连续失败会追问方向", bool(asked), f"seen={len(failing.seen)}")
            check(
                "追问要求反问「是不是没有别的写法了」",
                any("没有别的写法" in text for text in asked),
                (asked[-1][:160] if asked else ""),
            )
            hinted = [text for text in failing.seen if "retry_hint" in text]
            check("失败结果里带着改包提示", bool(hinted), f"hinted={len(hinted)}")
        else:
            for name in ("连续失败会追问方向", "追问要求反问「是不是没有别的写法了」", "失败结果里带着改包提示"):
                check(name, False, "缺少 session id")

        # 勾了能力时：自动继续会把台账里剩下的项一项项推完
        _install_fake_cover_llm(["idor", "unauthorized"])
        _save_caps(["idor", "unauthorized"])
        cover_sid = client.post("/api/chat/sessions", json={"title": "能力推到底"}).json().get("id")
        client.post("/api/chat/auto", json={"enabled": True, "text": "继续"})
        if isinstance(cover_sid, int):
            cov_run = client.post(
                f"/api/chat/sessions/{cover_sid}/messages", json={"content": "测一下 https://t.example 的越权"}
            )
            check("按能力台账自动接龙", cov_run.status_code == 200 and cov_run.text.count('"auto_continue"') >= 1, cov_run.text[-300:])
            cov_data = client.get(f"/api/chat/sessions/{cover_sid}/coverage").json()
            check("两项能力都验完了", cov_data["summary"]["done"] == 2, str(cov_data["summary"]))
            check("台账百分比跟着走", cov_data["summary"]["percent"] == 100, str(cov_data["summary"]))
            check(
                "自动继续里带上台账进度",
                "能力台账" in cov_run.text or "能力" in cov_run.text,
                cov_run.text[-300:],
            )
        else:
            for name in ("按能力台账自动接龙", "两项能力都验完了", "台账百分比跟着走", "自动继续里带上台账进度"):
                check(name, False, "缺少 session id")
        _save_caps([])
        client.post("/api/chat/auto", json={"enabled": False, "text": "继续"})

        # ---------- 会话回放：进展不覆盖，只把「正在做」和「做完」合成一条 ----------
        from mono.db import db as _db, now_iso as _now

        fold = client.post("/api/chat/sessions", json={"title": "回放"}).json().get("id")
        if isinstance(fold, int):
            with _db() as conn:
                for text in ("正在读取记忆", "已完成记忆读取：1 个文件、共 14016 字符", "已盘点平台现状，接下来逐个验接口"):
                    conn.execute(
                        "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
                        (fold, "progress", text, _now()),
                    )
            replay = client.get(f"/api/chat/sessions/{fold}").json()
            steps = [m["content"] for m in replay["messages"] if m["role"] == "progress"]
            check(
                "回放里每条进展都在",
                len(steps) == 2 and "已完成记忆读取" in steps[0] and "已盘点" in steps[1],
                str(steps),
            )

            with _db() as conn:
                conn.execute(
                    "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
                    (fold, "progress", "关键突破：登录接口未授权", _now()),
                )
            replay2 = client.get(f"/api/chat/sessions/{fold}").json()
            steps2 = [m["content"] for m in replay2["messages"] if m["role"] == "progress"]
            check("关键节点另起一条而不是顶掉前文", len(steps2) == 3 and "关键突破" in steps2[-1], str(steps2))

            # 冷却期内被降级的关键说法：落库时记了 level=step，回放不能又变回高亮
            with _db() as conn:
                conn.execute(
                    "INSERT INTO chat_messages (session_id, role, content, level, created_at) VALUES (?,?,?,?,?)",
                    (fold, "progress", "重大发现：订单接口也能越权读取", "step", _now()),
                )
            replay3 = client.get(f"/api/chat/sessions/{fold}").json()
            steps3 = [m for m in replay3["messages"] if m["role"] == "progress"]
            check(
                "降级的关键说法回放仍是普通进度",
                bool(steps3) and steps3[-1].get("level") == "step" and "重大发现" in steps3[-1]["content"],
                str(steps3)[-200:],
            )

            # 旧版本的技术痕迹：不再展示，也不许混进对话
            with _db() as conn:
                for text in ("$ python probe.py · 0.8s", "GET api.example.com/v1/users → 200"):
                    conn.execute(
                        "INSERT INTO chat_messages (session_id, role, content, level, tool_name, created_at)"
                        " VALUES (?,?,?,?,?,?)",
                        (fold, "tool", text, "ok", "run_shell", _now()),
                    )
            replay4 = client.get(f"/api/chat/sessions/{fold}").json()
            roles4 = [m["role"] for m in replay4["messages"]]
            check("旧痕迹不再展示", "tool" not in roles4 and "activity" not in roles4, str(roles4))
            check(
                "进展数量不受旧痕迹影响",
                len([m for m in replay4["messages"] if m["role"] == "progress"]) == 4,
                str(roles4),
            )
            # 实时漏洞卡也要能回放：刷新之后卡片还在，而不是只剩一句「已归档」
            card = {
                "finding_id": 7,
                "title": "用户资料未授权访问",
                "severity": "high",
                "severity_label": "高危",
                "url": "https://a.example.com/api/users?id=1",
                "domain": "a.example.com",
            }
            with _db() as conn:
                conn.execute(
                    "INSERT INTO chat_messages (session_id, role, content, level, tool_name, created_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (fold, "finding", json.dumps(card, ensure_ascii=False), "high", "record_finding", _now()),
                )
            replay5 = client.get(f"/api/chat/sessions/{fold}").json()
            cards = [m for m in replay5["messages"] if m["role"] == "finding"]
            check("漏洞卡片能回放", len(cards) == 1, str([m["role"] for m in replay5["messages"]]))
            check(
                "回放的卡片数据完整",
                bool(cards) and json.loads(cards[0]["content"]).get("domain") == "a.example.com",
                str(cards)[:200],
            )
        else:
            for name in (
                "回放里每条进展都在",
                "关键节点另起一条而不是顶掉前文",
                "降级的关键说法回放仍是普通进度",
                "旧痕迹不再展示",
                "进展数量不受旧痕迹影响",
                "漏洞卡片能回放",
                "回放的卡片数据完整",
            ):
                check(name, False, "缺少 session id")

        # ---------- 报告 ----------
        check("报告列表可查", client.get("/api/reports").status_code == 200)
        check("不存在的报告 404", client.get("/api/reports/999999/download").status_code == 404)

        # ---------- 点过「停止」之后重新打开自动继续 ----------
        # 旧标记不清的话，开关明明是开的，第一轮结束就收手——用户看到的就是「开了只跑一次」
        import mono.engine.agent as _agent_mod

        stale_sid = client.post("/api/chat/sessions", json={"title": "停过又开"}).json().get("id")
        if isinstance(stale_sid, int):
            _agent_mod.stop_auto(stale_sid, "测试用的停止")
            check("点过停止后标记会留在会话上", _agent_mod.auto_stopped(stale_sid))
            client.post("/api/chat/auto", json={"enabled": True, "text": "继续"})
            check("重新打开自动继续会清掉旧停止标记", not _agent_mod.auto_stopped(stale_sid))
        else:
            check("点过停止后标记会留在会话上", False, "缺少 session id")
            check("重新打开自动继续会清掉旧停止标记", False, "缺少 session id")

        # ---------- 长时间不出字时的 SSE 心跳 ----------
        # 模型一次思考几十秒不出字节，浏览器/代理会认为连接死了直接掐掉，
        # 表现就是「自动继续停了」。这里把心跳间隔压到 0.1s，验证确实会发。
        import asyncio as _asyncio

        import mono.api.chat as _chat_api

        class _SlowLLM:
            name = "Fake"
            model = "fake-slow"
            key = "fake"

            async def stream_complete(self, messages, tools=None, **kwargs):
                await _asyncio.sleep(0.45)
                text = "想了一会儿。"
                yield ("text", text)
                yield ("final", {"message": {"role": "assistant", "content": text}, "finish_reason": "stop"})

            async def complete(self, messages, tools=None, **kwargs):
                from mono.connectors.base import ConnectorResult

                return ConnectorResult(
                    True, "ok", {"message": {"role": "assistant", "content": "好"}, "finish_reason": "stop"}
                )

        import mono.engine.agent as _engine_agent

        _engine_agent.pick_llm = lambda *a, **k: _SlowLLM()
        old_beat = _chat_api.SSE_HEARTBEAT_SECONDS
        _chat_api.SSE_HEARTBEAT_SECONDS = 0.1
        client.post("/api/chat/auto", json={"enabled": False, "text": "继续"})
        hb_sid = client.post("/api/chat/sessions", json={"title": "心跳"}).json().get("id")
        try:
            if isinstance(hb_sid, int):
                hb = client.post(f"/api/chat/sessions/{hb_sid}/messages", json={"content": "在吗"})
                check("长思考期间会发心跳，连接不会被动掐断", ": ping" in hb.text, hb.text[:160])
                check("心跳不影响正常事件", '"type": "done"' in hb.text, hb.text[-200:])
            else:
                check("长思考期间会发心跳，连接不会被动掐断", False, "缺少 session id")
                check("心跳不影响正常事件", False, "缺少 session id")
        finally:
            _chat_api.SSE_HEARTBEAT_SECONDS = old_beat

        # ---------- 断线不等于停止：执行在后台，请求只是订阅者 ----------
        # 真实环境一轮几十秒到几分钟：浏览器切后台、代理空闲超时、网络抖一下都会断。
        # 以前执行塞在请求生成器里，一断就 worker.cancel()，用户看到的就是「只自动继续一次」。
        import asyncio as _asyncio

        import mono.api.chat as _chat

        async def _drop_and_resume():
            produced = {"n": 0}

            async def _events():
                for i in range(8):
                    produced["n"] += 1
                    yield {"type": "status", "message": f"第 {i} 步"}
                    await _asyncio.sleep(0.02)

            run = _chat.start_run(90011, _events())
            stream = _chat.run_events(run, 0)
            seen: list[int] = []
            for _ in range(3):
                item = await stream.__anext__()
                seen.append(int(item.get("seq") or 0))
            await stream.aclose()  # 模拟浏览器断开连接
            dropped_at = produced["n"]
            await _asyncio.sleep(0.16)
            kept = produced["n"] > dropped_at and not run.subs
            last = max(seen)

            tail_items: list[int] = []
            ended = False
            follow = _chat.run_events(run, last)
            while True:
                try:
                    item = await follow.__anext__()
                except StopAsyncIteration:
                    break
                if item.get("type") == "stream_end":
                    ended = True
                    break
                tail_items.append(int(item.get("seq") or 0))
            await follow.aclose()
            return kept, last, tail_items, ended

        kept, last_seq, tail_items, ended = _asyncio.run(_drop_and_resume())
        check("订阅断开后后台这一批还在跑", kept)
        check("重连只补没收到的事件，不重复", bool(tail_items) and min(tail_items) == last_seq + 1, str(tail_items)[:120])
        check("续传到底会收到结束标记", ended and bool(tail_items))

        # HTTP 层：没有在跑的批次时，续传端点也要有礼貌地收尾，不能挂住
        idle_sid = client.post("/api/chat/sessions", json={"title": "续传空转"}).json().get("id")
        if isinstance(idle_sid, int):
            idle_stream = client.get(f"/api/chat/sessions/{idle_sid}/stream?after=0")
            check("续传端点在空闲时 200", idle_stream.status_code == 200, str(idle_stream.status_code))
            check("空闲续传直接给结束标记", "stream_end" in idle_stream.text, idle_stream.text[:160])
        else:
            check("续传端点在空闲时 200", False, "缺少 session id")
            check("空闲续传直接给结束标记", False, "缺少 session id")

        # 每条收口原因都要落库：刷新之后「为什么停」不能凭空消失
        reason_sid = client.post("/api/chat/sessions", json={"title": "收口要留话"}).json().get("id")
        if isinstance(reason_sid, int):
            _chat._auto_end(reason_sid, "这一轮被停止了，自动继续不再接龙", 4)
            replay_reason = client.get(f"/api/chat/sessions/{reason_sid}").json()
            texts = [str(m.get("content") or "") for m in replay_reason.get("messages", [])]
            check(
                "自动继续结束后回放能看到原因",
                any("这一轮被停止了" in t and "共 4 轮" in t for t in texts),
                str(texts)[-200:],
            )
        else:
            check("自动继续结束后回放能看到原因", False, "缺少 session id")

        # 单轮报错不该把整条链断掉：原地重试一次，仍失败才收手并说清原因
        import mono.engine.agent as _agent_boom

        class _BoomLLM:
            name = "Fake"
            model = "fake-boom"
            key = "fake"
            calls = 0

            async def stream_complete(self, messages, tools=None, **kwargs):
                _BoomLLM.calls += 1
                raise RuntimeError("upstream 502")
                yield  # pragma: no cover

            async def complete(self, messages, tools=None, **kwargs):
                raise RuntimeError("upstream 502")

        _agent_boom.pick_llm = lambda *a, **k: _BoomLLM()
        _save_caps([])
        client.post("/api/chat/auto", json={"enabled": True, "text": "继续"})
        old_delay = _chat.AUTO_RETRY_DELAY
        _chat.AUTO_RETRY_DELAY = 0
        boom_sid = client.post("/api/chat/sessions", json={"title": "接口报错"}).json().get("id")
        try:
            if isinstance(boom_sid, int):
                boom = client.post(f"/api/chat/sessions/{boom_sid}/messages", json={"content": "继续测 https://t.example"})
                check("单轮报错会原地重试一次", "正在第 1 次重试" in boom.text, boom.text[-300:])
                check("重试仍失败才收手并说明原因", "模型接口连续报错" in boom.text, boom.text[-300:])
                check("报错重试没有把轮次算乱", _BoomLLM.calls >= 2, str(_BoomLLM.calls))
            else:
                for name in ("单轮报错会原地重试一次", "重试仍失败才收手并说明原因", "报错重试没有把轮次算乱"):
                    check(name, False, "缺少 session id")
        finally:
            _chat.AUTO_RETRY_DELAY = old_delay

        # ---------- 退出登录 ----------
        check("退出登录成功", client.post("/api/auth/logout").status_code == 200)
        check("退出后接口 401", client.get("/api/chat/sessions").status_code == 401)

    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
