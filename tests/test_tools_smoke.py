"""工具层冒烟测试：把模型能调用的每个工具都用最小参数打一遍，确认不异常、返回结构正常。

用法：
    python tests/test_tools_smoke.py
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-tools-")
WORK = Path(TMP) / "work"
WORK.mkdir(parents=True, exist_ok=True)
(WORK / "note.txt").write_text("hello", encoding="utf-8")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.db import db, init_db, set_settings  # noqa: E402
import mono.engine.agent as agent  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


async def call(name: str, args: dict | None = None, trusted: bool = False) -> dict:
    """trusted=True 等价于「用户在确认卡片上点了确认」，只有平台内部才这么调。"""
    try:
        return await agent.dispatch_tool(name, args or {}, "admin", trusted=trusted)
    except Exception as exc:  # 任何异常都算失败
        return {"_exception": f"{type(exc).__name__}: {exc}"}


async def main() -> int:
    init_db()
    set_settings({"work_dir": str(WORK), "memory_path": ""})

    # ---- 只读工具 ----
    overview = await call("platform_overview")
    check("platform_overview 正常", "_exception" not in overview and overview.get("ok") is True, str(overview)[:160])
    check("概览含连接器配置信息", "connectors_configured" in overview)

    assets = await call("list_assets", {"q": ""})
    check("list_assets 正常", assets.get("ok") is True and isinstance(assets.get("assets"), list))

    scans = await call("list_scans")
    check("list_scans 正常", scans.get("ok") is True)

    findings = await call("list_findings", {"limit": 10})
    check("list_findings 正常", findings.get("ok") is True)

    connectors = await call("list_connectors")
    check("list_connectors 正常", connectors.get("ok") is True and connectors.get("count", 0) > 0)

    # ---- 写操作 ----
    created = await call("create_asset", {"target": "https://demo.example.com", "name": "演示站"})
    check("create_asset 正常", created.get("ok") is True, str(created)[:160])
    asset_id = created.get("asset_id") or created.get("id")
    check("create_asset 返回 id", isinstance(asset_id, int))

    dup = await call("create_asset", {"target": "https://demo.example.com"})
    check("重复资产不抛异常", "_exception" not in dup, str(dup)[:120])

    bad = await call("create_asset", {"target": ""})
    check("空目标给出错误而不是异常", bad.get("ok") is False and "error" in bad, str(bad)[:120])

    # ---- 扫描：只验证参数校验，不真的发起网络扫描 ----
    # 授权范围已取消：任何域名都能直接建任务，不需要确认、也不留「越界」依据
    any_host = await call(
        "start_scan",
        {"targets": ["https://not-in-scope.invalid"], "mode": "passive"},
    )
    check("任意目标都能发起评估", any_host.get("ok") is True, str(any_host)[:160])
    with db() as conn:
        row = conn.execute("SELECT authorization_ref FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    check(
        "授权依据统一记为免责声明",
        "免责声明" in str(row["authorization_ref"] if row else ""),
        str(row)[:160],
    )

    auto_auth = await call("start_scan", {"targets": ["https://demo.example.com"], "mode": "passive"})
    check("不填编号也能发起评估", auto_auth.get("ok") is True, str(auto_auth)[:160])

    missing_scan = await call("get_scan", {"scan_id": 999999})
    check("不存在的扫描返回错误", missing_scan.get("ok") is False, str(missing_scan)[:120])

    cancel_missing = await call("cancel_scan", {"scan_id": 999999})
    check("取消不存在的任务返回错误", cancel_missing.get("ok") is False)

    # ---- 漏洞归档与状态流转 ----
    recorded = await call(
        "record_finding",
        {
            "url": "https://demo.example.com/login",
            "title": "反射型 XSS",
            "severity": "high",
            "description": "参数未转义",
            "request_packet": "GET /login?q=<script> HTTP/1.1",
            "response_packet": "HTTP/1.1 200 OK",
        },
    )
    check("record_finding 正常", recorded.get("ok") is True, str(recorded)[:160])
    finding_id = recorded.get("id") or recorded.get("finding_id")

    if isinstance(finding_id, int):
        updated = await call("update_finding_status", {"finding_id": finding_id, "status": "confirmed"})
        check("update_finding_status 正常", updated.get("ok") is True, str(updated)[:160])
        bad_status = await call("update_finding_status", {"finding_id": finding_id, "status": "nonsense"})
        check("非法状态被拒绝", bad_status.get("ok") is False)
    else:
        check("record_finding 返回漏洞 id", False, str(recorded)[:200])
        check("update_finding_status 正常", False, "缺少 finding_id")
        check("非法状态被拒绝", False, "缺少 finding_id")

    missing_finding = await call("update_finding_status", {"finding_id": 999999, "status": "fixed"})
    check("不存在的漏洞返回错误", missing_finding.get("ok") is False)

    # ---- 连接器检测 ----
    unknown = await call("test_connector", {"key": "not-a-connector"})
    check("未知连接器给出提示", unknown.get("ok") is False and "连接器" in str(unknown))

    unconfigured = await call("test_connector", {"key": "fofa"})
    check("未配置连接器不发网络请求", unconfigured.get("ok") is False and "尚未配置" in str(unconfigured))

    batch = await call("test_all_connectors", {"category": "recon"})
    check("批量检测接口可用", batch.get("ok") is True and "tested" in batch, str(batch)[:160])

    # ---- 工作目录文件工具 ----
    listed = await call("list_dir", {"path": ""})
    check("list_dir 正常", listed.get("ok") is True and listed.get("type") == "dir", str(listed)[:160])

    read = await call("read_file", {"path": "note.txt"})
    check("read_file 正常", read.get("ok") is True and "hello" in str(read.get("content")))

    escape = await call("read_file", {"path": "../../etc/passwd"})
    check("越界读取被拦下", escape.get("ok") is False, str(escape)[:120])

    written = await call("write_file", {"path": "out/result.txt", "content": "ok"})
    check("write_file 正常", written.get("ok") is True and (WORK / "out" / "result.txt").exists())

    no_path = await call("write_file", {"path": "", "content": "x"})
    check("空路径被拒绝", no_path.get("ok") is False)

    # ---- 命令执行 / 脚本 / 请求 ----
    shell = await call("run_shell", {"command": "echo smoke-ok"})
    check("run_shell 正常", shell.get("ok") is True and "smoke-ok" in str(shell.get("stdout")), str(shell)[:180])
    check("run_shell 带工作目录", bool(shell.get("cwd")), str(shell)[:120])

    shell_fail = await call("run_shell", {"command": "exit 7"})
    check("命令失败如实返回", shell_fail.get("ok") is False and shell_fail.get("exit_code") == 7, str(shell_fail)[:160])

    shell_block = await call("run_shell", {"command": "shutdown /s /t 0"})
    check("破坏性命令被拒", shell_block.get("ok") is False and "不可逆" in str(shell_block.get("error")), str(shell_block)[:160])

    python = await call("run_python", {"code": "import sys; print('py-ok', sys.version_info.major)"})
    check("run_python 正常", python.get("ok") is True and "py-ok" in str(python.get("stdout")), str(python)[:180])

    py_via_shell = await call("run_shell", {"command": "python -c \"print('shell-py')\""})
    check("shell 里能直接跑 python", py_via_shell.get("ok") is True and "shell-py" in str(py_via_shell.get("stdout")), str(py_via_shell)[:200])

    pipe = await call("run_shell", {"command": "echo pipe-ok > tmp.txt && type tmp.txt"})
    check("管道与重定向可用", pipe.get("ok") is True and "pipe-ok" in str(pipe.get("stdout")), str(pipe)[:200])

    python_bad = await call("run_python", {"code": "print(1/0)"})
    check("脚本异常带回 stderr", python_bad.get("ok") is False and "ZeroDivisionError" in str(python_bad.get("stderr")), str(python_bad)[:180])

    http_dead = await call(
        "http_request", {"url": "http://127.0.0.1:9/none", "timeout": 3}, trusted=True
    )
    check("请求失败不抛异常", http_dead.get("ok") is False and "error" in http_dead, str(http_dead)[:160])

    bad_method = await call(
        "http_request", {"url": "http://127.0.0.1:9/", "method": "NOPE"}, trusted=True
    )
    check("非法 method 被拒", bad_method.get("ok") is False and "method" in str(bad_method.get("error")), str(bad_method)[:160])

    no_url = await call("http_request", {"url": ""})
    check("空 URL 被拒", no_url.get("ok") is False)

    # ---- UA：默认就该是普通浏览器串，内置请求跟着平台设置走 ----
    from mono import db as _db
    from mono.config import DEFAULT_USER_AGENT
    from mono.engine import shell as _shell

    check("默认 UA 是 Chrome 浏览器串", DEFAULT_USER_AGENT.startswith("Mozilla/5.0") and "Chrome/124" in DEFAULT_USER_AGENT, DEFAULT_USER_AGENT[:80])
    check("设置项默认值同步", _db.DEFAULT_SETTINGS.get("user_agent") == DEFAULT_USER_AGENT, str(_db.DEFAULT_SETTINGS.get("user_agent"))[:80])
    check("内置请求用浏览器 UA", _shell._user_agent().startswith("Mozilla/5.0"), _shell._user_agent()[:80])

    # ---- 记忆：没配置时给出人话提示 ----
    no_memory = await call("read_memory", {})
    check("未配置记忆目录有提示", no_memory.get("ok") is False and "记忆目录" in str(no_memory.get("error")), str(no_memory)[:160])

    no_memory_search = await call("search_memory", {"keyword": "偏好"})
    check("未配置记忆检索有提示", no_memory_search.get("ok") is False and "记忆目录" in str(no_memory_search.get("error")), str(no_memory_search)[:160])

    # ---- 未注册工具 ----
    ghost = await call("does_not_exist")
    check("未知工具返回错误", ghost.get("ok") is False)

    # ---- 模型能力 ----
    caps = await call("list_capabilities")
    check("list_capabilities 正常", caps.get("ok") is True and "step_budget" in caps)

    # ---- 失败请求必须带「怎么改包」的提示 ----
    refused = await call("http_request", {"url": "http://127.0.0.1:1/probe", "method": "GET", "timeout": 5})
    check("连接失败也是失败（ok=False）", refused.get("ok") is False, str(refused)[:160])
    check("连接失败时给出改包/换连法提示", bool(refused.get("retry_hint")), str(refused)[:200])
    check("提示里要求反问「是不是已经试遍」", "试过" in str(refused.get("retry_hint")), str(refused.get("retry_hint"))[:120])

    hints = {
        404: "路径",
        401: "身份",
        403: "权限",
        422: "参数",
        500: "异常",
    }
    for code, word in hints.items():
        text = agent.retry_hint({"ok": False, "status": code})
        check(f"{code} 的提示对得上症状（含「{word}」）", word in text, text[:80])
    check("成功响应不附提示", agent.retry_hint({"ok": True, "status": 204}) == "")
    check("网络异常也附提示", agent.retry_hint({"ok": False, "error": "ConnectError"}) != "")

    # 用命令 / 脚本发包失败，同样要给「换写法再试」的提示
    shell_fail = await call("run_shell", {"command": "curl -s -m 2 http://127.0.0.1:1/x", "timeout": 5})
    check("命令里发包失败也带改包提示", bool(shell_fail.get("retry_hint")), str(shell_fail)[:160])
    shell_ok = await call("run_shell", {"command": "echo hi"})
    check("普通命令成功不附提示", not shell_ok.get("retry_hint"), str(shell_ok)[:120])

    prompt = agent.SYSTEM_PROMPT
    check("系统提示词有「失败必须先改包」硬性规则", "请求失败不等于这条路走不通" in prompt)
    check("规则要求时刻反问自己", "这个方向还有没有别的写法" in prompt)
    check("规则点名平台会给 retry_hint", "retry_hint" in prompt)
    check("规则要求写清试过哪些变体", "试过哪些变体" in prompt)

    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
