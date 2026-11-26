"""模型记忆空间的回归测试。

覆盖五件事：
1. 默认记忆跟「目录配置」走，不会凭空多出一份；
2. 新建/改名/删除：目录真的建出来，重名被拦，删配置不删文件；
3. 两栏隔离：左栏读自己的那份，右栏读默认那份，谁也不串味；
4. 接口层：列表、增删改、文件清单；
5. 发现互通：一条发现只入库一次，对方下一轮读得到。

用法：
    python tests/test_memory_spaces.py
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-mem-")
os.environ["MONO_DATA_DIR"] = TMP
os.environ["K7so_ADMIN_PASSWORD"] = "mem-test-pass"
sys.path.insert(0, str(ROOT))

from fastapi import HTTPException  # noqa: E402

from mono.api import memory as memory_api  # noqa: E402
from mono.db import db, init_db, set_settings  # noqa: E402
from mono.engine import memory_spaces, pairs, workspace  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


def read_as(session_id: int, limit: int = 400) -> str:
    """以某条会话的身份读记忆：就是模型调用 read_memory 时看到的东西。"""
    token = workspace.bind_tool_session(session_id)
    try:
        return workspace.read_memory(limit) or ""
    finally:
        workspace.TOOL_SESSION.reset(token)


init_db()
USER = {"u": "admin"}

# ---------------- 默认记忆 ----------------

default = memory_spaces.default_space()
check("默认记忆始终存在", default["id"] == 0 and default["name"] == "默认记忆")
check("默认记忆跟目录配置走", default["dir"] == memory_spaces.default_dir().resolve().as_posix()
      or default["dir"] == str(memory_spaces.default_dir()))

listed = memory_spaces.list_spaces("admin")
check("列表第一项是默认记忆", len(listed) >= 1 and listed[0]["id"] == 0)

# ---------------- 新建 / 重名 / 目录 ----------------

space_a = memory_spaces.create_space("admin", "客户A 白盒", note="只放 A 家的接口清单")
check("新建后拿到 id", space_a["id"] > 0)
check("目录真的建出来了", Path(space_a["dir"]).is_dir())
check("默认落在 memory_spaces 下", "memory_spaces" in space_a["dir"].replace("\\", "/"))
check("没配目录也能用", Path(space_a["dir"]).parent.is_dir())

try:
    memory_spaces.create_space("admin", "客户A 白盒")
    dup_blocked = False
except ValueError as exc:
    dup_blocked = "同名" in str(exc)
check("重名被拦", dup_blocked)

space_b = memory_spaces.create_space("admin", "客户B 黑盒")
check("第二份也能建", space_b["id"] > space_a["id"])

# 往两份记忆里塞不同内容：模型读到的东西应该不一样
Path(space_a["dir"], "a-notes.md").write_text("A 家：只测登录与越权，不动生产数据。", encoding="utf-8")
Path(space_b["dir"], "b-notes.md").write_text("B 家：先跑子域收集，再打接口。", encoding="utf-8")

check("A 记忆读得到自己的偏好", "只测登录与越权" in "".join(p.read_text(encoding="utf-8") for p in Path(space_a["dir"]).glob("*.md")))
check("B 记忆读不到 A 的内容", "只测登录" not in "".join(p.read_text(encoding="utf-8") for p in Path(space_b["dir"]).glob("*.md")))

# ---------------- 两栏隔离 ----------------

pair = pairs.create_pair("admin", "隔离测试", "deepseek", "openai", str(Path(TMP) / "ws"))
pairs.set_memories(int(pair["id"]), memory_a=int(space_a["id"]), memory_b=int(space_b["id"]))
pair = pairs.get_pair(int(pair["id"]))
check("配对记住了两份记忆", int(pair["memory_a"]) == int(space_a["id"]) and int(pair["memory_b"]) == int(space_b["id"]))

side_a, side_b = int(pair["session_a"]), int(pair["session_b"])
text_a = read_as(side_a)
text_b = read_as(side_b)
check("左栏读自己那份", "只测登录与越权" in text_a)
check("右栏读自己那份", "先跑子域收集" in text_b)
check("左栏看不到右栏的记忆", "先跑子域收集" not in text_a)
check("右栏看不到左栏的记忆", "只测登录与越权" not in text_b)

check("会话能认出自己的记忆名", memory_spaces.label_for_session(side_a) == "客户A 白盒")
check("提示词里写明两份记忆不同",
      "客户A 白盒" in pairs.prompt_block(side_a) and "客户B 黑盒" in pairs.prompt_block(side_a))
check("提示词要求发现互通", "发现要互通" in pairs.prompt_block(side_a))

# 单会话（没有配对）用默认那份
plain = db()
with plain as conn:
    sid = conn.execute(
        "INSERT INTO chat_sessions (title, username, created_at, updated_at) VALUES (?,?,?,?)",
        ("单会话", "admin", "2026-01-01T00:00:00", "2026-01-01T00:00:00"),
    ).lastrowid
check("单会话走默认记忆", memory_spaces.space_id_for_session(int(sid)) == 0)
check("单会话没有自己的记忆目录", memory_spaces.path_for_session(int(sid)) is None)
token = workspace.bind_tool_session(int(sid))
check("单会话读到的是默认目录", workspace.memory_path() == memory_spaces.default_dir())
workspace.TOOL_SESSION.reset(token)

# ---------------- 发现互通 ----------------

note = pairs.note_finding(side_a, {"title": "订单接口越权", "severity": "高危", "url": "https://shop.example.com/api/order/1"})
check("发现会贴进协同对话", bool(note) and "[发现]" in note["content"])
check("发现状态直接是已投递", note["status"] == "delivered")
again = pairs.note_finding(side_a, {"title": "订单接口越权", "severity": "高危", "url": "https://shop.example.com/api/order/1"})
check("同一条发现不重复入库", again is None)

peer_notes = pairs.take_pending(side_b)
check("对方下一轮读得到这条发现", any("订单接口越权" in item["content"] for item in peer_notes))
check("读过的会被标成已读", all(item["status"] in ("pending", "delivered") for item in peer_notes))
check("第二遍不再重复推送", not pairs.take_pending(side_b))

# ---------------- 改名 / 删除 ----------------

renamed = memory_spaces.update_space(int(space_b["id"]), "admin", name="客户B 黑盒（改）")
check("改名生效", renamed and renamed["name"] == "客户B 黑盒（改）")
check("改名不动目录", renamed["dir"] == space_b["dir"])

try:
    memory_spaces.update_space(0, "admin", name="想改默认")
    blocked = False
except ValueError as exc:
    blocked = "目录配置" in str(exc)
check("默认记忆不让在别处改名", blocked)

kept = Path(space_b["dir"], "b-notes.md")
removed = memory_spaces.delete_space(int(space_b["id"]), "admin")
check("删除记忆配置", removed is True)
check("删配置不删文件", kept.exists())
check("删掉的从列表消失", all(int(item["id"]) != int(space_b["id"]) for item in memory_spaces.list_spaces("admin")))
pair = pairs.get_pair(int(pair["id"]))
check("绑定到它的那一栏回落到默认", int(pair["memory_b"]) == 0)
check("删完右栏改读默认", "先跑子域收集" not in read_as(side_b))

# ---------------- 接口层 ----------------

data = asyncio.run(memory_api.list_spaces(USER))
check("接口列出记忆", any(item["id"] == 0 for item in data["spaces"]))
created = asyncio.run(memory_api.create_space(memory_api.SpaceIn(name="接口建的", note="x"), USER))
check("接口能新建", created.get("id", 0) > 0)
patched = asyncio.run(memory_api.patch_space(int(created["id"]), memory_api.SpacePatch(note="改备注"), USER))
check("接口能改备注", patched.get("note") == "改备注")
files = asyncio.run(memory_api.space_files(int(created["id"]), USER))
check("接口给文件清单", isinstance(files.get("files"), list) and files["space"]["id"] == int(created["id"]))
try:
    asyncio.run(memory_api.delete_space(0, USER))
    default_blocked = False
except HTTPException as exc:
    default_blocked = exc.status_code == 400
check("默认记忆删不掉", default_blocked)
check("接口能删除", asyncio.run(memory_api.delete_space(int(created["id"]), USER))["ok"] is True)

# ---------------- 配对接口 ----------------

from mono.api import chat as chat_api  # noqa: E402

detail = asyncio.run(chat_api.get_pair_detail(int(pair["id"]), USER))
check("配对详情带记忆 id", detail["memory"]["a"] == int(space_a["id"]))
check("配对详情带记忆名", detail["memory"]["names"]["a"] == "客户A 白盒")
check("配对详情给默认名", detail["memory"]["names"]["default"] == "默认记忆")

patched_pair = asyncio.run(
    chat_api.patch_pair(int(pair["id"]), chat_api.PairPatchIn(memory_b=int(space_a["id"])), USER)
)
check("接口能换某一栏的记忆", int(patched_pair["memory_b"]) == int(space_a["id"]))

try:
    asyncio.run(chat_api.patch_pair(int(pair["id"]), chat_api.PairPatchIn(memory_a=99999), USER))
    nonexistent_blocked = False
except HTTPException as exc:
    nonexistent_blocked = exc.status_code == 400
check("不存在的记忆被拦", nonexistent_blocked)

# ---------------- 界面 ----------------

html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
css = (ROOT / "mono/static/style.css").read_text(encoding="utf-8")
js = (ROOT / "mono/static/duo.js").read_text(encoding="utf-8")
appjs = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")

check("导航里有模型记忆", 'data-page="memory"' in html and "模型记忆" in html)
check("有记忆页容器", 'id="page-memory"' in html and 'id="memory-list"' in html)
check("两栏各有记忆下拉", 'id="duo-a-memory"' in html and 'id="duo-b-memory"' in html)
check("记忆下拉在栏头、挨着模型", html.index('id="duo-a-model"') < html.index('id="duo-a-memory"') < html.index('id="duo-a-state"'))
check("记忆卡片有样式", ".memory-grid" in css and ".memory-card" in css)
check("记忆下拉有样式", ".duo-memory" in css)
check("前端能拉记忆列表", "function duoFillMemories(" in js and "/api/memory/spaces" in js)
check("切换记忆会写回配对", "memory_a: value" in js and "memory_b: value" in js)
check("建配对时带上记忆", "memory_a: Number(" in js and "memory_b: Number(" in js)
check("记忆页有增删改", "function loadMemory(" in appjs and "/api/memory/spaces" in appjs)

# ---------------- 汇总 ----------------

shutil.rmtree(TMP, ignore_errors=True)
failed = [name for name, ok, _ in RESULTS if not ok]
print()
print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
if failed:
    raise SystemExit(1)
