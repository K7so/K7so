"""双模型协同的回归测试。

覆盖四件事：
1. 配对本身：一对会话、各自的车道、共享目录；
2. 两个模型之间的对话通道：留言、取件、预算；
3. 协同目录：进度自动落盘、同伴进度与目录变动能被读到；
4. 界面与接口：三栏布局的骨架、配对接口的校验、单会话列表不混进协同子会话。

用法：
    python tests/test_duo_pairs.py
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-duo-")
os.environ["MONO_DATA_DIR"] = TMP
os.environ["K7so_ADMIN_PASSWORD"] = "duo-test-pass"
sys.path.insert(0, str(ROOT))

from mono.db import db, init_db  # noqa: E402
from mono.engine import pairs, shared  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


init_db()
WS = Path(TMP) / "shared-ws"

# ---------------- 配对 ----------------

pair = pairs.create_pair("admin", "电商主站 双模型", "deepseek", "openai", str(WS))
check("配对建出来了", bool(pair.get("id")))
check("一对会话两条", int(pair["session_a"]) > 0 and int(pair["session_b"]) > 0)
check("两条会话不是同一条", pair["session_a"] != pair["session_b"])
check("记录了两个模型", pair["model_a"] == "deepseek" and pair["model_b"] == "openai")
check("共享目录被创建", WS.exists())
check("目录存的是绝对路径", Path(pair["workdir"]).is_absolute())

with db() as conn:
    rows = conn.execute(
        "SELECT id, pair_id, lane FROM chat_sessions WHERE id IN (?,?)",
        (pair["session_a"], pair["session_b"]),
    ).fetchall()
by_lane = {row["lane"]: int(row["pair_id"]) for row in rows}
check("两条会话都挂在同一个配对下", by_lane.get("a") == int(pair["id"]) and by_lane.get("b") == int(pair["id"]))
check("车道标记是 a / b", set(by_lane) == {"a", "b"})

check("按会话能反查配对", (pairs.pair_for_session(int(pair["session_a"])) or {}).get("id") == int(pair["id"]))
check("车道能查出来", pairs.lane_of_session(int(pair["session_b"])) == "b")
check("能拿到对方的会话", pairs.peer_session(pair, "a") == int(pair["session_b"]))
check("同伴车道对得上", pairs.peer_lane("a") == "b" and pairs.peer_lane("b") == "a")

listed = pairs.list_pairs("admin")
check("列表里能看到", len(listed) == 1 and listed[0]["title"] == "电商主站 双模型")
check("列表带了消息计数", "message_count" in listed[0] and "note_count" in listed[0])

# 只有一个模型配好时，两侧选同一个也能开两栏（两条会话，各跑各的上下文）
same = pairs.create_pair("admin", "同一个模型", "deepseek", "deepseek", str(Path(TMP) / "same-ws"))
check("两侧可以选同一个模型", same["model_a"] == "deepseek" and same["model_b"] == "deepseek")
check("按栏取模型", pairs.lane_model(same, "a") == "deepseek" and pairs.lane_model(same, "b") == "deepseek")
swapped = pairs.set_models(int(same["id"]), model_b="openai")
check("能单独换右侧模型", swapped["model_b"] == "openai" and swapped["model_a"] == "deepseek")
check("换模型不动会话", int(pairs.get_pair(int(same["id"]))["session_b"]) == int(same["session_b"]))
with db() as conn:
    lane_title = conn.execute("SELECT title FROM chat_sessions WHERE id=?", (int(same["session_b"]),)).fetchone()["title"]
check("会话标题跟着换模型", "openai" in str(lane_title))
with db() as conn:
    conn.execute("DELETE FROM chat_sessions WHERE id IN (?,?)", (int(same["session_a"]), int(same["session_b"])))
pairs.delete_pair(int(same["id"]))
check("临时配对删干净", pairs.get_pair(int(same["id"])) is None)

# ---------------- 共享目录 ----------------

check("会话拿到配对的工作目录", str(pairs.workdir_for_session(int(pair["session_a"]))) == pair["workdir"])

new_ws = Path(TMP) / "shared-ws-2"
pairs.set_workdir(int(pair["id"]), str(new_ws))
check("换目录后配对记录更新", str(pairs.get_pair(int(pair["id"]))["workdir"]) == str(new_ws.resolve()))
check("换目录后两条会话都跟着换", str(pairs.workdir_for_session(int(pair["session_b"]))) == str(new_ws.resolve()))
pairs.set_workdir(int(pair["id"]), str(WS))

# ---------------- 两个模型之间的对话 ----------------

note = pairs.add_note(pair, "a", "订单侧我跑完了，你接手对象存储")
check("留言落库", bool(note.get("id")))
check("留言方向正确", note["from_lane"] == "a" and note["to_lane"] == "b")
check("留言初始是待接收", note["status"] == "pending")

pending = pairs.take_pending(int(pair["session_b"]))
check("对方取到了这条", len(pending) == 1 and pending[0]["content"].startswith("订单侧"))
check("取过之后再取为空", pairs.take_pending(int(pair["session_b"])) == [])

pairs.add_note(pair, "b", "收到，桶权限我来查")
check("累计两条", len(pairs.notes(int(pair["id"]))) == 2)
check("增量拉取能按 id 切片", len(pairs.notes(int(pair["id"]), int(note["id"]))) == 1)

pairs.add_note(pair, "a", "对象存储的桶名在 /api/upload/policy 里")
block = pairs.notes_block(int(pair["session_b"]))
check("同伴消息进得了上下文", "同伴模型发给你的消息" in block and "对象存储的桶名" in block)
check("上下文里带车道名", "左栏" in block)

pairs.reset_budget(int(pair["id"]), 2)
check("预算能领", pairs.take_budget(int(pair["id"])) is True)
check("预算能领第二次", pairs.take_budget(int(pair["id"])) is True)
check("领完就不叫醒对方了", pairs.take_budget(int(pair["id"])) is False)
pairs.reset_budget(int(pair["id"]), pairs.DEFAULT_PEER_BUDGET)

prompt = pairs.prompt_block(int(pair["session_a"]))
check("提示里说清自己是哪一栏", "左栏" in prompt and "右栏" in prompt)
check("提示里带共享目录", str(WS.resolve()) in prompt)
check("提示里说明进度会自动落盘", "协同进度" in prompt)
check("提示里禁止客套式对齐", "致谢" in prompt)
check("单模型会话没有协同提示", pairs.prompt_block(0) == "")

# ---------------- 协同目录里的进度 ----------------

shared.reset(int(pair["session_a"]))
shared.reset(int(pair["session_b"]))
shared.log(int(pair["session_a"]), "progress", "已枚举 /api/order/{id}")
shared.log(int(pair["session_a"]), "finding", "high 订单详情接口未授权访问")
shared.log(int(pair["session_b"]), "progress", "接手对象存储")

root = WS / shared.PROGRESS_DIR
check("进度目录建出来了", root.exists())
check("左栏写了 a.md", (root / "a.md").exists())
check("右栏写了 b.md", (root / "b.md").exists())

text_a = (root / "a.md").read_text(encoding="utf-8")
check("进度文件带时间与标签", "[进展]" in text_a and "[漏洞]" in text_a)
check("进度文件写明是哪一栏", "左栏 进度" in text_a)

shared.log(int(pair["session_a"]), "progress", "正在核对上传策略的桶名")
shared.log(int(pair["session_a"]), "progress", "正在核对上传策略的桶名")
repeat = (root / "a.md").read_text(encoding="utf-8").count("正在核对上传策略的桶名")
check("连续重复的进展只写一次", repeat == 1)

check("左栏读到的是右栏的进度", any("接手对象存储" in line for line in shared.peer_log_lines(int(pair["session_a"]))))
check("右栏读到的是左栏的进度", any("已枚举" in line for line in shared.peer_log_lines(int(pair["session_b"]))))

# 目录变动：先建立基线，再写一个产物
shared.changes(int(pair["session_a"]))
(WS / "接口清单.md").write_text("# 接口\n- /api/order/{id}\n", encoding="utf-8")
moved = shared.changes(int(pair["session_a"]))
check("能发现新增的产物", any("接口清单.md" in item and "新增" in item for item in moved))
check("没有第二次改动就不重复报", shared.changes(int(pair["session_a"])) == [])

(WS / "payloads.txt").write_text("id=1\nid=2\n", encoding="utf-8")
peer_block = shared.peer_block(int(pair["session_a"]))
check("同伴进度进得了上下文", "右栏最近这些步骤" in peer_block)
check("目录变动也进上下文", "共享目录自上一轮以来" in peer_block and "payloads.txt" in peer_block)
check("提示别让模型重做", "不要重做" in peer_block)

tree = shared.tree(int(pair["session_a"]))
names = [item["name"] for item in tree]
check("目录清单含产物", "接口清单.md" in names)
check("目录清单含两份进度文件", f"{shared.PROGRESS_DIR}/a.md" in names and f"{shared.PROGRESS_DIR}/b.md" in names)
check("目录清单带大小与时间", all("size" in item and "mtime" in item for item in tree))

# 没配共享目录的会话：进度功能整体降级，不报错
check("非协同会话不写进度", shared.share_root(0) is None and shared.log(0, "progress", "x") is None)
check("非协同会话没有同伴块", shared.peer_block(0) == "")

# ---------------- 接口层 ----------------

from mono import api as api_pkg  # noqa: E402
import mono.api.chat as chat_api  # noqa: E402

routes = {route.path for route in chat_api.router.routes}
check("有建协同的接口", "/api/chat/pairs" in routes)
check("有协同详情接口", "/api/chat/pairs/{pair_id}" in routes)
check("有协同记录接口", "/api/chat/pairs/{pair_id}/notes" in routes)
check("有同时下发的接口", "/api/chat/pairs/{pair_id}/say" in routes)
check("有停止接口", "/api/chat/pairs/{pair_id}/stop" in routes)

# 单会话列表不能把协同里的两条子会话混进去
single = asyncio.run(chat_api.list_sessions({"u": "admin"}))
single_ids = {item["id"] for item in single}
check("单会话列表不含协同子会话", int(pair["session_a"]) not in single_ids and int(pair["session_b"]) not in single_ids)

detail = asyncio.run(chat_api.get_pair_detail(int(pair["id"]), {"u": "admin"}))
check("详情带回两栏", set(detail["lanes"].keys()) == {"a", "b"})
check("详情带模型显示名", detail["names"]["a"] and detail["names"]["b"])
check("详情带协同记录", len(detail["notes"]) == 3)
check("详情带预算", detail["budget"] == pairs.DEFAULT_PEER_BUDGET)

notes_payload = asyncio.run(chat_api.pair_notes(int(pair["id"]), 0, {"u": "admin"}))
check("协同记录接口带目录清单", isinstance(notes_payload.get("files"), list))
check("协同记录接口带运行状态", set(notes_payload.get("running", {}).keys()) == {"a", "b"})
check("协同记录接口带剩余预算", "budget" in notes_payload)

# 换模型接口要有「已配好」的连接器才算数：塞两条 ai 连接器（有密钥密文即视为可用）
from mono.db import now_iso as _now  # noqa: E402

with db() as conn:
    for key, name in (("deepseek", "DeepSeek"), ("openai", "OpenAI")):
        conn.execute(
            "INSERT OR REPLACE INTO connectors (key, name, category, auth_type, enabled, config_json, secret_enc, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (key, name, "ai", "bearer", 1, '{"model":"test-model"}', "enc", _now(), _now()),
        )
ready = chat_api.ready_providers()
check("配好的模型能被列出来", {item["key"] for item in ready} >= {"deepseek", "openai"})

patched_model = asyncio.run(
    chat_api.patch_pair(int(pair["id"]), chat_api.PairPatchIn(provider_b="deepseek"), {"u": "admin"})
)
check("换模型接口生效", patched_model["model_b"] == "deepseek")
check("换完左栏不受影响", patched_model["model_a"] == "deepseek")
try:
    asyncio.run(chat_api.patch_pair(int(pair["id"]), chat_api.PairPatchIn(provider_a="not-configured"), {"u": "admin"}))
    check("没配好的模型不许选", False, "应当报错")
except Exception as exc:  # HTTPException
    check("没配好的模型不许选", "还没配好" in str(getattr(exc, "detail", exc)))
pairs.set_models(int(pair["id"]), model_a="deepseek", model_b="openai")

# 下发时按栏带模型：把 start_run 换掉，只看它实际拿到的 provider 是不是这一栏选的那个
recorded: list[tuple[str, int, str]] = []
real_start, real_loop = chat_api.start_run, chat_api._auto_loop
chat_api._auto_loop = lambda sid, name, provider: recorded.append(("loop", int(sid), provider)) or iter(())
chat_api.start_run = lambda sid, events: recorded.append(("run", int(sid), "")) or None
try:
    asyncio.run(chat_api.pair_say(int(pair["id"]), chat_api.PairSayIn(lane="b", content="只测右栏"), {"u": "admin"}))
    asyncio.run(chat_api.pair_say(int(pair["id"]), chat_api.PairSayIn(lane="both", content="两边一起"), {"u": "admin"}))
finally:
    chat_api.start_run, chat_api._auto_loop = real_start, real_loop
providers = [provider for kind, _, provider in recorded if kind == "loop"]
check("单栏下发用本栏选的模型", providers[:1] == ["openai"])
check("同时下发各用各的模型", providers[1:3] == ["deepseek", "openai"])

# 换完模型再下发，跑的就是新模型
pairs.set_models(int(pair["id"]), model_b="deepseek")
recorded.clear()
chat_api._auto_loop = lambda sid, name, provider: recorded.append(("loop", int(sid), provider)) or iter(())
chat_api.start_run = lambda sid, events: None
try:
    asyncio.run(chat_api.pair_say(int(pair["id"]), chat_api.PairSayIn(lane="b", content="换模型后再试"), {"u": "admin"}))
finally:
    chat_api.start_run, chat_api._auto_loop = real_start, real_loop
check("换模型后下一轮就生效", [p for k, _, p in recorded if k == "loop"] == ["deepseek"])
pairs.set_models(int(pair["id"]), model_b="openai")

patched = asyncio.run(chat_api.patch_pair(int(pair["id"]), chat_api.PairPatchIn(workdir=str(Path(TMP) / "ws3"), ), {"u": "admin"}))
check("改目录接口生效", str(Path(TMP).resolve() / "ws3") in str(patched["workdir"]))
pairs.set_workdir(int(pair["id"]), str(WS))

# ---------------- 界面骨架 ----------------

html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
css = (ROOT / "mono/static/style.css").read_text(encoding="utf-8")
js = (ROOT / "mono/static/duo.js").read_text(encoding="utf-8")
appjs = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")
chat_src = (ROOT / "mono/api/chat.py").read_text(encoding="utf-8")

check("对话页有双模型容器", 'id="duo-view"' in html)
check("左右两栏各有消息区", 'id="duo-a-messages"' in html and 'id="duo-b-messages"' in html)
check("中间有协同记录区", 'id="duo-peer-list"' in html)
check("协同记录在左右两栏之间", html.index('id="duo-a-messages"') < html.index('id="duo-peer-list"') < html.index('id="duo-b-messages"'))
check("默认就是两栏，没有「先新建」的挡板", 'id="duo-blank"' not in html)
check("每栏顶部有模型下拉", 'id="duo-a-model"' in html and 'id="duo-b-model"' in html)
check("左栏模型下拉在消息区之前", html.index('id="duo-a-model"') < html.index('id="duo-a-messages"'))
check("有共享目录输入", 'id="duo-workdir"' in html)
check("历史抽屉默认收起", 'class="history-drawer hidden"' in html)
check("有同时下发入口", 'id="duo-both-form"' in html)
check("有历史抽屉", 'id="history-drawer"' in html)
check("协同目录清单在界面上", 'id="duo-files"' in html)
check("单会话布局还在", 'id="chat-layout"' in html and 'id="chat-messages"' in html)
check("单会话页能返回协同", 'id="chat-back-duo"' in html)
check("加载了双模型脚本", "/static/duo.js" in html)

check("三栏栅格：左右等宽、中间一小份", "grid-template-columns: minmax(0, 1fr) 192px minmax(0, 1fr)" in css)
check("侧栏收窄到 184", "grid-template-columns: 184px minmax(0, 1fr)" in css)
check("输入框有最小宽度兜底", "min-width: 150px" in css and "min-width: 120px" in css)
check("协同记录卡片有样式", ".duo-note" in css and ".duo-files" in css)
check("历史抽屉有样式", ".history-drawer" in css)

check("前端按栏分流事件", "function duoEvent(" in js and "function duoConsume(" in js)
check("前端能下发到单栏与两边", "function duoSay(" in js and 'keys.length === 2 ? "both"' in js)
check("前端会重置流的序号", "item.seq = 0" in js)
check("前端轮询目录变化", "duoPollNotes" in js and "data.files" in js)
check("没有配对时直接进草稿态", "function duoDraft(" in js and "duoBlank" not in js)
check("第一句话自动建配对", "function duoEnsurePair(" in js and 'provider_a: a' in js and 'provider_b: b' in js)
check("下拉里的模型来自接口返回", "state.chatProviders" in js and "function duoFillModels(" in js)
check("换模型会落库", "provider_a: select.value" in js and "provider_b: select.value" in js)
check("后端按栏取模型", "pairs.lane_model(pair, item)" in chat_src)
check("叫醒同伴也按栏取模型", "pairs.lane_model(pair, pairs.lane_of_session" in chat_src)
check("换模型接口收两栏参数", "provider_a: str | None" in chat_src and "provider_b: str | None" in chat_src)
check("导航进入对话页走协同", 'if (page === "chat") await duoBoot();' in appjs)
check("打开单会话会切回旧布局", "typeof duoShowSingle === \"function\"" in appjs)

# ---------------- 删除 ----------------

sa, sb = int(pair["session_a"]), int(pair["session_b"])
with db() as conn:
    conn.execute("DELETE FROM chat_messages WHERE session_id IN (?,?)", (sa, sb))
    conn.execute("DELETE FROM chat_sessions WHERE id IN (?,?)", (sa, sb))
pairs.delete_pair(int(pair["id"]))
check("删掉配对各表都清空", pairs.get_pair(int(pair["id"])) is None and pairs.notes(int(pair["id"])) == [])
check("删掉配对后单会话列表仍可用", asyncio.run(chat_api.list_sessions({"u": "admin"})) == [])

# ---------------- 汇总 ----------------

shutil.rmtree(TMP, ignore_errors=True)
passed = sum(1 for _, ok, _ in RESULTS if ok)
failed = len(RESULTS) - passed
print("\n共 %d 项，通过 %d 项，失败 %d 项" % (len(RESULTS), passed, failed))
if failed:
    for name, ok, detail in RESULTS:
        if not ok:
            print("  FAILED:", name, detail)
    sys.exit(1)
