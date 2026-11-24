"""端到端联调：让"模型"按用户级记忆干活，验证记忆能读全、进度能播报。

这里用一个脚本化模型扮演 AI：它按平台给的游标把记忆一页页读完，
读到最后一页才回答，并把记忆末尾约定的校验码写进结论。
跑通它说明链路（预载 → 分页读全 → 每步结论 → 落库回放）是通的；
换成真实大模型时，模型看到的是同一套上下文与工具。

用法：
    python tests/test_memory_worker.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-live-")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.db import db, init_db, now_iso, set_settings  # noqa: E402
from mono.engine.capabilities import set_switches  # noqa: E402
import mono.engine.agent as agent  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []

CODE = "MONO-7X3Q-2026"


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


def build_memory() -> tuple[Path, int]:
    """三个文件、四万来字，最后一条约定藏在末尾——只有读全才看得到。"""
    root = Path(TMP) / "memory"
    (root / "sub").mkdir(parents=True, exist_ok=True)
    (root / "MEMORY.md").write_text(
        "# 用户偏好\n"
        + "".join(f"- 第{i}条约定：每周五下班前给出一份风险变化简报。\n" for i in range(1, 700))
        + "\n## 交付格式\n报告一律用简体中文 Markdown，结论放在最前面。\n",
        encoding="utf-8",
    )
    (root / "sub" / "HISTORY.md").write_text(
        "# 历史决策\n"
        + "".join(f"- 2026-{1 + i % 12:02d}-{1 + i % 27:02d}：处理过一次接口越权问题，结论是补鉴权。\n" for i in range(600))
        + "\n## 上一次的教训\n批量导出前先确认授权范围。\n",
        encoding="utf-8",
    )
    (root / "sub" / "校验码.txt").write_text(
        "# 这一条在记忆的最后，只有把记忆读完才看得到\n"
        f"会话约定：回答的第一行写「记忆已读」，最后一行写「校验码：{CODE}」。\n",
        encoding="utf-8",
    )
    # 目录说明文件不算记忆，统计时按平台同一套规则排除
    total = sum(
        len(path.read_text(encoding="utf-8"))
        for path in root.rglob("*")
        if path.is_file() and path.name.lower() not in {"readme.md", "readme.txt"}
    )
    return root, total


class MemoryWorker:
    """按记忆里的约定工作的模型：先读全，再回答。"""

    name = "MemoryWorker"
    model = "memory-worker"
    key = "fake"

    def __init__(self) -> None:
        self.calls = 0
        self.reads: list[int] = []
        self.seen: list[list[dict]] = []
        self.preload_had_gap = False
        self.answer = ""
        self.next_cursor = 0
        self.done = False

    def _answer_payload(self) -> dict:
        self.answer = (
            f"记忆已读。\n\n**结论**：平台当前没有待处理的风险（这是联调数据）。\n"
            f"依据：平台概览与{vault_hint()}。\n\n校验码：{CODE}"
        )
        return {"message": {"role": "assistant", "content": self.answer}, "finish_reason": "stop"}

    def _read_payload(self, cursor: int, text: str) -> dict:
        self.reads.append(cursor)
        return {
            "message": {
                "role": "assistant",
                "content": text,
                "tool_calls": [
                    {
                        "id": f"call_r{len(self.reads)}",
                        "type": "function",
                        "function": {"name": "read_memory", "arguments": json.dumps({"cursor": cursor})},
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }

    async def stream_complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=180):
        self.calls += 1
        self.seen.append([dict(m) for m in messages])
        preload = "".join(
            str(m.get("content") or "") for m in messages if m.get("role") == "system"
        )
        if "【记忆未读完】" in preload:
            self.preload_had_gap = True

        last = messages[-1]
        if last.get("role") == "tool":
            data = json.loads(str(last.get("content") or "{}"))
            total = int(data.get("total_chars") or 0)
            self.next_cursor = int(data.get("next_cursor") or 0)
            self.done = not data.get("has_more")
            if not self.done:
                payload = self._read_payload(
                    self.next_cursor, f"已读记忆 {self.next_cursor}/{total} 字符，接下来继续读完。"
                )
            else:
                payload = self._answer_payload()
        elif last.get("role") == "system" and self.done:
            # 深度轮 / 收尾自检：记忆已经读全，按记忆里的约定直接给结论，不再从头再读一遍
            payload = self._answer_payload()
        elif last.get("role") == "system":
            # 还没读完就收到追加要求：从上次的位置接着读，不回到开头
            payload = self._read_payload(self.next_cursor, "记忆还没读完，接着上次的位置继续读。")
        else:
            payload = self._read_payload(0, "已确认记忆还没读完，接下来从头读。")

        text = str(payload["message"].get("content") or "")
        for start in range(0, len(text), 10):
            yield ("text", text[start : start + 10])
        yield ("final", payload)

    async def complete(self, messages, tools=None, temperature=0.2, max_tokens=1200, timeout=120):
        raise AssertionError("这一轮不应该走非流式兜底")


def vault_hint() -> str:
    return "三个记忆文件"


async def main() -> int:
    init_db()
    root, total = build_memory()
    set_settings({"memory_path": str(root), "work_dir": str(Path(TMP) / "work")})
    # 自动迭代已下线（等价于对话页的自动继续），这里不再设开关

    model = MemoryWorker()
    agent.pick_llm = lambda provider="": model  # type: ignore[assignment]

    with db() as conn:
        cur = conn.execute(
            "INSERT INTO chat_sessions (title, username, created_at, updated_at) VALUES (?,?,?,?)",
            ("记忆联调", "admin", now_iso(), now_iso()),
        )
        sid = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, created_at) VALUES (?,?,?,?)",
            (sid, "user", "把平台现在的资产和漏洞情况统计给我，按我的习惯汇报。", now_iso()),
        )

    events = []
    async for event in agent.run_agent(sid, "admin"):
        events.append(event)

    messages = [str(e.get("content") or "") for e in events if e.get("type") == "message"]
    progress = [str(e.get("content") or "") for e in events if e.get("type") == "progress"]
    check("预载提示了「记忆未读完」", model.preload_had_gap)
    check("确实分页读了多轮", len(model.reads) >= 3, f"读了 {len(model.reads)} 轮")
    check("每步都有结论", len(progress) >= 3, f"{len(progress)} 条")
    check("进度带读到的进度", any("/" in line and "字符" in line for line in progress), str(progress)[:200])
    check("最终结论按记忆约定开头", bool(messages) and messages[-1].startswith("记忆已读"), str(messages)[:120])
    check("读到记忆末尾的校验码", CODE in (messages[-1] if messages else ""), str(messages)[:200])
    check("结论没有半路截断", "记忆太长" not in "".join(messages))

    with db() as conn:
        rows = conn.execute(
            "SELECT role, content FROM chat_messages WHERE session_id=? AND role='progress' ORDER BY id", (sid,)
        ).fetchall()
    check("进度落库可回放", len(rows) >= 3, f"{len(rows)} 条")

    # 收尾前做一次自检（重读记忆、对着能力清单核对）；深度轮已随「自动迭代」一起下线
    prompts = [
        str(m.get("content") or "")
        for batch in model.seen
        for m in batch
        if m.get("role") == "system"
    ]
    check("深度轮提示词已随自动迭代下线", not any("【自动迭代·深度轮】" in item for item in prompts))
    check(
        "收尾自检把记忆摆到了模型面前",
        any("用户级记忆" in item for item in prompts),
        str(prompts)[-300:],
    )
    check("收尾自检把能力清单摆到了模型面前", any("已勾选测试能力" in item for item in prompts))
    check("自检这件事播报给了用户", any("收尾核对" in line for line in progress), str(progress)[-200:])

    # 记忆总量与清单一致，模型看到的字符数是对的
    manifest = agent.memory_manifest()
    check("记忆清单含三个文件", len(manifest) == 3, str(manifest))
    check("记忆字符数与文件一致", abs(sum(item["chars"] for item in manifest) - total) < 200, f"{sum(item['chars'] for item in manifest)} vs {total}")

    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
