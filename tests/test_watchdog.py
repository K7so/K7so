"""步骤看门狗：一步跑太久没有任何变化，要判卡住并终止 / 重启。

覆盖三件事：
    1. 命令边跑边出输出：跑得比阈值久也不算卡死（长任务不能被误杀）；
    2. 命令一直没输出：按阈值判卡死、杀掉，并把原因写清楚；
    3. 模型思考一直不出分片：重启一次，再卡就直接终止，不再干等。

用法：
    python tests/test_watchdog.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-dog-")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.engine import shell  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


async def model_stall_cases() -> None:
    """模型思考卡死：重启一次、再卡就终止。"""
    import mono.engine.agent as agent

    class DeadLLM:
        """连分片都不给：等价于上游一直「正在思考」。"""

        def __init__(self) -> None:
            self.calls = 0

        async def stream_complete(self, messages, tools=None, max_tokens=1200):
            self.calls += 1
            await asyncio.sleep(30)
            yield ("text", "never")

    class SlowStartLLM:
        """第一次憋着不出，第二次正常出结果：验证「重启」能救回来。"""

        def __init__(self) -> None:
            self.calls = 0

        async def stream_complete(self, messages, tools=None, max_tokens=1200):
            self.calls += 1
            if self.calls == 1:
                await asyncio.sleep(30)
            yield ("text", "ok")
            yield ("final", {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"})

    original = agent.STALL_SECONDS
    agent.STALL_SECONDS = 0.6
    try:
        dead = DeadLLM()
        events = [item async for item in agent._model_turn(dead, [], None)]
        kinds = [item[0] for item in events]
        started = time.time()
        _ = started
        check("思考卡死会先给一条「正在重开这一步」的说明", kinds[:1] == ["status"], str(kinds)[:120])
        check("思考卡死会真的重启这一步（请求发两次）", dead.calls == 2, f"calls={dead.calls}")
        check("重启后仍卡就直接终止", kinds[-1] == "error", str(kinds)[:120])
        check("终止原因写清「没有继续干等」", "没有继续干等" in str(events[-1][1]), str(events[-1][1])[:120])

        slow = SlowStartLLM()
        events2 = [item async for item in agent._model_turn(slow, [], None)]
        check("重启后拿到结果就继续（不报错）", events2[-1][0] == "final", str(events2)[-160:])
        check("救回来时正文只有一份", "".join(d for k, d in events2 if k == "delta") == "ok")
    finally:
        agent.STALL_SECONDS = original


def shell_cases() -> None:
    """命令 / 脚本：静默才判卡死，边跑边出输出的不误杀。"""
    cwd = Path(tempfile.mkdtemp(prefix="dog-work-"))
    original = shell.STALL_SECONDS
    shell.STALL_SECONDS = 2
    try:
        chatty = "import time\nfor i in range(6):\n    print(i, flush=True)\n    time.sleep(1)\n"
        started = time.time()
        result = shell.run_script(chatty, cwd, timeout=60)
        elapsed = time.time() - started
        check("有持续输出的脚本跑过阈值也不算卡死", not result.get("stalled"), str(result)[:160])
        check("有持续输出的脚本能正常跑完", result.get("ok") and result.get("exit_code") == 0, str(result)[:160])
        check("长任务真的跑够了时间（没被 2 秒阈值误杀）", elapsed >= 5.5, f"elapsed={elapsed:.1f}s")
        check("输出被完整收回来", "5" in str(result.get("stdout")), str(result.get("stdout"))[:80])

        silent = "import time\nprint('start', flush=True)\ntime.sleep(30)\nprint('never')\n"
        started = time.time()
        result = shell.run_script(silent, cwd, timeout=60)
        elapsed = time.time() - started
        check("没有输出的脚本被判定卡死", bool(result.get("stalled")), str(result)[:160])
        check("判定卡死时按阈值终止（没有等满 30 秒）", elapsed < 12, f"elapsed={elapsed:.1f}s")
        check("卡死原因写清「连续 N 秒没有任何输出」", "没有任何输出" in str(result.get("error")), str(result.get("error"))[:120])
        check("卡死时把终止前的输出也交回来", "start" in str(result.get("stdout")), str(result.get("stdout"))[:80])

        quiet = shell.run_command('python -c "import time; time.sleep(30)"', cwd, timeout=60)
        check("命令卡死同样会终止", bool(quiet.get("stalled")), str(quiet)[:160])
        check("命令卡死带「换个参数重试」的说明", "重试" in str(quiet.get("error")), str(quiet.get("error"))[:120])
    finally:
        shell.STALL_SECONDS = original


def config_cases() -> None:
    """阈值与默认超时：默认 300 秒，且命令默认时长不小于它。"""
    check("卡死阈值默认 300 秒", shell.STALL_SECONDS == 300, str(shell.STALL_SECONDS))
    check("命令默认总时长放到 300 秒量级", shell.DEFAULT_TIMEOUT >= 300, str(shell.DEFAULT_TIMEOUT))
    check("命令总时长上限比默认更宽（长任务可显式申请）", shell.MAX_TIMEOUT > shell.DEFAULT_TIMEOUT, f"{shell.MAX_TIMEOUT}")


def ui_cases() -> None:
    """界面：能力方块在标题右边、是方块不是胶囊、新会话会重算。"""
    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
    js = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")
    css = (ROOT / "mono/static/style.css").read_text(encoding="utf-8")
    check("能力徽标在会话标题同一个容器里", 'class="chat-head-title"' in html and "chat-head-title" in css)
    check("徽标位于标题之后（标题右边）", html.index('id="chat-title"') < html.index('id="cov-chip"'))
    check("徽标是方块（定宽定高、圆角不再 999px）", "border-radius: 3px" in css and "width: 58px" in css)
    check("方块里两行：已验/已勾 + 还差几项", "<b>${sum.done}/${sum.selected}</b>" in js and "还差 ${sum.pending}" in js)
    check("新建会话后重算能力方块", "updateCovChip();\n  $(\"#chat-input\").focus();" in js)
    check("并发请求只让最后一次结果落地", "seq !== state.covChipSeq" in js)
    check("跑着的时候能力方块自动刷新", "state.covTimer = setInterval" in js)
    check("一个会话都没有时也显示 0/N", "<b>0/${total}</b>" in js, js[:0])
    check("进对话页就重算一次方块", "一个会话都还没有时也要把" in js)
    check("保存能力后按新的勾选数重算", "state.capabilitySelected = Number(result.count" in js)


async def main() -> int:
    await model_stall_cases()
    shell_cases()
    config_cases()
    ui_cases()

    failed = [item for item in RESULTS if not item[1]]
    print("\n" + "=" * 60)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    for name, _, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
