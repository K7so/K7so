"""步骤看门狗：一步跑太久没有任何变化，就别干等。

用户的原话是「一个步骤每运行超过 300 秒之后还没变化，则检测该步骤是否正常执行，
不正常则终止或者重新开始这个步骤，如执行脚本、思考等，避免浪费时间」。

所以这里的判据不是「这一步总共跑了多久」，而是「多久没有新东西」：

- **模型思考**（流式一分片都不来）：上游没在出字，就是在干等。掐掉这一路请求，
  重新发一次——模型调用没有副作用，重启是安全的。
- **命令 / 脚本**：stdout / stderr 一个字节都不出，而且进程还活着，才算卡死。
  已经退出的进程不算卡死，照常把它攒下的输出交回去。卡死的进程直接杀掉，
  是否重跑交给调用方决定（重跑会重复执行，得看命令本身有没有副作用）。

阈值默认 300 秒，`:env:` 环境变量 ``STEP_STALL_SECONDS`` 可调。
"""
from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator

from ..config import env

STALL_SECONDS = int(env("STEP_STALL_SECONDS", "300") or 300)


class StepStalled(RuntimeError):
    """一步连续 ``seconds`` 秒没有任何新进展。"""

    def __init__(self, seconds: float, label: str = "") -> None:
        self.seconds = int(seconds)
        self.label = label or "这一步"
        super().__init__(f"{self.label}连续 {self.seconds} 秒没有任何新进展，判定卡住")


def stall_message(seconds: float, label: str = "") -> str:
    """给人看的一句话：说清多久没动、判定卡住、接下来做了什么。"""
    label = label or "这一步"
    return f"{label}连续 {int(seconds)} 秒没有任何新进展，判定为卡死"


async def iter_with_watchdog(
    agen: AsyncGenerator[Any, None],
    stall: float = 0,
    label: str = "",
) -> AsyncGenerator[Any, None]:
    """逐条转交上游的分片；超过 ``stall`` 秒没有下一片就抛 :class:`StepStalled`。

    用 ``asyncio.wait_for`` 包住 ``__anext__``：超时会取消这次「等下一片」，
    然后把这个生成器关掉，避免 httpx 连接一直挂着占资源。
    """
    limit = float(stall or STALL_SECONDS)
    iterator = agen.__aiter__()
    try:
        while True:
            try:
                item = await asyncio.wait_for(iterator.__anext__(), timeout=limit)
            except StopAsyncIteration:
                return
            except asyncio.TimeoutError as exc:  # noqa: PERF203 - 每片都要计时
                raise StepStalled(limit, label) from exc
            yield item
    finally:
        closer = getattr(iterator, "aclose", None)
        if closer is not None:
            try:
                await closer()
            except (RuntimeError, GeneratorExit):
                pass
            except Exception:  # noqa: BLE001 - 关流失败不影响结论
                pass
