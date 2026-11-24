"""扫描任务运行时：事件订阅、取消标记与任务队列。"""
from __future__ import annotations

import asyncio
from typing import Any

SCAN_QUEUE: asyncio.Queue[int] = asyncio.Queue()
CANCELLED: set[int] = set()


class EventHub:
    def __init__(self) -> None:
        self._subscribers: dict[int, set[asyncio.Queue]] = {}

    def subscribe(self, scan_id: int) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.setdefault(scan_id, set()).add(queue)
        return queue

    def unsubscribe(self, scan_id: int, queue: asyncio.Queue) -> None:
        subscribers = self._subscribers.get(scan_id)
        if subscribers:
            subscribers.discard(queue)
            if not subscribers:
                self._subscribers.pop(scan_id, None)

    def publish(self, scan_id: int, payload: dict[str, Any]) -> None:
        for queue in list(self._subscribers.get(scan_id, set())):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                pass


HUB = EventHub()
