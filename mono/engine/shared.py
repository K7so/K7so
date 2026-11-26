"""协同目录里的进度交换。

两个模型各写各的进度文件（`协同进度/a.md`、`协同进度/b.md`），
每完成一步就追加一行；下一轮开工前，把「同伴最近做了什么」和
「共享目录里哪些文件变了」一起塞进上下文。

这样对方不需要问「你做到哪了」：进度是边做边落的，读的人拿到的是
最新的一份，而不是靠对话里互相汇报。
"""
from __future__ import annotations

import time
from pathlib import Path

from ..db import db
from .pairs import lane_of_session, pair_for_session

# 进度目录名：中文，用户一眼能看懂这是两个模型互相交接的地方
PROGRESS_DIR = "协同进度"
LANE_FILE = {"a": "a.md", "b": "b.md"}
# 每轮注入多少行同伴进度：够看清它做到哪，又不至于把上下文塞满
DIGEST_LINES = 24
# 一轮里最多列多少个变动文件
CHANGE_LIMIT = 24
# 扫描目录时跳过的东西
SKIP_DIRS = {"协同进度", ".git", "__pycache__", "node_modules"}
SKIP_SUFFIX = {".pyc", ".pyo", ".log.tmp"}

# 每个会话上一次看到的目录状态：path -> (mtime, size)
_SNAPSHOT: dict[int, dict[str, tuple[float, int]]] = {}
# 写进文件的节流：同一条进展连着来不重复刷
_LAST_LINE: dict[int, str] = {}


def share_root(session_id: int) -> Path | None:
    """这条会话的共享目录：只有配对了、且配了工作目录才有。"""
    pair = pair_for_session(int(session_id or 0))
    if not pair:
        return None
    value = str(pair.get("workdir") or "").strip()
    return Path(value).expanduser() if value else None


def progress_root(session_id: int) -> Path | None:
    root = share_root(session_id)
    if root is None:
        return None
    target = root / PROGRESS_DIR
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return target


def log(session_id: int, kind: str, text: str) -> None:
    """把一步进展写进自己那份进度文件。

    只追加、不改写：对方随时读到的都是完整过程。同一条内容在极短时间内
    重复出现（进度事件常常连着发两遍）就跳过，免得文件里全是重复行。
    """
    sid = int(session_id or 0)
    body = str(text or "").strip().replace("\n", " ")
    if not sid or not body:
        return
    if _LAST_LINE.get(sid) == body:
        return
    root = progress_root(sid)
    if root is None:
        return
    lane = lane_of_session(sid) or "a"
    path = root / LANE_FILE.get(lane, f"{lane}.md")
    stamp = time.strftime("%H:%M:%S")
    tag = {"finding": "漏洞", "done": "收尾", "start": "开始"}.get(kind, "进展")
    try:
        new_file = not path.exists()
        with path.open("a", encoding="utf-8") as fh:
            if new_file:
                side = "左栏" if lane == "a" else "右栏"
                fh.write(f"# {side} 进度\n\n")
            fh.write(f"- {stamp} [{tag}] {body}\n")
        _LAST_LINE[sid] = body
    except OSError:
        return


def snapshot(session_id: int) -> dict[str, tuple[float, int]]:
    """扫一遍共享目录（浅两层），返回 path -> (mtime, size)。"""
    root = share_root(session_id)
    if root is None or not root.exists():
        return {}
    state: dict[str, tuple[float, int]] = {}
    try:
        for path in _walk(root, 2):
            try:
                stat = path.stat()
            except OSError:
                continue
            state[str(path.relative_to(root))] = (stat.st_mtime, stat.st_size)
    except OSError:
        return {}
    return state


def _walk(root: Path, depth: int):
    if depth < 0:
        return
    try:
        children = list(root.iterdir())
    except OSError:
        return
    for child in children:
        name = child.name
        if name.startswith(".") and name != ".":
            continue
        if child.is_dir():
            if name in SKIP_DIRS:
                continue
            yield from _walk(child, depth - 1)
        else:
            if child.suffix in SKIP_SUFFIX:
                continue
            yield child


def changes(session_id: int, limit: int = CHANGE_LIMIT) -> list[str]:
    """和上次相比，共享目录里新增或改动的文件。"""
    sid = int(session_id or 0)
    current = snapshot(sid)
    previous = _SNAPSHOT.get(sid)
    _SNAPSHOT[sid] = current
    if previous is None:
        return []
    out: list[str] = []
    for name, meta in current.items():
        if name in SKIP_DIRS or name.startswith(PROGRESS_DIR):
            continue
        old = previous.get(name)
        if old is None:
            out.append(f"新增 {name}（{meta[1]} 字节）")
        elif old != meta:
            out.append(f"更新 {name}（{meta[1]} 字节）")
        if len(out) >= limit:
            break
    return out


def peer_log_lines(session_id: int, lines: int = DIGEST_LINES) -> list[str]:
    """同伴那份进度文件的最后几行。"""
    sid = int(session_id or 0)
    lane = lane_of_session(sid) or "a"
    other = "b" if lane == "a" else "a"
    root = share_root(sid)
    if root is None:
        return []
    path = root / PROGRESS_DIR / LANE_FILE.get(other, f"{other}.md")
    if not path.exists():
        return []
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    body = [line for line in content if line.startswith("- ")]
    return body[-lines:]


def peer_block(session_id: int) -> str:
    """给模型看的「同伴做到哪了 + 目录里刚变了什么」。两样都没有就不注入。"""
    sid = int(session_id or 0)
    if not sid:
        return ""
    lines = peer_log_lines(sid)
    moved = changes(sid)
    if not lines and not moved:
        return ""
    lane = lane_of_session(sid) or "a"
    other = "右栏" if lane == "a" else "左栏"
    parts = ["【协同目录里的最新情况】"]
    if lines:
        parts.append(f"{other}最近这些步骤（来自 {PROGRESS_DIR}/ 下的进度文件）：")
        parts.extend(lines)
        parts.append("它已经做完的部分不要重做；要接着往下做就从它停的地方开始。")
    if moved:
        parts.append("共享目录自上一轮以来有这些变化：")
        parts.extend(f"- {item}" for item in moved)
        parts.append("要看内容直接读这些文件，不要在消息里让对方贴。")
    return "\n".join(parts)


def reset(session_id: int) -> None:
    """删会话时把缓存清掉，免得下次撞上旧快照。"""
    sid = int(session_id or 0)
    _SNAPSHOT.pop(sid, None)
    _LAST_LINE.pop(sid, None)


def tree(session_id: int, limit: int = 60) -> list[dict]:
    """给界面看的目录清单：文件、大小、更新时间。"""
    root = share_root(session_id)
    if root is None or not root.exists():
        return []
    out: list[dict] = []
    try:
        for path in _walk(root, 2):
            try:
                stat = path.stat()
            except OSError:
                continue
            out.append(
                {
                    "name": str(path.relative_to(root)).replace("\\", "/"),
                    "size": stat.st_size,
                    "mtime": time.strftime("%m-%d %H:%M", time.localtime(stat.st_mtime)),
                }
            )
    except OSError:
        return []
    out.sort(key=lambda item: item["mtime"], reverse=True)
    # 两份进度文件也列出来：用户能确认「进度确实落在共享目录里」
    if root is not None:
        for lane in ("a", "b"):
            path = root / PROGRESS_DIR / LANE_FILE[lane]
            if not path.exists():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            out.append(
                {
                    "name": f"{PROGRESS_DIR}/{LANE_FILE[lane]}",
                    "size": stat.st_size,
                    "mtime": time.strftime("%m-%d %H:%M", time.localtime(stat.st_mtime)),
                }
            )
    return out[:limit]
