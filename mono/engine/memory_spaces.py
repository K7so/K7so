"""模型记忆空间：一个模型一份长期记忆，互不串味。

平台上同时跑两个模型时，两边各自的偏好、历史结论、踩过的坑都不一样。
把它们塞进同一个记忆目录，等于让两个模型读对方的笔记本：容易串味，
也没法比较「同一个任务，不同记忆下谁做得更好」。

所以记忆做成「空间」：一个空间就是一个目录，可以单独配置、单独选择。
双模型的左右两栏各绑一个空间（`chat_pairs.memory_a / memory_b`），
`0` 表示跟随「目录配置」里那份全局默认记忆，老行为不变。

这一层只管空间本身（表 + 目录）；真正怎么读文件、怎么分页、怎么抽
Word/PDF 正文，仍然由 `workspace` 负责。
"""
from __future__ import annotations

import os
from pathlib import Path

from ..config import MEMORY_DIR
from ..db import db, get_settings, now_iso

# 0 号不是表里的行，代表「跟随平台默认记忆」：目录配置里那份
DEFAULT_ID = 0
DEFAULT_NAME = "默认记忆"
NAME_MAX = 40
NOTE_MAX = 200
# 各空间的落脚处：放在默认记忆目录之外，免得默认那份把它们一起读进来
SPACES_ROOT = MEMORY_DIR.parent / "memory_spaces"
# 统计文件数时跳过的目录：这些不是记忆内容
SKIP_DIRS = {".git", ".svn", ".hg", "__pycache__", "node_modules", ".venv", "venv", ".tox"}


def _row(row) -> dict | None:
    return dict(row) if row else None


def default_dir() -> Path:
    """全局默认记忆目录：目录配置里设过就用它，否则平台自带的那份。"""
    value = (get_settings().get("memory_path") or "").strip()
    root = Path(value).expanduser() if value else MEMORY_DIR
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return root


def _scan(path: Path) -> dict:
    """轻量统计：多少文件、多大。不读内容，列表页用得上。"""
    if path.is_file():
        try:
            stat = path.stat()
        except OSError:
            return {"files": 0, "bytes": 0, "updated": 0.0}
        return {"files": 1, "bytes": stat.st_size, "updated": stat.st_mtime}
    if not path.is_dir():
        return {"files": 0, "bytes": 0, "updated": 0.0}
    root = path
    files = 0
    size = 0
    newest = 0.0
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            if name.startswith("~$"):
                continue
            file_path = Path(current) / name
            # 平台自带的目录说明不算记忆内容
            if name == "README.md" and file_path.parent == root and _is_readme(file_path):
                continue
            try:
                stat = file_path.stat()
            except OSError:
                continue
            files += 1
            size += stat.st_size
            newest = max(newest, stat.st_mtime)
    return {"files": files, "bytes": size, "updated": newest}


def list_files(dir_path: str, limit: int = 200) -> list[dict]:
    """目录里的文件清单：名称（相对路径）、大小、改过的时间。只列，不读内容。"""
    root = Path(str(dir_path or "")).expanduser()
    if not root.exists():
        return []
    if root.is_file():
        stat = root.stat()
        return [{"name": root.name, "bytes": stat.st_size, "updated": stat.st_mtime}]
    items: list[dict] = []
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            if name.startswith("~$"):
                continue
            path = Path(current) / name
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = str(path.relative_to(root)).replace("\\", "/")
            # 平台自带的目录说明不算记忆内容
            if rel == "README.md" and _is_readme(path):
                continue
            items.append({"name": rel, "bytes": stat.st_size, "updated": stat.st_mtime})
            if len(items) >= limit:
                return items
    return items


def _is_readme(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:200]
    except OSError:
        return False
    return "用户级记忆目录" in head


def _with_stats(item: dict) -> dict:
    path = Path(item["dir"]).expanduser()
    info = _scan(path)
    item = dict(item)
    item.update({"exists": path.exists(), "files": info["files"], "bytes": info["bytes"]})
    return item


def default_space() -> dict:
    """默认记忆这份「虚拟空间」：没有行，但不能从列表里缺席。"""
    root = default_dir()
    return _with_stats(
        {
            "id": DEFAULT_ID,
            "name": DEFAULT_NAME,
            "dir": str(root),
            "note": "跟随「目录配置」里的用户级记忆目录",
            "created_at": "",
            "default": True,
        }
    )


def list_spaces(username: str) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM memory_spaces WHERE username=? ORDER BY id",
            (str(username or ""),),
        ).fetchall()
    return [default_space()] + [_with_stats(dict(r)) for r in rows]


def get_space(space_id: int, username: str = "") -> dict | None:
    sid = int(space_id or 0)
    if sid == DEFAULT_ID:
        return default_space()
    sql = "SELECT * FROM memory_spaces WHERE id=?"
    params: list[object] = [sid]
    if username:
        sql += " AND username=?"
        params.append(str(username))
    with db() as conn:
        row = conn.execute(sql, tuple(params)).fetchone()
    return _with_stats(dict(row)) if row else None


def _prepare_dir(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("记忆目录不能为空")
    root = Path(text).expanduser()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(f"目录不可用：{exc}") from exc
    return str(root.resolve())


def create_space(username: str, name: str, dir: str = "", note: str = "") -> dict:
    title = str(name or "").strip()[:NAME_MAX]
    if not title:
        raise ValueError("记忆名称不能为空")
    with db() as conn:
        clash = conn.execute(
            "SELECT id FROM memory_spaces WHERE username=? AND name=?",
            (str(username or ""), title),
        ).fetchone()
        if clash:
            raise ValueError("已经有同名的记忆了")
    # 没填目录就按名字建一份：记忆空间必须有自己的落脚处
    target = _prepare_dir(dir) if str(dir or "").strip() else _prepare_dir(
        str(SPACES_ROOT / _slug(title))
    )
    ts = now_iso()
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO memory_spaces (username, name, dir, note, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (str(username or ""), title, target, str(note or "")[:NOTE_MAX], ts, ts),
        )
        space_id = int(cursor.lastrowid)
    return get_space(space_id, username) or {}


def _slug(text: str) -> str:
    keep = [ch for ch in text if ch.isalnum() or ch in "-_"]
    value = "".join(keep)[:40]
    return value or "space"


def update_space(
    space_id: int,
    username: str,
    name: str | None = None,
    dir: str | None = None,
    note: str | None = None,
) -> dict | None:
    sid = int(space_id or 0)
    if sid == DEFAULT_ID:
        raise ValueError("默认记忆跟「目录配置」走，请到那一页修改")
    current = get_space(sid, username)
    if not current:
        return None
    fields: list[str] = []
    values: list[object] = []
    if name is not None:
        title = str(name).strip()[:NAME_MAX]
        if not title:
            raise ValueError("记忆名称不能为空")
        with db() as conn:
            clash = conn.execute(
                "SELECT id FROM memory_spaces WHERE username=? AND name=? AND id<>?",
                (str(username or ""), title, sid),
            ).fetchone()
        if clash:
            raise ValueError("已经有同名的记忆了")
        fields.append("name=?")
        values.append(title)
    if dir is not None:
        fields.append("dir=?")
        values.append(_prepare_dir(dir))
    if note is not None:
        fields.append("note=?")
        values.append(str(note)[:NOTE_MAX])
    if not fields:
        return current
    fields.append("updated_at=?")
    values.append(now_iso())
    values.append(sid)
    with db() as conn:
        conn.execute(f"UPDATE memory_spaces SET {', '.join(fields)} WHERE id=?", tuple(values))
    return get_space(sid, username)


def delete_space(space_id: int, username: str) -> bool:
    """删掉这条记忆配置。目录里的文件原地保留——误删配置不该顺手删资料。"""
    sid = int(space_id or 0)
    if sid == DEFAULT_ID:
        raise ValueError("默认记忆不能删除")
    with db() as conn:
        cursor = conn.execute(
            "DELETE FROM memory_spaces WHERE id=? AND username=?", (sid, str(username or ""))
        )
        removed = cursor.rowcount > 0
        if removed:
            # 配对上还指着它的，回落到默认记忆，别让某一栏读不到东西
            conn.execute("UPDATE chat_pairs SET memory_a=0 WHERE memory_a=?", (sid,))
            conn.execute("UPDATE chat_pairs SET memory_b=0 WHERE memory_b=?", (sid,))
    return removed


# ---------------- 会话怎么找到自己的那份记忆 ----------------

def _username_of_session(session_id: int) -> str:
    with db() as conn:
        row = conn.execute("SELECT username FROM chat_sessions WHERE id=?", (int(session_id),)).fetchone()
    return str(row["username"] or "") if row else ""


def space_id_for_session(session_id: int) -> int:
    """这条会话该用哪份记忆：配对里配了就用它，否走默认（0）。"""
    from . import pairs

    sid = int(session_id or 0)
    if not sid:
        return DEFAULT_ID
    pair = pairs.pair_for_session(sid)
    if not pair:
        return DEFAULT_ID
    lane = pairs.lane_of_session(sid)
    key = "memory_a" if lane == "a" else "memory_b"
    return int(pair.get(key) or DEFAULT_ID)


def path_for_session(session_id: int) -> Path | None:
    """会话自己的记忆目录；没单独配就返回 None，让调用方用全局默认。"""
    sid = int(session_id or 0)
    if not sid:
        return None
    space_id = space_id_for_session(sid)
    if space_id == DEFAULT_ID:
        return None
    space = get_space(space_id, _username_of_session(sid))
    if not space:
        return None
    path = Path(space["dir"]).expanduser()
    return path if path.exists() else None


def label_for_session(session_id: int) -> str:
    """给提示词用的一句话：这一栏读的是哪份记忆。"""
    sid = int(session_id or 0)
    space_id = space_id_for_session(sid)
    if space_id == DEFAULT_ID:
        return DEFAULT_NAME
    space = get_space(space_id, _username_of_session(sid))
    return str((space or {}).get("name") or DEFAULT_NAME)
