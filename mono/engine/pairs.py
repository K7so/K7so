"""双模型协同：一对会话、一份共享目录、一条两个模型之间的对话通道。

设计上不新造一套执行引擎：一个「配对」就是两条普通的 chat_session，
各自跑自己的 Agent（工具、权限、待确认、能力台账、SSE 全部照旧），
这层只负责三件事：

1. 把两条会话绑在一起（`chat_pairs`），并给它们同一个工作目录；
2. 记录两个模型之间的对话（`chat_peer_notes`），谁发给谁、对方看没看到；
3. 控制互相唤醒的次数，避免两个模型客套起来把额度烧穿。
"""
from __future__ import annotations

from pathlib import Path

from ..db import db, now_iso

# 单条协同消息的字数上限：交接要说人话，不是把整份报告贴过去
NOTE_MAX_CHARS = 1200
# 一次任务里允许互相唤醒的轮次：四轮足够分工与汇合，再多基本就是在互相客气
DEFAULT_PEER_BUDGET = 4
LANES = ("a", "b")

# 已登记的会话工作目录：进程内缓存，避免每次 exec_dir 都查库
_SESSION_DIRS: dict[int, Path] = {}


def _row_dict(row) -> dict | None:
    return dict(row) if row else None


# ---------------- 配对 ----------------

def create_pair(
    username: str,
    title: str,
    model_a: str,
    model_b: str,
    workdir: str,
) -> dict:
    """建一个配对：两条会话 + 一条配对记录。工作目录会被创建出来。"""
    ts = now_iso()
    root = Path(workdir).expanduser() if workdir.strip() else None
    if root is not None:
        root.mkdir(parents=True, exist_ok=True)
        workdir = str(root.resolve())

    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO chat_pairs (username, title, workdir, session_a, session_b, model_a, model_b, peer_budget, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (username, title[:60], workdir, 0, 0, model_a, model_b, 0, ts, ts),
        )
        pair_id = int(cursor.lastrowid)
        session_ids: list[int] = []
        for lane, model in (("a", model_a), ("b", model_b)):
            sid = conn.execute(
                "INSERT INTO chat_sessions (title, username, created_at, updated_at, pair_id, lane)"
                " VALUES (?,?,?,?,?,?)",
                (f"{title[:40]} · {model or lane.upper()}", username, ts, ts, pair_id, lane),
            ).lastrowid
            session_ids.append(int(sid))
        conn.execute(
            "UPDATE chat_pairs SET session_a=?, session_b=? WHERE id=?",
            (session_ids[0], session_ids[1], pair_id),
        )
    if workdir:
        for sid in session_ids:
            _SESSION_DIRS[sid] = Path(workdir)
    return get_pair(pair_id) or {}


def get_pair(pair_id: int) -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM chat_pairs WHERE id=?", (int(pair_id),)).fetchone()
    return _row_dict(row)


def list_pairs(username: str, limit: int = 50) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            """SELECT p.*,
                      (SELECT COUNT(*) FROM chat_messages m WHERE m.session_id IN (p.session_a, p.session_b)) AS message_count,
                      (SELECT COUNT(*) FROM chat_peer_notes n WHERE n.pair_id=p.id) AS note_count
               FROM chat_pairs p WHERE p.username=?
               ORDER BY p.updated_at DESC, p.id DESC LIMIT ?""",
            (username, int(limit)),
        ).fetchall()
    return [dict(r) for r in rows]


def pair_for_session(session_id: int) -> dict | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM chat_sessions WHERE id=?", (int(session_id),)
        ).fetchone()
        if not row or not int(row["pair_id"] or 0):
            return None
        pair = conn.execute(
            "SELECT * FROM chat_pairs WHERE id=?", (int(row["pair_id"]),)
        ).fetchone()
    return _row_dict(pair)


def lane_of_session(session_id: int) -> str:
    with db() as conn:
        row = conn.execute("SELECT lane FROM chat_sessions WHERE id=?", (int(session_id),)).fetchone()
    return str(row["lane"] or "") if row else ""


def peer_session(pair: dict, lane: str) -> int:
    return int(pair["session_b"] if lane == "a" else pair["session_a"])


def peer_lane(lane: str) -> str:
    return "b" if lane == "a" else "a"


def touch(pair_id: int) -> None:
    with db() as conn:
        conn.execute("UPDATE chat_pairs SET updated_at=? WHERE id=?", (now_iso(), int(pair_id)))


def delete_pair(pair_id: int) -> tuple[int, int]:
    pair = get_pair(pair_id)
    if not pair:
        return 0, 0
    _SESSION_DIRS.pop(int(pair["session_a"]), None)
    _SESSION_DIRS.pop(int(pair["session_b"]), None)
    with db() as conn:
        conn.execute("DELETE FROM chat_peer_notes WHERE pair_id=?", (int(pair_id),))
        conn.execute("DELETE FROM chat_pairs WHERE id=?", (int(pair_id),))
    return int(pair["session_a"]), int(pair["session_b"])


# ---------------- 共享工作目录 ----------------

def workdir_for_session(session_id: int) -> Path | None:
    """这条会话该落在哪个目录：配对配了共享目录就用它，否则交给平台设置。"""
    sid = int(session_id or 0)
    if not sid:
        return None
    if sid in _SESSION_DIRS:
        return _SESSION_DIRS[sid]
    pair = pair_for_session(sid)
    value = str((pair or {}).get("workdir") or "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    _SESSION_DIRS[sid] = path
    return path


def remember_workdir(session_id: int, workdir: str) -> None:
    value = str(workdir or "").strip()
    if value:
        _SESSION_DIRS[int(session_id)] = Path(value).expanduser()
    else:
        _SESSION_DIRS.pop(int(session_id), None)


def set_workdir(pair_id: int, workdir: str) -> dict | None:
    """换共享目录：库里改掉，两个会话的进程内缓存也跟着换。"""
    pair = get_pair(pair_id)
    if not pair:
        return None
    value = str(workdir or "").strip()
    root = Path(value).expanduser() if value else None
    if root is not None:
        root.mkdir(parents=True, exist_ok=True)
        value = str(root.resolve())
    with db() as conn:
        conn.execute(
            "UPDATE chat_pairs SET workdir=?, updated_at=? WHERE id=?",
            (value, now_iso(), int(pair_id)),
        )
    for sid in (int(pair["session_a"]), int(pair["session_b"])):
        remember_workdir(sid, value)
    return get_pair(pair_id)


def lane_model(pair: dict | None, lane: str) -> str:
    """这一栏该用哪个模型：建配对时选的那个，下一轮就用它跑。"""
    if not pair:
        return ""
    key = "model_a" if lane == "a" else "model_b"
    return str(pair.get(key) or "").strip()


def set_models(pair_id: int, model_a: str | None = None, model_b: str | None = None) -> dict | None:
    """换某一栏的模型：只改配对记录，两条会话的内容原样保留。

    换模型不等于清空对话——上一轮的进展、共享目录、协同记录都还在，
    新模型进来读得到上下文，接手继续干。
    """
    pair = get_pair(pair_id)
    if not pair:
        return None
    fields: list[str] = []
    values: list[str] = []
    for column, value in (("model_a", model_a), ("model_b", model_b)):
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        fields.append(f"{column}=?")
        values.append(text)
    if not fields:
        return pair
    fields.append("updated_at=?")
    values.append(now_iso())
    values.append(int(pair_id))
    with db() as conn:
        conn.execute(f"UPDATE chat_pairs SET {', '.join(fields)} WHERE id=?", tuple(values))
    updated = get_pair(pair_id) or pair
    # 会话标题里带着模型名，换完顺手对齐，列表里不会还写着旧模型
    for lane in LANES:
        model = lane_model(updated, lane)
        session_id = int(updated["session_a"] if lane == "a" else updated["session_b"])
        title = f"{str(updated.get('title') or '双模型协同')[:40]} · {model or lane.upper()}"
        with db() as conn:
            conn.execute("UPDATE chat_sessions SET title=? WHERE id=?", (title, session_id))
    return updated



# ---------------- 两个模型之间的对话 ----------------

def add_note(pair: dict, from_lane: str, content: str) -> dict:
    text = str(content or "").strip()
    if not text:
        raise ValueError("协同消息不能为空")
    text = text[:NOTE_MAX_CHARS]
    to = peer_lane(from_lane)
    ts = now_iso()
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO chat_peer_notes
               (pair_id, from_lane, to_lane, from_session, to_session, content, status, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                int(pair["id"]),
                from_lane,
                to,
                int(pair["session_a"] if from_lane == "a" else pair["session_b"]),
                int(pair["session_b"] if from_lane == "a" else pair["session_a"]),
                text,
                "pending",
                ts,
            ),
        )
        note_id = int(cursor.lastrowid)
        conn.execute("UPDATE chat_pairs SET updated_at=? WHERE id=?", (ts, int(pair["id"])))
    return get_note(note_id) or {}


def get_note(note_id: int) -> dict | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM chat_peer_notes WHERE id=?", (int(note_id),)).fetchone()
    return _row_dict(row)


def notes(pair_id: int, after: int = 0, limit: int = 200) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM chat_peer_notes WHERE pair_id=? AND id>? ORDER BY id LIMIT ?",
            (int(pair_id), int(after), int(limit)),
        ).fetchall()
    return [dict(r) for r in rows]


def take_pending(session_id: int) -> list[dict]:
    """取出「发给这条会话、还没被看到」的协同消息，并标成已读。

    在每一轮开工前调用：对方说的话会作为上下文进入这一轮的提示词。
    """
    sid = int(session_id or 0)
    if not sid:
        return []
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM chat_peer_notes WHERE to_session=? AND status IN ('pending','delivered') ORDER BY id",
            (sid,),
        ).fetchall()
        if rows:
            conn.execute(
                "UPDATE chat_peer_notes SET status='read' WHERE to_session=? AND status IN ('pending','delivered')",
                (sid,),
            )
    return [dict(r) for r in rows]


def mark_delivered(note_id: int) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE chat_peer_notes SET status='delivered', delivered_at=? WHERE id=? AND status='pending'",
            (now_iso(), int(note_id)),
        )


# ---------------- 互相唤醒的预算 ----------------

def reset_budget(pair_id: int, budget: int = DEFAULT_PEER_BUDGET) -> None:
    with db() as conn:
        conn.execute("UPDATE chat_pairs SET peer_budget=? WHERE id=?", (int(budget), int(pair_id)))


def take_budget(pair_id: int) -> bool:
    """领一次唤醒额度：领到了才允许叫醒同伴，领不到就只入库不打扰。"""
    with db() as conn:
        cursor = conn.execute(
            "UPDATE chat_pairs SET peer_budget=peer_budget-1 WHERE id=? AND peer_budget>0",
            (int(pair_id),),
        )
        return cursor.rowcount > 0


# ---------------- 给模型看的说明 ----------------

def prompt_block(session_id: int) -> str:
    """双模型模式下追加给系统提示的一段：你是谁、同伴是谁、目录在哪、怎么沟通。"""
    pair = pair_for_session(session_id)
    if not pair:
        return ""
    lane = lane_of_session(session_id) or "a"
    mine = _model_name(pair["model_a"] if lane == "a" else pair["model_b"], lane)
    other = _model_name(pair["model_b"] if lane == "a" else pair["model_a"], "b" if lane == "a" else "a")
    shared = pair.get("workdir") or "（未配置，使用平台默认工作目录）"
    return (
        "【双模型协同模式】\n"
        f"- 你是{_side(lane)}「{mine}」，同伴是{_side('b' if lane == 'a' else 'a')}「{other}」。"
        "用户同一句话会同时发给你们两个人，你们在同一份工作上并行推进。\n"
        f"- 共享工作目录：{shared}。双方的命令、脚本、落地文件都在这一个目录里，"
        "交接产物（清单、脚本、中间结果）直接写在这里，在消息里说文件名就行，不要把长内容贴来贴去。\n"
        "- 需要对方配合时用 talk_to_peer 发一句话：讲清要它做什么、产物放哪个文件、什么时候需要。"
        "对方发来的消息会以「同伴」身份出现在你的上下文里，按它的请求做，不要重复它已经做完的部分。\n"
        "- 你每完成一步，平台会自动把这一步写进共享目录的「协同进度」子目录，对方下一轮就能读到；"
        "同伴的进度和它刚改过的文件也会出现在你每一轮的上下文里。所以不要在对话里反复汇报进度、"
        "也不要问对方「你做到哪了」，直接往下做，交接靠文件和 talk_to_peer。\n"
        "- 不要为了对齐、致谢、报平安来回发消息；只在分工、交接、纠错、汇合这几种场合联系对方。"
        "已经有结论就直接往下做。\n"
    )


def _side(lane: str) -> str:
    return "左栏" if lane == "a" else "右栏"


def _model_name(key: str, lane: str) -> str:
    """模型 key 换成用户看得懂的名字：优先用 API 中心里配的显示名。"""
    value = str(key or "").strip()
    if not value:
        return "模型 " + lane.upper()
    with db() as conn:
        row = conn.execute("SELECT name FROM connectors WHERE key=?", (value,)).fetchone()
    return str(row["name"] or value) if row else value


def notes_block(session_id: int) -> str:
    """把「对方刚说的话」整理成一段上下文。没有就返回空串。"""
    items = take_pending(session_id)
    if not items:
        return ""
    lines = ["【同伴模型发给你的消息】"]
    for item in items:
        who = "左栏" if item.get("from_lane") == "a" else "右栏"
        lines.append(f"- {who}（{item.get('created_at', '')}）：{item.get('content', '')}")
    lines.append("按上面的请求去做；已经做完的部分不要重做。")
    return "\n".join(lines)
