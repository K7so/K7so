"""SQLite 持久层：建表、种子数据与通用查询助手。"""
from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable

from .catalog import CONNECTOR_CATALOG
from .config import (
    DB_PATH,
    DEFAULT_ADMIN,
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_USER_AGENT,
    INITIAL_PASSWORD_FILE,
    MEMORY_DIR,
    WORKSPACE_DIR,
    ensure_dirs,
)
from .security import encrypt_secret, hash_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'domain',
    org TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    criticality INTEGER NOT NULL DEFAULT 3,
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    asset_ids_json TEXT NOT NULL DEFAULT '[]',
    profile TEXT NOT NULL DEFAULT 'standard',
    mode TEXT NOT NULL DEFAULT 'active',
    authorization_ref TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER NOT NULL DEFAULT 0,
    stage TEXT DEFAULT '等待调度',
    summary TEXT DEFAULT '',
    stats_json TEXT DEFAULT '{}',
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_logs_scan ON scan_logs(scan_id, id);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    asset_id INTEGER,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    cvss REAL DEFAULT 0,
    confidence TEXT DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    dedupe_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);

CREATE TABLE IF NOT EXISTS connectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    vendor TEXT DEFAULT '',
    category TEXT NOT NULL,
    description TEXT DEFAULT '',
    auth_type TEXT NOT NULL,
    base_url TEXT DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT DEFAULT '{}',
    secret_enc TEXT DEFAULT '',
    docs_url TEXT DEFAULT '',
    last_check_at TEXT,
    last_check_ok INTEGER,
    last_check_msg TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'html',
    path TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT DEFAULT '',
    ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(id);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL DEFAULT '新会话',
    username TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    tool_name TEXT DEFAULT '',
    tool_args TEXT DEFAULT '',
    level TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_id, id);

CREATE TABLE IF NOT EXISTS chat_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    username TEXT DEFAULT '',
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL DEFAULT '{}',
    summary TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    decided_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_chat_actions_session ON chat_actions(session_id, id);

CREATE TABLE IF NOT EXISTS chat_choices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    username TEXT DEFAULT '',
    question TEXT NOT NULL DEFAULT '',
    options_json TEXT NOT NULL DEFAULT '[]',
    allow_custom INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    chosen TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    decided_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_chat_choices_session ON chat_choices(session_id, id);

-- 同一处敏感信息在同一会话里只问一次：用户点头后记在这里，后续直接放行
CREATE TABLE IF NOT EXISTS chat_grants (
    session_id INTEGER NOT NULL,
    signature TEXT NOT NULL,
    scope TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (session_id, signature)
);

-- 能力覆盖台账：用户勾选的每一项能力，在这个会话里到底验没验、结论是什么。
-- 「自动测试选中的能力」靠它算剩余量，不靠模型自己报进度。
CREATE TABLE IF NOT EXISTS coverage_marks (
    session_id INTEGER NOT NULL,
    cap_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'inconclusive',
    note TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (session_id, cap_key)
);

-- K7so工具：用户导入的本地工具（python / exe / jar / go），点一下就能跑起来。
-- 文件落在 data/tools/ 下，库里只记文件名 + 摘要，运行前会校验路径没有被拼接出去。
CREATE TABLE IF NOT EXISTS kits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'exe',
    filename TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    sha256 TEXT DEFAULT '',
    args TEXT DEFAULT '',
    note TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    last_run_at TEXT DEFAULT '',
    run_count INTEGER DEFAULT 0
);

-- 每次点开工具都留一条运行记录：谁、什么时候、退出码、输出（截断）
CREATE TABLE IF NOT EXISTS kit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kit_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    command TEXT DEFAULT '',
    output TEXT DEFAULT '',
    returncode INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT DEFAULT ''
);

-- 资产监管：一次导入 + 一轮收集形成一个「模块」，用户自己命名，带日期。
-- 比较两个模块就知道这段时间多出了哪些域名。
CREATE TABLE IF NOT EXISTS asset_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_by TEXT DEFAULT '',
    sources TEXT DEFAULT '',
    seed_count INTEGER DEFAULT 0,
    host_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ready',
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    kind TEXT DEFAULT 'domain',
    ip TEXT DEFAULT '',
    parent TEXT DEFAULT '',
    source TEXT DEFAULT '',
    note TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(module_id, host)
);

CREATE INDEX IF NOT EXISTS idx_asset_hosts_module ON asset_hosts(module_id);
CREATE INDEX IF NOT EXISTS idx_kit_runs_kit ON kit_runs(kit_id);

-- 双模型协同：一对会话 = 两条普通会话（各自跑自己的 Agent）+ 一份共享工作目录
CREATE TABLE IF NOT EXISTS chat_pairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    workdir TEXT NOT NULL DEFAULT '',
    session_a INTEGER NOT NULL,
    session_b INTEGER NOT NULL,
    model_a TEXT NOT NULL DEFAULT '',
    model_b TEXT NOT NULL DEFAULT '',
    -- 每次用户下发任务，允许互相唤醒的次数：防止两个模型你来我往把额度烧穿
    peer_budget INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_pairs_user ON chat_pairs(username, id);

-- 两个模型之间的对话：谁发给谁、说了什么、对方有没有看到
CREATE TABLE IF NOT EXISTS chat_peer_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pair_id INTEGER NOT NULL,
    from_lane TEXT NOT NULL DEFAULT 'a',
    to_lane TEXT NOT NULL DEFAULT 'b',
    from_session INTEGER NOT NULL DEFAULT 0,
    to_session INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    -- pending：已入库、对方还没看到；delivered：已塞进对方正在跑的那一轮；read：对方已经据此行动
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    delivered_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_chat_peer_notes_pair ON chat_peer_notes(pair_id, id);

-- 模型记忆空间：一个模型一份长期记忆（就是一个目录），互不串味。
-- 两个模型各自测试时读自己的记忆，同一个平台可以并存多份。
CREATE TABLE IF NOT EXISTS memory_spaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    dir TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_spaces_user ON memory_spaces(username, id);
"""

DEFAULT_SETTINGS: dict[str, str] = {
    # 授权范围（scope_domains / scope_cidrs / allow_private / require_authorization）
    # 已整体取消：登录时确认的免责声明就是授权。老库里残留的这些键不再读取，
    # init_db 时顺手清掉，免得设置页或接口再把它们带出来。
    "safe_mode": "true",
    "max_concurrency": "24",
    "request_timeout": "8",
    "user_agent": DEFAULT_USER_AGENT,
    "sensitive_path_checks": "true",
    "ai_enabled": "true",
    "memory_path": str(MEMORY_DIR),
    "work_dir": str(WORKSPACE_DIR),
    "capabilities": "[]",
    # 「自动迭代」已下线：它和「自动继续」是同一件事，只留后者。
    "capability_switches": (
        '{"confirm_actions": true, "ask_sensitive": true, "ask_delete": true}'
    ),
    # 能力权重：1-5，越大越先测；没设过的按 5（满格）
    "capability_weights": "{}",
    # 权重表结构版本：2 = 合并重复能力项、默认满格。老库第一次启动时清一次旧权重，
    # 否则升级后大家看到的还是按老默认 3 存下来的数字。
    "weights_schema": "2",
    # 自动继续：一轮跑完，平台把这句预设话原样当成用户消息发出去，让模型接着干。
    # 次数不设上限（用户要求），靠「连续空转」和用户手动停止来收。
    "auto_continue": "false",
    "auto_continue_text": "继续",
}


RETIRED_SETTINGS: tuple[str, ...] = (
    "scope_domains",
    "scope_cidrs",
    "allow_private",
    "require_authorization",
)


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # journal_mode 是数据库的持久属性，连一次设一次纯属浪费（Windows 上每次几十毫秒）。
    # 这里只留每连接必须的 busy_timeout，WAL 在 init_db 里设一次就够。
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def rows(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def _migrate_findings(conn: sqlite3.Connection) -> None:
    """为漏洞表补充按 URL 归档所需的字段。"""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for name, ddl in (
        ("url", "TEXT DEFAULT ''"),
        ("request_packet", "TEXT DEFAULT ''"),
        ("response_packet", "TEXT DEFAULT ''"),
        ("capability", "TEXT DEFAULT ''"),
        # 复现步骤（JSON）：每条漏洞「怎么一步步打出来的」，含每步目的、看到了什么、推出什么
        ("steps", "TEXT DEFAULT ''"),
    ):
        if name not in existing:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url)")


def _migrate_chat_messages(conn: sqlite3.Connection) -> None:
    """进度条目要记住自己的等级：冷却期内被降级的关键说法，刷新后不能又变回高亮。"""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(chat_messages)").fetchall()}
    if "level" not in existing:
        conn.execute("ALTER TABLE chat_messages ADD COLUMN level TEXT DEFAULT ''")


def _migrate_chat_sessions(conn: sqlite3.Connection) -> None:
    """双模型协同：一条会话要知道自己属于哪个配对、是左栏还是右栏。

    单模型会话这两列留空，老库升级后行为不变。
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(chat_sessions)").fetchall()}
    for name, ddl in (
        ("pair_id", "INTEGER DEFAULT 0"),
        ("lane", "TEXT DEFAULT ''"),
    ):
        if name not in existing:
            conn.execute(f"ALTER TABLE chat_sessions ADD COLUMN {name} {ddl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_sessions_pair ON chat_sessions(pair_id)")


def _migrate_chat_pairs(conn: sqlite3.Connection) -> None:
    """配对表要知道每一栏用哪份记忆空间。

    0 表示「跟随平台默认记忆」：老库升级后两栏都用默认那一份，行为不变。
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(chat_pairs)").fetchall()}
    for name, ddl in (
        ("memory_a", "INTEGER NOT NULL DEFAULT 0"),
        ("memory_b", "INTEGER NOT NULL DEFAULT 0"),
        # 这一栏参不参与：关掉一栏就只剩单模型干活，另一栏既不接话也不被唤醒
        ("active_a", "INTEGER NOT NULL DEFAULT 1"),
        ("active_b", "INTEGER NOT NULL DEFAULT 1"),
    ):
        if name not in existing:
            conn.execute(f"ALTER TABLE chat_pairs ADD COLUMN {name} {ddl}")


def _initial_admin_password() -> str:
    """首次启动的管理员口令：环境变量优先，没设就随机生成一个。

    仓库里不留固定口令——公开之后 `admin/admin123` 这种默认值等于给所有人
    发了一把钥匙。生成的随机口令写进 data/初始口令.txt（已被 .gitignore 排除），
    同时打到启动日志里；要固定口令的部署场景设 K7so_ADMIN_PASSWORD 即可。
    """
    if DEFAULT_ADMIN_PASSWORD:
        return DEFAULT_ADMIN_PASSWORD
    password = secrets.token_urlsafe(9)
    try:
        INITIAL_PASSWORD_FILE.write_text(
            "K7so 初始口令（首次启动随机生成，登录后请修改）\n"
            f"账号：{DEFAULT_ADMIN}\n"
            f"口令：{password}\n",
            encoding="utf-8",
        )
        try:
            INITIAL_PASSWORD_FILE.chmod(0o600)
        except OSError:
            pass
    except OSError:
        pass
    print(
        f"[K7so] 首次启动，已生成管理员口令：{password}\n"
        f"        已写入 {INITIAL_PASSWORD_FILE}，登录后请尽快修改（或用 K7so_ADMIN_PASSWORD 指定固定口令）。",
        flush=True,
    )
    return password


def init_db() -> None:
    ensure_dirs()
    invalidate_settings()
    with db() as conn:
        # 只在这里设一次：WAL 会写进库文件，后续连接自动继承
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _migrate_findings(conn)
        _migrate_chat_messages(conn)
        _migrate_chat_sessions(conn)
        _migrate_chat_pairs(conn)

        user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if user_count == 0:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                (DEFAULT_ADMIN, hash_password(_initial_admin_password()), "admin", now_iso()),
            )

        connector_count = conn.execute("SELECT COUNT(*) AS c FROM connectors").fetchone()["c"]
        existing_keys = set()
        if connector_count:
            existing_keys = {r["key"] for r in conn.execute("SELECT key FROM connectors").fetchall()}
        if connector_count == 0 or len(existing_keys) < len(CONNECTOR_CATALOG):
            ts = now_iso()
            for item in CONNECTOR_CATALOG:
                if item["key"] in existing_keys:
                    continue
                defaults = {f["key"]: f.get("default", "") for f in item.get("fields", [])}
                conn.execute(
                    """INSERT INTO connectors
                       (key, name, vendor, category, description, auth_type, base_url,
                        enabled, config_json, secret_enc, docs_url, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        item["key"],
                        item["name"],
                        item.get("vendor", ""),
                        item["category"],
                        item.get("description", ""),
                        item["auth_type"],
                        item.get("base_url", ""),
                        1,
                        json.dumps(defaults, ensure_ascii=False),
                        "",
                        item.get("docs_url", ""),
                        ts,
                        ts,
                    ),
                )

        # 目录回填：老库里留空的地址与模型名跟随目录补全，用户已填过的值不覆盖。
        for item in CONNECTOR_CATALOG:
            row = conn.execute("SELECT * FROM connectors WHERE key=?", (item["key"],)).fetchone()
            if not row:
                continue
            ts = now_iso()
            if (
                row["name"] != item["name"]
                or row["description"] != item.get("description", "")
                or row["docs_url"] != item.get("docs_url", "")
            ):
                conn.execute(
                    "UPDATE connectors SET name=?, vendor=?, description=?, docs_url=?, updated_at=? WHERE key=?",
                    (
                        item["name"],
                        item.get("vendor", ""),
                        item.get("description", ""),
                        item.get("docs_url", ""),
                        ts,
                        item["key"],
                    ),
                )
            if not (row["base_url"] or "").strip() and item.get("base_url"):
                conn.execute(
                    "UPDATE connectors SET base_url=?, updated_at=? WHERE key=?",
                    (item["base_url"], ts, item["key"]),
                )
            try:
                config = json.loads(row["config_json"] or "{}")
            except json.JSONDecodeError:
                config = {}
            if not isinstance(config, dict):
                config = {}
            changed = False
            for field in item.get("fields", []):
                if not str(config.get(field["key"]) or "").strip() and field.get("default"):
                    config[field["key"]] = field["default"]
                    changed = True
            if changed:
                conn.execute(
                    "UPDATE connectors SET config_json=?, updated_at=? WHERE key=?",
                    (json.dumps(config, ensure_ascii=False), ts, item["key"]),
                )

        existing = {r["key"] for r in conn.execute("SELECT key FROM settings").fetchall()}
        # 授权范围那套键已下线，老库里的残留直接清掉（不影响任何逻辑，只是别让它们再出现）
        for retired in RETIRED_SETTINGS:
            if retired in existing:
                conn.execute("DELETE FROM settings WHERE key=?", (retired,))
                existing.discard(retired)
        # 权重表升到 schema 2（能力项合并 + 默认满格）：老库一次清空旧权重
        if existing and "weights_schema" not in existing:
            conn.execute("DELETE FROM settings WHERE key='capability_weights'")
            existing.discard("capability_weights")
        for key, value in DEFAULT_SETTINGS.items():
            if key not in existing:
                conn.execute("INSERT INTO settings (key, value) VALUES (?,?)", (key, value))
        # 老库升级：只在第一次初始化时补默认目录；用户后来主动清空的不再覆盖
        if "paths_initialized" not in existing:
            for key, value in (("memory_path", str(MEMORY_DIR)), ("work_dir", str(WORKSPACE_DIR))):
                conn.execute(
                    "UPDATE settings SET value=? WHERE key=? AND TRIM(COALESCE(value,''))=''",
                    (value, key),
                )
            conn.execute("INSERT INTO settings (key, value) VALUES ('paths_initialized','1')")
    # 种子数据写完，把启动时可能缓存的空值丢掉
    invalidate_settings()


# 设置是读得最勤的一张表：构建一次对话上下文要读几十次（目录、记忆路径、开关、范围）。
# 每次开会话开一个 SQLite 连接，光这一项就吃掉两三百毫秒。改成进程内缓存，
# 写入 set_settings / init_db 时失效——单进程 uvicorn 下语义不变。
_SETTINGS_CACHE: dict[str, str] | None = None


def get_settings() -> dict[str, str]:
    global _SETTINGS_CACHE
    if _SETTINGS_CACHE is None:
        with db() as conn:
            _SETTINGS_CACHE = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}
    return dict(_SETTINGS_CACHE)


def invalidate_settings() -> None:
    global _SETTINGS_CACHE
    _SETTINGS_CACHE = None


def setting_bool(key: str, default: bool = False) -> bool:
    value = get_settings().get(key)
    if value is None:
        return default
    return str(value).lower() in ("1", "true", "yes", "on")


def set_settings(values: dict[str, Any]) -> None:
    with db() as conn:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
    invalidate_settings()


def audit(username: str, action: str, detail: str = "", ip: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_logs (ts, username, action, detail, ip) VALUES (?,?,?,?,?)",
            (now_iso(), username, action, detail, ip),
        )


def seed_connector_secret(key: str, secret: str) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE connectors SET secret_enc=?, updated_at=? WHERE key=?",
            (encrypt_secret(secret), now_iso(), key),
        )
