"""K7so工具：导入本地工具（Python / EXE / JAR / Go），在界面上点开就能跑。

只做三件事：把文件安全地落到 data/tools/、按类型拼出启动命令、把输出回传给界面。
路径一律先拼再校验，绝不允许顺着 ../ 跑到工具目录之外。
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from ..config import DATA_DIR
from ..db import db, now_iso
from .uploads import UploadSink, safe_filename, unique_path

TOOLS_DIR = DATA_DIR / "tools"

KIT_KINDS: dict[str, str] = {
    "python": "Python 脚本",
    "exe": "Windows 程序",
    "jar": "Java 包",
    "go": "Go 程序",
}
KIND_BY_EXT: dict[str, str] = {".py": "python", ".exe": "exe", ".jar": "jar"}

MAX_UPLOAD_BYTES = 300 * 1024 * 1024
MAX_OUTPUT_CHARS = 40000

_RUNS: dict[int, dict[str, Any]] = {}
_RUN_LOCK = threading.Lock()


def ensure_tools_dir() -> Path:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    return TOOLS_DIR


def detect_kind(filename: str, hint: str = "") -> str:
    hint = (hint or "").strip().lower()
    if hint in KIT_KINDS:
        return hint
    return KIND_BY_EXT.get(Path(filename).suffix.lower(), "exe")


def make_sink(filename: str) -> UploadSink:
    """给 API 层用的落盘器：工具都放进 data/tools/。"""
    ensure_tools_dir()
    return UploadSink(TOOLS_DIR, filename, MAX_UPLOAD_BYTES)


def create_kit(name: str, kind: str, path: Path, size: int, sha: str,
               note: str = "", args: str = "", username: str = "") -> dict[str, Any]:
    ts = now_iso()
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO kits (name, kind, filename, size, sha256, args, note,
                                 created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (name or path.stem, kind, path.name, size, sha, args, note, username, ts),
        )
        kit_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM kits WHERE id = ?", (kit_id,)).fetchone()
    return dict(row) if row else {}


def list_kits() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """SELECT k.*, (SELECT status FROM kit_runs r WHERE r.kit_id = k.id
                             ORDER BY r.id DESC LIMIT 1) AS last_status
               FROM kits k ORDER BY k.id DESC"""
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["kind_label"] = KIT_KINDS.get(str(item.get("kind")), "工具")
        item["exists"] = (TOOLS_DIR / str(item.get("filename"))).exists()
        item["running"] = running_run_id(int(item["id"])) is not None
        out.append(item)
    return out


def _decode(raw: bytes) -> str:
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _command(kit: dict[str, Any]) -> tuple[list[str], str]:
    """按类型拼启动命令；返回 (命令, 错误说明)。"""
    path = (TOOLS_DIR / str(kit.get("filename"))).resolve()
    try:
        path.relative_to(TOOLS_DIR.resolve())
    except ValueError:
        return [], "文件路径不在工具目录内，已拒绝执行"
    if not path.exists():
        return [], "文件不在了，重新导入一次"

    raw_args = str(kit.get("args") or "").strip()
    args = shlex.split(raw_args, posix=False) if raw_args else []
    kind = str(kit.get("kind") or "exe")

    if kind == "python":
        return [sys.executable, str(path), *args], ""
    if kind == "jar":
        java = shutil.which("java")
        if not java:
            home = os.environ.get("JAVA_HOME", "")
            guess = Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")
            java = str(guess) if home and guess.exists() else ""
        if not java:
            return [], "没找到 java：装个 JRE/JDK，或把 java 加进 PATH 再来"
        return [java, "-jar", str(path), *args], ""
    return [str(path), *args], ""


def _pump(proc: subprocess.Popen, run_id: int, kit_id: int, command: str) -> None:
    buffer: list[str] = []
    size = 0
    stream = proc.stdout
    if stream is not None:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            text = _decode(chunk)
            buffer.append(text)
            size += len(text)
            if size > MAX_OUTPUT_CHARS * 2:
                joined = "".join(buffer)
                joined = joined[-MAX_OUTPUT_CHARS:]
                buffer = [joined]
                size = len(joined)
            with _RUN_LOCK:
                state = _RUNS.get(run_id)
                if state is not None:
                    state["output"] = "".join(buffer)[-MAX_OUTPUT_CHARS:]
    code = proc.wait()
    output = "".join(buffer)[-MAX_OUTPUT_CHARS:]
    finished = now_iso()
    with _RUN_LOCK:
        state = _RUNS.get(run_id)
        if state is not None:
            state["status"] = "finished"
            state["returncode"] = code
            state["output"] = output
            state["finished_at"] = finished
    with db() as conn:
        conn.execute(
            "UPDATE kit_runs SET status=?, output=?, returncode=?, finished_at=? WHERE id=?",
            ("finished", output, code, finished, run_id),
        )
        conn.execute(
            "UPDATE kits SET last_run_at=?, run_count=run_count+1 WHERE id=?",
            (finished, kit_id),
        )


def launch(kit: dict[str, Any], username: str = "") -> dict[str, Any]:
    kit_id = int(kit["id"])
    if running_run_id(kit_id) is not None:
        return {"ok": False, "error": "这个工具上一次还在跑，先等它结束或点停止"}

    command, error = _command(kit)
    if error:
        return {"ok": False, "error": error}

    cwd = (TOOLS_DIR / str(kit.get("filename"))).resolve().parent
    try:
        proc = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except OSError as exc:
        return {"ok": False, "error": f"启动失败：{exc}"}

    started = now_iso()
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO kit_runs (kit_id, status, command, output, started_at)
               VALUES (?,?,?,?,?)""",
            (kit_id, "running", " ".join(command), "", started),
        )
        run_id = int(cur.lastrowid)

    with _RUN_LOCK:
        _RUNS[run_id] = {
            "id": run_id,
            "kit_id": kit_id,
            "status": "running",
            "command": " ".join(command),
            "output": "",
            "returncode": None,
            "started_at": started,
            "finished_at": "",
            "proc": proc,
            "by": username,
        }

    threading.Thread(
        target=_pump, args=(proc, run_id, kit_id, " ".join(command)), daemon=True
    ).start()
    return {"ok": True, "run_id": run_id, "command": " ".join(command), "pid": proc.pid}


def running_run_id(kit_id: int) -> int | None:
    with _RUN_LOCK:
        for run_id, state in _RUNS.items():
            if state["kit_id"] == kit_id and state["status"] == "running":
                return run_id
    return None


def run_state(run_id: int) -> dict[str, Any] | None:
    with _RUN_LOCK:
        state = _RUNS.get(run_id)
        if state is not None:
            return {k: v for k, v in state.items() if k != "proc"}
    with db() as conn:
        row = conn.execute("SELECT * FROM kit_runs WHERE id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


def latest_run(kit_id: int) -> dict[str, Any] | None:
    running = running_run_id(kit_id)
    if running is not None:
        return run_state(running)
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM kit_runs WHERE kit_id = ? ORDER BY id DESC LIMIT 1", (kit_id,)
        ).fetchone()
    return dict(row) if row else None


def stop(kit_id: int) -> dict[str, Any]:
    run_id = running_run_id(kit_id)
    if run_id is None:
        return {"ok": False, "error": "这个工具当前没在跑"}
    with _RUN_LOCK:
        state = _RUNS.get(run_id) or {}
        proc = state.get("proc")
    if proc is None:
        return {"ok": False, "error": "进程句柄丢了，可能已经结束"}
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=15,
            )
        else:
            proc.terminate()
    except Exception as exc:  # noqa: BLE001 - 停止失败要如实回报
        return {"ok": False, "error": f"停止失败：{exc}"}
    return {"ok": True, "run_id": run_id}


def delete_kit(kit_id: int, delete_file: bool = True) -> dict[str, Any]:
    if running_run_id(kit_id) is not None:
        return {"ok": False, "error": "还在运行，先停止再删"}
    with db() as conn:
        row = conn.execute("SELECT * FROM kits WHERE id = ?", (kit_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "工具不存在"}
        filename = str(row["filename"])
        conn.execute("DELETE FROM kit_runs WHERE kit_id = ?", (kit_id,))
        conn.execute("DELETE FROM kits WHERE id = ?", (kit_id,))
    if delete_file:
        target = TOOLS_DIR / filename
        try:
            if target.exists():
                target.unlink()
        except OSError:
            pass
    return {"ok": True}


def update_kit(kit_id: int, patch: dict[str, Any]) -> dict[str, Any]:
    fields = {}
    for key in ("name", "args", "note", "kind"):
        if key in patch and patch[key] is not None:
            value = str(patch[key])
            if key == "kind" and value not in KIT_KINDS:
                continue
            fields[key] = value[:2000] if key in ("args", "note") else value[:200]
    if not fields:
        return {"ok": False, "error": "没有可更新的字段"}
    sets = ", ".join(f"{key} = ?" for key in fields)
    with db() as conn:
        conn.execute(f"UPDATE kits SET {sets} WHERE id = ?", (*fields.values(), kit_id))
        row = conn.execute("SELECT * FROM kits WHERE id = ?", (kit_id,)).fetchone()
    return {"ok": True, "kit": dict(row) if row else None}


def get_kit(kit_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM kits WHERE id = ?", (kit_id,)).fetchone()
    return dict(row) if row else None
