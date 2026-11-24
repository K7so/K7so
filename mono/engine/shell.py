"""命令执行能力：真的能动手，而不只是查平台自己的数据。

三件事：
    run_command / run_script  —— shell 与 Python，拿得到 stdout、stderr、退出码；
    http_request             —— 内置 HTTP 客户端，等价 curl，并顺手给出请求包/响应包；
    urls_in_text             —— 从命令里挑出目标地址，供上层做留痕与展示。

安全边界：只拦「明确不可逆破坏」的命令（格式化、删除系统目录、关机、改引导），
输出统一截断，超时统一 kill，不留下挂起的子进程。
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..config import DEFAULT_USER_AGENT, env

MAX_OUTPUT_CHARS = int(env("CMD_OUTPUT_CHARS", "18000"))
# 一条命令能跑多久：默认放到跟卡死阈值同一个量级（300 秒），
# 真正的止损靠「多久没有新输出」来判断，而不是一刀切的总时长——
# 边跑边出输出的长任务（扫描、批量探测）不该被总时长掐死。
DEFAULT_TIMEOUT = int(env("CMD_TIMEOUT", "300"))
MAX_TIMEOUT = int(env("CMD_TIMEOUT_MAX", "900"))
# 连续多久没有新输出就判定卡死（与 agent 的步骤看门狗同一个口径）
STALL_SECONDS = int(env("STEP_STALL_SECONDS", "300"))
HTTP_BODY_CHARS = int(env("HTTP_BODY_CHARS", "14000"))
PACKET_CHARS = int(env("HTTP_PACKET_CHARS", "6000"))

# 这些命令不可能"只读验证"能用到，做了就是不可逆破坏：直接拒绝，不执行、不弹确认
BLOCKED_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"rm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+/(\s|$|\*)", "删除根目录"),
    (r"rm\s+-rf?\s+/(\s|$)", "删除根目录"),
    (r"\bmkfs(\.\w+)?\b", "格式化文件系统"),
    (r"\bdiskpart\b", "磁盘分区操作"),
    (r"format\s+[a-zA-Z]:", "格式化磁盘"),
    (r"\bshutdown\b", "关机"),
    (r"\breboot\b|\bpoweroff\b|\bhalt\b", "重启/关机"),
    (r"\bdel\s+/[a-zA-Z]*[sf][a-zA-Z]*\s+[a-zA-Z]:\\", "删除系统盘文件"),
    (r"\brd\s+/s\s+/q\s+[a-zA-Z]:\\?\s*$", "删除系统盘目录"),
    (r"remove-item\s+.*-recurse.*-force.*[a-zA-Z]:\\(\s|$)", "删除系统盘目录"),
    (r":\s*\(\s*\)\s*\{.*\};\s*:", "fork 炸弹"),
    (r"\breg\s+delete\s+hklm", "删除系统注册表"),
    (r"\bvssadmin\s+delete\b", "删除卷影副本"),
    (r"\bbcdedit\b", "修改启动配置"),
    (r"chmod\s+-R\s+777\s+/\s*$", "全盘权限放开"),
    (r">\s*/dev/sd[a-z]", "直写磁盘设备"),
)

# 命令里出现这些就意味着在读凭据文件：和 read_file 一样要先问用户
SENSITIVE_SHELL_HINTS: tuple[str, ...] = (
    ".env",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".git-credentials",
    ".npmrc",
    ".netrc",
    ".htpasswd",
    "credentials",
    "shadow",
    "/etc/passwd",
    "wallet.dat",
)

URL_PATTERN = re.compile(r"https?://[^\s\"'`<>|;]+", re.I)
# curl/wget 里常见的不带协议的写法：curl example.com、curl -X POST 1.2.3.4:8080
BARE_HOST_PATTERN = re.compile(
    r"(?:^|\s)(?:curl|wget|nmap|nc|http|https)\s+(?:-\S+\s+)*([a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?::\d+)?)",
    re.I,
)


def shell_prefix() -> list[str]:
    """真正执行命令的解释器；可用 K7so_SHELL 覆盖（例如 pwsh -Command），兼容旧的 MONO_SHELL。"""
    override = (env("SHELL") or "").strip()
    if override:
        return override.split()
    if os.name == "nt":
        return ["cmd", "/d", "/c"]
    return ["/bin/sh", "-c"]


def _decode(data: bytes) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "gbk", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _clip(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    """输出太长时保留头尾：开头有命令回显，结尾有报错。"""
    if len(text) <= limit:
        return text, False
    head = limit * 2 // 3
    tail = limit - head
    return text[:head] + f"\n…（中间省略 {len(text) - limit} 字符）…\n" + text[-tail:], True


# 删除类动作：不直接拒绝，交给上层问一次（用户可以在「操作询问」里关掉这项）
DELETE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?:^|[\s;&|(`])rm\s+(?:-[^\s]+\s+)*[^\s-]", "删除文件或目录"),
    (r"(?:^|[\s;&|(`])rmdir\s", "删除目录"),
    (r"(?:^|[\s;&|(`])rd\s+(?:/[a-z]\s+)*[^\s]", "删除目录"),
    (r"(?:^|[\s;&|(`])unlink\s", "删除文件"),
    (r"(?:^|[\s;&|(`])shred\s", "粉碎文件"),
    (r"\bgit\s+clean\b", "清理工作区文件"),
    (r"\bfind\b[^\n]*-delete\b", "批量删除文件"),
    (r"\bdrop\s+(?:table|database|schema)\b", "删库删表"),
    (r"\btruncate\s+table\b", "清空数据表"),
    (r"\bdelete\s+from\s+\w+", "删除数据记录"),
)

# Windows cmd 的删除命令，只在 shell 里判定（Python 代码里的 `del x` 是删变量，不算）
SHELL_DELETE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?:^|[\s;&|(`])del(?:ete)?\s", "删除文件"),
    (r"(?:^|[\s;&|(`])erase\s", "删除文件"),
    (r"(?:^|[\s;&|(`])deltree\s", "删除目录"),
    (r"\bremove-item\b", "删除文件"),
)

# Python 代码里的删除动作
PY_DELETE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bshutil\.rmtree\b", "删除目录"),
    (r"\bos\.(?:remove|unlink|rmdir|removedirs)\b", "删除文件"),
    (r"\.unlink\s*\(", "删除文件"),
    (r"\bsubprocess\.[a-z]+\([^)]*\brm\b", "删除文件"),
)


def blocked_reason(command: str) -> str:
    text = str(command or "")
    for pattern, label in BLOCKED_PATTERNS:
        if re.search(pattern, text, re.I):
            return f"这条命令属于「{label}」，会造成不可逆破坏，平台不会执行"
    return ""


def delete_reason(command: str, kind: str = "shell") -> str:
    """命令/脚本里是否包含删除动作；返回中文说明，空字符串表示没有。

    kind: shell 走完整命令规则，python 只看代码里的删除调用。
    """
    text = str(command or "")
    patterns = list(DELETE_PATTERNS)
    patterns += PY_DELETE_PATTERNS if kind == "python" else SHELL_DELETE_PATTERNS
    for pattern, label in patterns:
        if re.search(pattern, text, re.I):
            return label
    return ""


def touches_sensitive_file(command: str) -> bool:
    text = str(command or "").lower()
    return any(hint in text for hint in SENSITIVE_SHELL_HINTS)


def urls_in_text(command: str) -> list[str]:
    """从命令/脚本里挑出目标地址（留痕与展示用，授权已由免责声明覆盖）。"""
    text = str(command or "")
    found = [match.group(0).rstrip(".,;)") for match in URL_PATTERN.finditer(text)]
    found += [f"http://{match.group(1)}" for match in BARE_HOST_PATTERN.finditer(text)]
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique[:20]


def _python_bin() -> str:
    """平台自己就跑在虚拟环境里，直接用这个解释器，环境一定是对的。"""
    return sys.executable or ("python" if os.name == "nt" else "python3")


PY_DIRECT = re.compile(r"^\s*(?:python3?|py)(?:\.exe)?(\s+.*)?$", re.I | re.S)
SHELL_CHARS = ("&", "|", ">", "<", "%", "!")


def _strip_quotes(text: str) -> str:
    value = str(text or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _direct_argv(command: str) -> list[str] | None:
    """`python x.py` 这类不经过 shell，直接起解释器：引号、路径、编码都不会被 cmd 吃掉。"""
    match = PY_DIRECT.match(command)
    if not match:
        return None
    rest = (match.group(1) or "").strip()
    if rest and any(char in rest for char in SHELL_CHARS):
        return None  # 带管道/重定向/变量展开，还是交给 shell
    if not rest:
        return [_python_bin()]
    try:
        parts = shlex.split(rest, posix=(os.name != "nt"))
    except ValueError:
        return None
    if os.name == "nt":
        parts = [_strip_quotes(part) for part in parts]
    return [_python_bin(), *parts]


def _env_for(cwd: Path) -> dict[str, str]:
    environ = os.environ.copy()
    environ.setdefault("PYTHONIOENCODING", "utf-8")
    environ.setdefault("PYTHONUTF8", "1")
    environ["K7so_WORKSPACE"] = str(cwd)
    # 让命令里直接写 python / pip 时也用平台解释器
    scripts = Path(_python_bin()).parent
    if scripts.is_dir():
        environ["PATH"] = str(scripts) + os.pathsep + environ.get("PATH", "")
    return environ


# 正在跑的子进程：用户点「停止」时把它们一起收掉，别让 curl / nmap 在后台继续跑
_RUNNING: "set[subprocess.Popen]" = set()
_RUNNING_LOCK = threading.Lock()


def terminate_all() -> int:
    """终止所有仍在运行的命令与脚本，返回被终止的进程数。"""
    with _RUNNING_LOCK:
        procs = list(_RUNNING)
    killed = 0
    for proc in procs:
        try:
            if proc.poll() is None:
                proc.kill()
                killed += 1
        except OSError:
            continue
    return killed


def _kill_tree(proc: subprocess.Popen) -> None:
    """掐掉一个进程；Windows 上连带子进程（python 起的 curl / 子脚本）一起收。

    只 kill 父进程的话，子进程会被留下继续跑，既占资源又让控制台一直「没结束」。
    """
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        if proc.poll() is None:
            proc.kill()
    except OSError:
        pass


def _execute(argv: list[str], cwd: Path, timeout: int, stall: int = 0) -> dict[str, Any]:
    """跑一个子进程，同时盯着它「还在不在动」。

    两把尺子：
    - **总时长** ``timeout``：硬上限，到点收；
    - **静默时长** ``stall``：连续这么久一个字节输出都没有、进程却还活着，判卡死。

    之所以要分开：一条边跑边打印的扫描命令跑 5 分钟是正常的，一条 20 秒没反应的
    命令基本就是卡住了。以前只有「总时长」一个开关，短了会误杀长任务，长了会干等。
    """
    started = time.time()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_env_for(cwd),
            creationflags=flags,
        )
    except FileNotFoundError as exc:
        return {"ok": False, "error": f"解释器不可用：{exc}", "timeout": False}
    except OSError as exc:
        return {"ok": False, "error": f"启动失败：{exc}", "timeout": False}
    with _RUNNING_LOCK:
        _RUNNING.add(proc)

    buffers: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
    guard = threading.Lock()
    last_output = {"at": time.time()}

    def pump(stream: Any, slot: str) -> None:
        try:
            while True:
                # read1 才是「有多少拿多少」；read(n) 会一直等够 n 字节，
                # 那样少量输出就记不到，活动检测会误判成卡死
                block = stream.read1(65536) if hasattr(stream, "read1") else stream.read(4096)
                if not block:
                    break
                with guard:
                    buffers[slot].extend(block)
                    last_output["at"] = time.time()
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    readers = [
        threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True),
    ]
    for reader in readers:
        reader.start()

    stall_limit = float(stall or STALL_SECONDS)
    timed_out = False
    stalled = False
    try:
        while True:
            if proc.poll() is not None:
                break
            now = time.time()
            if now - started > timeout:
                timed_out = True
                _kill_tree(proc)
                break
            with guard:
                quiet = now - last_output["at"]
            # 进程还活着却一直没有新输出：这不叫「在跑」，叫卡住
            if quiet > stall_limit:
                stalled = True
                _kill_tree(proc)
                break
            time.sleep(0.2)
    finally:
        for reader in readers:
            reader.join(timeout=5)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        with _RUNNING_LOCK:
            _RUNNING.discard(proc)
    out = bytes(buffers["out"])
    err = bytes(buffers["err"])
    code = proc.returncode
    return {
        "ok": True,
        "code": code,
        "stdout": _decode(out),
        "stderr": _decode(err),
        "timed_out": timed_out,
        "stalled": stalled,
        "killed": (code is not None and code < 0 and not timed_out and not stalled),
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def run_command(command: str, cwd: Path, timeout: int = 0) -> dict[str, Any]:
    """执行一条 shell 命令。cwd 由调用方保证存在。"""
    command = str(command or "").strip()
    if not command:
        return {"ok": False, "error": "command 不能为空"}
    reason = blocked_reason(command)
    if reason:
        return {"ok": False, "blocked": True, "error": reason}
    limit = min(int(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT)
    limit = max(5, limit)
    argv = _direct_argv(command) or [*shell_prefix(), command]
    result = _execute(argv, cwd, limit)
    if not result.get("ok"):
        return result
    stdout, cut_out = _clip(result["stdout"])
    stderr, cut_err = _clip(result["stderr"])
    payload: dict[str, Any] = {
        "ok": result["code"] == 0,
        "command": command,
        "cwd": str(cwd),
        "exit_code": result["code"],
        "elapsed_ms": result["elapsed_ms"],
        "stdout": stdout,
        "stderr": stderr,
        "truncated": cut_out or cut_err,
    }
    if result["timed_out"]:
        payload["ok"] = False
        payload["timed_out"] = True
        payload["error"] = f"命令超过 {limit} 秒未结束，已终止（可调大 timeout 重试一次）"
    elif result.get("stalled"):
        # 进程还活着但一直没有输出：这不是「在跑」，是卡住了，别再干等
        payload["ok"] = False
        payload["stalled"] = True
        quiet = int((result["elapsed_ms"] or 0) / 1000)
        payload["error"] = (
            f"命令连续 {STALL_SECONDS} 秒没有任何输出（跑了 {quiet} 秒仍无新进展），"
            "已判定卡死并终止；换个参数或缩短范围重试一次"
        )
    elif result["code"] != 0:
        payload["error"] = f"命令退出码 {result['code']}，看 stderr"
    payload["hint"] = "命令已真实执行；需要看完整输出时把结果写进文件再分段读取。"
    return payload


def run_script(code: str, cwd: Path, timeout: int = 0, interpreter: str = "") -> dict[str, Any]:
    """跑一段 Python：写进工作目录临时文件后执行，报错行号与 traceback 都能拿到。"""
    code = str(code or "")
    if not code.strip():
        return {"ok": False, "error": "code 不能为空"}
    reason = blocked_reason(code)
    if reason:
        return {"ok": False, "blocked": True, "error": reason}
    limit = max(5, min(int(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    tmp_dir = cwd / ".mono_tmp"
    try:
        tmp_dir.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".py", dir=str(tmp_dir), delete=False, encoding="utf-8"
        )
        with handle:
            handle.write(code)
        script = Path(handle.name)
    except OSError as exc:
        return {"ok": False, "error": f"临时脚本写入失败：{exc}"}
    try:
        result = _execute([interpreter or _python_bin(), str(script)], cwd, limit)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if not result.get("ok"):
        return result
    stdout, cut_out = _clip(result["stdout"])
    stderr, cut_err = _clip(result["stderr"])
    payload: dict[str, Any] = {
        "ok": result["code"] == 0,
        "exit_code": result["code"],
        "elapsed_ms": result["elapsed_ms"],
        "stdout": stdout,
        "stderr": stderr,
        "truncated": cut_out or cut_err,
    }
    if result["timed_out"]:
        payload["ok"] = False
        payload["timed_out"] = True
        payload["error"] = f"脚本运行超过 {limit} 秒，已终止"
    elif result.get("stalled"):
        payload["ok"] = False
        payload["stalled"] = True
        payload["error"] = (
            f"脚本连续 {STALL_SECONDS} 秒没有任何输出（跑了 {int((result['elapsed_ms'] or 0) / 1000)} 秒仍无新进展），"
            "已判定卡死并终止；多半是卡在网络请求或死循环上，改小范围再试"
        )
    elif result["code"] != 0:
        payload["error"] = f"脚本退出码 {result['code']}，看 stderr 的 traceback"
    return payload


def _raw_request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for key, value in headers.items():
        if key.lower() in ("host", "content-length"):
            continue
        lines.append(f"{key}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines)
    text = head + "\r\n\r\n"
    if body:
        text += body[:4000].decode("utf-8", errors="replace")
    return text


def _raw_response(status: int, reason: str, headers: dict[str, str], body: str) -> str:
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _user_agent() -> str:
    """内置 HTTP 客户端用的 UA：跟随「平台设置」里的 user_agent，没配就用浏览器默认值。"""
    try:
        from ..db import get_settings

        value = str(get_settings().get("user_agent") or "").strip()
    except Exception:
        value = ""
    return value or DEFAULT_USER_AGENT


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
    follow_redirects: bool = True,
    verify_cert: bool = False,
    raw_body_is_json: bool = False,
) -> dict[str, Any]:
    """发一个真实的 HTTP 请求（等价 curl -i），并给出可复现的请求包/响应包。"""
    import httpx  # 局部导入：平台本来就有，但不要拖慢启动

    url = str(url or "").strip()
    if not url:
        return {"ok": False, "error": "url 不能为空"}
    if "://" not in url:
        url = "http://" + url
    method = (method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"):
        return {"ok": False, "error": f"不支持的 method：{method}"}
    send_headers = {"User-Agent": _user_agent()}
    for key, value in (headers or {}).items():
        if isinstance(key, str) and isinstance(value, str):
            send_headers[key] = value
    payload: bytes | None = body.encode("utf-8") if body else None
    if payload and not any(k.lower() == "content-type" for k in send_headers):
        send_headers["Content-Type"] = "application/json" if raw_body_is_json else "application/x-www-form-urlencoded"

    started = time.time()
    try:
        with httpx.Client(
            follow_redirects=follow_redirects,
            verify=verify_cert,
            timeout=max(3, min(int(timeout or 30), 120)),
            trust_env=False,
        ) as client:
            response = client.request(method, url, headers=send_headers, content=payload)
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "error": f"请求失败：{type(exc).__name__}: {exc}",
            "request_packet": _raw_request(method, url, send_headers, payload)[:PACKET_CHARS],
        }
    elapsed = int((time.time() - started) * 1000)
    body_text = _decode(response.content)
    shown, cut = _clip(body_text, HTTP_BODY_CHARS)
    response_headers = {key: value for key, value in response.headers.items()}
    return {
        "ok": 200 <= response.status_code < 400,
        "status": response.status_code,
        "reason": response.reason_phrase,
        "url": str(response.url),
        "method": method,
        "elapsed_ms": elapsed,
        "headers": response_headers,
        "body_chars": len(body_text),
        "body": shown,
        "truncated": cut,
        "request_packet": _raw_request(method, url, send_headers, payload)[:PACKET_CHARS],
        "response_packet": _raw_response(
            response.status_code, response.reason_phrase, response_headers, shown
        )[:PACKET_CHARS],
        "hint": "请求包与响应包可直接用于归档漏洞记录；需要完整响应体时写入工作目录再分段读。",
    }


def which(name: str) -> str:
    """看某个命令行工具在不在（curl / nmap / nuclei / gobuster…）。"""
    return shutil.which(name) or ""


def tool_snapshot() -> list[dict[str, str]]:
    """常用外部工具的存在性，交给模型判断"能不能这么干"。"""
    items = []
    for name in ("curl", "wget", "python", "git", "nmap", "nuclei", "ffuf", "gobuster", "sqlmap", "jq", "7z"):
        path = which(name)
        items.append({"name": name, "path": path, "ready": bool(path)})
    return items
