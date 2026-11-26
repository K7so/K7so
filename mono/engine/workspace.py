"""用户级记忆与工作目录：AI 每次执行前加载记忆，文件操作限定在已配置目录内。

记忆没有"大小上限"，也不挑文件类型：目录下的文本、Markdown、配置、日志、
Word / Excel / PPT / PDF 都会抽成文本，统一按游标分块读完（memory_chunk），
也能按关键词定位（memory_search）。预载只取开头一段，剩下的交给模型按需取全。
"""
from __future__ import annotations

import os
import re
import zipfile
from contextvars import ContextVar
from pathlib import Path

from ..config import env
from ..db import get_settings

MAX_MEMORY_CHARS = 0  # 0 = 不截断
DEFAULT_CHUNK = int(env("MEMORY_CHUNK", "16000"))
MEMORY_PRELOAD = int(env("MEMORY_PRELOAD", "12000"))
# 单文件读取上限：记忆里常见几十万字，正常文件都放行，只挡明显不是文档的巨型文件
MEMORY_MAX_FILE_BYTES = int(env("MEMORY_MAX_FILE_BYTES", str(64 * 1024 * 1024)))
# 版本库与缓存目录不是记忆内容，跟着一起读只会把上下文塞满
MEMORY_SKIP_DIRS = {".git", ".svn", ".hg", "__pycache__", "node_modules", ".venv", "venv", ".tox"}
OOXML_SUFFIXES = {".docx", ".docm", ".pptx", ".xlsx", ".xlsm"}
PDF_SUFFIXES = {".pdf"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff", ".psd"}

SCOPE_LABELS = {"work": "工作目录", "memory": "记忆目录"}

# 当前这次工具调用属于哪条会话。放在这里而不是 agent 里：目录解析要用它
# 判断「这条会话有没有自己的共享目录」（双模型协同就是这种情况）。
TOOL_SESSION: ContextVar[int] = ContextVar("k7so_tool_session", default=0)


def bind_tool_session(session_id: int):
    return TOOL_SESSION.set(int(session_id or 0))


def current_tool_session() -> int:
    return int(TOOL_SESSION.get() or 0)


class WorkspaceError(Exception):
    """工作目录未配置或目标路径越界。"""


def memory_path(session_id: int | None = None) -> Path | None:
    """记忆根目录：这一栏单独配了记忆空间就用它，否则用全局默认那份。

    双模型协同时左右两栏各读各的记忆，互不串味；单会话与老库行为不变。
    """
    sid = current_tool_session() if session_id is None else int(session_id or 0)
    if sid:
        try:
            from .memory_spaces import path_for_session

            override = path_for_session(sid)
        except Exception:  # 记忆空间出问题不该把整轮执行带崩，退回默认
            override = None
        if override is not None:
            return override
    value = (get_settings().get("memory_path") or "").strip()
    return Path(value).expanduser() if value else None


def work_dir() -> Path | None:
    """这条会话的工作目录：双模型协同优先用配对里配的共享目录。"""
    # 局部导入：pairs 依赖 db，和 workspace 没有循环；放函数里省得启动就加载
    try:
        from .pairs import workdir_for_session

        override = workdir_for_session(current_tool_session())
        if override is not None:
            return override
    except Exception:  # 目录解析不能因为协同模块出问题就整体不可用
        pass
    value = (get_settings().get("work_dir") or "").strip()
    return Path(value).expanduser() if value else None


# ---------------- 文本抽取：什么文件都能当记忆读 ----------------

def _xml_text(raw: bytes) -> str:
    """从 Office 的 XML 里抽纯文本：段落换行，去掉标签与转义。"""
    text = raw.decode("utf-8", errors="ignore")
    text = re.sub(r"</w:p>|</a:p>|</text:p>|</paragraph>", "\n", text)
    text = re.sub(r"<w:tab[^>]*/>|<a:br[^>]*/>", "\t", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = (
        text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", '"').replace("&apos;", "'")
    )
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _ooxml_text(path: Path) -> str:
    """docx/pptx/xlsx：按固定顺序拼出可读文本。"""
    suffix = path.suffix.lower()
    parts: list[str] = []
    try:
        with zipfile.ZipFile(path) as bundle:
            names = bundle.namelist()
            if suffix in (".docx", ".docm"):
                if "word/document.xml" in names:
                    parts.append(_xml_text(bundle.read("word/document.xml")))
                for name in names:
                    if re.match(r"word/(header|footer)\d*\.xml$", name):
                        parts.append(_xml_text(bundle.read(name)))
            elif suffix == ".pptx":
                slides = sorted(
                    (name for name in names if re.match(r"ppt/slides/slide\d+\.xml$", name)),
                    key=lambda item: int(re.findall(r"\d+", item)[0]),
                )
                for name in slides:
                    parts.append(f"[{Path(name).stem}]\n" + _xml_text(bundle.read(name)))
            else:  # xlsx
                shared: list[str] = []
                if "xl/sharedStrings.xml" in names:
                    raw = bundle.read("xl/sharedStrings.xml").decode("utf-8", errors="ignore")
                    shared = [
                        re.sub(r"<[^>]+>", "", item)
                        for item in re.findall(r"<si>(.*?)</si>", raw, re.S)
                    ]
                for name in sorted(n for n in names if re.match(r"xl/worksheets/sheet\d+\.xml$", n)):
                    raw = bundle.read(name).decode("utf-8", errors="ignore")
                    rows: list[str] = []
                    for row in re.findall(r"<row[^>]*>(.*?)</row>", raw, re.S):
                        cells: list[str] = []
                        for cell in re.findall(r"<c[^>]*?(?:/>|>.*?</c>)", row, re.S):
                            value = re.search(r"<v>(.*?)</v>", cell, re.S)
                            inline = re.search(r"<t[^>]*>(.*?)</t>", cell, re.S)
                            text = ""
                            if 't="s"' in cell and value:
                                index = int(value.group(1))
                                text = shared[index] if 0 <= index < len(shared) else ""
                            elif inline:
                                text = inline.group(1)
                            elif value:
                                text = value.group(1)
                            cells.append(re.sub(r"<[^>]+>", "", text).strip())
                        line = " | ".join(cell for cell in cells if cell)
                        if line:
                            rows.append(line)
                    if rows:
                        parts.append(f"[{Path(name).stem}]\n" + "\n".join(rows))
    except (zipfile.BadZipFile, KeyError, OSError, ValueError):
        return ""
    return "\n".join(part for part in parts if part.strip()).strip()


def _pdf_text(path: Path) -> str:
    """PDF：解压内容流后取 Tj/TJ 里的字面量，够读正文即可（不追求排版）。"""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if b"%PDF" not in raw[:1024]:
        return ""
    out: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        blob = match.group(1)
        try:
            import zlib

            data = zlib.decompress(blob)
        except Exception:
            data = blob
        for text in re.findall(rb"\((?:\\.|[^\\()])*\)\s*Tj", data):
            value = text[text.find(b"(") + 1 : text.rfind(b")")]
            out.append(value.decode("latin-1", errors="ignore"))
        for block in re.findall(rb"\[(.*?)\]\s*TJ", data, re.S):
            chunk = b"".join(re.findall(rb"\((?:\\.|[^\\()])*\)", block))
            chunk = re.sub(rb"[()]", b"", chunk)
            if chunk:
                out.append(chunk.decode("latin-1", errors="ignore"))
    text = "\n".join(item for item in out if item.strip())
    # PDF 里常见字面量转义，恢复一下可读性
    return text.replace("\\n", "\n").replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")


def extract_text(path: Path) -> str:
    """把任意文件读成文本：文本直接读，Office/PDF 抽正文，图片等返回空。"""
    suffix = path.suffix.lower()
    try:
        if path.stat().st_size > MEMORY_MAX_FILE_BYTES:
            return ""
    except OSError:
        return ""
    if suffix in OOXML_SUFFIXES:
        return _ooxml_text(path)
    if suffix in PDF_SUFFIXES:
        return _pdf_text(path)
    if suffix in IMAGE_SUFFIXES:
        return ""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in raw[:4096]:
        # 认不出的二进制：先试着按 OOXML/PDF 处理，再放弃
        return _ooxml_text(path) or _pdf_text(path)
    return raw.decode("utf-8", errors="ignore").replace("\r\n", "\n").replace("\r", "\n")


_TEXT_CACHE: dict[str, tuple[float, int, str]] = {}


def _read_text(path: Path) -> str:
    """读文本并缓存：翻页读大记忆时不用每次把整个目录重新读一遍。"""
    try:
        stat = path.stat()
    except OSError:
        return ""
    key = str(path)
    cached = _TEXT_CACHE.get(key)
    if cached and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
        return cached[2]
    text = extract_text(path)
    _TEXT_CACHE[key] = (stat.st_mtime, stat.st_size, text)
    return text


def _is_platform_readme(path: Path) -> bool:
    """只跳过平台自己写在记忆根目录的那份说明（它自己也写着"不是记忆内容"）。"""
    if path.name.lower() != "readme.md":
        return False
    root = memory_path()
    if root is None or root.is_file():
        return False
    try:
        if path.parent.resolve() != root.resolve():
            return False
    except OSError:
        return False
    return "用户级记忆目录" in _read_text(path)[:200]


def _all_files() -> list[Path]:
    """记忆目录下的所有文件（递归），只跳过版本库、缓存目录与平台自带的说明文件。"""
    root = memory_path()
    if root is None or not root.exists():
        return []
    if root.is_file():
        return [root]
    found: list[Path] = []
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in MEMORY_SKIP_DIRS]
        for name in names:
            path = Path(current) / name
            try:
                if not path.is_file():
                    continue
            except OSError:
                continue
            # Office 打开时留下的 ~$ 临时文件没有内容
            if name.startswith("~$"):
                continue
            if _is_platform_readme(path):
                continue
            found.append(path)
    return sorted(found, key=lambda item: (len(item.parts), str(item).lower()))


def memory_files() -> list[Path]:
    """记忆目录下有内容的全部文件（文本 + Office/PDF 已抽正文）。"""
    return [path for path in _all_files() if _read_text(path).strip()]


def _relative(path: Path) -> str:
    root = memory_path()
    try:
        if root is not None and root.is_dir():
            return str(path.relative_to(root)).replace("\\", "/")
    except (ValueError, OSError):
        pass
    return path.name


def memory_manifest() -> list[dict]:
    """记忆文件清单：名字、相对路径、字符数。模型据此判断要不要全部读。"""
    return [
        {"name": _relative(path), "chars": len(_read_text(path))}
        for path in memory_files()
    ]


def memory_document(only: str = "") -> str:
    """把整个记忆目录拼成一份带文件名标题的文档（only 指定单文件时只取它）。"""
    chunks: list[str] = []
    for path in memory_files():
        name = _relative(path)
        if only:
            target = str(only).replace("\\", "/")
            if name != target and path.name != target and not name.endswith(target):
                continue
        text = _read_text(path).strip()
        if not text:
            continue
        chunks.append(f"【{name}】\n{text}")
    return "\n\n".join(chunks).strip()


def read_memory(max_chars: int = MAX_MEMORY_CHARS) -> str:
    """读取全部记忆；max_chars>0 时才截断（预载用）。"""
    text = memory_document()
    if max_chars and max_chars > 0 and len(text) > max_chars:
        return text[:max_chars]
    return text


def memory_chunk(cursor: int = 0, limit: int = 0, only: str = "") -> dict:
    """按游标分块读取记忆：不限总量，读完 has_more 就是 False。"""
    document = memory_document(only)
    total = len(document)
    start = max(0, int(cursor or 0))
    size = int(limit or 0) or DEFAULT_CHUNK
    size = max(1000, min(size, 40000))
    if start >= total:
        return {
            "total_chars": total,
            "cursor": start,
            "next_cursor": total,
            "has_more": False,
            "content": "",
            "files": memory_manifest(),
        }
    end = min(total, start + size)
    return {
        "total_chars": total,
        "cursor": start,
        "next_cursor": end,
        "has_more": end < total,
        "content": document[start:end],
        "files": memory_manifest(),
    }


def memory_search(keyword: str, limit: int = 60, context: int = 90) -> list[dict]:
    """在记忆里按关键词（或正则）定位，返回文件、行号与该行内容。"""
    pattern: re.Pattern[str] | None = None
    if keyword:
        try:
            pattern = re.compile(keyword, re.I)
        except re.error:
            pattern = re.compile(re.escape(keyword), re.I)
    hits: list[dict] = []
    for path in memory_files():
        text = _read_text(path)
        if not text:
            continue
        name = _relative(path)
        for number, line in enumerate(text.splitlines(), start=1):
            matched = pattern.search(line) if pattern else True
            if not matched:
                continue
            stripped = line.strip()
            if len(stripped) > context * 2:
                index = max(0, matched.start() - context) if pattern else 0
                stripped = "…" + stripped[index : index + context * 2] + "…"
            hits.append({"file": name, "line": number, "text": stripped})
            if len(hits) >= limit:
                return hits
    return hits


def memory_info(preview_chars: int = 1600) -> dict:
    root = memory_path()
    text = read_memory()
    return {
        "configured": root is not None,
        "path": str(root) if root else "",
        "exists": bool(root and root.exists()),
        "files": [item["name"] for item in memory_manifest()],
        "chars": len(text),
        "preview": text[:preview_chars],
    }


def ensure_work_dir() -> Path | None:
    root = work_dir()
    if root is None:
        return None
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return root


def _root_base(path: Path) -> Path:
    """配置成单个文件时，只暴露这个文件本身，不带出同目录的其他内容。"""
    return path


def allowed_roots() -> list[tuple[str, str, Path]]:
    """已配置的可访问根：(scope, 中文标签, 路径)。"""
    items: list[tuple[str, str, Path]] = []
    root = work_dir()
    if root is not None:
        items.append(("work", SCOPE_LABELS["work"], root))
    memory = memory_path()
    if memory is not None:
        items.append(("memory", SCOPE_LABELS["memory"], _root_base(memory)))
    return items


def exec_dir() -> Path:
    """命令执行的落点：优先工作目录，没有就用临时目录，绝不占着平台自己的目录乱写。"""
    root = ensure_work_dir()
    if root is not None:
        return root
    import tempfile

    fallback = Path(tempfile.gettempdir()) / "mono-exec"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _inside(target: Path, base: Path) -> bool:
    try:
        resolved_base = base.resolve()
        resolved_target = target.resolve()
    except OSError:
        return False
    return resolved_target == resolved_base or resolved_base in resolved_target.parents


def _is_absolute(text: str) -> bool:
    return os.path.isabs(text) or bool(re.match(r"^[A-Za-z]:[\\/]", text))


def _clean(text: str) -> str:
    return str(text or "").strip().strip('"').strip("'").strip()


def resolve_doc(path: str = "", scope: str = "") -> tuple[Path, str]:
    """读取/列举用：允许工作目录与记忆目录，以及这两个目录内的绝对路径。

    返回 (真实路径, 所属范围中文名)；越界抛 WorkspaceError。
    """
    text = _clean(path)
    roots = allowed_roots()
    if not roots:
        raise WorkspaceError("尚未配置工作目录或记忆目录，请先在「目录配置」页面设置")

    scope = (scope or "").strip().lower()
    if scope in SCOPE_LABELS:
        picked = [item for item in roots if item[0] == scope]
        if not picked:
            raise WorkspaceError(f"{SCOPE_LABELS[scope]}尚未配置，请先在「目录配置」页面设置")
        roots = picked

    if not text:
        _, label, base = roots[0]
        return base.resolve(), label

    if _is_absolute(text):
        target = Path(text).expanduser()
        for _, label, base in roots:
            if _inside(target, base):
                return target.resolve(), label
        raise WorkspaceError("该路径不在已配置的工作目录或记忆目录内，已被拒绝")

    # 相对路径：优先工作目录，其次记忆目录；都不存在时给出第一个候选，由上层报"不存在"
    fallback: tuple[Path, str] | None = None
    for _, label, base in roots:
        if base.is_file():
            # 根本身就是单个文件：filename 或空路径都指向它
            if not text or Path(text).name == base.name:
                return base.resolve(), label
            continue
        candidate = (base / text).expanduser()
        if not _inside(candidate, base):
            continue
        if candidate.exists():
            return candidate.resolve(), label
        if fallback is None:
            fallback = (candidate.resolve(), label)
    if fallback is not None:
        return fallback
    raise WorkspaceError("路径超出已配置目录范围，已被拒绝")


def resolve_path(relative: str = "") -> Path:
    """写入用：只能落在工作目录内，避免 AI 改写记忆文件与平台自身文件。"""
    root = ensure_work_dir()
    if root is None:
        raise WorkspaceError("尚未配置可用的工作目录，请先在「目录配置」页面设置")
    base = root.resolve()
    target = (root / relative).resolve() if relative else base
    if target != base and base not in target.parents:
        raise WorkspaceError("路径超出工作目录范围，已被拒绝")
    return target


def work_info() -> dict:
    root = work_dir()
    exists = bool(root and root.exists())
    entries = 0
    if exists and root and root.is_dir():
        try:
            entries = len(list(root.iterdir()))
        except OSError:
            entries = 0
    return {
        "configured": root is not None,
        "path": str(root) if root else "",
        "exists": exists,
        "entries": entries,
    }
