"""原始字节流落盘：边写边算摘要，超过上限立刻回滚并删掉半截文件。

前端用 `fetch(url, {body: file})` 直接发二进制，后端不依赖 python-multipart，
所以这里自己管文件写入，避免把整个文件读进内存。
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

_BAD_NAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


class UploadError(Exception):
    """上传过程中的可预期错误（超限、空文件、名字非法），直接回给前端。"""


def safe_filename(name: str, fallback: str = "upload.bin") -> str:
    """只取最后一段，清掉 Windows 不允许的字符，防止 ../ 穿越。"""
    base = Path(str(name or "")).name.strip()
    base = _BAD_NAME.sub("_", base).strip(" .")
    if not base:
        base = fallback
    if len(base) > 150:
        stem, dot, ext = base.rpartition(".")
        base = (stem[:135] or "upload") + (dot + ext[:10] if dot else "")
    return base


def unique_path(directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    if not target.exists():
        return target
    stem, dot, ext = filename.rpartition(".")
    stem = stem or filename
    index = 2
    while True:
        candidate = directory / (f"{stem}-{index}{dot}{ext}" if dot else f"{stem}-{index}")
        if not candidate.exists():
            return candidate
        index += 1


class UploadSink:
    """逐块写入；出问题调用 abort()，成功调用 close()。"""

    def __init__(self, directory: Path, filename: str, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.path = unique_path(directory, safe_filename(filename))
        self.size = 0
        self._sha = hashlib.sha256()
        self._handle = open(self.path, "wb")

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.size += len(chunk)
        if self.size > self.max_bytes:
            self.abort()
            raise UploadError(
                f"文件超过上限（{self.max_bytes // (1024 * 1024)} MB），先压缩或拆分再导"
            )
        self._handle.write(chunk)
        self._sha.update(chunk)

    @property
    def sha256(self) -> str:
        return self._sha.hexdigest()

    def close(self) -> Path:
        self._handle.close()
        if self.size == 0:
            self.abort()
            raise UploadError("文件是空的")
        return self.path

    def abort(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass
