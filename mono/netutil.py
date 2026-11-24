"""URL / 主机串的归一化：漏洞按域名归组、实时输出时带上归属域名，都靠它。

目标串在库里可能是完整 URL（`https://a.com/x?y=1`）、带端口的 IP
（`10.0.0.5:8080`）、纯 IP（`10.0.0.5`）、IPv6（`[::1]:80`），也可能是
`a.com/path` 这种省略协议写法。归组要的是「同一台站点算一家」，
所以统一取主机名 + 非默认端口，把协议、路径、查询串都丢掉。
"""
from __future__ import annotations

from urllib.parse import urlsplit

UNKNOWN_HOST = "未标注域名"

DEFAULT_PORTS = {"http": "80", "https": "443"}


def host_of(value: str) -> str:
    """从 URL / 目标串里取出「域名（含非默认端口）」。

    - `https://a.com:8443/x` → `a.com:8443`
    - `http://a.com/x`        → `a.com`（80 端口不写出来）
    - `a.com/login`           → `a.com`
    - `10.0.0.5:8080`         → `10.0.0.5:8080`
    - `[::1]:9000`            → `[::1]:9000`
    - 空串 / 解析不出来         → `未标注域名`
    """
    text = str(value or "").strip()
    if not text:
        return UNKNOWN_HOST
    if "://" not in text:
        text = "//" + text.lstrip("/")
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").strip().lower()
        port = parts.port
    except ValueError:
        return UNKNOWN_HOST
    if not host:
        return UNKNOWN_HOST
    label = f"[{host}]" if ":" in host else host
    if port and str(port) != DEFAULT_PORTS.get(parts.scheme.lower(), ""):
        label = f"{label}:{port}"
    return label
