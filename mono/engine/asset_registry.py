"""资产监管：把文件里的域名/IP 抽出来，再顺着 DNS 往下收集子域名。

三步：
1. 解析文档（xlsx / docx / pdf / txt / md）——全用标准库，不额外装依赖；
2. 抽域名与 IP——正则打底，接了大模型时可以再让它复核一遍；
3. 收集子域名——常见三级前缀 + DNS 解析，能连外网时再查一次证书透明日志。

模块 = 一次导入 + 一轮收集，用户自己命名，带日期；两个模块一比就知道这段时间多了哪些域名。
"""
from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import socket
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable
from xml.etree import ElementTree

from ..db import db, now_iso

# 文件扩展名不能当域名：a.png / main.js 这类必须过滤掉
FILE_EXTS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tif", "tiff",
    "css", "js", "mjs", "json", "xml", "html", "htm", "php", "asp", "aspx", "jsp",
    "txt", "md", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv",
    "zip", "rar", "7z", "gz", "tar", "bz2", "exe", "msi", "apk", "ipa", "dmg",
    "mp4", "mp3", "wav", "avi", "mov", "flv", "mkv", "py", "go", "java", "jar",
    "dll", "so", "bin", "log", "conf", "ini", "yml", "yaml", "db", "sql", "bak",
    "old", "tmp", "lock", "map", "woff", "woff2", "ttf", "otf", "eot",
}

DOMAIN_RE = re.compile(
    # 注意不要把 @ 也放进排除集：资产表里常有一列「负责人邮箱」，
    # zhang@oa.example.com 的 oa.example.com 本身就是资产线索，漏掉很可惜。
    r"(?<![\w.\-])"
    r"((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})"
    r"(?![\w\-])"
)
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")

# 常见三级前缀：中小站点的对外入口基本都在这几十个里
PREFIXES = [
    "www", "m", "wap", "mobile", "app", "apps", "h5", "web",
    "api", "open", "gateway", "gw", "svc", "service", "ws",
    "admin", "manage", "manager", "console", "dashboard", "portal", "oa",
    "mail", "webmail", "smtp", "pop", "imap", "mx", "exchange",
    "vpn", "ssl", "remote", "rdp", "sslvpn", "citrix",
    "dev", "test", "uat", "sit", "pre", "preview", "stage", "staging", "beta", "demo",
    "prod", "release", "gray", "canary",
    "static", "assets", "img", "image", "images", "cdn", "file", "files", "upload", "download",
    "media", "video", "live", "stream", "play",
    "pay", "payment", "order", "shop", "mall", "store", "member", "user", "passport",
    "sso", "auth", "login", "id", "account", "uc", "center",
    "crm", "erp", "hr", "hrm", "finance", "report", "bi", "data", "bigdata",
    "monitor", "log", "logs", "kibana", "grafana", "prometheus", "zabbix",
    "db", "mysql", "redis", "mongo", "es", "kafka", "mq", "nacos", "eureka",
    "git", "gitlab", "jenkins", "ci", "cd", "nexus", "harbor", "registry",
    "docs", "doc", "wiki", "confluence", "help", "support", "kf", "cs",
    "blog", "news", "notice", "about", "job", "zhaopin", "survey",
    "ns", "ns1", "ns2", "dns", "ftp", "sftp", "backup", "bak",
]

MAX_PARSE_BYTES = 200 * 1024 * 1024
MAX_TEXT_CHARS = 4_000_000
DNS_WORKERS = 24
# 查 TXT/MX/NS 用：阿里与 114 在国内可达，Google 只当最后兜底
DNS_SERVERS = ("223.5.5.5", "114.114.114.114", "8.8.8.8")


# ---------------------------------------------------------------- 文档解析
def _decode_text(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _xml_text(data: bytes) -> str:
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return ""
    parts: list[str] = []
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if tag in {"t", "v"} and node.text:
            parts.append(node.text)
        elif tag in {"p", "row", "tr"}:
            parts.append("\n")
    return "".join(parts)


def _xlsx_text(data: bytes) -> str:
    out: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in zf.namelist():
            shared = _shared_strings(zf.read("xl/sharedStrings.xml"))
        for name in zf.namelist():
            if not re.match(r"xl/worksheets/sheet\d+\.xml$", name):
                continue
            raw = zf.read(name)
            try:
                root = ElementTree.fromstring(raw)
            except ElementTree.ParseError:
                continue
            for cell in root.iter():
                if cell.tag.rsplit("}", 1)[-1] != "c":
                    continue
                kind = cell.get("t") or ""
                value = ""
                for child in cell:
                    tag = child.tag.rsplit("}", 1)[-1]
                    if tag == "v":
                        value = child.text or ""
                    elif tag == "is":
                        value = "".join(
                            node.text or ""
                            for node in child.iter()
                            if node.tag.rsplit("}", 1)[-1] == "t"
                        )
                if not value:
                    continue
                if kind == "s":
                    try:
                        value = shared[int(value)]
                    except (ValueError, IndexError):
                        pass
                out.append(value)
                out.append("\t")
            out.append("\n")
    return "".join(out)


def _shared_strings(raw: bytes) -> list[str]:
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return []
    items: list[str] = []
    for si in root:
        items.append("".join(
            node.text or "" for node in si.iter() if node.tag.rsplit("}", 1)[-1] == "t"
        ))
    return items


def _docx_text(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        if "word/document.xml" not in zf.namelist():
            return ""
        return _xml_text(zf.read("word/document.xml"))


def _pdf_text(data: bytes) -> str:
    """只解文本层：流里的 Tj / TJ。扫描件和加密件解不出来，交给上层提示。"""
    chunks: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        raw = match.group(1)
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            # 不少工具导出的 PDF 压根不压缩，流里就是明文；解不开就按原文扫，
            # 否则这类文件会被判成「一个字都没读到」，白导一次。
            pass
        for literal in re.finditer(rb"\((?:\\.|[^\\()])*\)", raw):
            text = _pdf_unescape(literal.group(0)[1:-1])
            if text.strip():
                chunks.append(text)
        for hexed in re.finditer(rb"<([0-9A-Fa-f\s]{4,})>", raw):
            text = _pdf_hex(hexed.group(1))
            if text.strip():
                chunks.append(text)
    return " ".join(chunks)


def _pdf_unescape(raw: bytes) -> str:
    out = bytearray()
    index = 0
    while index < len(raw):
        byte = raw[index]
        if byte == 0x5C and index + 1 < len(raw):
            nxt = raw[index + 1]
            mapping = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}
            if nxt in mapping:
                out.append(mapping[nxt])
                index += 2
                continue
            if 0x30 <= nxt <= 0x37:
                digits = raw[index + 1:index + 4]
                out.append(int(digits, 8) & 0xFF)
                index += 1 + len(digits)
                continue
            out.append(nxt)
            index += 2
            continue
        out.append(byte)
        index += 1
    return _decode_text(bytes(out))


def _pdf_hex(raw: bytes) -> str:
    cleaned = re.sub(rb"\s+", b"", raw)
    if len(cleaned) % 2:
        cleaned += b"0"
    try:
        return _decode_text(bytes.fromhex(cleaned.decode("ascii")))
    except (ValueError, UnicodeDecodeError):
        return ""


def parse_document(filename: str, data: bytes) -> tuple[str, str]:
    """返回 (文本, 说明)。说明用来告诉用户「这份文件解出了什么」。"""
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if suffix in {"txt", "md", "csv", "log", "ini", "conf", "json"}:
        return _decode_text(data), ""
    if suffix in {"xlsx", "xlsm"}:
        return _xlsx_text(data), ""
    if suffix == "docx":
        return _docx_text(data), ""
    if suffix == "pdf":
        text = _pdf_text(data)
        note = "" if text.strip() else "这份 PDF 没有可提取的文本层（可能是扫描件或加密），转成 docx/txt 再导一次"
        return text, note
    # 其它后缀：当纯文本再试一次，能读出东西就不算白导
    text = _decode_text(data)
    printable = sum(1 for ch in text[:4000] if ch.isprintable() or ch.isspace())
    if text and printable > len(text[:4000]) * 0.75:
        return text, ""
    return "", f"暂不支持解析 .{suffix or '未知'} 文件"


# ---------------------------------------------------------------- 目标抽取
def _valid_domain(value: str) -> bool:
    value = value.strip(".").lower()
    if len(value) < 4 or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if any(not label or len(label) > 63 for label in labels):
        return False
    if labels[-1] in FILE_EXTS:
        return False
    if not labels[-1].isalpha():
        return False
    return True


def extract_targets(text: str) -> dict[str, list[str]]:
    domains: list[str] = []
    ips: list[str] = []
    seen_domains: set[str] = set()
    seen_ips: set[str] = set()

    for match in DOMAIN_RE.finditer(text or ""):
        host = match.group(1).strip(".").lower()
        if not _valid_domain(host) or host in seen_domains:
            continue
        seen_domains.add(host)
        domains.append(host)

    for match in IP_RE.finditer(text or ""):
        raw = match.group(1)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        value = str(ip)
        if value in seen_ips:
            continue
        seen_ips.add(value)
        ips.append(value)

    return {"domains": domains, "ips": ips}


def root_domain(host: str) -> str:
    """取主域。.com.cn / .gov.cn 这类二级后缀要多留一段。"""
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return ".".join(labels)
    two_level = {
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
        "com.hk", "com.tw", "co.uk", "co.jp", "com.sg", "com.au",
    }
    tail = ".".join(labels[-2:])
    if tail in two_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


# ---------------------------------------------------------------- DNS 收集
def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return []
    ips = sorted({str(item[4][0]) for item in infos if item[4]})
    return ips


def probe_hosts(candidates: Iterable[str]) -> dict[str, list[str]]:
    """并发解析一批主机名，返回「能解析的 → IP 列表」。"""
    names = [name for name in dict.fromkeys(candidates) if name]
    if not names:
        return {}
    found: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        for name, ips in zip(names, pool.map(_resolve, names)):
            if ips:
                found[name] = ips
    return found


def _dns_query(name: str, qtype: str, timeout: float = 3.0) -> list[bytes]:
    """手写一个极小 DNS 查询，只为拿记录里的文本线索。

    不装 dnspython，一是项目保持零新增依赖，二是只用得到 NS / MX / TXT / CNAME
    这几类记录的 rdata 文本，没必要引一整套解析库。
    """
    kind = {"NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}.get(qtype)
    if not kind:
        return []
    labels = [part for part in name.rstrip(".").split(".") if part]
    if not labels:
        return []
    packet = bytearray()
    tid = int.from_bytes(os.urandom(2), "big")
    packet += tid.to_bytes(2, "big")
    packet += (0x0100).to_bytes(2, "big")   # RD
    packet += (1).to_bytes(2, "big")        # QDCOUNT
    packet += (0).to_bytes(2, "big") * 3    # AN/NS/AR
    for label in labels:
        raw = label.encode("idna") if label.isascii() else label.encode()
        packet += bytes([len(raw)]) + raw
    packet += b"\x00"
    packet += kind.to_bytes(2, "big")
    packet += (1).to_bytes(2, "big")

    for server in DNS_SERVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(bytes(packet), (server, 53))
                data, _ = sock.recvfrom(4096)
        except (OSError, socket.timeout):
            continue
        if len(data) < 12 or data[:2] != tid.to_bytes(2, "big"):
            continue
        try:
            return _parse_dns_answers(data, kind)
        except (IndexError, ValueError):
            continue
    return []


def _dns_name(data: bytes, pos: int) -> tuple[str, int]:
    """解一个 DNS 名字：长度前缀标签 + 0xC0 压缩指针。

    MX / NS / CNAME 的 rdata 不是纯文本，是这种带长度前缀的标签串
    （例如 mail.python.org 编码成 04 mail 06 python 03 org 00），
    直接 decode 会得到一串乱码，必须按规则拼回去。
    """
    labels: list[str] = []
    end = pos
    jumped = False
    hops = 0
    while 0 <= pos < len(data):
        length = data[pos]
        if length & 0xC0 == 0xC0:                 # 压缩指针：跳到别处继续读
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
                jumped = True
            hops += 1
            if hops > 8 or pointer >= pos:        # 只允许往回跳，防环
                break
            pos = pointer
            continue
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        if length & 0xC0:                         # 0x40/0x80 属保留位，无法解析
            break
        pos += 1
        labels.append(data[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), end


def _parse_dns_answers(data: bytes, kind: int) -> list[bytes]:
    """从响应里把指定类型的 rdata 抠出来（TXT 是长度前缀串，需要拼）。"""
    ancount = int.from_bytes(data[6:8], "big")
    qdcount = int.from_bytes(data[4:6], "big")
    pos = 12
    for _ in range(qdcount):                      # 跳过 question
        while pos < len(data) and data[pos]:
            pos += data[pos] + 1
        pos += 5
    out: list[bytes] = []
    for _ in range(ancount):
        if pos >= len(data):
            break
        _name, pos = _dns_name(data, pos)         # 记录名（常是压缩指针）
        if pos + 10 > len(data):
            break
        rtype = int.from_bytes(data[pos:pos + 2], "big")
        rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
        pos += 10
        rdlen = min(rdlen, max(0, len(data) - pos))
        rdata_start = pos
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype != kind or rdlen == 0:
            continue
        if kind == 16:                            # TXT：多段 character-string 拼接
            chunks, cursor = [], 0
            while cursor < len(rdata):
                size = rdata[cursor]
                chunks.append(rdata[cursor + 1:cursor + 1 + size])
                cursor += 1 + size
            out.append(b"".join(chunks))
        elif kind in (2, 5):                      # NS / CNAME：整个 rdata 就是一个名字
            name, _ = _dns_name(data, rdata_start)
            if name:
                out.append(name.encode("ascii", "replace"))
        elif kind == 15:                          # MX：前 2 字节是优先级，后面才是主机名
            name, _ = _dns_name(data, rdata_start + 2)
            if name:
                out.append(name.encode("ascii", "replace"))
        else:
            out.append(rdata)
    return out


def record_subdomains(root: str) -> tuple[list[str], list[str]]:
    """从 NS / MX / TXT / CNAME 记录里挖线索。

    TXT 里的 SPF（include: / a: / ptr:）和站点验证记录经常直接写着内部子域，
    这是国内唯一不依赖境外接口就能拿到的「额外来源」。
    """
    hosts: set[str] = set()
    notes: list[str] = []
    for text in _dns_query(root, "TXT"):
        body = text.decode("utf-8", "replace")
        if "v=spf1" in body.lower() or "include:" in body.lower():
            notes.append(body[:200])
        for match in re.finditer(r"(?:include:|a:|ptr:|redirect=)([a-z0-9.\-]+\.[a-z]{2,24})", body, re.I):
            hosts.add(match.group(1).lower().strip("."))
        # 验证记录常以「域名 + 一串校验值」形式出现
        for match in DOMAIN_RE.finditer(body):
            hosts.add(match.group(1).lower())
    # MX / NS 的 rdata 已在 _parse_dns_answers 里解成主机名，这里直接用
    for qtype in ("MX", "NS"):
        for text in _dns_query(root, qtype):
            candidate = text.decode("ascii", "replace").strip("\x00").strip(".").strip().lower()
            if candidate and "." in candidate and " " not in candidate:
                hosts.add(candidate)
    clean: list[str] = []
    for host in hosts:
        host = host.strip(".").lower()
        if not _valid_domain(host):
            continue
        # 只留同根的，别的域是关联资产，混进来会把模块撑散
        if host == root or host.endswith("." + root):
            clean.append(host)
    return sorted(set(clean)), notes


def crt_subdomains(root: str, timeout: float = 4.0) -> list[str]:
    """证书透明日志里的子域。

    境外接口在国内经常连不上，所以多备一个源；全都失败就返回空，
    不影响本地 DNS 的结果——收集这件事不能因为一个源挂了就整条停掉。
    """
    try:
        import httpx
    except ImportError:
        return []
    names: list[str] = []
    for url, params, pick in (
        ("https://crt.sh/", {"q": f"%.{root}", "output": "json"}, "crt"),
        (
            "https://api.certspotter.com/v1/issuances",
            {"domain": root, "include_subdomains": "true", "expand": "dns_names"},
            "spotter",
        ),
    ):
        try:
            response = httpx.get(
                url, params=params, timeout=timeout, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if response.status_code != 200:
                continue
            rows = response.json()
        except Exception:
            continue
        for row in rows if isinstance(rows, list) else []:
            if pick == "crt":
                values = str(row.get("name_value", "")).splitlines()
            else:
                values = [str(item) for item in (row.get("dns_names") or [])]
            for value in values:
                value = value.strip().lower().lstrip("*.").strip(".")
                if value.endswith(root) and _valid_domain(value):
                    names.append(value)
        if names:
            break
    return sorted(set(names))


# ---------------------------------------------------------------- 模块读写
def list_modules() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """SELECT m.*, (SELECT COUNT(*) FROM asset_hosts h WHERE h.module_id = m.id) AS live_count
               FROM asset_modules m ORDER BY m.id DESC"""
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["sources"] = json.loads(item.get("sources") or "[]")
        except json.JSONDecodeError:
            item["sources"] = []
        item["host_count"] = int(item.get("live_count") or 0)
        out.append(item)
    return out


def create_module(name: str, username: str = "", note: str = "") -> dict[str, Any]:
    ts = now_iso()
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO asset_modules (name, created_by, sources, seed_count, host_count,
                                          status, note, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (name.strip()[:120] or "未命名模块", username, "[]", 0, 0, "ready", note, ts, ts),
        )
        module_id = int(cur.lastrowid)
    return get_module(module_id) or {}


def get_module(module_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM asset_modules WHERE id = ?", (module_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["live_count"] = conn.execute(
            "SELECT COUNT(*) AS c FROM asset_hosts WHERE module_id = ?", (module_id,)
        ).fetchone()["c"]
    try:
        item["sources"] = json.loads(item.get("sources") or "[]")
    except json.JSONDecodeError:
        item["sources"] = []
    item["host_count"] = int(item.get("live_count") or 0)
    return item


def delete_module(module_id: int) -> bool:
    with db() as conn:
        conn.execute("DELETE FROM asset_hosts WHERE module_id = ?", (module_id,))
        cur = conn.execute("DELETE FROM asset_modules WHERE id = ?", (module_id,))
    return cur.rowcount > 0


def save_hosts(module_id: int, entries: Iterable[dict[str, Any]]) -> int:
    """写入子域/资产；同一条不重复（UNIQUE 约束兜底），返回新增条数。"""
    added = 0
    ts = now_iso()
    with db() as conn:
        before = conn.execute(
            "SELECT COUNT(*) AS c FROM asset_hosts WHERE module_id = ?", (module_id,)
        ).fetchone()["c"]
        for entry in entries:
            host = str(entry.get("host") or "").strip().lower()
            if not host:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO asset_hosts
                   (module_id, host, kind, ip, parent, source, note, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    module_id, host, entry.get("kind") or "domain",
                    entry.get("ip") or "", entry.get("parent") or "",
                    entry.get("source") or "", entry.get("note") or "", ts,
                ),
            )
        after = conn.execute(
            "SELECT COUNT(*) AS c FROM asset_hosts WHERE module_id = ?", (module_id,)
        ).fetchone()["c"]
        added = int(after) - int(before)
        conn.execute(
            "UPDATE asset_modules SET host_count = ?, updated_at = ? WHERE id = ?",
            (after, ts, module_id),
        )
    return added


def host_rows(module_id: int, query: str = "", kind: str = "", limit: int = 2000,
              offset: int = 0) -> dict[str, Any]:
    where = ["module_id = ?"]
    params: list[Any] = [module_id]
    if query:
        where.append("host LIKE ?")
        params.append(f"%{query}%")
    if kind in {"domain", "ip"}:
        where.append("kind = ?")
        params.append(kind)
    clause = " AND ".join(where)
    with db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS c FROM asset_hosts WHERE {clause}", params
        ).fetchone()["c"]
        rows = conn.execute(
            f"""SELECT * FROM asset_hosts WHERE {clause}
                ORDER BY source DESC, host ASC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
    return {"total": int(total), "items": [dict(row) for row in rows]}


def _existing_hosts(module_id: int) -> set[str]:
    with db() as conn:
        rows = conn.execute(
            "SELECT host FROM asset_hosts WHERE module_id = ?", (module_id,)
        ).fetchall()
    return {str(row["host"]) for row in rows}


def import_document(
    module_id: int,
    filename: str,
    data: bytes,
    use_llm: bool = False,
    username: str = "",
) -> dict[str, Any]:
    """解析一份文件，把域名/IP 收进模块。"""
    if len(data) > MAX_PARSE_BYTES:
        return {"ok": False, "error": "文件太大，先拆分再导"}

    text, note = parse_document(filename, data)
    text = (text or "")[:MAX_TEXT_CHARS]
    if not text.strip():
        return {"ok": False, "error": note or "这份文件里没有可识别的文本"}

    targets = extract_targets(text)
    llm_used = False
    if use_llm:
        extra = _llm_extract(text)
        if extra:
            llm_used = True
            targets = {
                "domains": sorted(set(targets["domains"]) | set(extra.get("domains") or [])),
                "ips": sorted(set(targets["ips"]) | set(extra.get("ips") or [])),
            }

    entries: list[dict[str, Any]] = []
    for host in targets["domains"]:
        entries.append({
            "host": host, "kind": "domain",
            "parent": root_domain(host) if host != root_domain(host) else "",
            "source": "document", "note": filename,
        })
    for ip in targets["ips"]:
        entries.append({
            "host": ip, "kind": "ip", "ip": ip,
            "source": "document", "note": filename,
        })

    added = save_hosts(module_id, entries)

    with db() as conn:
        row = conn.execute("SELECT sources FROM asset_modules WHERE id = ?", (module_id,)).fetchone()
        try:
            sources = json.loads(row["sources"]) if row else []
        except (json.JSONDecodeError, TypeError):
            sources = []
        sources.append({
            "name": filename, "size": len(data), "kind": filename.rsplit(".", 1)[-1].lower(),
            "domains": len(targets["domains"]), "ips": len(targets["ips"]),
            "at": now_iso(),
        })
        conn.execute(
            "UPDATE asset_modules SET sources = ?, seed_count = seed_count + ?, updated_at = ? WHERE id = ?",
            (json.dumps(sources, ensure_ascii=False), len(entries), now_iso(), module_id),
        )

    return {
        "ok": True,
        "file": filename,
        "note": note,
        "domains": len(targets["domains"]),
        "ips": len(targets["ips"]),
        "added": added,
        "llm_used": llm_used,
        "sample": targets["domains"][:10],
    }


def collect_module(
    module_id: int,
    use_crt: bool = True,
    guess: bool = True,
    username: str = "",
) -> dict[str, Any]:
    """按模块里已有的域名往下收集三级子域名。

    三条路一起走：常见前缀猜解（最稳）、DNS 记录里的线索（国内可用）、
    证书透明日志（境外接口，连不上就跳过，不拖慢也不报错）。
    """
    existing = _existing_hosts(module_id)
    seeds = sorted({host for host in existing if _valid_domain(host)})
    roots = sorted({root_domain(host) for host in seeds})
    if not roots:
        return {"ok": False, "error": "模块里还没有域名，先导一份文件或手动加一个域名"}

    candidates: set[str] = set(seeds)
    if guess:
        for root in roots:
            for prefix in PREFIXES:
                candidates.add(f"{prefix}.{root}")

    # DNS 记录线索：SPF 的 include、MX/NS 主机名，都是真实存在的子域
    record_hits: list[str] = []
    record_notes: list[str] = []
    with ThreadPoolExecutor(max_workers=min(8, len(roots) or 1)) as pool:
        for hosts, notes in pool.map(record_subdomains, roots[:8]):
            record_hits.extend(hosts)
            record_notes.extend(notes)
    candidates.update(record_hits)

    crt_hits: list[str] = []
    if use_crt:
        with ThreadPoolExecutor(max_workers=min(5, len(roots) or 1)) as pool:
            for names in pool.map(crt_subdomains, roots[:5]):
                crt_hits.extend(names)
        candidates.update(crt_hits)

    resolved = probe_hosts(candidates)

    entries: list[dict[str, Any]] = []
    for host, ips in resolved.items():
        if host in crt_hits:
            source = "crt"
        elif host in record_hits:
            source = "record"
        else:
            source = "dns"
        for ip in ips or [""]:
            entries.append({
                "host": host, "kind": "domain", "ip": ip,
                "parent": root_domain(host) if host != root_domain(host) else "",
                "source": source,
            })
    added = save_hosts(module_id, entries)

    return {
        "ok": True,
        "roots": roots,
        "tried": len(candidates),
        "resolved": len(resolved),
        "added": added,
        "crt": len(crt_hits),
        "record": len(record_hits),
        "record_notes": record_notes[:5],
        "total": len(existing) + added,
    }


def compare_modules(left: int, right: int) -> dict[str, Any]:
    """对比两个模块：右边新增了什么、左边少了什么、两边都有哪些。"""
    with db() as conn:
        left_row = conn.execute("SELECT * FROM asset_modules WHERE id = ?", (left,)).fetchone()
        right_row = conn.execute("SELECT * FROM asset_modules WHERE id = ?", (right,)).fetchone()
        if not left_row or not right_row:
            return {"ok": False, "error": "模块不存在"}
        left_hosts = {
            str(row["host"]) for row in conn.execute(
                "SELECT host FROM asset_hosts WHERE module_id = ?", (left,)
            ).fetchall()
        }
        right_hosts = {
            str(row["host"]) for row in conn.execute(
                "SELECT host FROM asset_hosts WHERE module_id = ?", (right,)
            ).fetchall()
        }
    added = sorted(right_hosts - left_hosts)
    removed = sorted(left_hosts - right_hosts)
    common = sorted(left_hosts & right_hosts)
    return {
        "ok": True,
        "left": dict(left_row),
        "right": dict(right_row),
        "added": added,
        "removed": removed,
        "common_count": len(common),
        "left_count": len(left_hosts),
        "right_count": len(right_hosts),
        "sample_added": added[:200],
    }


def _llm_extract(text: str) -> dict[str, list[str]] | None:
    """让大模型复核一遍抽取结果；没接模型或调用失败就返回 None，全走正则。"""
    try:
        from ..connectors import connector_rows, load_connector
    except ImportError:
        return None
    key = ""
    for row in connector_rows():
        if row.get("category") != "ai" or not row.get("enabled"):
            continue
        if row.get("secret_enc") or row.get("last_check_ok"):
            key = str(row.get("key") or "")
            break
    if not key:
        return None
    connector = load_connector(key)
    if connector is None:
        return None
    prompt = (
        "从下面的文本里找出所有域名和 IP。只输出 JSON，形如 "
        '{"domains":["a.example.com"],"ips":["1.2.3.4"]}，不要解释。\n\n'
        + text[:6000]
    )
    try:
        import asyncio

        result = asyncio.run(connector.chat("你是资产信息抽取器，只输出 JSON。", prompt, max_tokens=800))
    except Exception:
        return None
    if not getattr(result, "ok", False):
        return None
    raw = str(getattr(result, "text", "") or "")
    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    domains = [item.lower().strip(".") for item in payload.get("domains", []) if isinstance(item, str)]
    ips = [item for item in payload.get("ips", []) if isinstance(item, str)]
    return {
        "domains": [item for item in domains if _valid_domain(item)],
        "ips": [item for item in ips if _is_ip(item)],
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
