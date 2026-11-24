"""内置被动探测与低风险检测逻辑（无需外部工具即可工作）。

所有检查均为只读、非破坏性的配置面探测，仅用于已获授权的目标。
"""
from __future__ import annotations

import asyncio
import html as html_lib
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

COMMON_PORTS: dict[str, list[int]] = {
    "quick": [80, 443, 22, 21, 25, 3389, 8080, 8443, 3306, 6379],
    "standard": [
        80, 443, 22, 21, 25, 53, 110, 143, 445, 873, 3389, 3306, 5432,
        6379, 7001, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017, 5900,
    ],
    "deep": [
        20, 21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 161, 389, 443, 445, 512,
        513, 514, 636, 873, 1080, 1521, 2049, 2375, 3128, 3306, 3389, 5000, 5432,
        5900, 5984, 6379, 6443, 7001, 8000, 8009, 8080, 8081, 8088, 8443, 8888,
        9000, 9042, 9090, 9200, 9300, 11211, 15672, 27017, 27018,
    ],
}

RISKY_PORTS: dict[int, tuple[str, str, str, float]] = {
    21: ("FTP 服务暴露", "medium", "明文文件传输协议，凭据与数据可被嗅探", 5.3),
    23: ("Telnet 服务暴露", "high", "明文远程管理协议，凭据可被嗅探", 7.5),
    2375: ("Docker API 未加密暴露", "critical", "可能导致容器逃逸与主机接管", 9.8),
    3306: ("MySQL 数据库暴露", "medium", "数据库端口直接暴露在攻击面", 5.3),
    3389: ("RDP 远程桌面暴露", "medium", "远程桌面暴露易遭受爆破与漏洞利用", 6.5),
    445: ("SMB 服务暴露", "medium", "文件共享服务暴露，存在横向移动风险", 5.3),
    5432: ("PostgreSQL 数据库暴露", "medium", "数据库端口直接暴露在攻击面", 5.3),
    5900: ("VNC 服务暴露", "medium", "远程桌面服务暴露", 6.5),
    6379: ("Redis 服务暴露", "high", "Redis 未授权访问可导致数据泄露或写入利用", 8.1),
    7001: ("WebLogic 服务暴露", "medium", "中间件控制端口暴露，需关注历史漏洞", 6.5),
    9200: ("Elasticsearch 暴露", "high", "搜索引擎接口暴露，可能未授权读取数据", 7.5),
    11211: ("Memcached 服务暴露", "high", "缓存服务暴露，可能被滥用或泄露数据", 7.5),
    15672: ("RabbitMQ 管理端口暴露", "medium", "消息队列管理面暴露", 6.5),
    27017: ("MongoDB 数据库暴露", "high", "数据库端口暴露，存在未授权访问风险", 7.5),
}


def make_finding(
    title: str,
    severity: str,
    category: str,
    source: str,
    description: str,
    evidence: str,
    remediation: str,
    dedupe_key: str,
    cvss: float = 0.0,
    confidence: str = "medium",
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "source": source,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "cvss": cvss,
        "confidence": confidence,
        "dedupe_key": dedupe_key,
    }


def normalize_url_candidates(target: str) -> list[str]:
    target = target.strip()
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return [target]
    host = target.split("/")[0]
    return [f"https://{host}", f"http://{host}"]


def extract_title(body: str) -> str:
    match = TITLE_RE.search(body or "")
    if not match:
        return ""
    return html_lib.unescape(re.sub(r"\s+", " ", match.group(1))).strip()[:160]


def tls_details(host: str, timeout: float = 5.0) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        expiry = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        return {
            "subject": subject,
            "issuer": issuer,
            "expires": expiry.strftime("%Y-%m-%d"),
            "days_left": (expiry.timestamp() - __import__("time").time()) / 86400,
            "self_signed": issuer == subject,
        }
    except Exception:
        return {}


def request_packet_text(method: str, url: str, user_agent: str) -> str:
    parsed = urlparse(url)
    target = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    return (
        f"{method} {target} HTTP/1.1\n"
        f"Host: {parsed.netloc}\n"
        f"User-Agent: {user_agent}\n"
        "Accept: */*\n"
        "Connection: close"
    )


def response_packet_text(resp: httpx.Response, body: str = "") -> str:
    head = [f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}"]
    head.extend(f"{key}: {value}" for key, value in resp.headers.items())
    return "\n".join(head) + "\n\n" + (body or "")[:1200]


async def fetch_sensitive_paths(
    client: httpx.AsyncClient, base_url: str, checks: dict[str, str]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path, signature in checks.items():
        url = base_url.rstrip("/") + path
        try:
            resp = await client.get(url, timeout=6)
        except Exception:
            continue
        body = resp.text[:4000] if resp.status_code < 300 else ""
        if resp.status_code != 200 or signature not in body:
            continue
        finding = make_finding(
            title=f"敏感文件/接口暴露：{path}",
            severity="high",
            category="敏感信息暴露",
            source="builtin",
            description=f"目标可直接访问 {path}，返回内容命中敏感特征，可能导致配置或源码泄露。",
            evidence=f"GET {url} -> HTTP 200，响应包含特征「{signature[:40]}」",
            remediation="删除或限制该资源的公网访问，增加鉴权，并在网关层统一拦截敏感路径。",
            dedupe_key=f"path:{urlparse(url).netloc}:{path}",
            cvss=8.2,
            confidence="high",
        )
        finding["url"] = url
        finding["request_packet"] = request_packet_text("GET", url, "K7so-Pentest/1.0")
        finding["response_packet"] = response_packet_text(resp, body)
        findings.append(finding)
    return findings


def header_findings(probe: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    headers = {k.lower(): v for k, v in (probe.get("headers") or {}).items()}
    url = probe.get("url", "")
    host = urlparse(url).netloc
    final_scheme = urlparse(url).scheme
    csp = headers.get("content-security-policy", "")
    is_html = "text/html" in headers.get("content-type", "")

    def add(title: str, severity: str, desc: str, evidence: str, fix: str, key: str, cvss: float):
        findings.append(
            make_finding(title, severity, "安全配置", "builtin", desc, evidence, fix, f"header:{host}:{key}", cvss)
        )

    if is_html and not csp:
        add(
            "缺少 Content-Security-Policy",
            "low",
            "未设置 CSP，浏览器对脚本来源缺乏约束，会放大 XSS 风险。",
            "响应头中未发现 Content-Security-Policy",
            "按业务需要配置 CSP，至少限制 default-src 与 script-src 来源。",
            "csp",
            3.7,
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        add(
            "缺少点击劫持防护",
            "medium",
            "页面可被第三方站点内嵌，存在点击劫持风险。",
            "X-Frame-Options 缺失且 CSP 未声明 frame-ancestors",
            "设置 X-Frame-Options: DENY 或 CSP frame-ancestors 'self'。",
            "clickjacking",
            4.3,
        )
    if "x-content-type-options" not in headers:
        add(
            "缺少 MIME 类型嗅探防护",
            "low",
            "浏览器可能对响应进行 MIME 嗅探，增加内容注入风险。",
            "未设置 X-Content-Type-Options: nosniff",
            "添加 X-Content-Type-Options: nosniff。",
            "nosniff",
            3.1,
        )
    if "referrer-policy" not in headers:
        add(
            "缺少 Referrer-Policy",
            "info",
            "跨站请求时可能泄露完整 URL 与查询参数。",
            "未设置 Referrer-Policy",
            "配置 Referrer-Policy: strict-origin-when-cross-origin 或更严格策略。",
            "referrer",
            0.0,
        )
    if final_scheme == "https" and "strict-transport-security" not in headers:
        add(
            "未启用 HSTS",
            "low",
            "未强制 HTTPS，存在降级到明文 HTTP 的风险。",
            "HTTPS 响应中缺少 Strict-Transport-Security",
            "设置 Strict-Transport-Security: max-age=31536000; includeSubDomains。",
            "hsts",
            3.7,
        )
    server = headers.get("server", "")
    if re.search(r"\d", server) and "/" in server:
        add(
            "中间件版本信息泄露",
            "low",
            "响应头暴露了中间件名称与版本，便于攻击者匹配已知漏洞。",
            f"Server: {server}",
            "移除或泛化 Server 响应头中的版本信息。",
            "server-banner",
            2.6,
        )
    if "x-powered-by" in headers:
        add(
            "技术栈信息泄露",
            "info",
            "响应头暴露后端技术栈。",
            f"X-Powered-By: {headers['x-powered-by']}",
            "移除 X-Powered-By 等指纹响应头。",
            "powered-by",
            0.0,
        )
    cookies = probe.get("cookies") or []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        if final_scheme == "https" and "secure" not in low:
            add(
                f"Cookie 缺少 Secure 标记：{name}",
                "low",
                "会话 Cookie 可能在明文信道中被传输。",
                cookie[:180],
                "为所有会话 Cookie 添加 Secure 标记。",
                f"cookie-secure:{name}",
                3.1,
            )
        if "httponly" not in low:
            add(
                f"Cookie 缺少 HttpOnly 标记：{name}",
                "low",
                "Cookie 可被脚本读取，增加 XSS 后的会话窃取风险。",
                cookie[:180],
                "为会话 Cookie 添加 HttpOnly 标记。",
                f"cookie-httponly:{name}",
                3.1,
            )
    return findings


def tls_findings(probe: dict[str, Any]) -> list[dict[str, Any]]:
    tls = probe.get("tls") or {}
    host = urlparse(probe.get("url", "")).netloc
    findings: list[dict[str, Any]] = []
    if not tls:
        return findings
    if tls.get("days_left", 999) < 0:
        findings.append(
            make_finding(
                "TLS 证书已过期",
                "medium",
                "证书已过期，浏览器将告警，且可能存在中间人风险。",
                f"证书有效期至 {tls.get('expires')}",
                "及时续签并更新 TLS 证书。",
                f"tls:expired:{host}",
                5.3,
                "high",
            )
        )
    if tls.get("self_signed"):
        findings.append(
            make_finding(
                "使用自签名 TLS 证书",
                "low",
                "自签名证书无法验证服务端身份。",
                f"issuer={tls.get('issuer')}",
                "使用受信任 CA 签发的证书。",
                f"tls:selfsigned:{host}",
                3.1,
            )
        )
    return findings


def port_findings(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in ports:
        port = int(item.get("port", 0))
        host = item.get("host", "")
        if port in RISKY_PORTS:
            title, severity, desc, cvss = RISKY_PORTS[port]
            service = item.get("product") or item.get("service") or ""
            findings.append(
                make_finding(
                    f"暴露服务：{port} {title}",
                    severity,
                    "暴露面",
                    "port-scan",
                    desc,
                    f"{host}:{port} open {service}".strip(),
                    "关闭不必要的公网端口，或通过防火墙 / 访问控制限制来源，并启用强认证。",
                    f"port:{host}:{port}",
                    cvss,
                    "high",
                )
            )
        elif port not in (80, 443):
            findings.append(
                make_finding(
                    f"开放端口：{host}:{port}",
                    "info",
                    "暴露面",
                    "port-scan",
                    "端口对外开放，建议确认业务必要性。",
                    f"{host}:{port} {item.get('service', '')}",
                    "核对端口归属与访问控制策略，关闭非必要服务。",
                    f"port:{host}:{port}",
                    0.0,
                    "high",
                )
            )
    return findings


async def builtin_port_scan(
    targets: list[str],
    profile: str = "standard",
    concurrency: int = 64,
    timeout: float = 1.5,
) -> list[dict[str, Any]]:
    ports = COMMON_PORTS.get(profile, COMMON_PORTS["standard"])
    semaphore = asyncio.Semaphore(max(4, concurrency))
    results: list[dict[str, Any]] = []

    async def probe(host: str, port: int) -> None:
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                results.append({"host": host, "port": port, "protocol": "tcp", "service": ""})
            except Exception:
                return

    tasks = [probe(target, port) for target in targets for port in ports]
    if tasks:
        await asyncio.gather(*tasks)
    return sorted(results, key=lambda x: (x["host"], x["port"]))


async def probe_targets(
    targets: list[str],
    user_agent: str,
    timeout: float = 8,
    concurrency: int = 16,
    sensitive_checks: bool = False,
) -> list[dict[str, Any]]:
    """对目标执行 HTTP 探测；失败时自动在 https/http 之间回退。"""
    semaphore = asyncio.Semaphore(max(2, concurrency))
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 6)),
        headers={"User-Agent": user_agent, "Accept": "*/*"},
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
    ) as client:

        async def one(target: str) -> None:
            async with semaphore:
                last_error = ""
                for url in normalize_url_candidates(target):
                    try:
                        resp = await client.get(url)
                        body = resp.text[:6000] if "text" in resp.headers.get("content-type", "") or resp.headers.get("content-type", "") == "" else ""
                        probe = {
                            "target": target,
                            "url": str(resp.url),
                            "status": resp.status_code,
                            "title": extract_title(body),
                            "headers": dict(resp.headers),
                            "server": resp.headers.get("server", ""),
                            "powered_by": resp.headers.get("x-powered-by", ""),
                            "cookies": resp.headers.get_list("set-cookie"),
                            "body_preview": body[:1500],
                            "request_packet": request_packet_text("GET", str(resp.url), user_agent),
                            "response_packet": response_packet_text(resp, body),
                            "error": "",
                        }
                        host = urlparse(str(resp.url)).hostname or ""
                        if urlparse(str(resp.url)).scheme == "https":
                            probe["tls"] = await asyncio.to_thread(tls_details, host, min(timeout, 6))
                        findings = header_findings(probe) + tls_findings(probe)
                        if "Index of /" in probe["title"]:
                            findings.append(
                                make_finding(
                                    "目录列表功能开启",
                                    "low",
                                    "信息泄露",
                                    "builtin",
                                    "Web 服务器开启了目录浏览，可能泄露文件结构。",
                                    f"{probe['url']} 标题为 {probe['title']}",
                                    "关闭目录浏览（如 Apache Options -Indexes / Nginx autoindex off）。",
                                    f"dirlist:{urlparse(probe['url']).netloc}",
                                    3.7,
                                     )
                            )
                        if sensitive_checks:
                            checks = {
                                "/.env": "APP_",
                                "/.git/HEAD": "ref: refs/",
                                "/actuator/env": "propertySources",
                                "/phpinfo.php": "PHP Version",
                                "/server-status": "Apache Server Status",
                            }
                            findings += await fetch_sensitive_paths(client, probe["url"], checks)
                        for item in findings:
                            item.setdefault("url", probe["url"])
                            item.setdefault("request_packet", probe["request_packet"])
                            item.setdefault("response_packet", probe["response_packet"])
                        probe["findings"] = findings
                        results.append(probe)
                        return
                    except Exception as exc:
                        last_error = f"{type(exc).__name__}: {exc}"
                results.append(
                    {
                        "target": target,
                        "url": target,
                        "status": 0,
                        "title": "",
                        "headers": {},
                        "server": "",
                        "powered_by": "",
                        "cookies": [],
                        "body_preview": "",
                        "error": last_error,
                        "findings": [],
                        "tls": {},
                    }
                )

        await asyncio.gather(*(one(t) for t in targets))
    return results
