"""资产测绘与威胁情报连接器。"""
from __future__ import annotations

import base64
from typing import Any

from .base import BaseConnector, ConnectorResult


def _clean_target(target: str) -> str:
    value = target.strip()
    for prefix in ("https://", "http://"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
    return value.split("/")[0].split("?")[0]


class FofaConnector(BaseConnector):
    key = "fofa"
    category = "recon"

    @property
    def email(self) -> str:
        return str(self.config.get("email") or "")

    def _size(self) -> int:
        try:
            return max(1, min(int(self.config.get("size", 50)), 200))
        except (TypeError, ValueError):
            return 50

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        if not self.email:
            return ConnectorResult(False, "尚未配置账号邮箱")
        resp, error = await self.http_get(
            "/api/v1/info/my", params={"email": self.email, "key": self.secret}
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("error"):
            return ConnectorResult(False, f"接口返回错误: {data.get('errmsg', '未知错误')}")
        return ConnectorResult(True, "FOFA 鉴权通过，账号可用", {"raw": data})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret or not self.email:
            return ConnectorResult(False, "FOFA 密钥或邮箱未配置")
        target = _clean_target(target)
        query = f'domain="{target}"' if kind == "domain" else f'ip="{target}"'
        qbase64 = base64.b64encode(query.encode()).decode()
        resp, error = await self.http_get(
            "/api/v1/search/all",
            params={
                "email": self.email,
                "key": self.secret,
                "qbase64": qbase64,
                "size": self._size(),
                "fields": "host,ip,port,title,domain,server,protocol",
            },
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("error"):
            return ConnectorResult(False, f"检索失败: {data.get('errmsg', '未知错误')}")
        fields = ["host", "ip", "port", "title", "domain", "server", "protocol"]
        items = []
        for row in data.get("results") or []:
            if isinstance(row, list):
                items.append({k: row[i] if i < len(row) else "" for i, k in enumerate(fields)})
            elif isinstance(row, dict):
                items.append(row)
        return ConnectorResult(True, f"FOFA 返回 {len(items)} 条结果", {"items": items, "query": query})


class HunterConnector(BaseConnector):
    key = "hunter"
    category = "recon"

    def _size(self) -> int:
        try:
            return max(1, min(int(self.config.get("size", 20)), 100))
        except (TypeError, ValueError):
            return 20

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        query = base64.urlsafe_b64encode(b'domain="example.com"').decode()
        resp, error = await self.http_get(
            "/openApi/search",
            params={"api-key": self.secret, "search": query, "page": 1, "page_size": 1, "is_web": 3},
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("code") != 200:
            return ConnectorResult(False, f"接口返回错误: {data.get('message', '鉴权或配额异常')}")
        return ConnectorResult(True, "Hunter 鉴权通过，账号可用", {})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret:
            return ConnectorResult(False, "Hunter 密钥未配置")
        target = _clean_target(target)
        query = f'domain="{target}"' if kind == "domain" else f'ip="{target}"'
        encoded = base64.urlsafe_b64encode(query.encode()).decode()
        resp, error = await self.http_get(
            "/openApi/search",
            params={
                "api-key": self.secret,
                "search": encoded,
                "page": 1,
                "page_size": self._size(),
                "is_web": 3,
            },
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("code") != 200:
            return ConnectorResult(False, f"检索失败: {data.get('message', '未知错误')}")
        items = (data.get("data") or {}).get("arr") or []
        return ConnectorResult(True, f"Hunter 返回 {len(items)} 条结果", {"items": items, "query": query})


class QuakeConnector(BaseConnector):
    key = "quake"
    category = "recon"

    def _size(self) -> int:
        try:
            return max(1, min(int(self.config.get("size", 20)), 100))
        except (TypeError, ValueError):
            return 20

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        resp, error = await self.http_post(
            "/api/v3/search/quake_service",
            headers={"X-QuakeToken": self.secret, "Content-Type": "application/json"},
            json={"query": 'domain:"example.com"', "start": 0, "size": 1, "ignore_cache": True},
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("code") != 0:
            return ConnectorResult(False, f"接口返回错误: {data.get('message', '鉴权或配额异常')}")
        return ConnectorResult(True, "Quake 鉴权通过，账号可用", {})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret:
            return ConnectorResult(False, "Quake 密钥未配置")
        target = _clean_target(target)
        query = f'domain:"{target}"' if kind == "domain" else f'ip:"{target}"'
        resp, error = await self.http_post(
            "/api/v3/search/quake_service",
            headers={"X-QuakeToken": self.secret, "Content-Type": "application/json"},
            json={"query": query, "start": 0, "size": self._size(), "ignore_cache": True},
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("code") != 0:
            return ConnectorResult(False, f"检索失败: {data.get('message', '未知错误')}")
        items = data.get("data") or []
        return ConnectorResult(True, f"Quake 返回 {len(items)} 条结果", {"items": items, "query": query})


class ZoomEyeConnector(BaseConnector):
    key = "zoomeye"
    category = "recon"

    def _size(self) -> int:
        try:
            return max(1, min(int(self.config.get("size", 20)), 100))
        except (TypeError, ValueError):
            return 20

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        resp, error = await self.http_get(
            "/web/search",
            params={"query": 'domain:"example.com"', "page": 1, "pagesize": 1},
            headers={"API-KEY": self.secret},
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        return ConnectorResult(True, f"ZoomEye 鉴权通过，配额总数 {data.get('total', 0)}", {})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret:
            return ConnectorResult(False, "ZoomEye 密钥未配置")
        target = _clean_target(target)
        query = f'domain:"{target}"' if kind == "domain" else f'ip:"{target}"'
        resp, error = await self.http_get(
            "/web/search",
            params={"query": query, "page": 1, "pagesize": self._size()},
            headers={"API-KEY": self.secret},
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        items = data.get("matches") or []
        return ConnectorResult(True, f"ZoomEye 返回 {len(items)} 条结果", {"items": items, "query": query})


class ShodanConnector(BaseConnector):
    key = "shodan"
    category = "recon"

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        resp, error = await self.http_get("/api-info", params={"key": self.secret})
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        return ConnectorResult(True, "Shodan 鉴权通过，账号可用", {"credits": data.get("query_credits")})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret:
            return ConnectorResult(False, "Shodan 密钥未配置")
        target = _clean_target(target)
        query = f'hostname:"{target}"' if kind == "domain" else f"ip:{target}"
        resp, error = await self.http_get(
            "/shodan/host/search", params={"key": self.secret, "query": query}
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        items = data.get("matches") or []
        return ConnectorResult(True, f"Shodan 返回 {len(items)} 条结果", {"items": items, "query": query})


class VirusTotalConnector(BaseConnector):
    key = "virustotal"
    category = "intel"

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        resp, error = await self.http_get(
            "/ip_addresses/8.8.8.8", headers={"x-apikey": self.secret}
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        return ConnectorResult(True, "VirusTotal 鉴权通过", {})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret:
            return ConnectorResult(False, "VirusTotal 密钥未配置")
        target = _clean_target(target)
        path = f"/ip_addresses/{target}" if kind == "ip" else f"/domains/{target}"
        resp, error = await self.http_get(path, headers={"x-apikey": self.secret})
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
        return ConnectorResult(
            True,
            f"VirusTotal 情报：恶意判定 {malicious} 项",
            {"attributes": attrs, "malicious": malicious},
        )


class ThreatBookConnector(BaseConnector):
    key = "threatbook"
    category = "intel"

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        resp, error = await self.http_post(
            "/v3/scene/ip_reputation",
            data={"apikey": self.secret, "resource": "8.8.8.8"},
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("response_code") != 0:
            return ConnectorResult(False, f"接口返回错误: {data.get('verbose_msg', '鉴权或配额异常')}")
        return ConnectorResult(True, "微步在线鉴权通过", {})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        if not self.secret:
            return ConnectorResult(False, "微步在线密钥未配置")
        target = _clean_target(target)
        path = "/v3/scene/ip_reputation" if kind == "ip" else "/v3/domain/domain_info"
        resp, error = await self.http_post(path, data={"apikey": self.secret, "resource": target})
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        if data.get("response_code") != 0:
            return ConnectorResult(False, f"查询失败: {data.get('verbose_msg', '未知错误')}")
        return ConnectorResult(True, "微步在线查询完成", {"raw": data.get("data") or {}})


class CensysConnector(BaseConnector):
    key = "censys"
    category = "recon"

    def _auth(self):
        api_id = str(self.config.get("api_id") or "")
        return (api_id, self.secret) if api_id and self.secret else None

    async def test(self) -> ConnectorResult:
        missing = self.require_secret()
        if missing:
            return missing
        auth = self._auth()
        if not auth:
            return ConnectorResult(False, "尚未配置 API ID")
        resp, error = await self.http_get(
            "/v2/hosts/search", params={"q": "8.8.8.8", "per_page": 1}, auth=auth
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        return ConnectorResult(True, "Censys 鉴权通过", {})

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        auth = self._auth()
        if not auth:
            return ConnectorResult(False, "Censys API ID 或 Secret 未配置")
        target = _clean_target(target)
        query = f'hostnames:"{target}"' if kind == "domain" else f'ip:"{target}"'
        resp, error = await self.http_get(
            "/v2/hosts/search",
            params={"q": query, "per_page": 20},
            auth=auth,
        )
        data, error = self.json_of(resp, error)
        if data is None:
            return ConnectorResult(False, error)
        result = data.get("result") or {}
        hits = result.get("hits") or []
        return ConnectorResult(True, f"Censys 返回 {len(hits)} 条结果", {"items": hits, "query": query})
