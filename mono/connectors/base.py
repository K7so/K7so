"""连接器基类与通用 HTTP 调用助手。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..security import decrypt_secret


@dataclass
class ConnectorResult:
    ok: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)


def parse_json_config(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        return {}


class BaseConnector:
    key: str = ""
    category: str = ""

    def __init__(self, row: dict[str, Any]):
        self.row = row
        self.config = parse_json_config(row.get("config_json"))
        self.base_url = (row.get("base_url") or "").rstrip("/")
        self.secret = decrypt_secret(row.get("secret_enc") or "")
        self.enabled = bool(row.get("enabled"))

    @property
    def name(self) -> str:
        return self.row.get("name", self.key)

    @property
    def timeout(self) -> float:
        try:
            return float(self.config.get("timeout", 15))
        except (TypeError, ValueError):
            return 15.0

    def url(self, path: str) -> str:
        if not path:
            return self.base_url
        if path.startswith("http"):
            return path
        return f"{self.base_url}{path if path.startswith('/') else '/' + path}"

    async def test(self) -> ConnectorResult:
        raise NotImplementedError

    async def search(self, target: str, kind: str = "domain") -> ConnectorResult:
        return ConnectorResult(False, "该连接器不支持资产检索")

    async def http_get(self, path: str, **kwargs: Any) -> tuple[httpx.Response | None, str]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(self.url(path), **kwargs)
                return resp, ""
        except Exception as exc:  # 网络错误统一转成可读信息
            return None, f"请求异常: {type(exc).__name__}: {exc}"

    async def http_post(self, path: str, **kwargs: Any) -> tuple[httpx.Response | None, str]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.post(self.url(path), **kwargs)
                return resp, ""
        except Exception as exc:
            return None, f"请求异常: {type(exc).__name__}: {exc}"

    @staticmethod
    def json_of(resp: httpx.Response | None, error: str) -> tuple[dict[str, Any] | None, str]:
        if resp is None:
            return None, error
        if resp.status_code >= 400:
            snippet = resp.text[:240].replace("\n", " ")
            return None, f"HTTP {resp.status_code}: {snippet}"
        try:
            data = resp.json()
        except ValueError:
            return None, "接口返回非 JSON 数据"
        if not isinstance(data, dict):
            return None, "接口返回结构异常"
        return data, ""

    def require_secret(self) -> ConnectorResult | None:
        if not self.secret:
            return ConnectorResult(False, "尚未配置密钥，请先在 API 中心填写")
        return None
