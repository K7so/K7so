"""漏洞平台连接器：补天、NCC（可配置 REST 适配器）。"""
from __future__ import annotations

from .base import BaseConnector, ConnectorResult


class ConfigurablePlatformConnector(BaseConnector):
    """面向企业版 / 私有化漏洞平台的通用适配器。

    平台开放的具体接口路径差异较大，因此将 endpoint 与鉴权头做成可配置项：
      - endpoint 为空时仅做站点连通性检测；
      - 配置后使用密钥访问该路径，HTTP 4xx/2xx 视为可达，5xx 视为异常。
    """

    default_auth_header = "Authorization"

    async def test(self) -> ConnectorResult:
        endpoint = str(self.config.get("endpoint") or "").strip()
        auth_header = str(self.config.get("auth_header") or self.default_auth_header)
        headers = {}
        if self.secret:
            headers[auth_header] = self.secret if auth_header.lower() == "authorization" else self.secret
        resp, error = await self.http_get(endpoint, headers=headers, timeout=20)
        if resp is None:
            return ConnectorResult(False, error or "无法连接平台")
        if resp.status_code >= 500:
            return ConnectorResult(False, f"平台返回 HTTP {resp.status_code}，服务异常")
        if not endpoint:
            return ConnectorResult(
                True,
                f"站点可达（HTTP {resp.status_code}）。未配置接口路径，仅完成连通性检测",
                {"status_code": resp.status_code},
            )
        return ConnectorResult(
            True,
            f"接口可达（HTTP {resp.status_code}），鉴权与配额请以平台控制台为准",
            {"status_code": resp.status_code, "endpoint": endpoint},
        )


class ButianConnector(ConfigurablePlatformConnector):
    key = "butian"
    category = "vuln"
    default_auth_header = "X-API-KEY"


class NccConnector(ConfigurablePlatformConnector):
    key = "ncc"
    category = "vuln"
    default_auth_header = "Authorization"
