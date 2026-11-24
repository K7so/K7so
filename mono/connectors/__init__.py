"""连接器注册表与运行时装配。"""
from __future__ import annotations

from typing import Any

from ..db import db, now_iso
from .base import BaseConnector, ConnectorResult
from .llm import (
    AnthropicConnector,
    BaiduConnector,
    CustomLLMConnector,
    DeepSeekConnector,
    DoubaoConnector,
    GeminiConnector,
    GenericOpenAIConnector,
    HunyuanConnector,
    MiniMaxConnector,
    MoonshotConnector,
    NccLLMConnector,
    OllamaConnector,
    QwenConnector,
    SiliconFlowConnector,
    ZhipuConnector,
)
from .platforms import ButianConnector, NccConnector
from .recon import (
    CensysConnector,
    FofaConnector,
    HunterConnector,
    QuakeConnector,
    ShodanConnector,
    ThreatBookConnector,
    VirusTotalConnector,
    ZoomEyeConnector,
)
from .tools import HttpxConnector, NmapConnector, NucleiConnector

REGISTRY: dict[str, type[BaseConnector]] = {
    cls.key: cls
    for cls in (
        DeepSeekConnector,
        GenericOpenAIConnector,
        AnthropicConnector,
        GeminiConnector,
        QwenConnector,
        MoonshotConnector,
        ZhipuConnector,
        DoubaoConnector,
        HunyuanConnector,
        BaiduConnector,
        MiniMaxConnector,
        SiliconFlowConnector,
        OllamaConnector,
        NccLLMConnector,
        CustomLLMConnector,
        FofaConnector,
        HunterConnector,
        QuakeConnector,
        ZoomEyeConnector,
        ShodanConnector,
        CensysConnector,
        VirusTotalConnector,
        ThreatBookConnector,
        ButianConnector,
        NccConnector,
        NmapConnector,
        NucleiConnector,
        HttpxConnector,
    )
}


def load_connector(key: str) -> BaseConnector | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM connectors WHERE key=?", (key,)).fetchone()
    if not row:
        return None
    cls = REGISTRY.get(key)
    if not cls:
        return None
    return cls(dict(row))


def connector_rows() -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM connectors ORDER BY category, id")]


async def run_connector_test(key: str) -> ConnectorResult:
    connector = load_connector(key)
    if not connector:
        return ConnectorResult(False, "连接器不存在")
    try:
        result = await connector.test()
    except Exception as exc:  # 避免单个适配器异常导致接口 500
        result = ConnectorResult(False, f"检测异常: {type(exc).__name__}: {exc}")
    with db() as conn:
        conn.execute(
            "UPDATE connectors SET last_check_at=?, last_check_ok=?, last_check_msg=? WHERE key=?",
            (now_iso(), 1 if result.ok else 0, result.message[:500], key),
        )
    return result
