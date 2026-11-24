"""模型能力：查看与保存 AI 专项测试能力开关、测试权重。"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..db import audit
from ..engine.capabilities import (
    ASK_DELETE_KEY,
    ASK_SENSITIVE_KEY,
    AUTO_PENTEST_KEY,
    CAPABILITIES,
    DEFAULT_WEIGHT,
    GROUP_ORDER,
    SWITCHES,
    WEIGHT_MAX,
    WEIGHT_MIN,
    enabled_keys,
    get_hints,
    get_switches,
    get_weights,
    save_enabled,
    save_hints,
    save_weights,
    set_switches,
    weighted_items,
)
from .deps import get_current_user

router = APIRouter(prefix="/api/capabilities", tags=["capabilities"])


class CapabilitiesIn(BaseModel):
    keys: list[str] = []
    switches: dict[str, bool] | None = None
    weights: dict[str, int] | None = None
    # 整表替换：传了就以它为准（空串＝删掉这条提示）；不传则不动已有提示
    hints: dict[str, str] | None = None


def _ask_state(switches: dict[str, bool]) -> dict[str, bool]:
    """两个询问开关平级；不再有总开关。"""
    return {
        "ask_sensitive": bool(switches.get(ASK_SENSITIVE_KEY, True)),
        "ask_delete": bool(switches.get(ASK_DELETE_KEY, True)),
    }


@router.get("")
async def list_capabilities():
    active = set(enabled_keys())
    switches = get_switches()
    asks = _ask_state(switches)
    weights = get_weights()
    hints = get_hints()
    ordered = [item["key"] for item in weighted_items()]
    return {
        "items": [
            {
                **item,
                "enabled": item["key"] in active,
                "weight": weights.get(item["key"], DEFAULT_WEIGHT),
                "user_prompt": hints.get(item["key"], ""),
            }
            for item in CAPABILITIES
        ],
        "enabled": sorted(active),
        "total": len(CAPABILITIES),
        "groups": GROUP_ORDER,
        "weights": weights,
        "hints": hints,
        "order": ordered,
        "weight_scale": {"min": WEIGHT_MIN, "max": WEIGHT_MAX, "default": DEFAULT_WEIGHT},
        "switches": [{**item, "enabled": bool(switches.get(item["key"]))} for item in SWITCHES],
        # 保留字段只为兼容旧客户端：还有开关在问就算开启
        "confirm_actions": any(asks.values()),
        **asks,
    }


@router.put("")
async def update_capabilities(payload: CapabilitiesIn, user=Depends(get_current_user)):
    keys = save_enabled(payload.keys)
    switches = set_switches(payload.switches or {})
    weights = save_weights(payload.weights or {})
    hints = get_hints()
    if payload.hints is not None:
        hints = save_hints(payload.hints)
    asks = _ask_state(switches)
    ask_text = "、".join(
        [
            f"敏感信息={'问' if asks['ask_sensitive'] else '不问'}",
            f"删除操作={'问' if asks['ask_delete'] else '不问'}",
        ]
    )
    auto_text = "自动渗透=开" if switches.get(AUTO_PENTEST_KEY) else "自动渗透=关"
    top = [item["name"] for item in weighted_items()[:3]]
    hint_text = f"用户提示 {len(hints)} 项" if hints else "用户提示 0 项"
    audit(
        user.get("u", ""),
        "capabilities_update",
        f"测试能力启用 {len(keys)} 项；{auto_text}；操作询问（{ask_text}）；"
        f"{hint_text}；优先顺序（{'、'.join(top) or '无'}）",
    )
    return {
        "ok": True,
        "enabled": keys,
        "count": len(keys),
        "weights": weights,
        "hints": hints,
        "order": [item["key"] for item in weighted_items()],
        "switches": switches,
        "auto_pentest": bool(switches.get(AUTO_PENTEST_KEY)),
        "confirm_actions": any(asks.values()),
        **asks,
    }
