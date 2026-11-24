"""平台设置：安全开关、运行参数与 AI 目录配置。

授权范围（授权域名 / 授权网段 / 允许内网）已整体取消：用户登录时确认的免责声明
就是操作授权，平台不再维护白名单、也不再逐条确认目标是否在范围内。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..db import audit, get_settings, set_settings
from ..engine.workspace import memory_info, work_info
from .deps import get_current_user

router = APIRouter(prefix="/api/settings", tags=["settings"])

ALLOWED = {
    "safe_mode", "max_concurrency", "request_timeout", "user_agent",
    "sensitive_path_checks", "ai_enabled", "memory_path", "work_dir",
}
BOOL_KEYS = {"safe_mode", "sensitive_path_checks", "ai_enabled"}
PATH_KEYS = {"memory_path", "work_dir"}


class SettingsIn(BaseModel):
    safe_mode: bool | None = None
    max_concurrency: int | None = None
    request_timeout: float | None = None
    user_agent: str | None = None
    sensitive_path_checks: bool | None = None
    ai_enabled: bool | None = None
    memory_path: str | None = None
    work_dir: str | None = None


@router.get("")
async def read_settings():
    settings = get_settings()

    def _num(key: str, fallback: float) -> float:
        try:
            return float(settings.get(key) or fallback)
        except (TypeError, ValueError):
            return fallback

    # 只吐出仍然有效的键：老库里残留下线的配置也不会漏到前端
    data = {key: settings[key] for key in ALLOWED if key in settings}
    data.update(
        {
            "safe_mode": settings.get("safe_mode", "true") in ("1", "true", "yes", "on"),
            "sensitive_path_checks": settings.get("sensitive_path_checks", "true") in ("1", "true", "yes", "on"),
            "ai_enabled": settings.get("ai_enabled", "true") in ("1", "true", "yes", "on"),
            "max_concurrency": int(_num("max_concurrency", 24)),
            "request_timeout": _num("request_timeout", 8),
            "authorization_mode": "disclaimer",
        }
    )
    return data


@router.get("/paths")
async def read_paths():
    settings = get_settings()
    return {
        "memory_path": settings.get("memory_path", ""),
        "work_dir": settings.get("work_dir", ""),
        "memory": memory_info(),
        "work": work_info(),
    }


@router.put("")
async def update_settings(payload: SettingsIn, user=Depends(get_current_user)):
    values: dict[str, Any] = {}
    for key, value in payload.model_dump(exclude_none=True).items():
        if key not in ALLOWED:
            continue
        if key in BOOL_KEYS:
            values[key] = "true" if bool(value) else "false"
        elif key == "max_concurrency":
            values[key] = str(max(2, min(int(value), 128)))
        elif key == "request_timeout":
            values[key] = str(max(1, min(float(value), 60)))
        elif key in PATH_KEYS:
            text = str(value).strip()
            if key == "work_dir" and text:
                try:
                    Path(text).expanduser().mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    raise HTTPException(status_code=400, detail=f"工作目录不可用：{exc}")
            if key == "memory_path" and text:
                target = Path(text).expanduser()
                try:
                    # 指向目录就建目录；指向单个记忆文件就先建它的父目录
                    if target.exists() and target.is_file():
                        pass
                    elif target.suffix.lower() in {".md", ".markdown", ".txt", ".yaml", ".yml", ".json"}:
                        target.parent.mkdir(parents=True, exist_ok=True)
                    else:
                        target.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    raise HTTPException(status_code=400, detail=f"记忆目录不可用：{exc}")
            values[key] = text[:500]
        elif key == "user_agent":
            text = str(value).strip()
            if not text:
                raise HTTPException(status_code=400, detail="User-Agent 不能为空")
            values[key] = text[:200]
        else:
            values[key] = str(value).strip()[:2000]
    set_settings(values)
    audit(user.get("u", ""), "settings_update", "更新平台设置：" + ", ".join(values.keys()))
    return {"ok": True, "updated": list(values.keys())}
