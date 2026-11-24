"""API 通用依赖：会话校验与客户端信息。"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from ..config import SESSION_COOKIE
from ..security import read_session


def get_current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        header = request.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
    payload = read_session(token)
    if not payload:
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    return payload


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""
