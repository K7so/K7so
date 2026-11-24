"""登录 / 登出 / 当前用户。"""
from __future__ import annotations

import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from ..config import APP_VERSION, DEFAULT_ADMIN, SESSION_COOKIE, SESSION_TTL
from ..db import audit, db
from ..security import create_session, hash_password, verify_password
from .deps import client_ip, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

_failures: dict[str, list[float]] = defaultdict(list)
LOCK_WINDOW = 300
MAX_FAILURES = 8


def _check_lock(ip: str) -> None:
    now = time.time()
    recent = [t for t in _failures.get(ip, []) if now - t < LOCK_WINDOW]
    _failures[ip] = recent
    if len(recent) >= MAX_FAILURES:
        raise HTTPException(status_code=429, detail="失败次数过多，请 5 分钟后再试")


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(payload: LoginIn, request: Request, response: Response):
    ip = client_ip(request)
    _check_lock(ip)
    with db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (payload.username.strip(),)
        ).fetchone()
    if not user or not verify_password(payload.password, user["password_hash"]):
        _failures[ip].append(time.time())
        audit(payload.username, "login_failed", "用户名或口令错误", ip)
        raise HTTPException(status_code=401, detail="用户名或口令错误")
    _failures.pop(ip, None)
    token = create_session(user["username"], user["role"])
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
    )
    audit(user["username"], "login", "登录成功", ip)
    return {
        "ok": True,
        "username": user["username"],
        "role": user["role"],
        "version": APP_VERSION,
    }


@router.post("/disclaimer")
async def accept_disclaimer(request: Request, user=Depends(get_current_user)):
    """登录后确认免责声明，写入审计留痕。"""
    audit(user.get("u", ""), "disclaimer_accept", "确认免责声明并进入控制台", client_ip(request))
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response, user=Depends(get_current_user)):
    response.delete_cookie(SESSION_COOKIE)
    audit(user.get("u", ""), "logout", "退出登录")
    return {"ok": True}


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return {
        "username": user.get("u"),
        "role": user.get("r"),
        "version": APP_VERSION,
        "default_admin": DEFAULT_ADMIN,
    }


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


@router.post("/password")
async def change_password(payload: PasswordIn, request: Request, user=Depends(get_current_user)):
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="新口令至少需要 8 位")
    if payload.old_password == payload.new_password:
        raise HTTPException(status_code=400, detail="新口令不能与当前口令相同")
    with db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username=?", (user.get("u"),)
        ).fetchone()
        if not row or not verify_password(payload.old_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="当前口令不正确")
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (hash_password(payload.new_password), user.get("u")),
        )
    audit(user.get("u", ""), "password_change", "修改登录口令", client_ip(request))
    return {"ok": True}
