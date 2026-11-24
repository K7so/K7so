"""API 中心：连接器配置、密钥托管与连通性检测。"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..catalog import CATALOG_BY_KEY, CATEGORY_LABELS
from ..connectors import connector_rows, run_connector_test
from ..db import audit, db, now_iso
from ..security import decrypt_secret, encrypt_secret
from .deps import get_current_user

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


def mask_secret(secret: str) -> str:
    """把托管的密钥改写成可辨认但不可用的样子：sk-abc…9f2c。

    要求是「配完能看见自己的 Key 长什么样」，不是把 Key 再交出去一遍，
    所以只留头尾各几位，中间一律打星；太短的值干脆只留后四位。
    """
    text = (secret or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return "****" + text[-2:]
    if len(text) <= 16:
        return text[:3] + "*" * 6 + text[-2:]
    return text[:6] + "…" + text[-4:]


class ConnectorIn(BaseModel):
    enabled: bool | None = None
    base_url: str | None = None
    config: dict[str, Any] | None = None
    secret: str | None = None


def present(row: dict[str, Any]) -> dict[str, Any]:
    meta = CATALOG_BY_KEY.get(row["key"], {})
    try:
        config = json.loads(row.get("config_json") or "{}")
    except json.JSONDecodeError:
        config = {}
    encrypted = row.get("secret_enc") or ""
    masked = mask_secret(decrypt_secret(encrypted)) if encrypted else ""
    base_url = str(row.get("base_url") or "").strip()
    # 自定义模型允许自己起名：配置页与对话页的模型下拉都优先显示这个名字
    label = str(config.get("label") or "").strip()
    return {
        "key": row["key"],
        "name": label or row["name"],
        "vendor": row.get("vendor", ""),
        "category": row["category"],
        "category_label": CATEGORY_LABELS.get(row["category"], row["category"]),
        "description": row.get("description", ""),
        "auth_type": row.get("auth_type", ""),
        "base_url": row.get("base_url", ""),
        "enabled": bool(row.get("enabled")),
        # 「已配置」= 真的能用：有托管密钥、是本地 CLI，或者上次检测确实出了结果。
        # 自定义模型/内网网关可以不带 Key，只认最后一条——否则检测成功了也不进「已接入」列表。
        "configured": bool(encrypted) or row.get("auth_type") == "cli" or bool(row.get("last_check_ok")),
        # 「已接入」列表按这个收：保存过但还没检测的自定义模型也要看得见，
        # 否则用户刚填完就看到「尚未配置大模型」，会以为没存上。
        # 只对 custom 放宽——其它内置连接器目录里本来就带着默认地址与模型名，
        # 放宽的话没配过的 DeepSeek / Claude 会一起冒出来，列表立刻变成一锅粥。
        "saved": bool(encrypted)
        or row.get("auth_type") == "cli"
        or bool(row.get("last_check_ok"))
        or (
            row["key"] == "custom"
            and bool(base_url)
            and bool(str(config.get("model") or "").strip())
        ),
        "secret_masked": masked,
        "config": config,
        "fields": meta.get("fields", []),
        "secret_label": meta.get("secret_label", "API Key"),
        "secret_required": meta.get("secret_required", False),
        "docs_url": row.get("docs_url", ""),
        "last_check_at": row.get("last_check_at"),
        "last_check_ok": row.get("last_check_ok"),
        "last_check_msg": row.get("last_check_msg"),
    }


@router.get("")
async def list_connectors():
    return [present(row) for row in connector_rows()]


@router.put("/{key}")
async def update_connector(key: str, payload: ConnectorIn, user=Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM connectors WHERE key=?", (key,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="连接器不存在")
        fields: dict[str, Any] = {}
        if payload.enabled is not None:
            fields["enabled"] = 1 if payload.enabled else 0
        if payload.base_url is not None:
            base_url = payload.base_url.strip().rstrip("/")
            if base_url and not base_url.startswith(("http://", "https://")):
                raise HTTPException(status_code=400, detail="Base URL 必须以 http:// 或 https:// 开头")
            fields["base_url"] = base_url
        if payload.config is not None:
            fields["config_json"] = json.dumps(payload.config, ensure_ascii=False)
        if payload.secret is not None and payload.secret.strip():
            # 空字符串表示「不改动已托管的 Key」，别让一次误保存把 Key 清掉
            fields["secret_enc"] = encrypt_secret(payload.secret.strip())
        fields["updated_at"] = now_iso()
        columns = ", ".join(f"{k}=?" for k in fields)
        conn.execute(f"UPDATE connectors SET {columns} WHERE key=?", (*fields.values(), key))
    audit(user.get("u", ""), "connector_update", f"更新连接器 {key}")
    return {
        "ok": True,
        "secret_masked": mask_secret(payload.secret.strip()) if payload.secret and payload.secret.strip() else "",
    }


@router.delete("/{key}")
async def remove_connector(key: str, user=Depends(get_current_user)):
    """移除已接入的模型：清空托管密钥、停用、清掉上次检测结果。

    连接器本身留在目录里（用户随时可以重新填一行 Key 再接回来），
    但密钥是真的从库里删掉，不是打个标记——「移除」就该是移除。
    """
    with db() as conn:
        row = conn.execute("SELECT * FROM connectors WHERE key=?", (key,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="连接器不存在")
        conn.execute(
            "UPDATE connectors SET secret_enc='', enabled=0, last_check_at=NULL,"
            " last_check_ok=NULL, last_check_msg='已移除接入，可重新填写密钥再接入', updated_at=?"
            " WHERE key=?",
            (now_iso(), key),
        )
    audit(user.get("u", ""), "connector_remove", f"移除连接器接入 {key}")
    return {"ok": True}


@router.post("/{key}/test")
async def test_connector(key: str, user=Depends(get_current_user)):
    if key not in CATALOG_BY_KEY:
        raise HTTPException(status_code=404, detail="连接器不存在")
    result = await run_connector_test(key)
    audit(user.get("u", ""), "connector_test", f"检测连接器 {key}：{result.message[:120]}")
    return {"ok": result.ok, "message": result.message, "data": result.data}
