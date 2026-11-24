"""资产台账 CRUD。"""
from __future__ import annotations

import ipaddress
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..db import audit, db, now_iso
from .deps import get_current_user

router = APIRouter(prefix="/api/assets", tags=["assets"])


class AssetIn(BaseModel):
    name: Optional[str] = None
    target: str = Field(min_length=1, max_length=500)
    kind: Optional[str] = None
    org: str = ""
    tags: str = ""
    criticality: int = 3
    notes: str = ""


class AssetPatch(BaseModel):
    """局部更新：只改传进来的字段，没传的保持原值。"""

    name: Optional[str] = None
    target: Optional[str] = Field(default=None, max_length=500)
    kind: Optional[str] = None
    org: Optional[str] = None
    tags: Optional[str] = None
    criticality: Optional[int] = None
    notes: Optional[str] = None


def detect_kind(target: str) -> str:
    if target.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def asset_payload(row: dict) -> dict:
    return row


@router.get("")
async def list_assets(q: str = Query("", max_length=120)):
    with db() as conn:
        if q:
            rows = conn.execute(
                """SELECT a.*,
                          (SELECT COUNT(*) FROM findings f WHERE f.asset_id=a.id) AS finding_count
                   FROM assets a
                   WHERE a.name LIKE ? OR a.target LIKE ? OR a.org LIKE ? OR a.tags LIKE ?
                   ORDER BY a.id DESC""",
                (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT a.*,
                          (SELECT COUNT(*) FROM findings f WHERE f.asset_id=a.id) AS finding_count
                   FROM assets a ORDER BY a.id DESC"""
            ).fetchall()
    return [asset_payload(dict(r)) for r in rows]


@router.post("")
async def create_asset(payload: AssetIn, user=Depends(get_current_user)):
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="目标不能为空")
    name = (payload.name or target).strip()
    kind = (payload.kind or detect_kind(target)).lower()
    if kind not in ("domain", "ip", "url"):
        kind = detect_kind(target)
    ts = now_iso()
    with db() as conn:
        exists = conn.execute("SELECT id FROM assets WHERE target=?", (target,)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="该目标已存在资产台账中")
        cursor = conn.execute(
            """INSERT INTO assets (name, target, kind, org, tags, criticality, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                name[:200],
                target,
                kind,
                payload.org.strip()[:200],
                payload.tags.strip()[:200],
                max(1, min(5, payload.criticality)),
                payload.notes.strip()[:1000],
                ts,
                ts,
            ),
        )
        asset_id = cursor.lastrowid
    audit(user.get("u", ""), "asset_create", f"新增资产 #{asset_id} {target}")
    return {"id": asset_id, "ok": True}


@router.patch("/{asset_id}")
async def update_asset(asset_id: int, payload: AssetPatch, user=Depends(get_current_user)):
    with db() as conn:
        existing = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="资产不存在")
        current = dict(existing)

        target = (payload.target if payload.target is not None else current["target"]).strip()
        if not target:
            raise HTTPException(status_code=400, detail="目标不能为空")
        if target != current["target"]:
            dup = conn.execute(
                "SELECT id FROM assets WHERE target=? AND id<>?", (target, asset_id)
            ).fetchone()
            if dup:
                raise HTTPException(status_code=409, detail="该目标已存在资产台账中")

        raw_kind = payload.kind if payload.kind is not None else (current.get("kind") or "")
        kind = (raw_kind or detect_kind(target)).lower()
        if kind not in ("domain", "ip", "url"):
            kind = detect_kind(target)

        name = payload.name if payload.name is not None else current["name"]
        org = payload.org if payload.org is not None else current.get("org", "")
        tags = payload.tags if payload.tags is not None else current.get("tags", "")
        notes = payload.notes if payload.notes is not None else current.get("notes", "")
        criticality = payload.criticality
        if criticality is None:
            criticality = current.get("criticality") or 3

        conn.execute(
            """UPDATE assets SET name=?, target=?, kind=?, org=?, tags=?, criticality=?, notes=?, updated_at=?
               WHERE id=?""",
            (
                (name or target).strip()[:200],
                target,
                kind,
                (org or "").strip()[:200],
                (tags or "").strip()[:200],
                max(1, min(5, int(criticality))),
                (notes or "").strip()[:1000],
                now_iso(),
                asset_id,
            ),
        )
    audit(user.get("u", ""), "asset_update", f"更新资产 #{asset_id} {target}")
    return {"ok": True}


@router.delete("/{asset_id}")
async def delete_asset(asset_id: int, user=Depends(get_current_user)):
    with db() as conn:
        existing = conn.execute("SELECT target FROM assets WHERE id=?", (asset_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="资产不存在")
        conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    audit(user.get("u", ""), "asset_delete", f"删除资产 #{asset_id} {existing['target']}")
    return {"ok": True}
