"""模型记忆空间：一个个可以单独配置、单独选择的长期记忆。

跟 API 中心里的模型配置是同一套思路：先建好一条（名字 + 目录），
再在协同页的左右两栏各挑一条。两个模型各读各的，互不串味。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..db import audit
from ..engine import memory_spaces
from .deps import get_current_user

router = APIRouter(prefix="/api/memory", tags=["memory"])


class SpaceIn(BaseModel):
    name: str = ""
    dir: str = ""
    note: str = ""


class SpacePatch(BaseModel):
    name: str | None = None
    dir: str | None = None
    note: str | None = None


@router.get("/spaces")
async def list_spaces(user=Depends(get_current_user)):
    """全部记忆空间：第一条永远是「默认记忆」，跟目录配置走。"""
    return {"spaces": memory_spaces.list_spaces(user.get("u", ""))}


@router.post("/spaces")
async def create_space(payload: SpaceIn, user=Depends(get_current_user)):
    username = user.get("u", "")
    try:
        space = memory_spaces.create_space(username, payload.name, payload.dir, payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(username, "memory_create", f"新建记忆空间「{space.get('name')}」→ {space.get('dir')}")
    return space


@router.patch("/spaces/{space_id}")
async def patch_space(space_id: int, payload: SpacePatch, user=Depends(get_current_user)):
    username = user.get("u", "")
    try:
        space = memory_spaces.update_space(
            space_id, username, name=payload.name, dir=payload.dir, note=payload.note
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not space:
        raise HTTPException(status_code=404, detail="记忆空间不存在")
    audit(username, "memory_update", f"修改记忆空间 #{space_id}「{space.get('name')}」")
    return space


@router.delete("/spaces/{space_id}")
async def delete_space(space_id: int, user=Depends(get_current_user)):
    username = user.get("u", "")
    try:
        removed = memory_spaces.delete_space(space_id, username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(status_code=404, detail="记忆空间不存在")
    audit(username, "memory_delete", f"删除记忆空间 #{space_id}（目录内的文件保留）")
    return {"ok": True}


@router.get("/spaces/{space_id}/files")
async def space_files(space_id: int, user=Depends(get_current_user)):
    """目录里有什么：名字、大小、改过的时间。只列清单，不把内容摊开。"""
    space = memory_spaces.get_space(space_id, user.get("u", ""))
    if not space:
        raise HTTPException(status_code=404, detail="记忆空间不存在")
    return {"space": space, "files": memory_spaces.list_files(space.get("dir") or "")}
