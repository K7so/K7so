"""K7so工具接口：导入、列表、运行、停止、查看输出、删除。

文件走原始字节流（不依赖 multipart），运行状态由 engine/kits 管。
"""
from __future__ import annotations

from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..db import audit
from ..engine import kits
from ..engine.uploads import UploadError
from .deps import get_current_user

router = APIRouter(prefix="/api/kits", tags=["kits"])


class KitPatch(BaseModel):
    name: str | None = None
    args: str | None = None
    note: str | None = None
    kind: str | None = None


@router.get("")
def list_kits(user=Depends(get_current_user)):
    items = kits.list_kits()
    return {
        "items": items,
        "total": len(items),
        "kinds": [{"key": key, "label": label} for key, label in kits.KIT_KINDS.items()],
        "dir": str(kits.TOOLS_DIR),
        "running": sum(1 for item in items if item.get("running")),
    }


@router.post("/upload")
async def upload_kit(
    request: Request,
    name: str = "",
    kind: str = "",
    note: str = "",
    user=Depends(get_current_user),
):
    filename = unquote(request.headers.get("x-file-name", "") or "")
    if not filename:
        raise HTTPException(status_code=400, detail="缺少文件名（X-File-Name）")

    sink = kits.make_sink(filename)
    try:
        async for chunk in request.stream():
            sink.write(chunk)
        path = sink.close()
    except UploadError as exc:
        sink.abort()
        raise HTTPException(status_code=413 if "上限" in str(exc) else 400, detail=str(exc))
    except Exception:
        sink.abort()
        raise

    kit_kind = kits.detect_kind(path.name, kind)
    row = kits.create_kit(
        name=name.strip() or path.stem,
        kind=kit_kind,
        path=path,
        size=sink.size,
        sha=sink.sha256,
        note=note,
        username=user.get("u", ""),
    )
    audit(
        user.get("u", ""),
        "kit_upload",
        f"导入工具 #{row.get('id')} {row.get('name')}（{kits.KIT_KINDS.get(kit_kind)}，{sink.size} 字节）",
    )
    return {"ok": True, "kit": row, "kind_label": kits.KIT_KINDS.get(kit_kind, "")}


@router.patch("/{kit_id}")
def patch_kit(kit_id: int, payload: KitPatch, user=Depends(get_current_user)):
    result = kits.update_kit(kit_id, payload.model_dump(exclude_none=True))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    audit(user.get("u", ""), "kit_update", f"更新工具 #{kit_id}")
    return result


@router.post("/{kit_id}/run")
def run_kit(kit_id: int, user=Depends(get_current_user)):
    kit = kits.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="工具不存在")
    result = kits.launch(kit, user.get("u", ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    audit(user.get("u", ""), "kit_run", f"运行工具 #{kit_id} {kit.get('name')}：{result.get('command')}")
    return result


@router.post("/{kit_id}/stop")
def stop_kit(kit_id: int, user=Depends(get_current_user)):
    result = kits.stop(kit_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    audit(user.get("u", ""), "kit_stop", f"停止工具 #{kit_id}")
    return result


@router.get("/{kit_id}/latest")
def kit_latest(kit_id: int, user=Depends(get_current_user)):
    state = kits.latest_run(kit_id)
    return {"ok": True, "run": state}


@router.get("/runs/{run_id}")
def get_run(run_id: int, user=Depends(get_current_user)):
    state = kits.run_state(run_id)
    if not state:
        raise HTTPException(status_code=404, detail="运行记录不存在")
    return {"ok": True, "run": state}


@router.delete("/{kit_id}")
def delete_kit(kit_id: int, keep_file: bool = False, user=Depends(get_current_user)):
    kit = kits.get_kit(kit_id)
    if not kit:
        raise HTTPException(status_code=404, detail="工具不存在")
    result = kits.delete_kit(kit_id, delete_file=not keep_file)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    audit(user.get("u", ""), "kit_delete", f"删除工具 #{kit_id} {kit.get('name')}")
    return result
