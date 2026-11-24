"""资产监管接口：模块、导入、收集、明细、对比。"""
from __future__ import annotations

from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..db import audit
from ..engine import asset_registry
from ..engine.uploads import UploadError, UploadSink
from .deps import get_current_user

router = APIRouter(prefix="/api/asset-modules", tags=["asset-modules"])

MAX_IMPORT_BYTES = asset_registry.MAX_PARSE_BYTES


class ModuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    note: str = ""


class HostIn(BaseModel):
    host: str = Field(min_length=2, max_length=253)
    note: str = ""


@router.get("")
def list_modules(user=Depends(get_current_user)):
    items = asset_registry.list_modules()
    return {"items": items, "total": len(items)}


@router.post("")
def create_module(payload: ModuleIn, user=Depends(get_current_user)):
    module = asset_registry.create_module(payload.name, user.get("u", ""), payload.note)
    audit(user.get("u", ""), "asset_module_create", f"新建资产模块 #{module.get('id')} {payload.name}")
    return {"ok": True, "module": module}


@router.get("/compare")
def compare(left: int, right: int, user=Depends(get_current_user)):
    result = asset_registry.compare_modules(left, right)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error") or "模块不存在")
    return result


@router.get("/{module_id}")
def module_detail(module_id: int, user=Depends(get_current_user)):
    module = asset_registry.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="模块不存在")
    hosts = asset_registry.host_rows(module_id, limit=100, offset=0)
    return {"ok": True, "module": module, "hosts": hosts["items"], "total": hosts["total"]}


@router.post("/{module_id}/import")
async def import_file(
    module_id: int,
    request: Request,
    use_llm: bool = False,
    user=Depends(get_current_user),
):
    module = asset_registry.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="模块不存在")
    filename = unquote(request.headers.get("x-file-name", "") or "")
    if not filename:
        raise HTTPException(status_code=400, detail="缺少文件名（X-File-Name）")

    # 文件要留着复用，但解析只需要字节：先落一份到 data/assets/，再读回来解
    from ..config import DATA_DIR

    sink = UploadSink(DATA_DIR / "assets", filename, MAX_IMPORT_BYTES)
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

    try:
        data = path.read_bytes()
    finally:
        pass

    result = asset_registry.import_document(
        module_id, filename, data, use_llm=use_llm, username=user.get("u", "")
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    audit(
        user.get("u", ""),
        "asset_module_import",
        f"模块 #{module_id} 导入 {filename}：域名 {result['domains']}、IP {result['ips']}、新增 {result['added']}",
    )
    return result


@router.post("/{module_id}/collect")
def collect(
    module_id: int,
    use_crt: bool = True,
    guess: bool = True,
    user=Depends(get_current_user),
):
    module = asset_registry.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="模块不存在")
    result = asset_registry.collect_module(module_id, use_crt=use_crt, guess=guess,
                                           username=user.get("u", ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    audit(
        user.get("u", ""),
        "asset_module_collect",
        f"模块 #{module_id} 收集：试了 {result['tried']} 个候选，解析到 {result['resolved']}，新增 {result['added']}",
    )
    return result


@router.get("/{module_id}/hosts")
def hosts(
    module_id: int,
    q: str = "",
    kind: str = "",
    limit: int = 800,
    offset: int = 0,
    user=Depends(get_current_user),
):
    module = asset_registry.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="模块不存在")
    data = asset_registry.host_rows(module_id, query=q, kind=kind,
                                    limit=max(1, min(5000, limit)), offset=max(0, offset))
    return {"ok": True, **data, "module": module}


@router.post("/{module_id}/hosts")
def add_host(module_id: int, payload: HostIn, user=Depends(get_current_user)):
    module = asset_registry.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="模块不存在")
    host = payload.host.strip().lower()
    is_ip = asset_registry._is_ip(host)  # noqa: SLF001 - 同包工具函数
    if not is_ip and not asset_registry._valid_domain(host):  # noqa: SLF001
        raise HTTPException(status_code=400, detail="看着不像域名或 IP")
    added = asset_registry.save_hosts(module_id, [{
        "host": host,
        "kind": "ip" if is_ip else "domain",
        "ip": host if is_ip else "",
        "parent": "" if is_ip else asset_registry.root_domain(host),
        "source": "manual",
        "note": payload.note,
    }])
    return {"ok": True, "added": added, "host": host}


@router.delete("/{module_id}")
def delete_module(module_id: int, user=Depends(get_current_user)):
    module = asset_registry.get_module(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="模块不存在")
    asset_registry.delete_module(module_id)
    audit(user.get("u", ""), "asset_module_delete", f"删除资产模块 #{module_id} {module.get('name')}")
    return {"ok": True}
