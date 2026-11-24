"""安全评估：创建、列表、详情、实时日志、终止与导出。"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..db import audit, db, now_iso
from ..engine.tasks import TaskError, create_scan_task
from ..runtime import CANCELLED, HUB
from .deps import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ScanIn(BaseModel):
    name: str = ""
    asset_ids: list[int] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    profile: Literal["quick", "standard", "deep"] = "standard"
    mode: Literal["active", "passive"] = "active"
    authorization_ref: str = ""


def scan_to_dict(row) -> dict:
    data = dict(row)
    data["targets"] = json.loads(data.pop("targets_json") or "[]")
    data["asset_ids"] = json.loads(data.pop("asset_ids_json") or "[]")
    data["stats"] = json.loads(data.pop("stats_json") or "{}")
    return data


def severity_breakdown(scan_ids: list[int]) -> dict[int, dict[str, int]]:
    if not scan_ids:
        return {}
    placeholders = ",".join(["?"] * len(scan_ids))
    with db() as conn:
        rows = conn.execute(
            f"SELECT scan_id, severity, COUNT(*) AS c FROM findings WHERE scan_id IN ({placeholders}) "
            "GROUP BY scan_id, severity",
            scan_ids,
        ).fetchall()
    result: dict[int, dict[str, int]] = {}
    for row in rows:
        result.setdefault(row["scan_id"], {})[row["severity"]] = row["c"]
    return result


@router.get("")
async def list_scans(limit: int = Query(50, ge=1, le=200)):
    with db() as conn:
        rows = conn.execute(
            """SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS finding_count
               FROM scans s ORDER BY s.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        scans = [scan_to_dict(r) for r in rows]
        breakdowns = severity_breakdown([s["id"] for s in scans])
    for scan in scans:
        scan["severity"] = breakdowns.get(scan["id"], {})
    return scans


@router.post("")
async def create_scan(payload: ScanIn, user=Depends(get_current_user)):
    try:
        return await create_scan_task(
            name=payload.name,
            asset_ids=payload.asset_ids,
            targets=payload.targets,
            profile=payload.profile,
            mode=payload.mode,
            authorization_ref=payload.authorization_ref,
            username=user.get("u", ""),
        )
    except TaskError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{scan_id}")
async def get_scan(scan_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="任务不存在")
        scan = scan_to_dict(row)
        scan["severity"] = severity_breakdown([scan_id]).get(scan_id, {})
        scan["logs"] = [
            dict(r)
            for r in conn.execute(
                "SELECT ts, level, message FROM scan_logs WHERE scan_id=? ORDER BY id DESC LIMIT 300",
                (scan_id,),
            ).fetchall()
        ][::-1]
        scan["findings"] = [
            dict(r)
            for r in conn.execute(
                """SELECT id, title, severity, category, target, source FROM findings
                   WHERE scan_id=? ORDER BY CASE severity
                     WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3 ELSE 4 END, id LIMIT 100""",
                (scan_id,),
            ).fetchall()
        ]
    return scan


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: int, request: Request):
    queue = HUB.subscribe(scan_id)

    async def event_stream():
        try:
            yield "retry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    continue
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") == "done":
                    break
        finally:
            HUB.unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int, user=Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="任务不存在")
        status = row["status"]
        if status in ("completed", "failed", "cancelled"):
            raise HTTPException(status_code=400, detail="任务已结束，无法取消")
        CANCELLED.add(scan_id)
        if status == "queued":
            conn.execute(
                "UPDATE scans SET status='cancelled', stage='已取消', finished_at=? WHERE id=?",
                (now_iso(), scan_id),
            )
        else:
            conn.execute("UPDATE scans SET stage='取消中...' WHERE id=?", (scan_id,))
    audit(user.get("u", ""), "scan_cancel", f"取消任务 #{scan_id}")
    return {"ok": True}


@router.get("/{scan_id}/export")
async def export_scan(scan_id: int, format: str = Query("json")):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="任务不存在")
        findings = [
            dict(r)
            for r in conn.execute(
                "SELECT target, title, severity, category, source, description, evidence, "
                "remediation, cvss, confidence, status, created_at FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        ]
    if format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=[
                "target", "title", "severity", "category", "source", "cvss",
                "confidence", "status", "description", "evidence", "remediation", "created_at",
            ],
        )
        writer.writeheader()
        writer.writerows(findings)
        return StreamingResponse(
            io.BytesIO(buffer.getvalue().encode("utf-8-sig")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"},
        )
    payload = {"scan": scan_to_dict(row), "findings": findings}
    return StreamingResponse(
        io.BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"},
    )
