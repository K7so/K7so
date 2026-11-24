"""报告中心：生成、列表与下载。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ..config import REPORTS_DIR
from ..db import audit, db
from ..engine.tasks import TaskError, create_report_task
from .deps import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportIn(BaseModel):
    scan_id: int
    title: str = ""


@router.get("")
async def list_reports():
    with db() as conn:
        rows = conn.execute(
            """SELECT r.*, s.name AS scan_name FROM reports r
               LEFT JOIN scans s ON s.id=r.scan_id ORDER BY r.id DESC LIMIT 100"""
        ).fetchall()
    return [dict(r) for r in rows]


@router.post("")
async def create_report(payload: ReportIn, user=Depends(get_current_user)):
    # 报告要读全部结论、拼一整份 HTML 再落盘：同步跑会把事件循环占住，页面就"没响应"了
    try:
        return await run_in_threadpool(
            create_report_task, payload.scan_id, payload.title, user.get("u", "")
        )
    except TaskError as exc:
        status = 404 if str(exc) == "任务不存在" else 400
        raise HTTPException(status_code=status, detail=str(exc))


@router.get("/{report_id}/download")
async def download_report(report_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    path = REPORTS_DIR / row["path"].split("\\")[-1].split("/")[-1]
    if not path.exists():
        raise HTTPException(status_code=404, detail="报告文件已丢失，请重新生成")
    return FileResponse(
        path,
        media_type="text/html",
        filename=f"K7so-report-{row['scan_id']}.html",
    )


@router.delete("/{report_id}")
async def delete_report(report_id: int, user=Depends(get_current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="报告不存在")
        conn.execute("DELETE FROM reports WHERE id=?", (report_id,))
    try:
        (REPORTS_DIR / row["path"].split("\\")[-1].split("/")[-1]).unlink(missing_ok=True)
    except OSError:
        pass
    audit(user.get("u", ""), "report_delete", f"删除报告 #{report_id}")
    return {"ok": True}
