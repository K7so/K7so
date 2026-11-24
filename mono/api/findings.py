"""漏洞结果：检索、详情与状态流转。"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..db import audit, db
from ..netutil import host_of
from .deps import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])

VALID_STATUS = {"open", "confirmed", "fixed", "accepted", "false_positive"}
SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


class StatusIn(BaseModel):
    status: Literal["open", "confirmed", "fixed", "accepted", "false_positive"]


@router.get("")
async def list_findings(
    scan_id: int | None = None,
    severity: str = "",
    status: str = "",
    source: str = "",
    q: str = "",
    limit: int = Query(300, ge=1, le=1000),
):
    clauses = []
    params: list = []
    if scan_id:
        clauses.append("f.scan_id=?")
        params.append(scan_id)
    if severity:
        clauses.append("f.severity=?")
        params.append(severity)
    if status:
        clauses.append("f.status=?")
        params.append(status)
    if source:
        clauses.append("f.source=?")
        params.append(source)
    if q:
        clauses.append("(f.title LIKE ? OR f.target LIKE ? OR f.url LIKE ? OR f.evidence LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with db() as conn:
        rows = conn.execute(
            f"""SELECT f.*, s.name AS scan_name FROM findings f
                LEFT JOIN scans s ON s.id=f.scan_id
                {where}
                ORDER BY CASE f.severity
                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                  WHEN 'low' THEN 3 ELSE 4 END, f.id DESC
                LIMIT ?""",
            (*params, limit),
        ).fetchall()
    return [dict(r) for r in rows]


@router.get("/domains")
async def findings_by_domain(
    severity: str = "",
    status: str = "",
    source: str = "",
    scan_id: int | None = None,
    q: str = "",
    limit: int = Query(2000, ge=1, le=5000),
):
    """按域名归组统计漏洞：一个站点一行，带各危害等级的条数与最新发现时间。

    漏洞本身还是逐条给出来（`findings`），前端按域名折叠展示，
    不用为了展开一个域名再发一轮请求。
    """
    rows = await list_findings(
        scan_id=scan_id,
        severity=severity,
        status=status,
        source=source,
        q=q,
        limit=limit,
    )
    groups: dict[str, dict] = {}
    for item in rows:
        domain = host_of(item.get("url") or item.get("target") or "")
        group = groups.get(domain)
        if group is None:
            group = {
                "domain": domain,
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "open": 0,
                "latest": "",
                "findings": [],
            }
            groups[domain] = group
        group["total"] += 1
        if item.get("severity") in SEVERITY_KEYS:
            group[item["severity"]] += 1
        if item.get("status") in ("open", "confirmed"):
            group["open"] += 1
        if str(item.get("created_at") or "") > str(group["latest"] or ""):
            group["latest"] = item.get("created_at") or ""
        group["findings"].append(item)
    # 域名之间按危害排序：有高危的排前面，同档按条数与最近发现时间
    ordered = sorted(
        groups.values(),
        key=lambda g: (
            -g["critical"],
            -g["high"],
            -g["medium"],
            -g["total"],
            str(g["latest"]),
        ),
    )
    return ordered


@router.get("/{finding_id}")
async def get_finding(finding_id: int):
    with db() as conn:
        row = conn.execute(
            """SELECT f.*, s.name AS scan_name FROM findings f
               LEFT JOIN scans s ON s.id=f.scan_id WHERE f.id=?""",
            (finding_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="漏洞记录不存在")
    return dict(row)


@router.patch("/{finding_id}")
async def update_status(finding_id: int, payload: StatusIn, user=Depends(get_current_user)):
    if payload.status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="无效状态")
    with db() as conn:
        row = conn.execute("SELECT title FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="漏洞记录不存在")
        conn.execute("UPDATE findings SET status=? WHERE id=?", (payload.status, finding_id))
    audit(
        user.get("u", ""),
        "finding_status",
        f"漏洞 #{finding_id}「{row['title']}」状态变更为 {payload.status}",
    )
    return {"ok": True}
