"""仪表盘统计与审计日志。"""
from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Query

from ..config import APP_NAME, APP_SUBTITLE, APP_VERSION, SEVERITY_LABELS
from ..db import db

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
async def dashboard():
    with db() as conn:
        asset_count = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
        scan_count = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        running_count = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE status IN ('queued','running')"
        ).fetchone()["c"]
        report_count = conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
        open_count = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE status IN ('open','confirmed')"
        ).fetchone()["c"]
        severity_rows = conn.execute(
            """SELECT severity, COUNT(*) AS c FROM findings
               WHERE status IN ('open','confirmed') GROUP BY severity"""
        ).fetchall()
        severity = {row["severity"]: row["c"] for row in severity_rows}
        recent_scans = [
            dict(r)
            for r in conn.execute(
                """SELECT s.id, s.name, s.status, s.progress, s.stage, s.profile, s.mode,
                          s.created_at, s.summary,
                          (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS finding_count
                   FROM scans s ORDER BY s.id DESC LIMIT 8"""
            ).fetchall()
        ]
        recent_findings = [
            dict(r)
            for r in conn.execute(
                """SELECT id, title, severity, target, source, created_at FROM findings
                   WHERE status IN ('open','confirmed')
                   ORDER BY CASE severity
                     WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT 8"""
            ).fetchall()
        ]
        connectors = [
            dict(r)
            for r in conn.execute(
                """SELECT key, name, category, enabled, last_check_ok, last_check_msg, last_check_at,
                          secret_enc, auth_type FROM connectors ORDER BY category, id"""
            ).fetchall()
        ]
        activity = [
            dict(r)
            for r in conn.execute(
                "SELECT ts, username, action, detail FROM audit_logs ORDER BY id DESC LIMIT 10"
            ).fetchall()
        ]
        trend_rows = conn.execute(
            """SELECT substr(created_at,1,10) AS day, COUNT(*) AS c FROM scans
               WHERE created_at >= date('now','localtime','-6 days') GROUP BY day"""
        ).fetchall()
        finding_trend = conn.execute(
            """SELECT substr(created_at,1,10) AS day, COUNT(*) AS c FROM findings
               WHERE created_at >= date('now','localtime','-6 days') GROUP BY day"""
        ).fetchall()
        settings = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}

    trend = []
    for offset in range(6, -1, -1):
        day = (date.today() - timedelta(days=offset)).isoformat()
        trend.append(
            {
                "day": day[5:],
                "scans": next((r["c"] for r in trend_rows if r["day"] == day), 0),
                "findings": next((r["c"] for r in finding_trend if r["day"] == day), 0),
            }
        )

    configured = sum(1 for c in connectors if c["secret_enc"] or c["auth_type"] == "cli")
    healthy = sum(1 for c in connectors if c["last_check_ok"] == 1)
    risk_score = min(
        100,
        sum(
            {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}.get(k, 0) * v
            for k, v in severity.items()
        ),
    )
    return {
        "app": {"name": APP_NAME, "subtitle": APP_SUBTITLE, "version": APP_VERSION},
        "stats": {
            "assets": asset_count,
            "scans": scan_count,
            "running": running_count,
            "reports": report_count,
            "open_findings": open_count,
            "connectors": len(connectors),
            "connectors_configured": configured,
            "connectors_healthy": healthy,
            "risk_score": risk_score,
        },
        "severity": {key: severity.get(key, 0) for key in SEVERITY_LABELS},
        "severity_labels": SEVERITY_LABELS,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
        "connectors": [
            {
                "key": c["key"],
                "name": c["name"],
                "category": c["category"],
                "enabled": bool(c["enabled"]),
                "configured": bool(c["secret_enc"]) or c["auth_type"] == "cli",
                "ok": c["last_check_ok"],
                "message": c["last_check_msg"],
                "checked_at": c["last_check_at"],
            }
            for c in connectors
        ],
        "activity": activity,
        "trend": trend,
        # 授权范围已取消：登录时确认的免责声明即授权。字段保留为「授权状态」，
        # 前端据此渲染顶部横幅，不再显示域名 / 网段数量。
        "authorization": {
            "mode": "disclaimer",
            "confirmed": True,
            "text": "授权：登录免责声明已确认（点名的目标即为已授权目标）",
            "safe_mode": settings.get("safe_mode", "true") == "true",
        },
    }


@router.get("/audit")
async def audit_logs(
    limit: int = Query(60, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str = "",
):
    with db() as conn:
        where = ""
        params: list = []
        if q:
            where = "WHERE username LIKE ? OR action LIKE ? OR detail LIKE ?"
            params = [f"%{q}%", f"%{q}%", f"%{q}%"]
        total = conn.execute(f"SELECT COUNT(*) AS c FROM audit_logs {where}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}
