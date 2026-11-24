"""任务服务：渗透测试任务与报告的创建逻辑，供 REST API 与智能工作复用。"""
from __future__ import annotations

import json
from datetime import datetime

from ..config import REPORTS_DIR
from ..db import audit, db, now_iso
from ..reporting import build_report_html
from ..runtime import SCAN_QUEUE
from .scanner import validate_scope


class TaskError(ValueError):
    """可直接反馈给调用方的业务错误。"""


# 登录时确认的免责声明即操作授权，落库时统一记这句依据，不再打扰用户填编号
DEFAULT_AUTHORIZATION = "登录免责声明（平台内授权确认）"


def resolve_targets(asset_ids: list[int], targets: list[str]) -> list[str]:
    merged: list[str] = []
    if asset_ids:
        with db() as conn:
            placeholders = ",".join(["?"] * len(asset_ids))
            rows = conn.execute(
                f"SELECT target FROM assets WHERE id IN ({placeholders})", asset_ids
            ).fetchall()
            merged.extend(row["target"] for row in rows)
    for item in targets:
        merged.extend(part.strip() for part in item.replace(",", "\n").splitlines())
    return [t for t in dict.fromkeys(merged) if t]


async def create_scan_task(
    *,
    name: str,
    asset_ids: list[int],
    targets: list[str],
    profile: str,
    mode: str,
    authorization_ref: str,
    username: str,
) -> dict:
    authorization_ref = (authorization_ref or "").strip() or DEFAULT_AUTHORIZATION

    items = resolve_targets(asset_ids, targets)
    if not items:
        raise TaskError("请至少选择一个资产或填写一个目标")
    if len(items) > 60:
        raise TaskError("单次测试最多支持 60 个目标")
    # 授权范围已取消：登录免责声明即为授权，用户给出的目标直接进队列。
    # 这里只挡格式上有问题的目标（空、带空格、超长），不再按域名 / 网段核对。
    format_errors = validate_scope(items)
    if format_errors:
        raise TaskError("；".join(format_errors[:3]))

    name = name.strip() or f"{mode}-{profile}-{datetime.now().strftime('%m%d-%H%M')}"
    ts = now_iso()
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO scans
               (name, targets_json, asset_ids_json, profile, mode, authorization_ref,
                status, progress, stage, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name[:120],
                json.dumps(items, ensure_ascii=False),
                json.dumps(asset_ids),
                profile,
                mode,
                authorization_ref.strip()[:200],
                "queued",
                0,
                "排队中",
                username,
                ts,
            ),
        )
        scan_id = cursor.lastrowid
    audit(
        username,
        "scan_create",
        f"任务 #{scan_id} {name} 目标 {len(items)} 个 profile={profile} mode={mode}",
    )
    await SCAN_QUEUE.put(scan_id)
    return {"id": scan_id, "status": "queued", "targets": items, "name": name[:120]}


def create_report_task(scan_id: int, title: str, username: str) -> dict:
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            raise TaskError("任务不存在")
        if row["status"] != "completed":
            raise TaskError("仅已完成的测试可生成报告")
        scan = dict(row)
        scan["targets"] = json.loads(scan.pop("targets_json") or "[]")
        scan["stats"] = json.loads(scan.pop("stats_json") or "{}")
        findings = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()
        ]
        logs = [
            dict(r)
            for r in conn.execute(
                "SELECT ts, level, message FROM scan_logs WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        ]

    title = title.strip() or f"{scan.get('name')} 渗透测试报告"
    html = build_report_html(scan, findings, logs)
    filename = f"report-{scan_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
    path = REPORTS_DIR / filename
    path.write_text(html, encoding="utf-8")
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO reports (scan_id, title, format, path, size, created_by, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (scan_id, title[:200], "html", str(path), path.stat().st_size, username, now_iso()),
        )
        report_id = cursor.lastrowid
    audit(username, "report_create", f"生成报告 #{report_id} {title}")
    return {"id": report_id, "title": title, "size": path.stat().st_size}
