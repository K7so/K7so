"""评估编排引擎：范围校验 -> 资产测绘 -> HTTP 配置核查 -> 端口探测 -> 模板检测 -> AI 研判。"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

from ..config import DEFAULT_USER_AGENT
from ..connectors import load_connector
from ..connectors.base import ConnectorResult
from ..connectors.tools import NmapConnector, NucleiConnector
from ..db import db, get_settings, now_iso
from ..runtime import CANCELLED, HUB, SCAN_QUEUE
from .checks import (
    builtin_port_scan,
    make_finding,
    port_findings,
    probe_targets,
)
from .capabilities import enabled_items


class ScanCancelled(Exception):
    pass


def update_scan(scan_id: int, **fields: Any) -> None:
    if not fields:
        return
    columns = ", ".join(f"{key}=?" for key in fields)
    with db() as conn:
        conn.execute(f"UPDATE scans SET {columns} WHERE id=?", (*fields.values(), scan_id))


class ScanLogger:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id

    def log(self, message: str, level: str = "info") -> None:
        ts = now_iso()
        with db() as conn:
            conn.execute(
                "INSERT INTO scan_logs (scan_id, ts, level, message) VALUES (?,?,?,?)",
                (self.scan_id, ts, level, message),
            )
        HUB.publish(self.scan_id, {"type": "log", "level": level, "message": message, "ts": ts})

    def stage(self, progress: int, text: str) -> None:
        update_scan(self.scan_id, progress=progress, stage=text)
        HUB.publish(self.scan_id, {"type": "progress", "progress": progress, "stage": text})

    def checkpoint(self) -> None:
        if self.scan_id in CANCELLED:
            raise ScanCancelled()


def classify_target(target: str) -> str:
    if target.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def host_of(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target


def split_lines(value: str) -> list[str]:
    return [line.strip() for line in (value or "").replace(",", "\n").splitlines() if line.strip()]


def validate_scope(targets: list[str], settings: dict[str, str] | None = None) -> list[str]:
    """目标可用性检查（授权范围已取消）。

    平台不再维护「授权域名 / 授权网段」这套东西：用户登录时确认的免责声明就是授权，
    他给出的目标即为已授权目标，不需要再逐个域名核对白名单，也不会因此弹确认卡。
    这里只保留最基础的目标格式检查，挡掉空目标、带空格与超长字符串这类根本发不出去的输入。
    settings 参数保留只为兼容旧调用点，不再参与判断。
    """
    errors: list[str] = []
    for target in targets:
        text = str(target or "").strip()
        if not text:
            errors.append("目标为空")
        elif len(text) > 500:
            errors.append(f"目标过长（超过 500 字符）：{text[:40]}")
        elif " " in text:
            errors.append(f"目标格式无效（不能含空格）：{text[:40]}")
    return errors


def collect_entities(payload: Any, bucket: set[str], depth: int = 0) -> None:
    if depth > 4:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key.lower() in ("host", "domain", "ip", "url", "matched-at", "hostname") and isinstance(value, str):
                value = value.strip()
                if value and len(value) < 300:
                    bucket.add(value)
            else:
                collect_entities(value, bucket, depth + 1)
    elif isinstance(payload, list):
        for item in payload[:100]:
            collect_entities(item, bucket, depth + 1)


def normalize_entity(entity: str) -> str:
    entity = entity.strip()
    if entity.startswith(("http://", "https://")):
        return entity
    if entity.startswith("[") or entity.count(":") >= 3:
        return entity
    try:
        ipaddress.ip_address(entity)
        return entity
    except ValueError:
        return f"https://{entity.split('/')[0]}"


def persist_findings(
    scan_id: int,
    target: str,
    asset_id: int | None,
    findings: list[dict[str, Any]],
) -> int:
    inserted = 0
    with db() as conn:
        for finding in findings:
            url = str(finding.get("url") or "")
            if not url and target.startswith(("http://", "https://")):
                url = target
            cursor = conn.execute(
                """INSERT OR IGNORE INTO findings
                   (scan_id, asset_id, target, url, title, severity, category, source, description,
                    evidence, remediation, cvss, confidence, status, capability,
                    request_packet, response_packet, dedupe_key, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    asset_id,
                    target[:500],
                    url[:1000],
                    finding["title"][:300],
                    finding["severity"],
                    finding.get("category", ""),
                    finding.get("source", ""),
                    finding.get("description", ""),
                    finding.get("evidence", "")[:2000],
                    finding.get("remediation", ""),
                    float(finding.get("cvss", 0)),
                    finding.get("confidence", "medium"),
                    "open",
                    finding.get("capability", "")[:100],
                    str(finding.get("request_packet") or "")[:6000],
                    str(finding.get("response_packet") or "")[:6000],
                    finding["dedupe_key"][:500],
                    now_iso(),
                ),
            )
            inserted += cursor.rowcount
    return inserted


def build_asset_map(asset_ids: list[int]) -> dict[str, int]:
    if not asset_ids:
        return {}
    with db() as conn:
        rows = conn.execute(
            f"SELECT id, target FROM assets WHERE id IN ({','.join(['?'] * len(asset_ids))})",
            asset_ids,
        ).fetchall()
    return {row["target"].strip(): row["id"] for row in rows}


async def passive_recon(
    targets: list[str], logger: ScanLogger
) -> tuple[list[str], dict[str, Any]]:
    discovered: set[str] = set()
    sources: dict[str, int] = {}
    notes: list[str] = []

    with db() as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM connectors WHERE enabled=1 AND category IN ('recon','intel') ORDER BY id"
            ).fetchall()
        ]

    domain_targets = [t for t in targets if classify_target(t) == "domain"][:3]
    if not domain_targets:
        return [], {"sources": {}, "notes": ["无域名目标，跳过资产测绘"]}

    usable: list[Any] = []
    for row in rows:
        connector = load_connector(row["key"])
        if not connector or not connector.enabled:
            continue
        if not connector.secret:
            notes.append(f"{connector.name}: 未配置密钥，已跳过")
            continue
        usable.append(connector)

    async def run_one(connector: Any, target: str):
        try:
            result = await asyncio.wait_for(connector.search(target, "domain"), timeout=35)
            return connector, target, result
        except asyncio.TimeoutError:
            return connector, target, ConnectorResult(False, "查询超时")
        except Exception as exc:
            return connector, target, ConnectorResult(False, f"查询异常: {exc}")

    jobs = [run_one(c, t) for c in usable for t in domain_targets]
    if jobs:
        results = await asyncio.gather(*jobs)
        for connector, target, result in results:
            if result.ok:
                bucket: set[str] = set()
                collect_entities(result.data, bucket)
                discovered.update(bucket)
                count = result.data.get("count")
                if count is None:
                    items = result.data.get("items")
                    count = len(items) if isinstance(items, list) else 0
                sources[connector.key] = sources.get(connector.key, 0) + int(count or 0)
                logger.log(f"{connector.name} 检索 {target}：{result.message}", "success")
            else:
                logger.log(f"{connector.name} 检索 {target} 失败：{result.message}", "warn")

    for note in notes:
        logger.log(note, "muted")

    return sorted(discovered), {"sources": sources, "notes": notes}


def summary_text(
    targets: list[str], severity_counts: dict[str, int], ai_summary: str
) -> str:
    total = sum(severity_counts.values())
    parts = [f"目标 {len(targets)} 个", f"风险项 {total} 个"]
    labels = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
    for key in ("critical", "high", "medium", "low", "info"):
        if severity_counts.get(key):
            parts.append(f"{labels[key]} {severity_counts[key]}")
    base = "评估完成：" + "，".join(parts) + "。"
    if ai_summary:
        return f"{ai_summary.strip()}\n\n[统计] {base}"
    return base + " 未启用 AI 研判，建议结合漏洞详情人工复核。"


async def ai_analyze(
    scan_targets: list[str],
    stats: dict[str, Any],
    findings: list[dict[str, Any]],
) -> tuple[str, bool]:
    settings = get_settings()
    if settings.get("ai_enabled", "true").lower() not in ("1", "true", "yes", "on"):
        return "", False

    candidates = []
    for key in ("deepseek", "openai"):
        connector = load_connector(key)
        if not connector or not connector.enabled:
            continue
        local_gateway = any(h in connector.base_url for h in ("127.0.0.1", "localhost"))
        if connector.secret or (key == "openai" and local_gateway):
            candidates.append(connector)
    if not candidates:
        return "", False

    top = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5),
    )[:25]
    lines = [f"- [{f['severity']}] {f['title']} | 目标: {f['target'][:120]}" for f in top]
    user_prompt = (
        f"已授权评估目标：{', '.join(scan_targets[:10])}\n"
        f"风险统计：{json.dumps(stats.get('severity', {}), ensure_ascii=False)}\n"
        f"资产测绘来源：{json.dumps(stats.get('recon', {}).get('sources', {}), ensure_ascii=False)}\n"
        f"开放端口数量：{len(stats.get('ports', []))}\n"
        f"主要发现：\n" + ("\n".join(lines) if lines else "无")
    )
    system_prompt = (
        "你是资深安全评估负责人，正在为已获得书面授权的安全评估项目撰写研判结论。"
        "只依据给定的评估数据，不编造未验证的风险项，不提供任何攻击操作步骤。"
        "请用中文输出 4 段纯文本：1) 总体风险判断；2) 最可能的攻击路径（基于已发现项）；"
        "3) 按优先级排列的修复清单；4) 复测建议。总字数不超过 500 字。"
    )
    for connector in candidates:
        try:
            result = await asyncio.wait_for(
                connector.chat(system_prompt, user_prompt, max_tokens=800), timeout=100
            )
            if result.ok:
                return str(result.data.get("content", "")).strip(), True
        except Exception:
            continue
    return "", False


async def run_scan(scan_id: int) -> None:
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return
        scan = dict(row)
    if scan["status"] in ("completed", "failed", "cancelled", "running"):
        return

    logger = ScanLogger(scan_id)
    settings = get_settings()
    capabilities = enabled_items()
    started = time.time()
    update_scan(scan_id, status="running", started_at=now_iso(), progress=2, stage="初始化", summary="")
    logger.log(f"任务「{scan['name']}」开始，profile={scan['profile']} mode={scan['mode']}", "info")
    logger.log(
        "启用的专项能力：" + ("、".join(item["name"] for item in capabilities) if capabilities else "无"),
        "info",
    )
    HUB.publish(scan_id, {"type": "state", "status": "running"})

    stats: dict[str, Any] = {
        "targets": [],
        "recon": {},
        "ports": [],
        "probes": [],
        "nuclei": 0,
        "severity": {},
    }
    temp_nuclei_path = ""
    try:
        targets = list(dict.fromkeys([t.strip() for t in json.loads(scan["targets_json"]) if t.strip()]))
        targets = targets[:60]
        if not targets:
            raise ValueError("没有可评估的目标")
        stats["targets"] = targets

        logger.stage(4, "目标可用性检查")
        errors = validate_scope(targets, settings)
        if errors:
            raise ValueError("目标不可用：" + "；".join(errors[:5]))
        logger.log(
            f"目标可用；授权依据：{scan.get('authorization_ref') or '登录免责声明'}；"
            "授权范围为登录免责声明覆盖，不再按域名 / 网段二次校验",
            "success",
        )
        logger.checkpoint()

        asset_ids = json.loads(scan.get("asset_ids_json") or "[]")
        asset_map = build_asset_map(asset_ids)

        # 1. 被动侦察
        logger.stage(10, "被动资产测绘")
        original_count = len(targets)
        discovered, recon_stats = await passive_recon(targets, logger)
        stats["recon"] = recon_stats
        added = 0
        skipped = 0
        for item in discovered:
            normalized = normalize_entity(item)
            if not normalized or normalized in targets:
                continue
            if validate_scope([normalized], settings):
                skipped += 1
                continue
            targets.append(normalized)
            added += 1
            if len(targets) >= 100:
                break
        stats["targets"] = targets
        logger.log(
            f"被动侦察完成，扩展目标 {added} 个，格式无效跳过 {skipped} 个，当前共 {len(targets)} 个",
            "info",
        )
        logger.checkpoint()

        if scan["mode"] == "passive":
            severity_counts: dict[str, int] = {}
            ai_summary, ai_ok = await ai_analyze(targets, stats, [])
            stats["severity"] = severity_counts
            stats["ai"] = ai_ok
            stats["duration"] = round(time.time() - started, 1)
            update_scan(
                scan_id,
                status="completed",
                progress=100,
                stage="完成",
                finished_at=now_iso(),
                summary=summary_text(targets, severity_counts, ai_summary),
                stats_json=json.dumps(stats, ensure_ascii=False),
            )
            logger.log("被动模式任务完成", "success")
            HUB.publish(scan_id, {"type": "done", "status": "completed"})
            return

        # 2. HTTP 探测
        logger.stage(34, "HTTP 存活与配置探测")
        timeout = float(settings.get("request_timeout", "8") or 8)
        concurrency = int(settings.get("max_concurrency", "24") or 24)
        sensitive = settings.get("sensitive_path_checks", "true").lower() in ("1", "true", "yes", "on")
        probes = await probe_targets(
            targets,
            settings.get("user_agent") or DEFAULT_USER_AGENT,
            timeout=timeout,
            concurrency=concurrency,
            sensitive_checks=sensitive,
        )
        alive = [p for p in probes if p.get("status")]
        stats["probes"] = [
            {
                "target": p.get("target"),
                "url": p.get("url"),
                "status": p.get("status"),
                "title": p.get("title"),
                "server": p.get("server"),
                "error": p.get("error"),
            }
            for p in probes
        ][:120]
        total_inserted = 0
        for probe in probes:
            asset_id = asset_map.get(probe.get("target", ""))
            total_inserted += persist_findings(
                scan_id,
                probe.get("url") or probe.get("target") or "",
                asset_id,
                probe.get("findings") or [],
            )
        logger.log(
            f"HTTP 探测完成：存活 {len(alive)} / {len(probes)}，新增风险 {total_inserted} 项",
            "success",
        )
        logger.checkpoint()

        # 3. 端口扫描
        logger.stage(60, "端口暴露面探测")
        host_targets = list(dict.fromkeys(host_of(t) for t in targets))[:10]
        nmap = load_connector("nmap")
        ports: list[dict[str, Any]] = []
        if nmap and isinstance(nmap, NmapConnector) and nmap.enabled and nmap.available():
            logger.log("执行端口探测", "info")
            result = await nmap.scan_ports(host_targets, scan["profile"], timeout=300)
            if result.ok:
                ports = result.data.get("ports", [])
            else:
                logger.log(f"Nmap 不可用，降级为内置探测：{result.message}", "warn")
        if not ports:
            logger.log("使用内置 TCP 探测（非侵入式）", "info")
            ports = await builtin_port_scan(
                host_targets,
                scan["profile"],
                concurrency=max(32, concurrency),
                timeout=1.5,
            )
        stats["ports"] = ports
        port_hits = persist_findings(scan_id, ", ".join(host_targets[:3]), None, port_findings(ports))
        logger.log(f"端口探测完成：开放 {len(ports)} 个，新增风险 {port_hits} 项", "success")
        logger.checkpoint()

        # 4. Nuclei 模板检测
        logger.stage(80, "模板化漏洞检测")
        nuclei = load_connector("nuclei")
        if nuclei and isinstance(nuclei, NucleiConnector) and nuclei.enabled and nuclei.available():
            url_targets = list(dict.fromkeys(p["url"] for p in alive if p.get("url")))[:25]
            if url_targets:
                logger.log(f"Nuclei 开始检测 {len(url_targets)} 个 URL", "info")
                fd, temp_nuclei_path = tempfile.mkstemp(suffix=".jsonl")
                os.close(fd)
                result = await nuclei.scan(
                    url_targets,
                    scan["profile"],
                    output_path=temp_nuclei_path,
                    timeout=900,
                    safe_mode=settings.get("safe_mode", "true").lower() in ("1", "true", "yes", "on"),
                )
                if result.ok:
                    items = result.data.get("items", [])
                    mapped: list[tuple[str, dict[str, Any]]] = []
                    for item in items:
                        info = item.get("info") or {}
                        matched = item.get("matched-at", item.get("host", ""))
                        mapped.append(
                            (
                                matched,
                                {
                                    "title": info.get("name", item.get("template-id", "Nuclei 命中")),
                                    "severity": str(info.get("severity", "info")).lower(),
                                    "category": ", ".join(info.get("tags") or [])[:100],
                                    "source": "nuclei",
                                    "description": info.get("description", "") or "Nuclei 模板命中。",
                                    "evidence": matched[:1500],
                                    "url": matched,
                                    "request_packet": str(item.get("request") or "")[:6000],
                                    "response_packet": str(item.get("response") or "")[:6000],
                                    "capability": "component_vuln",
                                    "remediation": info.get("remediation", "") or "根据模板说明修复对应漏洞。",
                                    "cvss": float((info.get("classification") or {}).get("cvss-score") or 0),
                                    "confidence": "high",
                                    "dedupe_key": f"nuclei:{item.get('template-id', '')}:{matched}",
                                },
                             )
                        )
                    inserted = 0
                    for matched, finding in mapped:
                        inserted += persist_findings(scan_id, matched, None, [finding])
                    stats["nuclei"] = len(mapped)
                    logger.log(f"Nuclei 完成：命中 {len(mapped)} 条，新增 {inserted} 条", "success")
                else:
                    logger.log(f"Nuclei 检测失败：{result.message}", "warn")
            else:
                logger.log("没有可用的存活 URL，跳过 Nuclei", "muted")
        else:
            logger.log("Nuclei 未安装或未启用，跳过模板检测", "muted")
        logger.checkpoint()

        # 5. AI 研判
        logger.stage(92, "AI 风险研判")
        with db() as conn:
            finding_rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT severity, title, target FROM findings WHERE scan_id=? ORDER BY id",
                    (scan_id,),
                ).fetchall()
            ]
            severity_counts = {
                r["severity"]: r["c"]
                for r in conn.execute(
                    "SELECT severity, COUNT(*) AS c FROM findings WHERE scan_id=? GROUP BY severity",
                    (scan_id,),
                ).fetchall()
            }
        stats["severity"] = severity_counts
        ai_summary, ai_ok = await ai_analyze(targets, stats, finding_rows)
        stats["ai"] = ai_ok
        if ai_ok:
            logger.log("AI 研判完成", "success")
        else:
            logger.log("AI 研判未启用或调用失败，已使用本地摘要", "muted")

        stats["risk_score"] = min(
            100,
            sum(
                {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}.get(k, 0) * v
                for k, v in severity_counts.items()
            ),
        )
        stats["duration"] = round(time.time() - started, 1)
        update_scan(
            scan_id,
            status="completed",
            progress=100,
            stage="完成",
            finished_at=now_iso(),
            summary=summary_text(targets, severity_counts, ai_summary),
            stats_json=json.dumps(stats, ensure_ascii=False),
        )
        logger.log("任务完成", "success")
        HUB.publish(scan_id, {"type": "done", "status": "completed"})
    except ScanCancelled:
        stats["duration"] = round(time.time() - started, 1)
        update_scan(
            scan_id,
            status="cancelled",
            stage="已取消",
            finished_at=now_iso(),
            stats_json=json.dumps(stats, ensure_ascii=False),
        )
        logger.log("任务已取消", "warn")
        HUB.publish(scan_id, {"type": "done", "status": "cancelled"})
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        stats["duration"] = round(time.time() - started, 1)
        update_scan(
            scan_id,
            status="failed",
            stage="失败",
            finished_at=now_iso(),
            summary=f"任务执行失败：{message}",
            stats_json=json.dumps(stats, ensure_ascii=False),
        )
        logger.log(f"任务失败：{message}", "error")
        HUB.publish(scan_id, {"type": "done", "status": "failed", "error": message})
    finally:
        CANCELLED.discard(scan_id)
        if temp_nuclei_path:
            try:
                os.unlink(temp_nuclei_path)
            except OSError:
                pass


async def scan_worker() -> None:
    while True:
        scan_id = await SCAN_QUEUE.get()
        try:
            await run_scan(scan_id)
        except Exception:
            pass
        finally:
            SCAN_QUEUE.task_done()
