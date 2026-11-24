"""HTML 报告生成（纯黑白样式，自包含）。"""
from __future__ import annotations

import html
from typing import Any

from .config import APP_NAME, APP_SUBTITLE, APP_VERSION, SEVERITY_LABELS


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def render_finding(finding: dict[str, Any]) -> str:
    sev = finding.get("severity", "info")
    return f"""
    <article class="finding sev-{esc(sev)}">
      <header>
        <span class="badge">{esc(SEVERITY_LABELS.get(sev, sev))}</span>
        <h3>{esc(finding.get('title'))}</h3>
        <span class="cvss">{esc(finding.get('cvss') or '')}</span>
      </header>
      <div class="meta">
        <span>目标：{esc(finding.get('target'))}</span>
        <span>来源：{esc(finding.get('source'))}</span>
        <span>分类：{esc(finding.get('category'))}</span>
        <span>状态：{esc(finding.get('status'))}</span>
      </div>
      <p>{esc(finding.get('description'))}</p>
      <div class="block"><label>证据</label><pre>{esc(finding.get('evidence'))}</pre></div>
      <div class="block"><label>修复建议</label><p>{esc(finding.get('remediation'))}</p></div>
    </article>
    """


def build_report_html(
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    logs: list[dict[str, Any]] | None = None,
) -> str:
    stats = scan.get("stats") or {}
    counts = stats.get("severity") or {}
    summary = esc(scan.get("summary") or "").replace("\n", "<br>")
    probes = stats.get("probes") or []
    ports = stats.get("ports") or []
    recon = stats.get("recon") or {}
    ordered = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            f.get("severity", "info"), 5
        ),
    )
    findings_html = "".join(render_finding(item) for item in ordered) or '<p class="empty">未发现风险项。</p>'

    cards = "".join(
        f'<div class="card"><span>{esc(SEVERITY_LABELS[key])}</span><strong>{int(counts.get(key, 0))}</strong></div>'
        for key in ("critical", "high", "medium", "low", "info")
    )

    probe_rows = "".join(
        f"<tr><td>{esc(p.get('url'))}</td><td>{esc(p.get('status'))}</td>"
        f"<td>{esc(p.get('title'))}</td><td>{esc(p.get('server'))}</td>"
        f"<td>{esc(p.get('error'))}</td></tr>"
        for p in probes[:80]
    ) or '<tr><td colspan="5" class="empty">无探测数据</td></tr>'

    port_rows = "".join(
        f"<tr><td>{esc(p.get('host'))}</td><td>{esc(p.get('port'))}</td>"
        f"<td>{esc(p.get('protocol'))}</td><td>{esc(p.get('service'))}</td></tr>"
        for p in ports[:200]
    ) or '<tr><td colspan="4" class="empty">无开放端口</td></tr>'

    source_html = "".join(
        f"<li>{esc(k)}：{esc(v)} 条</li>" for k, v in (recon.get("sources") or {}).items()
    ) or "<li>未启用或未配置资产测绘 API</li>"

    log_rows = "".join(
        f"<tr><td>{esc(item.get('ts'))}</td><td>{esc(item.get('level'))}</td>"
        f"<td>{esc(item.get('message'))}</td></tr>"
        for item in (logs or [])[-120:]
    ) or '<tr><td colspan="3" class="empty">无日志</td></tr>'

    targets = ", ".join(scan.get("targets") or [])
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(scan.get('name'))} - {esc(APP_NAME)} 报告</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background:#050505; color:#f4f4f4;
        font-family: Consolas, "SF Mono", "Courier New", monospace; font-size:13px; line-height:1.7; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 48px 32px 80px; }}
  .brand {{ display:flex; justify-content:space-between; align-items:flex-end;
            border-bottom:1px solid #333; padding-bottom:20px; margin-bottom:32px; }}
  .logo {{ font-size:34px; letter-spacing:4px; font-weight:700; }}
  .logo span {{ color:#777; }}
  .meta {{ color:#888; text-align:right; }}
  h1 {{ font-size:22px; margin: 0 0 8px; font-weight:600; letter-spacing:1px; }}
  h2 {{ font-size:14px; letter-spacing:3px; text-transform:uppercase; color:#bbb;
        border-left:3px solid #fff; padding-left:10px; margin:48px 0 18px; }}
  .sub {{ color:#8a8a8a; }}
  .cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:24px 0; }}
  .card {{ border:1px solid #2c2c2c; padding:16px; background:#0d0d0d; }}
  .card span {{ display:block; color:#888; font-size:11px; letter-spacing:2px; }}
  .card strong {{ font-size:26px; }}
  .summary {{ white-space: normal; border:1px dashed #444; padding:18px; background:#0a0a0a; }}
  table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
  th, td {{ border-bottom:1px solid #222; padding:8px 10px; text-align:left; vertical-align:top; word-break:break-all; }}
  th {{ color:#999; font-weight:500; font-size:11px; letter-spacing:1px; }}
  .finding {{ border:1px solid #262626; border-left-width:4px; background:#0b0b0b;
              padding:16px 18px; margin-bottom:12px; break-inside:avoid; }}
  .finding.sev-critical {{ border-left-color:#fff; }}
  .finding.sev-high {{ border-left-color:#d0d0d0; }}
  .finding.sev-medium {{ border-left-color:#8a8a8a; }}
  .finding.sev-low {{ border-left-color:#555; }}
  .finding.sev-info {{ border-left-color:#333; }}
  .finding header {{ display:flex; gap:10px; align-items:center; }}
  .finding h3 {{ font-size:14px; margin:0; flex:1; }}
  .badge {{ border:1px solid #777; padding:1px 8px; font-size:11px; }}
  .cvss {{ color:#888; font-size:11px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:14px; color:#888; font-size:11px;
           text-align:left; margin:10px 0; }}
  .block label {{ display:block; color:#999; font-size:11px; letter-spacing:1px; margin:10px 0 4px; }}
  pre {{ margin:0; padding:12px; background:#000; border:1px solid #222; white-space:pre-wrap; word-break:break-all; }}
  p {{ margin:8px 0; }}
  ul {{ margin:0; padding-left:20px; color:#bbb; }}
  .empty {{ color:#666; }}
  footer {{ margin-top:64px; border-top:1px solid #222; padding-top:16px;
            display:flex; justify-content:space-between; color:#666; font-size:11px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <div>
      <div class="logo">K7so<span>//</span>REPORT</div>
      <div class="sub">{esc(APP_SUBTITLE)} · v{esc(APP_VERSION)}</div>
    </div>
    <div class="meta">
      报告编号 #{esc(scan.get('id'))}<br>
      生成时间 {esc(__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M'))}<br>
      授权依据 {esc(scan.get('authorization_ref') or '未填写')}
    </div>
  </div>

  <h1>{esc(scan.get('name'))}</h1>
  <div class="sub">执行人 {esc(scan.get('created_by'))} · 模式 {esc(scan.get('mode'))} ·
      强度 {esc(scan.get('profile'))} · 时间 {esc(scan.get('created_at'))}</div>

  <h2>风险总览</h2>
  <div class="cards">{cards}</div>
  <div class="summary">{summary or '暂无摘要'}</div>

  <h2>目标范围</h2>
  <p>{esc(targets)}</p>

  <h2>资产测绘来源</h2>
  <ul>{source_html}</ul>

  <h2>漏洞与风险项</h2>
  {findings_html}

  <h2>HTTP 探测</h2>
  <table><thead><tr><th>URL</th><th>状态</th><th>标题</th><th>Server</th><th>错误</th></tr></thead>
  <tbody>{probe_rows}</tbody></table>

  <h2>开放端口</h2>
  <table><thead><tr><th>主机</th><th>端口</th><th>协议</th><th>服务</th></tr></thead>
  <tbody>{port_rows}</tbody></table>

  <h2>执行日志</h2>
  <table><thead><tr><th>时间</th><th>级别</th><th>内容</th></tr></thead>
  <tbody>{log_rows}</tbody></table>

  <footer>
    <span>{esc(APP_NAME)} // {esc(APP_SUBTITLE)}</span>
    <span>本报告仅限授权项目使用，请妥善保管</span>
  </footer>
</div>
</body>
</html>
"""
