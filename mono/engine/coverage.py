"""能力覆盖台账：用户勾选的那些能力，这个会话里到底验了几项、结论是什么。

为什么要单独记一本账：

模型每轮都会说「已测的部分覆盖了……其余大部分没测」，但它说的是一句话，不是账。
平台没有账，就没法判断「是不是真的还有没验的」，只能靠催——催到第三次它不写了，
活就停在那里。有了这本账，剩余量是**算出来的**：勾了 66 项，已验 4 项，还剩 62 项，
每轮都把下一批点名叫出来，直到每一项都有结论。

状态只有四种，都能落到「能不能交付」上：

- ``vulnerable``  验出了漏洞（归档了 finding）
- ``clean``       验过，没有这个问题
- ``blocked``     被目标挡住（401/403/WAF 统一拦截），不是没测，是测不动
- ``inconclusive`` 测了但证据不足（保留原样，下次可以再补）
"""
from __future__ import annotations

from typing import Any

from ..db import db, now_iso
from .capabilities import CAPABILITY_BY_KEY, auto_pentest_enabled, enabled_keys, get_hints

# 补测顺序：按「命中率 × 危害」排，模型照着往下走，不需要回头问用户先测哪一类
COVERAGE_ORDER: tuple[str, ...] = (
    "unauthorized",
    "idor",
    "horizontal_escalation",
    "privilege_escalation",
    "sqli_char",
    "sensitive_info",
    "api_doc_leak",
    "file_download",
    "backup_file",
    "source_leak",
    "xss_reflected",
    "ssrf",
    "cve_nday",
    "component_vuln",
    "weak_password",
    "default_cred",
    "cloud_storage",
    "debug_endpoint",
)

VALID_STATUS = ("vulnerable", "clean", "blocked", "inconclusive")
STATUS_LABEL = {
    "vulnerable": "有漏洞",
    "clean": "验过没问题",
    "blocked": "被目标挡住",
    "inconclusive": "证据不足",
}


def order_keys(keys: list[str]) -> list[str]:
    """按补测顺序排，把不在顺序表里的放最后（用户新勾的能力也不会被漏掉）。"""
    rank = {key: index for index, key in enumerate(COVERAGE_ORDER)}
    return sorted(dict.fromkeys(keys), key=lambda k: (rank.get(k, len(rank)), k))


def resolve(name: str) -> str:
    """把 key、中文名、大小写变体都归到能力 key；认不出来返回空串。

    模型有时会把「任意文件读取」写成「文件读取」，所以再补一层模糊匹配：
    彼此包含就算命中，但必须有唯一解，否则宁可不认（记错项比不记更糟）。
    """
    text = str(name or "").strip()
    if not text:
        return ""
    if text in CAPABILITY_BY_KEY:
        return text
    lowered = text.lower()
    for key, item in CAPABILITY_BY_KEY.items():
        if key.lower() == lowered or str(item.get("name") or "") == text:
            return key
    fuzzy = [
        key
        for key, item in CAPABILITY_BY_KEY.items()
        if lowered in key.lower() or lowered in str(item.get("name") or "").lower()
        or (str(item.get("name") or "") and str(item.get("name")).lower() in lowered)
    ]
    return fuzzy[0] if len(fuzzy) == 1 else ""


def selected_keys() -> list[str]:
    """用户勾选的能力，按补测顺序排。一项都没勾时返回空列表（此时不做覆盖判定）。"""
    return order_keys([key for key in enabled_keys() if key in CAPABILITY_BY_KEY])


def mark(session_id: int, cap_key: str, status: str, note: str = "", evidence: str = "") -> dict[str, Any]:
    """记一项能力的结论；同一项重复上报时以最后一次为准（后面那次往往证据更足）。"""
    key = resolve(cap_key)
    if not key:
        return {"ok": False, "error": f"未知能力：{cap_key}"}
    state = status if status in VALID_STATUS else "inconclusive"
    ts = now_iso()
    with db() as conn:
        conn.execute(
            """INSERT INTO coverage_marks (session_id, cap_key, status, note, evidence, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(session_id, cap_key) DO UPDATE SET
                 status=excluded.status, note=excluded.note,
                 evidence=excluded.evidence, updated_at=excluded.updated_at""",
            (int(session_id), key, state, str(note or "")[:400], str(evidence or "")[:1200], ts, ts),
        )
    return {"ok": True, "capability": key, "name": CAPABILITY_BY_KEY[key]["name"], "status": state}


def marks(session_id: int) -> dict[str, dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT cap_key, status, note, evidence, updated_at FROM coverage_marks WHERE session_id=?",
            (int(session_id),),
        ).fetchall()
    return {str(row["cap_key"]): dict(row) for row in rows}


def plan(session_id: int) -> list[dict[str, Any]]:
    """勾选的能力逐项列出状态：没记过的算「还没验」。"""
    recorded = marks(session_id)
    hints = get_hints()
    out: list[dict[str, Any]] = []
    for key in selected_keys():
        item = recorded.get(key) or {}
        out.append(
            {
                "key": key,
                "name": CAPABILITY_BY_KEY[key]["name"],
                "status": str(item.get("status") or "pending"),
                "note": str(item.get("note") or ""),
                "updated_at": str(item.get("updated_at") or ""),
                # 用户给这项写的要求：界面要显示，催测时要一并交下去
                "user_prompt": hints.get(key, ""),
            }
        )
    return out


def pending(session_id: int, limit: int = 0) -> list[dict[str, Any]]:
    """还没验的（含证据不足待补的），按补测顺序。"""
    todo = [item for item in plan(session_id) if item["status"] in ("pending", "inconclusive")]
    return todo[:limit] if limit else todo


def summary(session_id: int) -> dict[str, Any]:
    items = plan(session_id)
    done = [item for item in items if item["status"] in ("vulnerable", "clean", "blocked")]
    decided = [item for item in items if item["status"] in ("vulnerable", "clean")]
    return {
        "selected": len(items),
        "done": len(done),
        "decided": len(decided),
        "vulnerable": len([item for item in items if item["status"] == "vulnerable"]),
        "blocked": len([item for item in items if item["status"] == "blocked"]),
        "pending": len(items) - len(done),
        "percent": round(len(done) * 100 / len(items)) if items else 0,
        "next": [item["name"] for item in items if item["status"] in ("pending", "inconclusive")][:6],
    }


def all_done(session_id: int) -> bool:
    """勾了的都验过了才算完；一项没勾时返回 True（不做覆盖判定，别把人卡住）。"""
    items = plan(session_id)
    return all(item["status"] in ("vulnerable", "clean", "blocked") for item in items)


def summary_line(session_id: int) -> str:
    data = summary(session_id)
    if not data["selected"]:
        return "能力清单里一项都没勾，按用户给的目标自己判断该测什么。"
    line = (
        f"已勾选 {data['selected']} 项能力，已验 {data['done']} 项"
        f"（{data['percent']}%），其中 {data['vulnerable']} 项验出漏洞、"
        f"{data['blocked']} 项被目标挡住，还剩 {data['pending']} 项没验。"
    )
    if data["next"]:
        line += f"下一批：{'、'.join(data['next'])}。"
    return line


def next_batch_prompt(session_id: int, batch: int = 3) -> str:
    """推给模型的「接着验」指令：点名剩余项，要求逐项给结论并上报。"""
    todo = pending(session_id, limit=batch)
    if not todo:
        return ""
    names = "\n".join(
        f"   {index + 1}. {item['name']}（{item['key']}）"
        + (f"\n      用户提示·必须照做：{item['user_prompt']}" if item.get("user_prompt") else "")
        for index, item in enumerate(todo)
    )
    rest = summary(session_id)
    if auto_pentest_enabled():
        scope = (
            "自动渗透已开启：上面这几项必须验，清单之外看到可测的类型也一起测，"
            "验出问题照样归档（清单外的发现不计入这里的台账，但必须写进结论）。\n"
        )
    else:
        scope = "自动渗透关闭：只验清单内这几项，清单外的类型先不展开，在正文里记一句线索即可。\n"
    return (
        "【平台判定：能力清单还没验完，不能收口】\n"
        f"{summary_line(session_id)}\n"
        "这一轮先把下面这几项真正测一遍（每项都要发出请求拿到响应，不能只在正文里写「建议测」）：\n"
        f"{names}\n"
        + scope
        + "带「用户提示」的项，先逐字读完提示再动手：提示里点名的入口、参数、检查点一个都不能少，"
        "提示说不要碰的就不碰；少做一条就等于这项没测。\n"
        "每测完一项，立刻调用 report_capability 报结论：\n"
        "   capability 填括号里的 key；status 只能是 vulnerable / clean / blocked / inconclusive；\n"
        "   note 写清测了哪个入口、看到什么；有用户提示的，还要逐个说明提示里的要求各自是什么结果；\n"
        "   验出问题的一律先 record_finding 归档再上报。\n"
        f"验完这几项再继续下一批，直到 {rest['selected']} 项全部有结论；"
        "确实测不动的（401/403/WAF 统一拦截）报 blocked，不要空着。\n"
        "红线不变：只做只读验证，不写改删数据、不压测、不爆破、不横向。"
    )


def gate_line(session_id: int, limit: int = 8) -> str:
    """收尾/结论里那行「任务未完成」：把还差哪几项直接摆出来。

    这条是给用户看的：只要台账没满，就不许出现「测试完成」这种说法。
    """
    data = summary(session_id)
    if not data["selected"]:
        return ""
    if all_done(session_id):
        tail = (
            "清单内可以交付；自动渗透已开启，清单外若还有入口就继续测，不算超范围。"
            if auto_pentest_enabled()
            else "可以交付。"
        )
        return (
            f"【能力台账 {data['done']}/{data['selected']} · 全部有结论（{data['percent']}%）】"
            f"其中 {data['vulnerable']} 项验出漏洞、{data['blocked']} 项被目标挡住，{tail}"
        )
    names = [item["name"] for item in pending(session_id, limit=limit)]
    more = data["pending"] - len(names)
    tail = f" 等 {data['pending']} 项" if more > 0 else ""
    return (
        f"【任务未完成 · 能力台账 {data['done']}/{data['selected']}（{data['percent']}%），"
        f"还差 {data['pending']} 项没有结论】\n"
        f"还差：{'、'.join(names)}{tail}。\n"
        "这一轮不能算测完，也不会被当成交付：自动继续会按顺序接着补测；"
        "要提前收手请点「停止」，或在能力页把不测的项取消勾选。"
    )


def set_status_note(session_id: int, cap_key: str, note: str) -> None:
    """只更新备注，不动状态（模型又补了一句说明时用）。"""
    key = resolve(cap_key)
    if not key:
        return
    with db() as conn:
        conn.execute(
            "UPDATE coverage_marks SET note=?, updated_at=? WHERE session_id=? AND cap_key=?",
            (str(note)[:400], now_iso(), int(session_id), key),
        )
