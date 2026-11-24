"""智能工作引擎：把自然语言指令转换为平台操作（工具调用循环）。"""
from __future__ import annotations

import asyncio
import hashlib
import os
import inspect
import ipaddress
import json
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, AsyncGenerator
from urllib.parse import urlsplit

from ..config import BASE_DIR, DATA_DIR, MEMORY_DIR, SEVERITY_LABELS, WORKSPACE_DIR, env
from ..connectors import connector_rows, load_connector, run_connector_test
from ..db import audit, db, get_settings, now_iso
from ..netutil import UNKNOWN_HOST, host_of
from ..runtime import CANCELLED
from .tasks import TaskError, create_scan_task, resolve_targets
from .capabilities import (
    ASK_DELETE_KEY,
    ASK_SENSITIVE_KEY,
    CAPABILITY_BY_KEY,
    DEFAULT_WEIGHT,
    ask_enabled,
    auto_pentest_enabled,
    context_text as capabilities_context,
    enabled_items,
    enabled_keys,
    get_hints as capability_hints,
    snapshot as capabilities_snapshot,
    step_budget,
    weighted_items,
)
from . import coverage
from .watchdog import STALL_SECONDS, StepStalled, iter_with_watchdog, stall_message
from .shell import (
    blocked_reason as shell_blocked_reason,
    delete_reason as shell_delete_reason,
    http_request as shell_http_request,
    run_command as shell_run_command,
    run_script as shell_run_script,
    terminate_all as shell_terminate_all,
    tool_snapshot as shell_tool_snapshot,
    touches_sensitive_file as shell_touches_sensitive,
)
from .workspace import (
    MEMORY_PRELOAD,
    WorkspaceError,
    allowed_roots,
    exec_dir,
    memory_chunk,
    memory_files,
    memory_manifest,
    memory_path,
    memory_search,
    read_memory,
    resolve_doc,
    resolve_path,
    work_dir,
)

# 上下文与输出预算（可用环境变量覆盖，K7so_ 前缀，兼容旧的 MONO_ 前缀）
# 输出上限：8000 时一到写报告就被截断，续写又只肯接两次，长结论根本落不下来。
# 默认放到 16000，并在模型明确拒绝这个值时自动减半重试（见 _model_turn）。
MAX_OUTPUT_TOKENS = int(env("MAX_OUTPUT_TOKENS", "16000"))
# 一次回答被截断后最多接着写几段：报告类输出经常要三四段才写得完
CONTINUE_ROUNDS = int(env("CONTINUE_ROUNDS", "6"))
# 单轮总时长上限：深度测试放开了轮次，但用户不能干等半小时
TURN_MAX_SECONDS = int(env("TURN_MAX_SECONDS", "900"))
# 台账没满时「一轮」必须能自己跑完：58 项按 15 分钟 / 50 步收口，
# 结果就是第一轮草草结束、把大半活推给下一轮——用户明确不要这种排法。
# 一项按 8 步估（发请求 → 看响应 → 必要时改包 → 上报），再叠一点余量。
LEDGER_STEPS_PER_ITEM = int(env("LEDGER_STEPS_PER_ITEM", "8"))
LEDGER_HARD_STEPS = int(env("LEDGER_HARD_STEPS", "1200"))
# 时间同样给够：6 小时是兜底，正常 58 项也就一两个小时
LEDGER_HARD_SECONDS = int(env("LEDGER_HARD_SECONDS", "21600"))
CONTEXT_CHAR_BUDGET = int(env("CONTEXT_CHAR_BUDGET", "80000"))
HISTORY_CHAR_BUDGET = int(env("HISTORY_CHAR_BUDGET", "24000"))
TOOL_RESULT_CHARS = int(env("TOOL_RESULT_CHARS", "5000"))
# 命令输出、HTTP 响应、文件/记忆正文这类结果不能被压到 5000 字，否则等于没读
LARGE_RESULT_CHARS = int(env("TOOL_RESULT_LARGE", "24000"))
# 单次返回的正文上限：必须小于上面那个预算，否则 JSON 会被截断，
# 模型"以为读到了"其实少了尾巴（这是最坑的一种错）
READ_CHUNK_MAX = max(4000, LARGE_RESULT_CHARS - 3000)

VALID_FINDING_STATUS = ("open", "confirmed", "fixed", "accepted", "false_positive")

# 工具执行时所在的会话：report_capability / record_finding 要把结论记到这本账上，
# 而工具签名只有 (args, username)，所以用 ContextVar 把会话带进去
# （asyncio.to_thread 会复制当前 context，线程里也读得到）。
_TOOL_SESSION: ContextVar[int] = ContextVar("k7so_tool_session", default=0)

# 本会话归档过哪些漏洞：用户要求「最后的结果要把每一个漏洞的标题、请求包、响应包
# 在控制台写出来」，模型写不写全由平台兜底——收尾时按这份清单核对，缺的补上。
_SESSION_FINDINGS: dict[int, list[int]] = {}

# 清单口径是「域名」，不是「轮」：
# 这一轮测了哪些域名，就把这些域名在本次对话里出现过的漏洞全部摊出来；
# 多域名就每个域名各列一份，同一条漏洞只列一次（不重复列举）。
# 所以这里要记三样：这一轮碰过的域名、这次对话碰过的域名、这次对话归档过的全部漏洞。
_ROUND_DOMAINS: dict[int, list[str]] = {}
_SESSION_DOMAINS: dict[int, list[str]] = {}
_SESSION_ALL_FINDINGS: dict[int, list[int]] = {}

# 用户硬性要求：输出要写清楚「怎么一步一步打出来的」，不能只丢一对报文。
# 所以每发一次包就把这一步记下来（目的、看到什么、报文），归档时挂到那条漏洞上。
# 模型自己会在 steps 里写过程，那是第一顺位；没写就用这里记录的真实步骤兜底。
_SESSION_STEPS: dict[int, list[dict]] = {}

# 用户给某项能力写过提示时，必须先「读到」才允许记账：
# 第一次 report_capability 会返回提示原文（hint_required），模型读完再报一次才落账。
# 这一本记的就是「这次会话里哪几项能力的提示已经读过」。
_SESSION_HINTS_READ: dict[int, set[str]] = {}
MAX_STEPS_PER_SESSION = 80
MAX_STEPS_PER_FINDING = 6
STEP_PACKET_CHARS = 2400
# 结论里贴报文是给人看的，不是把整页搬过来：请求包留请求行 + 关键头部，
# 响应包留状态行 + 关键头部 + 前面一段正文就够判断了，太长就截断并注明节选。
DIGEST_REQUEST_CHARS = 900
DIGEST_RESPONSE_CHARS = 700

# 收尾被推回补测的次数上限。
# 只对「结论太薄 / 三个方向没说清」这类质量问题生效；能力台账没满时不受它限制——
# 用户定死了「所有模型能力测完才算结束」，所以那一类要一直推，推到有结论为止。
MAX_COVERAGE_PUSHES = 8


def forget_session_findings(session_id: int) -> None:
    """会话被删掉时把清单缓存一起清掉，别留着占内存。"""
    key = int(session_id or 0)
    for bucket in (
        _SESSION_FINDINGS,
        _SESSION_ALL_FINDINGS,
        _ROUND_DOMAINS,
        _SESSION_DOMAINS,
        _SESSION_STEPS,
        _SESSION_HINTS_READ,
    ):
        bucket.pop(key, None)


# 清单缓存按会话累积，长跑进程里会话越开越多，留一个上限兜底
MAX_TRACKED_SESSIONS = 200


def _trim_tracked() -> None:
    while len(_SESSION_ALL_FINDINGS) > MAX_TRACKED_SESSIONS:
        forget_session_findings(next(iter(_SESSION_ALL_FINDINGS)))
    while len(_SESSION_STEPS) > MAX_TRACKED_SESSIONS:
        _SESSION_STEPS.pop(next(iter(_SESSION_STEPS)), None)


def _note_domain(url: str) -> str:
    """把一次真实动作（发包 / 归档）的域名登记到「这一轮」和「这次对话」。"""
    host = host_of(str(url or ""))
    if host == UNKNOWN_HOST:
        return ""
    session_id = int(_TOOL_SESSION.get() or 0)
    if not session_id:
        return host
    for bucket_map in (_ROUND_DOMAINS, _SESSION_DOMAINS):
        bucket = bucket_map.setdefault(session_id, [])
        if host not in bucket:
            bucket.append(host)
    _trim_tracked()
    return host


def _clip_packet(text: str) -> str:
    body = str(text or "")
    if len(body) <= STEP_PACKET_CHARS:
        return body
    return body[:STEP_PACKET_CHARS] + "\n…（报文过长，这里截断，完整内容见该漏洞归档的报文）"


def _clip_for_digest(text: str, limit: int, label: str) -> str:
    """结论里只贴报文的关键部分：太长就截断，并明确写「这是节选」。

    用户的要求是「响应包太大只写一小部分即可」——结论是给人看的，
    把几万字的响应体整页贴进来反而没法读；完整报文在漏洞结果页里。
    """
    body = str(text or "").strip()
    if len(body) <= limit:
        return body
    cut = body[:limit]
    # 尽量在行尾断开，别把响应体切成半行
    if "\n" in cut:
        cut = cut.rsplit("\n", 1)[0]
    return cut + f"\n…（{label}过长，这里只保留前 {len(cut)} 字符作为节选，完整内容见漏洞结果页对应条目）"


def _note_step(url: str, result: dict, note: str = "") -> None:
    """把刚发出去的一次请求记成「一步」。

    这一步做了什么、返回了什么、当时想验证什么，都留着；归档时按域名挑出来，
    收尾清单就能按时间顺序讲清楚漏洞是怎么被打出来的。
    """
    session_id = int(_TOOL_SESSION.get() or 0)
    host = host_of(str(url or ""))
    if not session_id or host == UNKNOWN_HOST:
        return
    bucket = _SESSION_STEPS.setdefault(session_id, [])
    bucket.append(
        {
            "seq": (int(bucket[-1].get("seq") or 0) + 1) if bucket else 1,
            "host": host,
            "method": str(result.get("method") or "GET").upper(),
            "url": str(result.get("url") or url or ""),
            "status": result.get("status"),
            "reason": str(result.get("reason") or ""),
            "note": str(note or "").strip()[:240],
            "request_packet": _clip_packet(result.get("request_packet") or ""),
            "response_packet": _clip_packet(result.get("response_packet") or ""),
            "used": False,
        }
    )
    if len(bucket) > MAX_STEPS_PER_SESSION:
        del bucket[: len(bucket) - MAX_STEPS_PER_SESSION]
    _trim_tracked()


def _step_path(url: str) -> str:
    """步骤里尽量写「方法 + 路径」，比甩一整条长 URL 更好读。"""
    text = str(url or "").strip()
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path[:200]


def _step_line(step: dict) -> tuple[str, str]:
    """把一步写成人话：做了什么 / 看到什么。"""
    action = f"{step.get('method') or 'GET'} {_step_path(step.get('url') or '')}"
    note = str(step.get("note") or "").strip()
    if note:
        action = f"{action}（目的：{note}）"
    status = step.get("status")
    if status:
        seen = f"返回 {status}"
        reason = str(step.get("reason") or "").strip()
        if reason:
            seen += f" {reason}"
    else:
        seen = "请求没打通（连接失败或被拦），这一步没有拿到响应"
    return action, seen


def _steps_for_finding(url: str) -> list[dict]:
    """给一条漏洞挑出「怎么打出来的」的步骤：同域名、还没被别的漏洞用过的优先。

    没挑到新的（同一条漏洞重新归档补报文）就退回该域名最近几步，别交空步骤。
    """
    session_id = int(_TOOL_SESSION.get() or 0)
    bucket = list(_SESSION_STEPS.get(session_id) or [])
    if not bucket:
        return []
    host = host_of(str(url or ""))
    same = [step for step in bucket if _same_domain(str(step.get("host") or ""), host)]
    pool = [step for step in same if not step.get("used")]
    if not pool:
        pool = same[-MAX_STEPS_PER_FINDING:]
    picked = pool[-MAX_STEPS_PER_FINDING:]
    for step in picked:
        step["used"] = True
    steps: list[dict] = []
    for step in picked:
        action, seen = _step_line(step)
        steps.append(
            {
                "action": action,
                "result": seen,
                "why": "",
                "request_packet": str(step.get("request_packet") or ""),
                "response_packet": str(step.get("response_packet") or ""),
            }
        )
    return steps


def _normalize_steps(raw: Any) -> list[dict]:
    """模型传来的复现步骤，接受四种写法：字符串 / 字符串数组 / 对象 / 对象数组。"""
    items: Any = raw
    if isinstance(items, str):
        text = items.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = [text]
        items = parsed
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        return []
    steps: list[dict] = []
    for item in items:
        if len(steps) >= MAX_STEPS_PER_FINDING:
            break
        if isinstance(item, str):
            text = item.strip()
            if text:
                steps.append(
                    {"action": text[:600], "result": "", "why": "", "request_packet": "", "response_packet": ""}
                )
            continue
        if not isinstance(item, dict):
            continue
        action = str(item.get("action") or item.get("step") or item.get("do") or "").strip()
        seen = str(item.get("result") or item.get("observe") or item.get("seen") or "").strip()
        why = str(item.get("why") or item.get("conclusion") or item.get("note") or "").strip()
        request = str(item.get("request_packet") or item.get("request") or "").strip()
        response = str(item.get("response_packet") or item.get("response") or "").strip()
        if not any((action, seen, request, response)):
            continue
        steps.append(
            {
                "action": action[:600],
                "result": seen[:600],
                "why": why[:600],
                "request_packet": _clip_packet(request),
                "response_packet": _clip_packet(response),
            }
        )
    return steps


def _load_steps(text: str) -> list[dict]:
    """从库里读回步骤，坏数据就当没有，别让收尾直接报错。"""
    raw = str(text or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    return _normalize_steps(data) if isinstance(data, list) else []


def _body_has_steps(body: str) -> bool:
    """正文里是不是已经按步骤写了（模型可能写「步骤1」「第 1 步」「第一步」）。"""
    text = str(body or "")
    if "复现步骤" in text or "复现过程" in text:
        return True
    for pattern in (
        r"步骤\s*1",
        r"第\s*1\s*步",
        r"第一步",
        r"step\s*1\b",
    ):
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    return False


def _same_domain(left: str, right: str) -> bool:
    """`www.a.com` 与 `a.com` 算同一家，别因为一个前缀漏列。"""
    def norm(value: str) -> str:
        text = str(value or "").strip().lower()
        return text[4:] if text.startswith("www.") else text

    return norm(left) == norm(right)


def set_tool_session(session_id: int):
    """给「不在 run_agent 里」的工具调用（比如确认卡片触发的执行）补上会话上下文。"""
    return _TOOL_SESSION.set(int(session_id or 0))


@contextmanager
def tool_session(session_id: int):
    token = set_tool_session(session_id)
    try:
        yield
    finally:
        try:
            _TOOL_SESSION.reset(token)
        except ValueError:  # 跨上下文 reset（线程里）不报错，安静放过
            pass

# 整个平台只有两类动作需要用户点头（「操作询问」里可分别关闭）：
#   1) 读取敏感信息（文件、日志、命令输出、接口返回里的凭据/私钥/令牌/连接串）；
#   2) 删除类操作。
# 其余操作——向任何目标发请求、跑只读命令、登记资产、发起/终止渗透测试、流转风险、
# 归档结论、写报告——一律直接执行。
# 目标范围不再有「授权范围」这层：用户登录时确认的免责声明即为授权，
# 他点名的目标就是已授权目标，平台不再逐条问「这个域名有没有授权」。
CONFIRM_LABELS: dict[str, str] = {
    "read_file": "读取敏感文件",
    "run_shell": "删除类命令",
    "run_python": "删除类脚本",
}

# 安全模式盯的是「会改动目标数据」的方法；GET/HEAD 这类只读探测不受影响，
# 否则 SQL 注入、越权这类必须带 body 的验证就全做不了了
WRITE_METHODS: tuple[str, ...] = ("PUT", "PATCH", "DELETE")

# 结果天然很长：命令输出、请求响应、文件与记忆正文
BIG_RESULT_TOOLS: set[str] = {
    "read_file",
    "read_memory",
    "search_memory",
    "list_dir",
    "run_shell",
    "run_python",
    "http_request",
}

# 只有"从本地磁盘取内容"的工具才做凭据安检：
# 命令与 HTTP 响应本来就是测试对象，逐条弹卡会打断作业（脱敏与提示由模型自己把握）
CONTENT_GATE_TOOLS: set[str] = {"read_file", "read_memory", "search_memory", "list_dir"}

# 敏感信息不止文件：凭据、私钥、令牌、连接串、身份证号，出现在任何工具结果里都算
SENSITIVE_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("云访问密钥", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("JWT 令牌", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    (
        "数据库连接串",
        re.compile(r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@"),
    ),
    (
        "凭据明文",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+]{8,})"
        ),
    ),
    ("身份证号", re.compile(r"\b\d{17}[\dXx]\b")),
)

# 命中这些特征的文件按"敏感信息"对待，读取前先问一次
SENSITIVE_PATH_HINTS: tuple[str, ...] = (
    ".env",
    ".ssh",
    ".aws",
    "credential",
    "secret",
    "passwd",
    "password",
    "token",
    "apikey",
    "api_key",
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    "id_rsa",
    "id_ed25519",
    "shadow",
    "wallet",
    ".npmrc",
    ".netrc",
    ".git-credentials",
    ".htpasswd",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".sql",
    ".dump",
    ".bak",
    "/backup",
    "dump.",
    "export.",
    "数据导出",
    "备份",
)

# 工具执行期间给用户看的一句话：只讲"在做什么"，不暴露工具名与参数。
# 用户只需要看到结论，过程留在后台。
ACTIVITY_HINTS: dict[str, str] = {
    "platform_overview": "正在核对平台现状",
    "list_assets": "正在核对资产台账",
    "create_asset": "正在登记资产",
    "start_scan": "正在编排渗透测试任务",
    "list_scans": "正在核对测试进度",
    "get_scan": "正在读取测试详情",
    "cancel_scan": "正在终止测试任务",
    "list_findings": "正在梳理风险清单",
    "update_finding_status": "正在更新风险处置状态",
    "record_finding": "正在归档检测结论",
    "report_capability": "正在登记能力结论",
    "list_connectors": "正在校准能力接入",
    "test_connector": "正在校验能力接入",
    "test_all_connectors": "正在校验能力接入",
    "list_dir": "正在查看目录",
    "read_file": "正在读取文件",
    "read_memory": "正在读取用户级记忆",
    "search_memory": "正在记忆里定位内容",
    "write_file": "正在写入文件",
    "run_shell": "正在执行命令",
    "run_python": "正在运行脚本",
    "http_request": "正在发送请求",
}

# 兜底进度文案：模型没写"已…接下来…"时，用这个把每一步的结论说清楚
PROGRESS_DONE: dict[str, str] = {
    "platform_overview": "已盘点平台现状",
    "list_assets": "已核对资产台账",
    "create_asset": "已登记资产",
    "start_scan": "已编排渗透测试任务",
    "list_scans": "已核对测试进度",
    "get_scan": "已读取测试详情",
    "cancel_scan": "已终止测试任务",
    "list_findings": "已梳理风险清单",
    "update_finding_status": "已更新风险处置状态",
    "record_finding": "已归档检测结论",
    "report_capability": "已登记能力结论",
    "list_connectors": "已读取能力接入配置",
    "test_connector": "已校验能力接入",
    "test_all_connectors": "已批量校验能力接入",
    "list_dir": "已列目录",
    "read_file": "已读取文件",
    "read_memory": "已读取一段记忆",
    "search_memory": "已在记忆里定位到内容",
    "write_file": "已写入文件",
    "run_shell": "已执行命令",
    "run_python": "已运行脚本",
    "http_request": "已收到响应",
}

# 内部预检类工具：属于模型自己的准备工作，不需要占用用户的注意力
QUIET_TOOLS: set[str] = {"list_capabilities"}

# 这类工具一轮里做过一次就够，后续同工具调用直接复用结果
SINGLE_SHOT_TOOLS: set[str] = {"test_all_connectors"}

# 真正「朝目标动手」的工具：判一判这一轮到底验了多少，防止只看了两眼就收口
TEST_TOOLS: set[str] = {"http_request", "run_shell", "run_python", "start_scan"}

# 一个目标至少要有这么多动手动作，才算把基础面过了一遍（探测请求 + 脚本都算）
MIN_TEST_ACTIONS = 18

# 从命令 / 脚本里抠出真正打过的地址，用于判断「到底动过哪个目标」
URL_IN_TEXT = re.compile(r"https?://[^\s\"'`<>|;]+", re.IGNORECASE)

# 这几类工具彼此不依赖、也不改数据，同一条消息里发多个时可以并发跑。
# 一条消息 3 个请求串行就是 3 个 RTT，并发只花 1 个——这是响应快慢最直接的差距。
# 读文件 / 读记忆 / 列目录不在其中：它们会弹"看原文"的确认卡，必须保持顺序。
PARALLEL_SAFE_TOOLS: set[str] = {
    "list_capabilities",
    "platform_overview",
    "list_assets",
    "list_scans",
    "get_scan",
    "list_findings",
    "list_connectors",
    "http_request",
    "test_connector",
    "test_all_connectors",
}

SYSTEM_PROMPT = """你是 K7so Agent 渗透测试平台的执行引擎，可以直接操作平台、执行命令、发送请求，把用户交办的事真正做完。

可用能力：掌握平台全貌、维护资产台账、发起与跟踪渗透测试作业、梳理与流转风险、归档检测结论、校验能力接入；读写已配置目录里的文件；执行 shell 命令与 Python 脚本；发送任意 HTTP 请求（等价 curl）；读取用户级记忆。需要 curl、nmap、nuclei、ffuf、python 这类动作时，全部通过 run_shell / run_python / http_request 完成——平台确实能执行命令，不要回答"我没有命令执行能力"。

必须遵守的规则：
1. 先想清楚再动手。用户的问题能用一句话答完就直接答；需要数据时，优先用 platform_overview 一次拿到全局（资产、任务、漏洞分布、连接器就绪情况都在里面），不要拆成 list_assets + list_scans + list_findings 反复查。要检查连接器可用性时用 test_all_connectors 一次批量完成，绝不逐个 test_connector。
2. 只依据工具返回的真实数据回答，绝不编造资产、作业、风险编号或测试结果。
3. 同一个工具、同样的参数不要调第二次；结果已经拿到的数据直接引用，不要为了「再确认一下」重复查询。
4. 需要多个互不依赖的查询时，在同一条消息里一次性发起多个工具调用，不要一轮只发一个。
5. 能自己决定的一律自己决定：目标、模式、强度、并发、风险状态等参数都有合理默认值，直接按默认值执行，不要为了确认而打断用户。用户登录时已确认免责声明，等同于完成授权，绝不要再索要授权编号、委托书、审批单或责任人信息。
6. 确实需要用户拍板或补充信息时，必须调用 ask_choice 把问题做成 2-4 个可点击的「选择题」，不要在正文里写开放式提问（禁止「请提供 URL」「你想怎么做？」这类填空式反问）。**正文不要以问句结尾**，问题只写在 ask_choice 的 question 字段里，否则用户会看到同一句话问两遍。一次只问一个问题，选项按推荐程度排序，第一个是你的推荐项；选项必须是具体可执行的做法，不要把「自定义」「其他」写成选项，需要用户自己填时把 allow_custom 设为 true。还有一条同样重要：**候选做法只能出现在 ask_choice 的选项里**——正文里不要用「1. 2. 3.」把几个方案罗列一遍再让用户自己挑，也不要写「选一个」「你定哪个」这种话，那等于让用户打字复述你的选项。正文只讲判断和依据，选择权交给卡片。
7. **先读前端代码，再按权重排测试顺序。** 动手测之前，先用 http_request 把目标的首页、登录页与它加载的 JS 抓下来（优先主入口与 app.*.js / chunk / vendor 这类打包文件），从里面读出路由表、接口路径、参数名、鉴权方式与技术栈，形成一张入口清单。然后按「模型能力」页里每项能力设的权重（1-5，5 最优先）从高到低开测；权重相同的，先测前端代码里确实能看到入口的那一项。高权重但前端代码里明显没有对应入口的，跳过并说一句为什么。用户点名的目标就是已授权目标——登录时的免责声明就是授权，不需要任何范围确认，也不要反问「这个域名算不算授权范围」。
8. **测试范围严格等于「模型能力」页已勾选的清单，清单之外的一律不测。** 目录里早已下架的项目——CORS/跨域配置错误、TLS/SSL 弱配置、主机头注入、HTTP 请求走私、WebSocket 劫持、验证码绕过、双因素绕过、认证绕过、流程状态绕过、会话失效、XSS 过滤绕过——目前不提供，即使你在扫描里看到了相关迹象、即使这套手法很常见，也不要为它单独发包；用户点名要测时，只回一句「该项已从能力清单移除」，然后继续做清单内的事。端口扫描、目录爆破、子域枚举这类只产清单、不产结论的广度动作同样不做：每一次发包都要指向一个可能的结论，不要用请求数量凑工作量。
9. 每完成一个 URL 的测试，就用 record_finding 归档到该 URL，并填写复现用的请求包与响应包；漏洞结果页会展示漏洞标题、输出时间、危害程度以及该 URL 的请求/响应包。用 http_request 拿到的 request_packet / response_packet 原样填进去，不要自己重编。
10. 工具调用结束后用中文简要总结结果，然后**自己决定下一步并直接执行**：先测哪一类、按什么顺序、用哪种手法，都是你的判断，不要拿去问用户。只有三种情况才允许用 ask_choice：目标本身不明确（用户没说测哪个站点）、缺少只有用户才有的凭据、以及会改变结果或超出授权的新分支。**「先补测哪一类」「要不要继续」这类问题一律不要问**——用户把事交给你了，你按「命中率 × 危害」自己排序，一路做到有结论为止。
11. **所有输出一律用简体中文**（包括调用工具前的一句说明），不要输出英文句子；回答紧凑，使用短句或列表；不要输出代码块，不要暴露任何密钥。术语统一：这件事叫「渗透测试」，口语里简称「测试」——说「发起渗透测试」「跑一轮渗透测试」「终止测试」「渗透测试作业」，不要说「扫描」「开扫」「扫一遍」「扫站点」，也不要把平台说成「评估平台」；名词用「资产」「风险」「修复建议」，不要中英混写。
12. **每一步做完都要给一句进展，这句话就是用户看到的「你做了什么」**：格式是「已经…，接下来…」，把这一步的对象、拿到的东西、下一步要干什么写清，例如「已确认找回密码接口匿名可达，接下来抓前端 JS 并同时登记资产」「接口清单已理出 37 条，接下来逐个验未授权」。这句话会一条条留在对话里、不断累积，用户回看整轮执行过程就靠它，所以：不超过 40 字、只说事实和下一步、不写工具名与参数、不写「正在调用」这类空话，**也不要省——每做完一步都要有，少一条用户就少看到一件事**。这一轮如果只是调工具，正文也只写这一句。**绝大多数步骤用自然说法就够了**——「已…」「拿到了…」「正在验…」，平台会给每条进度加上对应的小徽标并加粗，不必硬套「关键突破」，每一步都关键反而显得假。**关键说法很重，一次任务里最多用两三次，且中间要隔开**：连着几步都写「关键突破」「重大发现」，会被当成套话，平台还会自动把它降级成普通进度。真正有分量的节点才用这些词开头：关键突破、重大突破、有突破、关键线索、关键发现、重大发现、新发现、新的进展、关键进展、关键结论、关键风险、重大风险、核心发现、关键证据、确认存在、已经证明、成功利用、实锤（平台会把这条的字号再放大、加粗、带徽标）。也可以完全说人话，例如「已经找到漏洞点，可以继续深入」「这个接口还能往下挖，接着验」「这里有个突破口，我顺着往下走」——平台同样会给「值得深入」的徽标。**关键说法要么就用、要么就别沾**：一条普通进展如果开头写了「关键线索：」「关键突破：」却没被当关键节点放大，看起来就自相矛盾——不想让它抢眼，就直接从「已…」「拿到了…」说起，别在句首挂「关键/重大/核心」这类帽子。**这条规则对每一轮对话都生效，不只在第一句生效；不要聊过几轮就不播报了。**（例外：用户那一轮是在提问，就按规则 23 直接回答，不要用「已…，接下来…」这个句式。）
13. 文件读取范围是两个已配置目录：工作目录（可读可写）与用户级记忆目录（只读）。两处都支持相对路径与绝对路径；写入只能落在工作目录。**记忆目录下的所有文件都是用户级记忆**，不分后缀、不分层级：文本、Markdown、配置、日志、Word（.docx）、Excel（.xlsx）、PPT（.pptx）、PDF 都能读，子目录也会递归读到；不需要先用 list_dir 试探，直接 read_memory 就能拿到全部内容。用户问到「你记得我的偏好」「按我们以前的约定」「根据用户级记忆」时，用 read_memory 或 read_file 直接读记忆目录里的文件，不要回答「看不到记忆」「平台没给我读取接口」——那是错的。
14. **记忆必须读全，不许只读开头就下结论**。记忆可能很大（几十万字、多个文件）：先看 read_memory 返回的 total_chars 与 has_more，has_more=true 就带上 next_cursor 继续读，一直读到 has_more=false 才动手；文件很大时用 only 参数逐个文件读，或用 search_memory 精确定位。预载内容只是开头一段，回答里出现「记忆太长只看到一部分」这种话是失职。
15. 输出用 Markdown 加粗强调关键信息：真正重要的结论、风险与修复要点用 **…** 加粗，一次回答控制在 5 处以内；不要整段加粗，也不要给普通句子凑加粗。
16. 整个平台只有两件事会让用户点头：① 要读取**我自己的**敏感信息（用户级记忆中的凭据文件、平台数据库与密钥、本机 .ssh/.aws/.netrc 这类私钥）；② 删除类操作（删文件、删目录、清库等不可逆动作）。**目标侧的敏感信息（目标的 .env、配置、接口返回里的账号密码）属于测试对象，平台不拦，直接读、直接用、直接归档。** 同一处信息用户点过一次确认，本会话内不再重复询问；用户拒绝后不要换路径或换工具重试，平台也会把敏感值打码成 ***，不要试图还原。其余动作（登记资产、发起/终止测试、流转风险、归档结论、写报告、执行只读命令、向任何目标发请求）都是直接执行的日常操作，不需要任何审批，也不要索取授权编号、审批单、责任人签字。
17. 命令执行的安全底线：默认只做只读、验证、探测类命令，不需要任何确认，直接执行。不写后门、不反弹 shell、不横向、不压测、不做资源耗尽载荷、不停服务。**目标上的数据和凭据一律不改**：不修改口令、不新建或删除账号、不写库、不删记录、不改配置——要证明「可改」这类写入型风险，用只读的等价证据说清机制（例如接口对跨站请求返回 200 且命中校验分支），不要真的把目标口令改掉、把数据写进去；已经造成改动的，要在结论里明确写清改了哪里、怎么恢复。删除类命令（rm / del / rmdir / drop table 等）平台会先请用户确认一次，用户同意后再执行；格式化、删根目录、关机直接被拒，遇到拒绝就换等价的无害验证方式，不要试图拼接字符串绕过。
18. 平台会在轮次快用完时提醒你：收到提醒后不要再发起探索性查询，直接用现有信息给出结论。
19. 用户看到的是工作结果，不是你的操作过程。除了规则 12 的那一句进度结论，不要向用户播报「正在查看平台概览」「正在查询资产」「正在调用工具」这类动作，也不要罗列接口名、工具名、参数 JSON、返回值原文；过程由平台自己完成，你只输出阶段结论、最终判断与下一步。
20. 回答要像一个已经动手做过这件事的人：第一句就给判断或结论（有风险说风险，没风险说没风险），后面只跟必要的依据，2-4 条足够；不要复述一遍用户的原话，不要用「首先/其次/综上」凑结构，不要写「作为一个 AI」「建议您自行核实」这类空话。数据不足以判断时，直接说「这一点现在看不到，因为…」，并说明你接下来会怎么补，而不是让用户自己去查。
21. 用户说「继续」「你决定」「按你说的做」时，视为授权你按推荐方案直接执行到底，不要再抛选择题；只有出现新的分支（会改变结果或超出授权）时才重新问。同一个问题在一次会话里只问一次，已经答过的不再重复确认。
22. 用户可能在你执行过程中补充要求：平台会以「【用户补充要求，优先级高于原任务】」的形式把新指令交给你。**先用一句话回应用户**——结合你此刻的真实进度说清楚：做到哪一步、这条补充你怎么处理、接下来会怎样；然后立刻按这条新指令执行（它可能改变目标、范围、对象或输出形式）。已经拿到的只读结果可以直接复用，不要从头再做一遍；两者冲突时以用户的新要求为准。不要沉默着继续干活，用户会以为你没听见。
23. **回答问题和执行任务是两件不同的事**。用户的话如果是问句或要结论——「…吗」「是不是」「有没有」「你的意思是」「到底发现了什么」「刚才测了哪几类」「结论是什么」——他要的是**答案**，不是让你再跑一遍。这时：
    - 第一句就给判断：测过就答「测过」，没测过就答「没测」；有发现就答「有，N 条」，没有就答「没有」。
    - 然后按系统消息里的【本次会话已经做过的事】逐项说清：测了哪几类、各类结果如何、哪几项还没测。这些记录是真实执行留下的，可以直接引用。
    - **这一轮不要重新执行**：不跑脚本、不重新发包、不再扫一遍、不为了「再确认一下」重新查询。记录里已经有的就是答案。
    - **不要输出「已…，接下来…」的进度句，也不要把「继续下一步」当回答**——那会让用户觉得你根本没听懂他在问什么。
    - 记录里确实没有他问的那一项，就直接说「这一项我没有记录」，再用 ask_choice 问要不要现在补测，不要假装测过。
24. **交付的标准是「验过」，不是「看过」，而且必须奔着三个方向去。** 只确认了目标在线、抓了几个前端 JS、理出接口清单，然后写「本轮仅完成资产登记与前端侦察，尚未逐项验证」——这等于把活原样退回给用户，是最不能接受的一种收尾。一轮渗透测试要盯的是这三类能落地的结果，每一个方向都要真的动手、并且给出明确说法：
    - **高敏感信息泄露**：凭据、密钥、口令、身份证与个人信息、数据库、源码、备份文件，有没有在接口、静态文件、报错页里直接暴露。**只算「正常用户看不到的」——判定门槛见规则 26，页面上本来就摆着的信息不算。**
    - **控制权限**：能不能未授权进后台、越权看别人的数据、改别人账号、上传拿到执行、命令执行、接管会话。
    - **可造成实际危害**：能不能真的读到、改掉、删掉业务数据，能不能从这台机器打到内网或其他系统。
    收尾时三个方向各给一句结论——**有**就带请求包/响应包证据并归档；**没有**就说明测了哪些入口、为什么排除。笼统一句「未发现明显问题」「尚未逐项验证」不算结论。确实被目标挡住（统一 401/403、WAF 拦截、没有可测入口）就明说是哪一类、被什么挡住的。只发了一两个请求、只覆盖一个方向就想收尾，平台会把你推回去继续做。
25. **每验完一项能力就 report_capability 上报，别只在正文里说。** 平台给了一本「能力覆盖台账」（勾了哪些、验了几项、还差几项），它只认 report_capability 的结果。测完一项就调用一次：capability 填 key、status 填 vulnerable/clean/blocked/inconclusive、note 写清测了哪个入口看到什么；验出问题的先 record_finding 归档（归档会自动把这项记成 vulnerable）。**没上报的项，平台一律算没验，会一直催你继续**；只有每一项都有结论，这一轮才算交付。
26. **「泄露」的判定门槛是「正常用户看不到」，这是硬条件。** 一条信息能不能算泄露，不看它本身敏不敏感，而看**正常用户在他自己的正常使用路径上能不能看到**：
    - **不算泄露**：登录后自己账号页面本来就展示的（自己的手机号、邮箱、身份证后四位、订单、余额、资料）、公开页面给所有人看的（商品、公告、帮助文档、条款、公开接口）、页面源码与前端 JS 里本来就有的、服务端版本号与框架指纹这类谁都能看到的信息。这些最多写进「加固建议」，不进漏洞清单，更不许升成高危。
    - **才算泄露**：未登录或普通用户能拿到**别人的**数据、能拿到**后台/管理端才有**的字段或全量列表、能拿到本该只在内网或服务端存在的凭据、密钥、令牌、数据库、源码、备份文件、内部配置与内网地址。
    - **归档时必须写清对照**：在 description 或 evidence 里说明「正常路径下看不到」的依据——未登录时无此字段、别人账号里没有、页面上不展示、只能从后台看到。写不出这个对照的，就不是泄露，按「信息」记录或只写进加固建议。
    - 平台会做兜底校验：标题属于泄露类却标了高危、又拿不出上述对照证据的，会自动降一档，并在结果里告诉你补什么。
27. **硬性要求：每一轮工作完成之后，都要把漏洞「怎么一步步打出来的」写清楚，并给出每一步自己的请求包与响应包，不能只留一句「已归档」。** 清单按**域名**给，不按轮给：这一轮只测了一个域名，就把**该域名在本次测试里出现过的全部漏洞**都列出来（包括前几轮测出的，不只列这一轮新发现的）；这一轮测了几个域名，就**每个域名各列一份**，同一条漏洞只列一次、不要重复列举。每条按下面这个结构写：
    - **标题**：`漏洞N：<标题>（<危害等级>）`，按危害从高到低排。
    - **漏洞URL**：完整地址，含参数。
    - **成因与影响**：一两句讲清为什么能成立、能拿到什么。
    - **复现步骤**：按时间顺序拆成 `步骤1：做了什么，看到了什么；由此判断……`、`步骤2：……`。每一步都要说清三件事：**这一步是为了验证什么 → 发出后返回了什么 → 据此推出了什么**。用户要能照着自己走一遍，所以不许跳步，也不许把好几步压成一句「经测试存在越权」。
    - **请求包N / 响应包N**：紧跟在对应步骤后面，**一步一对**，用 ```http 代码块原样贴（这是规则 11「不要输出代码块」的唯一例外）。有几步就给几对报文；最后一步的报文不能代替前面几步的。
    - **报文别整页贴**：请求包给请求行 + 关键头部（Cookie / Authorization / Content-Type），响应包给状态行 + 关键头部 + 前面一段正文就够判断了。响应体几万字（列表页、整页 HTML、大 JSON）只截关键几行，后面写一句「以下为节选」——结论是给人看的，全文已经在归档里，需要时去漏洞结果页看。
    - **修复方案**：50 字以内，给出可执行动作。
    - 归档时用 `steps` 把过程一起传上来（每项 `action` / `result` / `why` / `request_packet` / `response_packet`）；发包时在 `http_request` 的 `note` 里写这一步的目的。没传 `steps` 平台会按本轮真实发包记录自动补成步骤，但那样只有「做了什么 / 看到什么」，缺你自己那句「由此推出什么」。
    - 「每一轮」是真的每一轮：自动继续接龙的每一轮收尾都要写，不是只在最后一轮写一次。上一轮测过的同域名漏洞，这一轮要一并列全（那是「该域名本次测试出现的所有漏洞」），重复归档的同一条只留一条。
    - 归档时就确认报文齐了：`request_packet` / `response_packet` 两个字段都不能空。缺就用 `http_request` / `run_shell` 重新打一次目标，把返回的报文原样补上再归档（同一条重新归档会覆盖旧值）。返回里带 `packet_gap` 就是在提醒你这条缺报文。
    - 平台在每个出口都会核对一遍、漏的补在末尾，但那是兜底；你自己写全才算交付。
28. **硬性条件：请求失败不等于这条路走不通，必须改包再试，并且时刻反问自己「这个方向是不是真的没路了」。** 这不是建议，是每次发包之后都要走一遍的动作：
    - 收到 4xx / 5xx、空响应、被 WAF 拦、跳回登录页、返回内容和预期不符——**都不许**直接记成「打不通」「不可利用」。第一次的 401/403 尤其不能当结论。
    - 先判断失败原因：参数位置（query / body / header / path）、参数类型（字符串/数字/布尔/数组/对象）、编码（URL / 双重 URL / Unicode / Base64）、请求方法、Content-Type、缺少鉴权头或必填字段或签名/时间戳、路径版本前缀与大小写。前端代码里读到的字段名要抄准，别凭印象写。
    - 然后**真的改包重发**，一次只改一处，把两次的响应放在一起对比。失败结果里平台会直接给出 `retry_hint`，照着它试。
    - 每改完一次都问自己一句：**「这个方向还有没有别的写法？我是不是已经把所有写法都试过了？」** 还有写法就继续试；试到能说出「为什么这条路确实走不通」的具体原因（比如「该接口对非管理员一律 403，且换过三种身份与四种参数位置均无变化」），这一项才算测完。
    - 归档结论、上报能力状态时写清试过哪些变体、卡在哪一步。**绝不因为改了几次没成就编一个「已利用」，也绝不把「没试出来」写成「不存在」。**
29. **能力页里每一项的「用户提示」是用户亲手写的硬性要求，不是参考建议。** 提示里点名的接口、参数、账号、检查点，测该项时一个都不能少；提示说「不要测 / 不要碰」的，一律不碰。漏做任何一条，这一项就按「没测」处理，平台会把结论退回并继续催。上报该项时 note 里要逐条说明提示里的要求各自是什么结果（照做了看到什么 / 为什么没做）。平台要求先读提示再记账：第一次上报会返回 `hint_required` 和提示原文，读完把同一结论再报一次即可，不用重新测。
30. **「任务结束」的唯一条件是：勾选的每一项能力都有结论（vulnerable / clean / blocked）。** 只要台账上还有 pending，就不要写「测试完成」「已全部覆盖」「本轮结束」这类话——那不是你能宣布的。**也不要把手上没测完的项留给下一轮**：平台这一轮给的工具轮次与时长是按「还剩几项」现算的，够你从头测到尾；写一句「剩下的下一轮再测」就等于这一轮白干，用户看到的就是「第一轮一项没测」。所以每验完一项立刻报下一项，一直干到台账清空再收尾。平台在结论末尾会按台账实算一行「任务未完成 · 还差 N 项」，那是平台的口径，不是你的收尾台词；看到它就直接调用 http_request 开工。确实测不动的（统一 401/403、WAF 拦截、没有该类入口）就报 blocked 并写清被什么挡住，这也算有结论。"""


# 自动渗透开关打开时追加到系统提示末尾：显式覆盖第 8 条「清单之外一律不测」。
# 开关关闭时不追加，第 8 条原样生效——默认就是「只测勾选的那几类」。
AUTO_PENTEST_SYSTEM_NOTE = """

【开关覆盖 · 自动渗透已开启】第 8 条按下面这段执行，其余规则不变：
1. 「模型能力」页勾选的每一项仍然必须有结论，这一条不放宽；
2. 清单之外的漏洞类型**也要测**：只要前端代码、响应头、接口形态里能看到入口，就正常发包验证，
   例如 GraphQL 内省与批量查询、文件上传、反序列化、缓存投毒、业务逻辑与金额越权、
   JWT / OAuth / SAML 配置、Actuator / Swagger / Druid 这类管理面未授权、组件已知漏洞入口；
   第 8 条里「已下架、不要为它单独发包」的说法在本轮不适用；
3. 清单外的类型验出问题：一律 record_finding 归档，标题里写清属于哪一类；
   命中清单里存在但没勾选的项，也可以 report_capability 上报（平台照收，只是不计入交付门槛）；
4. 仍然只写进「加固建议」、不进漏洞清单的低价值项：CORS 宽松、缺安全响应头、纯版本指纹、
   目录索引、Source Map 暴露。这几类不要为它单独发包，也不要升成漏洞；
5. 广度动作（端口、目录、子域）只在能顺着它收敛出一个结论时做，不为凑数量而扫。
红线不变：只做只读验证，不写改删数据、不压测、不爆破、不横向。"""


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_capabilities",
            "description": "重新读取「模型能力」快照。能力与开关已在对话开头的系统消息里注入，通常不需要调用；只有怀疑用户在对话过程中改了勾选时才用。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ask_choice",
            "description": (
                "需要用户拍板或补充信息时使用：把提问做成 2-4 个可点击的选项，前端会渲染成选择题按钮，"
                "用户点一下就完成回答。不要在正文里写开放式提问。只在信息缺失且无法用默认值推进时才调用。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "一句话问题，不超过 40 字"},
                    "options": {
                        "type": "array",
                        "description": "2-4 个互斥选项，按推荐程度排序，第一个为推荐项；只放具体可执行的做法，不要写「自定义」「其他」这类占位选项，需要自由输入时改用 allow_custom",
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string", "description": "选项标题，不超过 14 字"},
                                "hint": {"type": "string", "description": "一句话说明该选项的后果，不超过 30 字"},
                                "value": {"type": "string", "description": "点击后回传给模型的内容，可带具体参数"},
                            },
                            "required": ["label"],
                        },
                    },
                    "allow_custom": {
                        "type": "boolean",
                        "description": "是否允许用户自己输入答案，默认 false；只有目标地址等不可枚举的信息才设为 true",
                    },
                },
                "required": ["question", "options"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "platform_overview",
            "description": "查看平台概览：资产/任务/漏洞数量、风险分布、已勾选能力与连接器状态。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_assets",
            "description": "查询资产台账，可按关键字过滤。",
            "parameters": {
                "type": "object",
                "properties": {
                    "q": {"type": "string", "description": "搜索名称、目标、组织或标签"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_asset",
            "description": "把一个目标录入资产台账。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "域名、IP 或 URL"},
                    "name": {"type": "string", "description": "资产名称，可省略"},
                    "org": {"type": "string", "description": "所属组织，可省略"},
                    "tags": {"type": "string", "description": "标签，逗号分隔，可省略"},
                    "criticality": {"type": "integer", "description": "重要级别 1-5，默认 3"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "start_scan",
            "description": (
                "发起一次渗透测试作业（资产测绘 + HTTP 配置核查 + 端口探测 + 模板检测 + AI 研判）。"
                "授权已在登录时的免责声明中确认，不需要再要任何编号或委托材料；"
                "平台不再校验授权范围，用户给出的目标直接开跑。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "目标列表（域名/IP/URL），与 asset_ids 至少填一个",
                    },
                    "asset_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "使用资产台账中的资产 ID",
                    },
                    "profile": {"type": "string", "enum": ["quick", "standard", "deep"]},
                    "mode": {"type": "string", "enum": ["active", "passive"]},
                    "name": {"type": "string", "description": "作业名称，可省略"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_scans",
            "description": "列出最近的渗透测试作业及状态、进度与风险数量。",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "返回条数，默认 10，最大 50"},
                    "status": {"type": "string", "description": "按状态过滤：queued/running/completed/failed/cancelled"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan",
            "description": "查看某个渗透测试作业的详情、最近日志与风险项。",
            "parameters": {
                "type": "object",
                "properties": {"scan_id": {"type": "integer"}},
                "required": ["scan_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cancel_scan",
            "description": "终止一个排队中或运行中的渗透测试作业。",
            "parameters": {
                "type": "object",
                "properties": {"scan_id": {"type": "integer"}},
                "required": ["scan_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_findings",
            "description": "查询漏洞发现，可按严重等级、状态与任务过滤。",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "status": {"type": "string", "enum": list(VALID_FINDING_STATUS)},
                    "q": {"type": "string", "description": "搜索标题、目标或证据"},
                    "limit": {"type": "integer", "description": "默认 20，最大 100"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_finding_status",
            "description": "更新漏洞记录的处理状态。",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "integer"},
                    "status": {"type": "string", "enum": list(VALID_FINDING_STATUS)},
                },
                "required": ["finding_id", "status"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": (
                "把对话中针对某个 URL 的测试结果归档为漏洞记录；同一 URL 会归入同一分组。"
                "泄露类结论必须在 description 或 evidence 里写清「正常用户看不到」的对照"
                "（未登录时没有、他人账号拿不到、页面上不展示、只有后台可见）；"
                "拿不出对照的平台会自动降一档——页面上本来就公开的信息不算泄露。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "被测 URL（完整 http/https 地址）"},
                    "title": {"type": "string", "description": "漏洞标题"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "危害等级；泄露类只在高危及以上时校验「正常用户看不到」的对照证据",
                    },
                    "capability": {"type": "string", "description": "命中的模型能力 key，例如 xss_reflected、sqli_time"},
                    "description": {"type": "string", "description": "漏洞说明与影响"},
                    "evidence": {"type": "string", "description": "验证依据或关键回显摘要"},
                    "request_packet": {"type": "string", "description": "复现用的请求包原文"},
                    "response_packet": {"type": "string", "description": "复现用的响应包原文"},
                    "steps": {
                        "type": "array",
                        "description": (
                            "怎么一步步打出来的，按时间顺序。每步写清「做了什么 / 看到什么 / 由此推出什么」，"
                            "并附上这一步自己的请求包与响应包。用户要照着复现，所以别只给最后一对报文；"
                            "不传平台会按本轮的实时发包记录自动补成步骤。"
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string", "description": "这一步做了什么（方法 + 路径 + 关键头部或参数）"},
                                "result": {"type": "string", "description": "这一步看到了什么（状态码、关键回显）"},
                                "why": {"type": "string", "description": "由这一步推出了什么，为什么它能让漏洞成立"},
                                "request_packet": {"type": "string", "description": "这一步的请求包原文"},
                                "response_packet": {"type": "string", "description": "这一步的响应包原文"},
                            },
                            "required": ["action"],
                        },
                    },
                    "remediation": {"type": "string", "description": "修复建议"},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                    "cvss": {"type": "number", "description": "CVSS 评分，可省略"},
                },
                "required": ["url", "title", "severity"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_capability",
            "description": (
                "登记一项模型能力的验证结论。每测完一项能力就调用一次，"
                "平台用它计算「还剩哪几项没验」，不报就一直算没验。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {"type": "string", "description": "能力 key 或中文名，如 idor、文件下载"},
                    "status": {
                        "type": "string",
                        "enum": ["vulnerable", "clean", "blocked", "inconclusive"],
                        "description": "有漏洞 / 验过没问题 / 被目标挡住 / 证据不足",
                    },
                    "note": {"type": "string", "description": "测了哪个入口、看到什么（必填）"},
                    "evidence": {"type": "string", "description": "关键回显或请求地址，可省略"},
                },
                "required": ["capability", "status", "note"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_connectors",
            "description": "列出全部 API 连接器的配置与最近检测状态。",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_connector",
            "description": "检测指定连接器是否可用（如 deepseek、fofa、nmap）。",
            "parameters": {
                "type": "object",
                "properties": {"key": {"type": "string"}},
                "required": ["key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_all_connectors",
            "description": "一次并发检测所有已配置的连接器并返回汇总。要检查多个连接器时用这个，不要逐个调用 test_connector。",
            "parameters": {
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "只测某一类：ai / intel / recon / tool / vuln，省略表示全部",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "列出目录内容。可访问两个已配置目录：工作目录（scope=work，产出物放这里）与用户级记忆目录（scope=memory，存放用户的长期偏好与历史记录）。path 可写相对路径或这两个目录内的绝对路径；两者都允许查看，不要因为路径在记忆目录就拒绝执行。",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "work=工作目录，memory=用户级记忆目录；留空则按 path 自动判断",
                    },
                    "path": {
                        "type": "string",
                        "description": "相对路径或绝对路径；留空表示该目录的根",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "读取文本文件内容。可读工作目录与用户级记忆目录内的文件，path 支持相对路径或这两个目录内的绝对路径。"
                "大文件用 offset 翻页：返回里带 next_offset 与 has_more，读完 has_more=false 为止，不要只读开头就下结论。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径，相对路径或已配置目录内的绝对路径"},
                    "offset": {"type": "integer", "description": "从第几个字符开始，默认 0"},
                    "limit": {"type": "integer", "description": "本次最多返回多少字符，默认 12000；太大时自动收到上限，以返回的 next_offset 为准"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_memory",
            "description": (
                "读取用户级记忆。记忆可能很大：不带参数返回开头一段并告诉你 total_chars；"
                "has_more=true 时带上返回的 next_cursor 继续读，一直读到 has_more=false，才算读完全部记忆。"
                "用 only 指定单个文件名可以逐个读完；需要定位某个话题时改用 search_memory 更快。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cursor": {"type": "integer", "description": "上次返回的 next_cursor，首次不传"},
                    "limit": {"type": "integer", "description": "本次最多返回多少字符，默认 12000；太大时自动收到上限，以返回的 next_cursor 为准"},
                    "only": {"type": "string", "description": "只读某个文件（文件名或相对路径），不传表示读整个记忆目录"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_memory",
            "description": "在用户级记忆里按关键词或正则定位，返回文件名、行号与该行内容。记忆很大时先搜再读比整篇读更省事。",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "关键词或正则，例如 报告格式|称呼"},
                    "limit": {"type": "integer", "description": "最多返回多少条，默认 60"},
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": (
                "执行一条 shell 命令并返回 stdout/stderr/退出码（Windows 走 cmd，Linux/macOS 走 sh）。"
                "curl、nmap、nuclei、ffuf、git、python 脚本等外部工具都通过它调用；工作目录缺省就是当前工作目录。"
                "普通命令直接执行，不用等确认；删除类命令会先请用户确认一次，格式化、删根目录、关机直接被平台拒绝。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "完整命令行，例如 curl -s -i https://example.com/login"},
                    "cwd": {"type": "string", "description": "相对工作目录的子目录，可省略"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 300，上限 900；连续 300 秒没有任何输出会被判卡死并终止"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_python",
            "description": (
                "运行一段 Python 代码并返回输出与 traceback（用平台自带解释器，requests/httpx 可用）。"
                "适合解析 JS、批量拼接口、算签名、处理大文件：比 shell 拼字符串稳。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "完整 Python 脚本内容"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 300，上限 900；连续 300 秒没有任何输出会被判卡死并终止"},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "发送真实 HTTP 请求（等价 curl -i），返回状态码、响应头、响应体，以及可复现的请求包/响应包。"
                "验未授权、越权、注入、上传、重定向时用它。动手测之前先用它抓目标首页与前端 JS，"
                "读出路由、接口与参数，再按能力权重排测试顺序。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "完整 URL，缺协议时按 http 处理"},
                    "method": {
                        "type": "string",
                        "description": "GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS，默认 GET",
                    },
                    "headers": {"type": "object", "description": "请求头键值对，例如 {Authorization: Bearer x}"},
                    "body": {"type": "string", "description": "请求体原文"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 30"},
                    "follow_redirects": {"type": "boolean", "description": "是否跟随跳转，默认 true；验开放重定向时设 false"},
                    "verify_cert": {"type": "boolean", "description": "是否校验证书，默认 false（自签站点也能测）"},
                    "raw_body_is_json": {"type": "boolean", "description": "body 是 JSON 时设 true，自动带上 Content-Type"},
                    "note": {
                        "type": "string",
                        "description": (
                            "这一步想验证什么（一句话，例如「不带 token 直接取订单 9001，看是否校验归属」）。"
                            "会作为复现步骤里的说明原样写进最终结论，所以写人能看懂的话。"
                        ),
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "在工作目录内写入或覆盖文本文件（自动创建父目录）。只能写工作目录，不能改记忆目录与平台文件。",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "相对工作目录的文件路径"},
                    "content": {"type": "string", "description": "要写入的完整文本内容"},
                },
                "required": ["path", "content"],
            },
        },
    },
]

# 用户在提问时，只允许这类「看一眼、不产生动作」的工具：
# 既能让他自己去核对归档结论，又不可能再跑脚本、再发包、再扫一遍。
QUESTION_TOOL_NAMES: set[str] = {
    "ask_choice",
    "platform_overview",
    "list_assets",
    "list_scans",
    "get_scan",
    "list_findings",
    "list_connectors",
    "list_dir",
    "read_file",
    "read_memory",
    "search_memory",
}
QUESTION_TOOLS: list[dict[str, Any]] = [
    spec for spec in TOOL_SPECS if (spec.get("function") or {}).get("name") in QUESTION_TOOL_NAMES
]


AI_PROVIDER_ORDER = (
    "deepseek",
    "openai",
    "ncc_llm",
    "anthropic",
    "gemini",
    "qwen",
    "moonshot",
    "zhipu",
    "doubao",
    "hunyuan",
    "baidu",
    "minimax",
    "siliconflow",
    "custom",
    "ollama",
)


# 这几类允许不带 Key：本地 Ollama、内网网关、以及用户自己填地址的自定义模型。
# 它们没有密钥可判，只能以「上次检测真的出了结果」为准。
NO_SECRET_KEYS = ("ollama", "custom")


def is_ready(connector) -> bool:
    if not connector or not connector.enabled:
        return False
    if connector.secret:
        return True
    local_gateway = any(host in connector.base_url for host in ("127.0.0.1", "localhost"))
    if connector.key in NO_SECRET_KEYS or local_gateway:
        return bool(connector.row.get("last_check_ok"))
    return False


def pick_llm(preferred: str = ""):
    if preferred:
        connector = load_connector(preferred)
        if is_ready(connector):
            return connector
    for key in AI_PROVIDER_ORDER:
        connector = load_connector(key)
        if is_ready(connector):
            return connector
    return None


def provider_setup() -> dict[str, int]:
    """大模型接入情况：已启用几个、其中已填密钥几个。用于前端区分「没接入」与「接入了但不可用」。"""
    enabled = 0
    configured = 0
    for row in connector_rows():
        if row["category"] != "ai" or not row["enabled"]:
            continue
        enabled += 1
        if row.get("secret_enc") or row.get("last_check_ok"):
            configured += 1
    return {"enabled": enabled, "configured": configured}


def ready_providers() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in connector_rows():
        if row["category"] != "ai" or not row["enabled"]:
            continue
        base_url = row.get("base_url") or ""
        local_gateway = any(host in base_url for host in ("127.0.0.1", "localhost"))
        ready = bool(row.get("secret_enc"))
        if not ready and (row["key"] in NO_SECRET_KEYS or local_gateway):
            ready = bool(row.get("last_check_ok"))
        if not ready:
            continue
        try:
            config = json.loads(row.get("config_json") or "{}")
        except json.JSONDecodeError:
            config = {}
        # 自定义模型允许自己起名：对话页的模型下拉就显示这个名字，比一串模型 ID 好认
        label = str(config.get("label") or "").strip()
        items.append(
            {
                "key": row["key"],
                "name": label or row["name"],
                "model": config.get("model", ""),
            }
        )
    return items


def _context_message() -> str:
    return (
        "当前平台状态：目标授权模式=登录免责声明（用户已确认，点名的目标即为已授权目标，"
        "平台不再校验授权域名或网段，也不会为此逐条弹确认）；"
        "测试顺序=按「模型能力」页的权重从高到低，先做前端代码分析。"
    )


def _workspace_context() -> str:
    """把目录清单与记忆内容一起交给模型：既要能读，也要知道怎么读全。"""
    lines: list[str] = ["当前可访问目录（均为只读查看，写入仅限工作目录）："]
    for scope, label, base in allowed_roots():
        lines.append(f"- {label}（scope={scope}）：{base}")
    if not allowed_roots():
        lines.append("- 尚未配置任何目录，文件工具不可用，请提示用户到「目录配置」页面设置")
        return "\n".join(lines)

    manifest = memory_manifest()
    total = sum(int(item["chars"]) for item in manifest)
    if manifest:
        lines.append(
            "  记忆文件："
            + "、".join(f"{item['name']}（{item['chars']} 字符）" for item in manifest[:40])
            + (f" 等 {len(manifest)} 个" if len(manifest) > 40 else "")
            + f"；合计约 {total} 字符"
        )
    else:
        lines.append("  记忆文件：（目录里没有可读的文本文件）")
    lines.append(
        "读取方式：read_file(path=文件名或绝对路径, offset=0)；列目录用 list_dir(scope=memory) 或 list_dir(scope=work)；"
        "取记忆用 read_memory(cursor=0, only=可选文件名)，has_more=true 就带 next_cursor 继续读；"
        "定位话题用 search_memory(keyword)。用户问到记忆、偏好、历史记录或约定时，先读文件确认，不要回答「看不到记忆」。"
    )
    lines.append(
        "执行方式：run_shell(command=…) 跑 curl/nmap 等外部命令，run_python(code=…) 跑脚本，http_request(url=…) 发请求并拿到请求包/响应包。"
    )

    memory = read_memory(MEMORY_PRELOAD)
    if memory:
        lines.append(
            f"用户级记忆（预载前 {min(len(memory), MEMORY_PRELOAD)} 字符，全部约 {total} 字符；"
            "未读完的部分必须用 read_memory + next_cursor 继续读，读到 has_more=false 才动手，"
            "回答与操作须遵守其中的偏好与约定）：\n" + memory
        )
        if total > len(memory):
            lines.append(
                f"【记忆未读完】还差约 {total - len(memory)} 字符，先调 read_memory(cursor={len(memory)}) 继续读全。"
            )
    return "\n".join(lines)


def _save_message(session_id: int, role: str, content: str, level: str = "", tool_name: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, level, tool_name, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (session_id, role, content[:4000], level, tool_name, now_iso()),
        )
        conn.execute(
            "UPDATE chat_sessions SET updated_at=? WHERE id=?", (now_iso(), session_id)
        )


def _history(session_id: int, limit: int = 40, budget: int = HISTORY_CHAR_BUDGET) -> list[dict[str, str]]:
    """取最近的对话历史：条数和总字数双约束，长会话也不会把上下文撑爆。"""
    with db() as conn:
        rows = conn.execute(
            """SELECT role, content FROM chat_messages
               WHERE session_id=? AND role IN ('user','assistant') AND content <> ''
               ORDER BY id DESC LIMIT ?""",
            (session_id, limit),
        ).fetchall()
    picked: list[dict[str, str]] = []
    used = 0
    for row in rows:  # 从最近往更早收集，超出预算就停
        text = str(row["content"] or "")
        if used + len(text) > budget and picked:
            break
        picked.append({"role": row["role"], "content": text[:2000]})
        used += min(len(text), 2000)
    return list(reversed(picked))


# ---------------- 提问还是干活 ----------------

# 用户这句话是在「问结果、要结论」，不是在下新任务
_QUESTION_HEADS = (
    "你的意思", "我的意思", "意思", "所以", "那就是", "也就是说", "是不是", "有没有", "是否",
    "到底", "究竟", "结论", "结果", "发现什么", "发现了什么", "测过", "测了", "做过", "做了",
    "汇报", "总结", "说说", "说一下", "解释", "为什么", "怎么回事", "哪几项", "哪些",
)
_QUESTION_TAILS = ("吗", "么", "呢", "？", "?")
# 明确在派活的说法：出现这些就当新任务，不进提问模式
# （否则「帮我看看有没有未授权接口」这种会被当成闲聊，反而耽误事）
_TASK_MARKS = (
    "帮我", "帮忙", "继续", "接着", "再测", "再试", "再去", "再验", "重新", "开始", "动手",
    "跑一下", "跑一遍", "跑下", "测一下", "测下", "试一下", "试下", "扫一下", "扫一遍", "扫下",
    "查一下", "查下", "看一下", "看下", "看看", "找一下", "挖一下", "验一下", "验下",
    "深入", "往下", "验证一下", "执行一下", "过一遍", "走一遍", "你来", "去做", "去测", "去验",
    "确认一下", "核实一下", "按这个", "直接做", "就这样", "开测", "开扫", "全测",
)


def question_turn(text: str) -> bool:
    """判断用户这一句是「提问/要结论」还是「派活」。

    问句要的是答案：模型拿已有的执行记录回答就行，不该重新跑一遍。
    Python 侧先判一道，是因为真实场景里模型太容易被「继续测试」的惯性带跑。
    """
    value = str(text or "").strip()
    if not value or len(value) > 240:
        return False
    body = value.rstrip(" \t\r\n")
    for tail in ("。", "，", ","):
        if body.endswith(tail):
            body = body[: -len(tail)].rstrip()
    if not body:
        return False
    tail_q = body.endswith(_QUESTION_TAILS)
    head_q = any(mark in body[:16] for mark in _QUESTION_HEADS)
    if not (tail_q or head_q):
        return False
    return not any(mark in body for mark in _TASK_MARKS)


DIGEST_MAX_CHARS = 2600
_PROGRESS_TAILS = ("接下来", "下一步", "继续下一步", "继续往下", "接着往下", "继续执行")


def _one_line(text: str, limit: int = 160) -> str:
    value = " ".join(str(text or "").replace("*", "").split())
    return value[:limit].strip()


def _last_user_text(session_id: int) -> str:
    """用户这一轮到底说了什么。直接从库里取，不受历史字数预算影响。"""
    with db() as conn:
        row = conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='user' ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
    return str(row["content"] or "") if row else ""


# 用户说过这些话，就是「别问我、你自己定」的授权，后面再抛选择题等于明知故问
AUTONOMY_HINTS: tuple[str, ...] = (
    "你决定",
    "你自己",
    "自己看着办",
    "按你的",
    "全测",
    "都测",
    "全补",
    "全都",
    "都补",
    "全部测",
    "直接做",
    "继续",
    "随便",
)


def autonomy_granted(session_id: int, limit: int = 3) -> bool:
    """最近几条用户消息里有没有「自己决定、全做」的授权。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT content FROM chat_messages WHERE session_id=? AND role='user' ORDER BY id DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
    text = " ".join(str(row["content"] or "") for row in rows)
    return any(hint in text for hint in AUTONOMY_HINTS)


def _auto_choice(options: list[dict[str, str]]) -> dict[str, str]:
    """自动拍板时选哪一个：优先「全都测/按顺序」这类覆盖面最大的选项，否则取第一个。"""
    wide = ("全测", "都测", "全补", "全部", "按顺序", "全量")
    for option in options:
        label = str(option.get("label") or "")
        if any(hint in label for hint in wide):
            return option
    return options[0]


def _work_digest(session_id: int) -> str:
    """把「这次会话到底做过什么」压成一份台账，每轮都塞给模型。

    `_history` 有字数预算，长会话里最早的结论会被裁掉；而且它只收 user/assistant，
    平台自己记的进度小字（「已确认管理接口全部 302 到登录页」这类）根本进不了历史。
    用户随后问一句「你测过 SQL 注入了吗」，模型看不到记录，就当成新任务又跑一遍——
    这正是「没听懂问题、还在瞎执行」的根因。所以进度行单独收、单独占预算，
    不会被后面那些长篇正文挤掉。
    """
    with db() as conn:
        progress_rows = conn.execute(
            """SELECT content FROM chat_messages
               WHERE session_id=? AND role='progress' AND content <> ''
               ORDER BY id DESC LIMIT 60""",
            (session_id,),
        ).fetchall()
        assistant_rows = conn.execute(
            """SELECT content FROM chat_messages
               WHERE session_id=? AND role='assistant' AND content <> ''
               ORDER BY id DESC LIMIT 12""",
            (session_id,),
        ).fetchall()
        findings = conn.execute(
            """SELECT title, severity, target FROM findings
               WHERE status IN ('open','confirmed')
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC
               LIMIT 12"""
        ).fetchall()

    steps: list[str] = []
    seen: set[str] = set()
    used = 0
    for row in reversed(progress_rows):  # 进度行短，先按时间顺序铺开
        line = _one_line(row["content"], 120)
        if not line or line in seen:
            continue
        seen.add(line)
        if used + len(line) > 1800 and steps:
            break
        steps.append(line)
        used += len(line) + 3

    notes: list[str] = []
    for row in assistant_rows:  # 结论取开头一句，长的报告也只占一行
        line = _one_line(row["content"], 160)
        if not line or line in seen:
            continue
        seen.add(line)
        if used + len(line) > DIGEST_MAX_CHARS:
            break
        notes.append(line)
        used += len(line) + 3

    parts: list[str] = []
    if steps:
        parts.append("【本次会话已执行的步骤（按时间先后，取自真实执行记录，可直接引用）】")
        parts.extend(f"- {line}" for line in steps)
    if notes:
        parts.append("【最近给出的结论（由近及远）】")
        parts.extend(f"- {line}" for line in notes)
    if findings:
        parts.append("【已归档的检测结论】")
        for row in findings:
            sev = SEVERITY_CN.get(str(row["severity"]), str(row["severity"]))
            parts.append(f"- [{sev}] {row['title']}｜{row['target']}")
    else:
        parts.append("【已归档的检测结论】暂无：record_finding 一次都没调用过，说明还没确认到可归档的漏洞。")
    return "\n".join(parts)


# ---------------- 承上：每轮开工前把「已经知道的」收成一份 ----------------
#
# 用户的原话是「每一轮开始都要自动总结之前已知的内容，再以这个为基础往下做，
# 不能重复之前的输出」。历史里的正文会被字数预算裁掉、而且是流水账，
# 所以这里另做一份：只留结论性的东西（台账、已归档漏洞、做过的动作、上一轮写到哪），
# 每轮开工前塞给模型，并明确禁止它把这些再抄一遍。

ROUND_BRIEF = (
    "【本轮开工前 · 平台把已经知道的收成一份，从这里往下做】\n"
    "{known}\n"
    "使用规矩（用户定死的，违反就算没听懂）：\n"
    "1. 开口只用 1-2 句接上进度（「上一轮已经…，这一轮接着…」），不要把上面这份清单再抄一遍；\n"
    "2. 只做没做过的事：测过的入口不重测，给过的结论不再给；要复核必须说明为什么值得复核；\n"
    "3. 正文只写这一轮的新结论、新证据、新发现。上一轮写过的段落、清单、漏洞三件套都不要重复——"
    "平台在每轮收尾会统一附漏洞清单，正文里不用再抄；\n"
    "4. 确实要引用旧结论，写一句「（同上）」带过，不要整段重写。"
)

BRIEF_STEP_LINES = 8
BRIEF_CONCLUSION_CHARS = 240
PARA_MIN_CHARS = 100
# 报文、代码块是要原样交付的证据：哪怕和上一轮一样，也不能当成「重复输出」删掉
_NO_REPEAT_SKIP = ("请求包", "响应包", "```", "HTTP/1.", "GET /", "POST /")


def _max_message_id(session_id: int) -> int:
    """这一轮开工时库里的最大消息 id：用它把「本轮自己写的」和「之前轮次的」分开。"""
    with db() as conn:
        row = conn.execute(
            "SELECT MAX(id) AS m FROM chat_messages WHERE session_id=?", (int(session_id),)
        ).fetchone()
    return int((row and row["m"]) or 0)


def _round_brief(session_id: int) -> str:
    """本轮开工前的「已知」：台账 + 已归档漏洞 + 做过的动作 + 上一轮写到哪。"""
    with db() as conn:
        step_rows = conn.execute(
            """SELECT content FROM chat_messages
               WHERE session_id=? AND role='progress' AND content <> ''
               ORDER BY id DESC LIMIT 24""",
            (int(session_id),),
        ).fetchall()
        last_rows = conn.execute(
            """SELECT content FROM chat_messages
               WHERE session_id=? AND role='assistant' AND content <> ''
               ORDER BY id DESC LIMIT 2""",
            (int(session_id),),
        ).fetchall()
        findings = conn.execute(
            """SELECT title, severity, target FROM findings
               WHERE status IN ('open','confirmed')
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC
               LIMIT 40"""
        ).fetchall()

    parts: list[str] = []
    if coverage.selected_keys():
        parts.append(f"· 能力台账：{coverage.summary_line(int(session_id))}")
    if findings:
        parts.append(f"· 已归档漏洞 {len(findings)} 条（结论里可直接引用，不要整段重抄）：")
        for row in findings[:8]:
            sev = SEVERITY_CN.get(str(row["severity"]), str(row["severity"]))
            parts.append(f"  - [{sev}] {_one_line(row['title'], 60)}｜{_one_line(row['target'], 60)}")
        if len(findings) > 8:
            parts.append(f"  - 其余 {len(findings) - 8} 条见每轮收尾的清单")
    else:
        parts.append("· 已归档漏洞：还没有（record_finding 一次都没调用过）")

    steps: list[str] = []
    seen: set[str] = set()
    for row in reversed(step_rows):
        line = _one_line(row["content"], 90)
        if not line or line in seen:
            continue
        seen.add(line)
        steps.append(line)
    if steps:
        parts.append("· 已经做过的动作（按时间先后，别重复做）：")
        for line in steps[-BRIEF_STEP_LINES:]:
            parts.append(f"  - {line}")

    if last_rows:
        last = _one_line(last_rows[0]["content"], BRIEF_CONCLUSION_CHARS)
        if last:
            parts.append(f"· 上一轮结尾说的：{last}")
        heads: list[str] = []
        for line in str(last_rows[0]["content"] or "").splitlines():
            if re.match(r"^\s{0,3}#{1,4}\s+\S", line):
                head = _one_line(line.strip("# ").strip(), 28)
                if head and head not in heads:
                    heads.append(head)
        if heads:
            parts.append(f"· 上一轮已经写过的小节（不要换个说法再写一遍）：{'、'.join(heads[:6])}")
    return "\n".join(parts)


def _round_brief_line(session_id: int) -> str:
    """给界面看的短版承上摘要：一行说清「从哪接着干」。"""
    data = coverage.summary(session_id) if coverage.selected_keys() else {}
    with db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE status IN ('open','confirmed')"
        ).fetchone()
        steps = conn.execute(
            "SELECT COUNT(*) AS c FROM chat_messages WHERE session_id=? AND role='progress'",
            (int(session_id),),
        ).fetchone()
    found = int((row and row["c"]) or 0)
    done_steps = int((steps and steps["c"]) or 0)
    if not data and not found and not done_steps:
        return ""
    bits: list[str] = []
    if data:
        bits.append(f"已验 {data['done']}/{data['selected']} 项能力")
    if found:
        bits.append(f"已归档 {found} 条漏洞")
    if done_steps:
        bits.append(f"已完成 {done_steps} 步")
    if not bits:
        return ""
    return f"承上：{'，'.join(bits)}；这一轮接着做没做过的，写过的内容不再重复。"


def _norm_para(text: str) -> str:
    """段落指纹：去掉空白与标点后比较，避免「只差一个空格」被当成新内容。"""
    return re.sub(r"[\s\*_`#>·、，。；：！？,.;:!?\-—–\|（）()\[\]【】\"'“”‘’]+", "", str(text or ""))


def _previous_paragraphs(session_id: int, upto: int = 0, limit: int = 8) -> set[str]:
    """之前轮次写过的长段落指纹。upto>0 时只看这个 id 之前的，避开本轮自己的输出。"""
    sql = "SELECT content FROM chat_messages WHERE session_id=? AND role='assistant' AND content <> ''"
    args: list[Any] = [int(session_id)]
    if upto:
        sql += " AND id<=?"
        args.append(int(upto))
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with db() as conn:
        rows = conn.execute(sql, args).fetchall()
    known: set[str] = set()
    for row in rows:
        for block in re.split(r"\n\s*\n", str(row["content"] or "")):
            norm = _norm_para(block)
            if len(norm) >= PARA_MIN_CHARS:
                known.add(norm)
    return known


def _strip_repeated_paragraphs(session_id: int, text: str, upto: int = 0) -> tuple[str, int]:
    """删掉与之前轮次一字不差的长段落，返回（新正文，删掉的段数）。

    只认「规范化后完全相同」且长度 ≥ 100 字，报文与代码块一律不动：
    这是「不要重复之前的输出」的兜底，宁可不删，也不能误删这一轮的新结论。
    """
    body = str(text or "")
    if len(_norm_para(body)) < PARA_MIN_CHARS:
        return body, 0
    known = _previous_paragraphs(session_id, upto)
    if not known:
        return body, 0
    kept: list[str] = []
    dropped = 0
    for block in re.split(r"\n\s*\n", body):
        norm = _norm_para(block)
        if (
            len(norm) >= PARA_MIN_CHARS
            and norm in known
            and not any(mark in block for mark in _NO_REPEAT_SKIP)
        ):
            dropped += 1
            continue
        kept.append(block)
    if not dropped:
        return body, 0
    out = "\n\n".join(kept).strip()
    note = f"（有 {dropped} 段与前面轮次一字不差，已省略；要哪一段我按你点的那条重发。）"
    return (f"{out}\n\n{note}" if out else note), dropped


def _looks_like_progress_report(text: str) -> bool:
    """模型把「已…，接下来…」的过程播报当成了回答：这不是答案。"""
    value = str(text or "").strip()
    if not value or len(value) > 220:
        return False
    if not value.startswith(("已", "正在")):
        return False
    return any(mark in value for mark in _PROGRESS_TAILS)


# ---------------- 工具实现 ----------------


def _tool_list_capabilities(args: dict, username: str) -> dict:
    data = capabilities_snapshot()
    items = data["capabilities"]
    hints = data.get("hints") or {}
    auto = bool(data.get("auto_pentest"))
    order = [
        {"key": item["key"], "name": item["name"], "weight": item["weight"]}
        for item in weighted_items()
    ]
    scope_note = (
        "自动渗透已开启：**清单是底线，不是边界**。上面这些项都必须有结论，"
        "同时清单之外的漏洞类型也要按目标真实暴露面主动测——例如 GraphQL 内省与批量查询、"
        "文件上传、反序列化、缓存投毒、业务逻辑/金额越权、JWT/OAuth/SAML 配置、"
        "Actuator / Swagger / Druid 这类管理面未授权、组件已知漏洞入口。"
        "验出问题直接 record_finding 归档，标题里写清属于哪一类；"
        "命中清单里存在但没勾选的项，也可以 report_capability 上报（平台照收，不计入交付门槛）。"
        "仍然不进漏洞清单的低价值项：CORS 宽松、缺安全响应头、纯版本指纹、目录索引、Source Map 暴露。"
    ) if auto else (
        "只在上述已勾选能力范围内工作；未勾选的能力不要主动探测。"
        "自动渗透已关闭：清单之外的漏洞类型不展开，顺手看到的线索在正文写一句「值得单独测」即可。"
    )
    return {
        "ok": True,
        "count": len(items),
        "capabilities": [
            {
                "key": item["key"],
                "name": item["name"],
                "group": item["group"],
                # 用户给这项写的要求，取的时候顺手带走：模型不用另外再查一遍
                "user_prompt": hints.get(item["key"], ""),
            }
            for item in items
        ],
        "user_prompts": hints,
        "testing_order": order,
        "switches": data["switches"],
        "auto_pentest": auto,
        "ask": {
            "敏感信息": bool(data["switches"].get(ASK_SENSITIVE_KEY)),
            "删除类操作": bool(data["switches"].get(ASK_DELETE_KEY)),
        },
        "step_budget": data["steps"],
        "note": (
            scope_note
            + "testing_order 是按权重（1-5，越大越先测）排好的开测顺序，"
            "先抓目标首页与前端 JS 分析入口，再按这个顺序往下做。"
            "带 user_prompt 的项是用户亲手写的硬性要求：测该项前逐字读完、照它执行，"
            "提示里点名的入口/参数/检查点一个都不能少，提示说不要碰的就不碰。"
        ),
    }


def _tool_platform_overview(args: dict, username: str) -> dict:
    """一次拿全平台状态，避免模型为了拼图反复调用多个查询工具。"""
    with db() as conn:
        assets = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
        scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        running = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE status IN ('queued','running')"
        ).fetchone()["c"]
        open_findings = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE status IN ('open','confirmed')"
        ).fetchone()["c"]
        by_sev = {
            row["severity"]: row["c"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings "
                "WHERE status IN ('open','confirmed') GROUP BY severity"
            ).fetchall()
        }
        asset_rows = conn.execute(
            "SELECT id, name, target, kind FROM assets ORDER BY id DESC LIMIT 8"
        ).fetchall()
        scan_rows = conn.execute(
            "SELECT id, name, status, mode, progress FROM scans ORDER BY id DESC LIMIT 5"
        ).fetchall()
        finding_rows = conn.execute(
            "SELECT id, title, severity, url, status FROM findings "
            "WHERE status IN ('open','confirmed') ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, id DESC "
            "LIMIT 5"
        ).fetchall()
    connectors = connector_rows()
    ready = [row["key"] for row in connectors if row["enabled"] and row["last_check_ok"]]
    configured = [
        row["key"]
        for row in connectors
        if bool(row.get("secret_enc")) or row.get("auth_type") == "cli"
    ]
    return {
        "ok": True,
        "assets": assets,
        "scans": scans,
        "running_scans": running,
        "open_findings": open_findings,
        "severity": by_sev,
        "asset_preview": [dict(row) for row in asset_rows],
        "scan_preview": [dict(row) for row in scan_rows],
        "finding_preview": [dict(row) for row in finding_rows],
        "authorization": {
            "mode": "disclaimer",
            "confirmed": True,
            "note": "登录时已确认免责声明，用户给出的目标即为已授权目标；平台不再校验授权范围。",
        },
        "testing_order": [
            {"key": item["key"], "name": item["name"], "weight": item["weight"]}
            for item in weighted_items()[:10]
        ],
        "connectors_ready": ready,
        "connectors_configured": configured,
        "note": "这份数据已经覆盖资产、任务、漏洞、能力权重与连接器，通常无需再逐个调用查询工具。",
    }


def _tool_list_assets(args: dict, username: str) -> dict:
    q = str(args.get("q") or "").strip()
    with db() as conn:
        if q:
            rows = conn.execute(
                """SELECT id, name, target, kind, org, tags, criticality,
                          (SELECT COUNT(*) FROM findings f WHERE f.asset_id=a.id) AS finding_count
                   FROM assets a
                   WHERE name LIKE ? OR target LIKE ? OR org LIKE ? OR tags LIKE ?
                   ORDER BY id DESC LIMIT 50""",
                (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, name, target, kind, org, tags, criticality,
                          (SELECT COUNT(*) FROM findings f WHERE f.asset_id=a.id) AS finding_count
                   FROM assets a ORDER BY id DESC LIMIT 50"""
            ).fetchall()
    return {"ok": True, "count": len(rows), "assets": [dict(r) for r in rows]}


def _tool_create_asset(args: dict, username: str) -> dict:
    target = str(args.get("target") or "").strip()
    if not target:
        return {"ok": False, "error": "target 不能为空"}
    with db() as conn:
        exists = conn.execute("SELECT id FROM assets WHERE target=?", (target,)).fetchone()
        if exists:
            return {"ok": False, "error": f"该目标已存在资产台账（ID {exists['id']}）"}
        kind = "url" if target.lower().startswith(("http://", "https://")) else "domain"
        try:
            ipaddress.ip_address(target)
            kind = "ip"
        except ValueError:
            pass
        criticality = args.get("criticality", 3)
        try:
            criticality = max(1, min(5, int(criticality)))
        except (TypeError, ValueError):
            criticality = 3
        name = str(args.get("name") or target).strip()[:200]
        ts = now_iso()
        cursor = conn.execute(
            """INSERT INTO assets (name, target, kind, org, tags, criticality, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                name,
                target,
                kind,
                str(args.get("org") or "").strip()[:200],
                str(args.get("tags") or "").strip()[:200],
                criticality,
                "",
                ts,
                ts,
            ),
        )
        asset_id = cursor.lastrowid
    audit(username, "asset_create", f"新增资产 #{asset_id} {target}")
    return {"ok": True, "asset_id": asset_id, "target": target, "kind": kind}


async def _tool_start_scan(args: dict, username: str) -> dict:
    targets = args.get("targets") or []
    asset_ids = args.get("asset_ids") or []
    if not isinstance(targets, list):
        targets = [str(targets)]
    try:
        asset_ids = [int(item) for item in asset_ids]
    except (TypeError, ValueError):
        return {"ok": False, "error": "asset_ids 必须是整数数组"}
    items = resolve_targets(asset_ids, [str(t) for t in targets])
    if not items:
        return {"ok": False, "error": "请提供目标或资产 ID"}
    profile = args.get("profile") or "quick"
    if profile not in ("quick", "standard", "deep"):
        profile = "quick"
    mode = args.get("mode") or "active"
    if mode not in ("active", "passive"):
        mode = "active"
    try:
        result = await create_scan_task(
            name=str(args.get("name") or ""),
            asset_ids=asset_ids,
            targets=[str(t) for t in targets],
            profile=profile,
            mode=mode,
            authorization_ref=str(args.get("authorization_ref") or ""),
            username=username,
        )
    except TaskError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, **result}


def _tool_list_scans(args: dict, username: str) -> dict:
    try:
        limit = max(1, min(50, int(args.get("limit", 10))))
    except (TypeError, ValueError):
        limit = 10
    status = str(args.get("status") or "").strip()
    clauses = "WHERE s.status=?" if status else ""
    params: tuple = (status, limit) if status else (limit,)
    with db() as conn:
        rows = conn.execute(
            f"""SELECT s.id, s.name, s.status, s.mode, s.profile, s.progress, s.stage,
                       s.authorization_ref, s.created_at, s.finished_at,
                       (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS finding_count
                FROM scans s {clauses} ORDER BY s.id DESC LIMIT ?""",
            params,
        ).fetchall()
    return {"ok": True, "count": len(rows), "scans": [dict(r) for r in rows]}


def _tool_get_scan(args: dict, username: str) -> dict:
    try:
        scan_id = int(args.get("scan_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "scan_id 必须是整数"}
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return {"ok": False, "error": f"任务 #{scan_id} 不存在"}
        scan = dict(row)
        scan["targets"] = json.loads(scan.pop("targets_json") or "[]")
        scan["stats"] = json.loads(scan.pop("stats_json") or "{}")
        findings = [
            dict(r)
            for r in conn.execute(
                """SELECT id, title, severity, status, target, source FROM findings
                   WHERE scan_id=? ORDER BY CASE severity
                     WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3 ELSE 4 END, id LIMIT 20""",
                (scan_id,),
            ).fetchall()
        ]
        logs = [
            dict(r)
            for r in conn.execute(
                "SELECT ts, level, message FROM scan_logs WHERE scan_id=? ORDER BY id DESC LIMIT 12",
                (scan_id,),
            ).fetchall()
        ][::-1]
    return {"ok": True, "scan": scan, "findings": findings, "logs": logs}


def _tool_cancel_scan(args: dict, username: str) -> dict:
    try:
        scan_id = int(args.get("scan_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "scan_id 必须是整数"}
    with db() as conn:
        row = conn.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return {"ok": False, "error": f"任务 #{scan_id} 不存在"}
        status = row["status"]
        if status in ("completed", "failed", "cancelled"):
            return {"ok": False, "error": f"任务 #{scan_id} 已结束（{status}），无法取消"}
        CANCELLED.add(scan_id)
        if status == "queued":
            conn.execute(
                "UPDATE scans SET status='cancelled', stage='已取消', finished_at=? WHERE id=?",
                (now_iso(), scan_id),
            )
        else:
            conn.execute("UPDATE scans SET stage='取消中...' WHERE id=?", (scan_id,))
    audit(username, "scan_cancel", f"取消任务 #{scan_id}")
    return {"ok": True, "scan_id": scan_id, "status": "cancelled"}


def _tool_list_findings(args: dict, username: str) -> dict:
    clauses: list[str] = []
    params: list[Any] = []
    for key, column in (("severity", "f.severity"), ("status", "f.status")):
        value = str(args.get(key) or "").strip()
        if value:
            clauses.append(f"{column}=?")
            params.append(value)
    if args.get("scan_id"):
        try:
            clauses.append("f.scan_id=?")
            params.append(int(args["scan_id"]))
        except (TypeError, ValueError):
            return {"ok": False, "error": "scan_id 必须是整数"}
    q = str(args.get("q") or "").strip()
    if q:
        clauses.append("(f.title LIKE ? OR f.target LIKE ? OR f.evidence LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    try:
        limit = max(1, min(100, int(args.get("limit", 20)))
                    )
    except (TypeError, ValueError):
        limit = 20
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with db() as conn:
        rows = conn.execute(
            f"""SELECT f.id, f.scan_id, f.title, f.severity, f.status, f.target, f.url,
                       f.capability, f.source, f.cvss, f.created_at, s.name AS scan_name
                FROM findings f LEFT JOIN scans s ON s.id=f.scan_id
                {where}
                ORDER BY CASE f.severity
                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                  WHEN 'low' THEN 3 ELSE 4 END, f.id DESC
                LIMIT ?""",
            (*params, limit),
        ).fetchall()
    return {"ok": True, "count": len(rows), "findings": [dict(r) for r in rows]}


def _tool_update_finding_status(args: dict, username: str) -> dict:
    try:
        finding_id = int(args.get("finding_id"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "finding_id 必须是整数"}
    status = str(args.get("status") or "").strip()
    if status not in VALID_FINDING_STATUS:
        return {"ok": False, "error": f"无效状态，可选：{', '.join(VALID_FINDING_STATUS)}"}
    with db() as conn:
        row = conn.execute("SELECT title FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return {"ok": False, "error": f"漏洞 #{finding_id} 不存在"}
        conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
    audit(username, "finding_status", f"漏洞 #{finding_id}「{row['title']}」状态变更为 {status}")
    return {"ok": True, "finding_id": finding_id, "status": status}


# 用户定下的硬条件：泄露的信息，必须是「正常用户看不到的」才算泄露。
# 光靠提示词不够——模型偶尔会把公开页面上的手机号、自己的订单、前端 JS 里的接口地址
# 也写成「高危泄露」。所以归档时再做一道兜底：泄露类的高危结论，必须拿得出对照证据。
LEAK_TITLE_HINTS: tuple[str, ...] = (
    "泄露",
    "泄漏",
    "暴露",
    "明文",
    "未授权访问",
    "越权访问",
    "可下载",
    "可读取",
)

# 「正常用户看不到」的对照证据：写了任意一类就算过了门槛
LEAK_PROOF_HINTS: tuple[str, ...] = (
    "未授权",
    "未登录",
    "未登陆",
    "匿名",
    "无需登录",
    "无需认证",
    "不带凭证",
    "无凭证",
    "无 cookie",
    "普通用户",
    "他人",
    "别人的",
    "别人的账号",
    "其他用户",
    "其他账号",
    "非本人",
    "不属于自己",
    "越权",
    "后台",
    "管理端",
    "管理后台",
    "仅内部",
    "内部字段",
    "隐藏字段",
    "不应看到",
    "看不到",
    "无权查看",
    "本该",
    "正常页面",
    "页面上不展示",
    "不对外",
    "未公开",
    "非公开",
    "内部配置",
)

LEAK_DEMOTE_NOTE = (
    "【平台按判定门槛降级】未给出「正常用户看不到」的对照证据（未登录时无此字段、他人账号拿不到、"
    "页面上不展示、只有后台可见），从严按低一档记录。补齐对照证据后可重新归档。"
)


def leak_gate(title: str, severity: str, description: str, evidence: str) -> tuple[str, str]:
    """泄露类高危结论的兜底校验。

    标题像泄露、等级又是高危/严重，但说明与证据里找不到任何「正常用户看不到」的对照，
    就降到下一档并标注原因——避免把公开可见的信息当成高危往报告里塞。
    """
    if severity not in ("critical", "high"):
        return severity, ""
    if not any(hint in str(title or "") for hint in LEAK_TITLE_HINTS):
        return severity, ""
    body = f"{description or ''}\n{evidence or ''}".lower()
    if any(hint.lower() in body for hint in LEAK_PROOF_HINTS):
        return severity, ""
    lowered = "high" if severity == "critical" else "medium"
    return lowered, LEAK_DEMOTE_NOTE


DIGEST_HEAD = "【漏洞清单·逐条复核】"


def _findings_rows(ids: list[int]) -> list[dict]:
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    with db() as conn:
        rows = conn.execute(
            f"""SELECT id, title, url, target, severity, request_packet, response_packet,
                       description, remediation, steps
                FROM findings WHERE id IN ({marks}) ORDER BY id""",
            ids,
        ).fetchall()
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["steps"] = _load_steps(item.get("steps") or "")
        items.append(item)
    return items


def _packet_sig(packet: str) -> str:
    """报文里能用来判重的那一行：请求行 / 响应状态行。"""
    for raw in str(packet or "").splitlines():
        line = raw.strip()
        if line:
            return line[:40]
    return ""


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _dedupe_rows(rows: list[dict]) -> list[dict]:
    """同一条漏洞只列一次：域名、标题、URL 三样都一样的，保留最新那条。

    只在标题上判重会把「同一个越权点在两个接口都能打通」压成一条——那两条
    URL 不同、报文不同，是两份证据，得各列各的。
    """
    kept: dict[tuple[str, str, str], dict] = {}
    order: list[tuple[str, str, str]] = []
    for row in rows:
        host = host_of(str(row.get("url") or row.get("target") or ""))
        title = re.sub(r"\s+", "", str(row.get("title") or "")).lower()
        url = str(row.get("url") or row.get("target") or "").strip().lower()
        key = (host, title, url)
        if key not in kept:
            order.append(key)
        kept[key] = row
    result = [kept[key] for key in order]
    result.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(str(item.get("severity") or "info"), 1),
            int(item.get("id") or 0),
        )
    )
    return result


def _digest_scope(session_id: int) -> tuple[list[str], list[dict]]:
    """这一轮要摊开的域名清单，以及这些域名名下的全部漏洞。

    用户定的口径：这一轮测的是一个域名，就列该域名在本次测试里的所有漏洞；
    这一轮测了几个域名，就每个域名各列一份，同一条不重复列举。
    所以取数范围是「本次对话归档过的全部漏洞」，再按这一轮碰过的域名筛。
    """
    sid = int(session_id or 0)
    # 跨轮累积的那份才是「本次测试出现的所有漏洞」；老会话没累积记录时退回本轮
    rows = _findings_rows(list(_SESSION_ALL_FINDINGS.get(sid) or []))
    if not rows:
        rows = _findings_rows(list(_SESSION_FINDINGS.get(sid) or []))
    if not rows:
        return [], []
    targets = list(_ROUND_DOMAINS.get(sid) or []) or list(_SESSION_DOMAINS.get(sid) or [])
    if targets:
        scoped = [
            row
            for row in rows
            if any(
                _same_domain(host_of(str(row.get("url") or row.get("target") or "")), target)
                for target in targets
            )
        ]
        # 这一轮只碰了 A 域名、却把漏洞归档在 B 域名：宁可全列，也不要交一份空清单
        rows = scoped or rows
    hosts: list[str] = []
    for row in rows:
        host = host_of(str(row.get("url") or row.get("target") or ""))
        if not any(_same_domain(host, seen) for seen in hosts):
            hosts.append(host)
    return hosts, _dedupe_rows(rows)


def _one_line(text: Any, limit: int = 180) -> str:
    """把一段说明压成一行，方便塞进清单里当「成因与影响」。"""
    body = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(body) > limit:
        body = body[:limit].rstrip() + "…"
    return body


def findings_digest(session_id: int, content: str) -> str:
    """收尾兜底：把「这次测的域名」下的每个漏洞摊在结论里，并讲清是怎么一步步打出来的。

    用户的要求是「在控制台就能逐条核对」，不能只有一句「已归档，去漏洞结果页看」。
    范围按域名算而不是按轮算：这一轮测了哪些域名，就把这些域名在本次对话里出现过
    的漏洞全部列出来（多域名各列一份，同一条只列一次）。
    每条按「漏洞N → 漏洞URL → 成因与影响 → 复现步骤（步骤N + 请求包N + 响应包N）
    → 修复方案」摊开：用户要能照着一步一步复现，不是只看到最后一对报文。
    模型自己写全了（标题、报文、步骤都在）就不重复；有缺的才补，补在正文末尾。
    """
    hosts, rows = _digest_scope(int(session_id or 0))
    if not rows:
        return content
    body = str(content or "")
    has_steps = _body_has_steps(body)
    this_round = set(_SESSION_FINDINGS.get(int(session_id or 0)) or [])
    missing: list[dict] = []
    for row in rows:
        title = str(row.get("title") or "")
        req_sig = _packet_sig(row.get("request_packet"))
        resp_sig = _packet_sig(row.get("response_packet"))
        # 标题 + 请求行 + 响应状态行都在正文里，才算这条已经摊开过
        complete = (
            title
            and title in body
            and (not req_sig or req_sig in body)
            and (not resp_sig or resp_sig in body)
        )
        # 还要看有没有讲清过程：有步骤记录、正文却一段步骤都没有，照样补
        if complete and (has_steps or not (row.get("steps") or [])):
            continue
        missing.append(row)
    if not missing:
        return body
    scope = "、".join(hosts) if hosts else UNKNOWN_HOST
    if len(hosts) <= 1:
        lead = f"本次测试针对 {scope}，该域名累计登记 {len(rows)} 条漏洞"
    else:
        lead = f"本次测试覆盖 {len(hosts)} 个域名（{scope}），这几个域名累计登记 {len(rows)} 条漏洞"
    head = (
        f"{lead}。下面逐条写清漏洞是怎么一步步打出来的，每一步都附该步的请求包与响应包（太长只保留关键部分，完整报文见漏洞结果页）"
        + (f"（其中 {len(missing)} 条结论里没摊开，补在这里）" if len(missing) < len(rows) else "")
        + "。"
    )
    lines = [DIGEST_HEAD, head, ""]
    current = ""
    for index, row in enumerate(missing, 1):
        host = host_of(str(row.get("url") or row.get("target") or ""))
        if host != current:
            current = host
            total_here = sum(
                1 for item in rows if _same_domain(host_of(str(item.get("url") or item.get("target") or "")), host)
            )
            lines.append(f"### 域名 {host}（{total_here} 条）")
            lines.append("")
        severity = str(row.get("severity") or "info")
        tag = "（本轮新增）" if int(row.get("id") or 0) in this_round else ""
        url = str(row.get("url") or row.get("target") or "—")
        lines.append(f"**漏洞{index}：{row.get('title') or ''}**（{SEVERITY_LABELS.get(severity, '信息')}）{tag}")
        lines.append("")
        lines.append(f"漏洞URL：{url}")
        cause = _one_line(row.get("description"), 200)
        if cause:
            lines.append(f"成因与影响：{cause}")
        lines.append("")
        steps = row.get("steps") or []
        if not steps:
            # 老记录只留了一对报文：也要能照着复现，就当成「一步」
            steps = [
                {
                    "action": f"直接请求 {url}（方法与路径见请求包）",
                    "result": "见下方响应包",
                    "why": "",
                    "request_packet": str(row.get("request_packet") or ""),
                    "response_packet": str(row.get("response_packet") or ""),
                }
            ]
        lines.append("复现步骤：")
        lines.append("")
        for step_no, step in enumerate(steps, 1):
            action = str(step.get("action") or "").strip() or "（这一步没写说明，报文如下）"
            seen = str(step.get("result") or "").strip()
            why = str(step.get("why") or "").strip()
            line = f"步骤{step_no}：{action}"
            if seen:
                line += f"，{seen}" if seen[0] not in "，,。；：" else f"{seen}"
            if why:
                line += f"；由此判断：{why}"
            lines.append(line)
            request = str(step.get("request_packet") or "").strip() or (
                str(row.get("request_packet") or "").strip() if step_no == 1 else ""
            )
            response = str(step.get("response_packet") or "").strip() or (
                str(row.get("response_packet") or "").strip() if step_no == 1 else ""
            )
            if request:
                lines.append(f"请求包{step_no}：")
                lines.append("```http")
                lines.append(_clip_for_digest(request, DIGEST_REQUEST_CHARS, "请求包"))
                lines.append("```")
            else:
                lines.append(
                    f"请求包{step_no}：（归档时没记录请求包，这条要重新打一次目标补上，否则无法复现）"
                )
            if response:
                lines.append(f"响应包{step_no}：")
                lines.append("```http")
                lines.append(_clip_for_digest(response, DIGEST_RESPONSE_CHARS, "响应包"))
                lines.append("```")
            else:
                lines.append(
                    f"响应包{step_no}：（归档时没记录响应包，这条要重新打一次目标补上，否则无法复现）"
                )
            lines.append("")
        remediation = _one_line(row.get("remediation"), 60)
        if remediation:
            lines.append(f"修复方案：{remediation}")
            lines.append("")
    return (body.rstrip() + "\n\n" + "\n".join(lines)).strip()


def _tool_record_finding(args: dict, username: str) -> dict:
    url = str(args.get("url") or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": "url 必须是完整的 http/https 地址"}
    title = str(args.get("title") or "").strip()
    if not title:
        return {"ok": False, "error": "title 不能为空"}
    severity = str(args.get("severity") or "info").strip().lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "info"
    description_text = str(args.get("description") or "")
    evidence_text = str(args.get("evidence") or "")
    severity, demote_note = leak_gate(title, severity, description_text, evidence_text)
    if demote_note:
        evidence_text = (evidence_text + "\n" + demote_note).strip()
    capability = str(args.get("capability") or "").strip()
    if capability and capability not in CAPABILITY_BY_KEY:
        return {"ok": False, "error": f"未知模型能力：{capability}"}
    if capability and capability not in enabled_keys():
        return {"ok": False, "error": "该专项能力未在「模型能力」页勾选，已拒绝执行"}
    category = CAPABILITY_BY_KEY[capability]["name"] if capability else "对话测试"
    confidence = str(args.get("confidence") or "").strip().lower()
    if confidence not in ("low", "medium", "high"):
        confidence = "high" if args.get("request_packet") and args.get("response_packet") else "medium"
    try:
        cvss = float(args.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    dedupe = f"chat:{url}:{title}:{capability}"[:500]
    # 用户要求「写清楚是怎么一步一步打出来的」：模型传了步骤就用它的，
    # 没传就用平台在发包时记下的真实步骤兜底（同域名、按时间顺序、不跨漏洞重复用）。
    steps = _normalize_steps(args.get("steps"))
    if not steps:
        steps = _steps_for_finding(url)
    steps_json = json.dumps(steps, ensure_ascii=False) if steps else ""
    with db() as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO findings
               (scan_id, asset_id, target, url, title, severity, category, source, description,
                evidence, remediation, cvss, confidence, status, capability,
                request_packet, response_packet, steps, dedupe_key, created_at)
               VALUES (0, NULL, ?, ?, ?, ?, ?, 'ai-agent', ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)""",
            (
                url[:500],
                url[:1000],
                title[:300],
                severity,
                category[:100],
                description_text,
                evidence_text[:2000],
                str(args.get("remediation") or ""),
                cvss,
                confidence,
                capability[:100],
                str(args.get("request_packet") or "")[:6000],
                str(args.get("response_packet") or "")[:6000],
                steps_json,
                dedupe,
                now_iso(),
            ),
        )
        if cursor.rowcount:
            finding_id = cursor.lastrowid
        else:
            row = conn.execute(
                "SELECT id FROM findings WHERE scan_id=0 AND dedupe_key=?", (dedupe,)
            ).fetchone()
            finding_id = row["id"] if row else 0
            # 同一条结论再归档一次（补了对照证据、或补了完整报文）就覆盖旧值，
            # 否则「补齐证据后可以升级」这句话在库层面就不成立
            if finding_id:
                conn.execute(
                    """UPDATE findings SET severity=?, description=?, evidence=?, remediation=?,
                       cvss=?, confidence=?, request_packet=?, response_packet=?,
                       steps=COALESCE(NULLIF(?, ''), steps) WHERE id=?""",
                    (
                        severity,
                        description_text,
                        evidence_text[:2000],
                        str(args.get("remediation") or ""),
                        cvss,
                        confidence,
                        str(args.get("request_packet") or "")[:6000],
                        str(args.get("response_packet") or "")[:6000],
                        steps_json,
                        finding_id,
                    ),
                )
    audit(username, "finding_record", f"AI 归档漏洞「{title}」到 {url}")
    # 记进本会话的清单：收尾时按它核对「每个漏洞的标题/请求包/响应包是不是都摊给用户看了」
    sid = _TOOL_SESSION.get()
    if sid and finding_id:
        bucket = _SESSION_FINDINGS.setdefault(int(sid), [])
        if int(finding_id) not in bucket:
            bucket.append(int(finding_id))
        # 这份跨轮累积不清：清单按域名列「本次测试出现的所有漏洞」，不是只列这一轮新发现的
        all_bucket = _SESSION_ALL_FINDINGS.setdefault(int(sid), [])
        if int(finding_id) not in all_bucket:
            all_bucket.append(int(finding_id))
    # 归档到这个域名，说明这一轮确实测过它
    _note_domain(url)
    # 归档即视为该能力「验出漏洞」：覆盖台账跟着走，不用模型再报一次
    if capability and _TOOL_SESSION.get():
        coverage.mark(
            _TOOL_SESSION.get(), capability, "vulnerable", note=title, evidence=evidence_text
        )
    result = {
        "ok": True,
        "finding_id": finding_id,
        "url": url,
        "severity": severity,
        "capability": capability,
        "group": "该结果已关联对应 URL",
    }
    if demote_note:
        result["severity_note"] = (
            f"这条按 {severity} 记录：标题属于泄露类，但说明与证据里没有「正常用户看不到」的对照。"
            "补上对照证据（未登录时无此字段、他人账号拿不到、只有后台可见）后重新归档，才会按高危计；"
            "本来就公开可见的信息，应该直接删掉这条，不要留在报告里。"
        )
    # 硬性要求：每轮收尾都要把每个漏洞的标题、请求包、响应包写出来。
    # 归档时就把报文补齐，别等到收尾再发现没法交差（同一条重新归档会覆盖旧值）。
    missing_packets = [
        label
        for label, value in (
            ("请求包", args.get("request_packet")),
            ("响应包", args.get("response_packet")),
        )
        if not str(value or "").strip()
    ]
    if missing_packets:
        result["packet_gap"] = (
            f"这条没记录{'和'.join(missing_packets)}。收尾要逐条给出标题、请求包、响应包三样，"
            "缺报文就重新打一次目标（http_request 会直接返回 request_packet / response_packet），"
            "拿到后原样补上再 record_finding 一次（同一条会覆盖旧值）。"
        )
    result["steps"] = len(steps)
    if not steps:
        result["step_gap"] = (
            "这条没留下任何复现步骤，收尾时讲不清漏洞是怎么一步步打出来的。"
            "下一次归档时用 steps 传过程：每步写清「做了什么 / 看到什么 / 由此推出什么」，"
            "并附上该步的请求包与响应包；发包时在 http_request 里填 note，平台也会自动记成步骤。"
        )
    return result


def _tool_report_capability(args: dict, username: str) -> dict:
    """登记一项能力的验证结论——「自动测试选中的能力」靠这一次登记推进。

    没有这一步，平台只能看模型正文里怎么说；有了这一步，剩余多少项是算出来的。
    """
    session_id = _TOOL_SESSION.get()
    if not session_id:
        return {"ok": False, "error": "当前没有会话上下文，无法登记能力结论"}
    key = coverage.resolve(str(args.get("capability") or args.get("key") or ""))
    if not key:
        # 自动渗透开着时，清单外的类型多半不在能力表里：别让它卡在「未知能力」上，
        # 指一条明路——按漏洞归档，结论照样进报告
        if auto_pentest_enabled():
            return {
                "ok": False,
                "error": (
                    f"未知能力：{args.get('capability')}（不在能力表里）。"
                    "自动渗透已开启，清单外的类型不用报能力：把验到的结果用 record_finding 归档，"
                    "标题里写清属于哪一类即可；能力台账只记已勾选的那几项。"
                ),
            }
        return {"ok": False, "error": f"未知能力：{args.get('capability')}，请填能力 key 或完整名称"}
    status = str(args.get("status") or "").strip().lower()
    if status not in coverage.VALID_STATUS:
        return {
            "ok": False,
            "error": "status 只能是 vulnerable / clean / blocked / inconclusive",
        }
    note = str(args.get("note") or "").strip()
    if not note:
        return {"ok": False, "error": "note 不能为空：写清测了哪个入口、看到什么"}
    # 用户给这一项写过提示：先让它「读到」，才允许把结论记进台账。
    # 这不是测试失败，只是强制阅读——第一次把提示原文交回去，模型读完再报一次即可。
    hint = capability_hints().get(key, "")
    if hint:
        read = _SESSION_HINTS_READ.setdefault(session_id, set())
        if key not in read:
            read.add(key)
            return {
                "ok": False,
                "hint_required": True,
                "capability": key,
                "name": coverage.CAPABILITY_BY_KEY[key]["name"],
                "user_prompt": hint,
                "next": (
                    "这不是测试失败：用户为这一项写了硬性要求，平台要求先读完再记账。\n"
                    "现在做两件事：① 对照上面的 user_prompt 检查这一项是不是已经按它做了——"
                    "提示里点名的入口/参数/检查点有没有漏，提示说不要碰的有没有碰；"
                    "② 把同一个结论再调用一次 report_capability，note 里逐条说明提示里的要求各自是什么结果。"
                    "如果刚才漏做了某几处，现在补测完再报；不用整项重测。"
                ),
            }
    result = coverage.mark(session_id, key, status, note=note, evidence=str(args.get("evidence") or ""))
    if not result.get("ok"):
        return result
    data = coverage.summary(session_id)
    return {
        "ok": True,
        "capability": key,
        "name": result["name"],
        "status": status,
        "status_label": coverage.STATUS_LABEL[status],
        "coverage": data,
        "next_batch": data["next"],
        "user_prompt": hint,
        "hint": (
            f"这一项已记下。还剩 {data['pending']} 项没验"
            + (f"，下一批：{'、'.join(data['next'])}。" if data["next"] else "。")
            + ("（这一项用户写了提示，平台已记录你已读；没照做的那部分要补测重报。）" if hint else "")
        ),
    }


def _tool_list_connectors(args: dict, username: str) -> dict:
    rows = connector_rows()
    items = []
    for row in rows:
        config = {}
        try:
            config = json.loads(row.get("config_json") or "{}")
        except json.JSONDecodeError:
            config = {}
        items.append(
            {
                "key": row["key"],
                "name": row["name"],
                "category": row["category"],
                "enabled": bool(row["enabled"]),
                "configured": bool(row.get("secret_enc")) or row.get("auth_type") == "cli",
                "model": config.get("model", ""),
                "last_check_ok": row.get("last_check_ok"),
                "last_check_msg": row.get("last_check_msg") or "",
            }
        )
    return {"ok": True, "count": len(items), "connectors": items}


async def _tool_test_connector(args: dict, username: str) -> dict:
    key = str(args.get("key") or "").strip()
    if not key:
        return {"ok": False, "error": "key 不能为空"}
    row = next((item for item in connector_rows() if item.get("key") == key), None)
    if row is None:
        return {"ok": False, "key": key, "message": "没有这个连接器，请先 list_connectors 确认 key。"}
    configured = bool(row.get("secret_enc")) or row.get("auth_type") == "cli"
    if not configured:
        return {
            "ok": False,
            "key": key,
            "message": (
                f"{row.get('name') or key} 尚未配置密钥，检测必然失败；"
                "不要再重试这个连接器，直接告诉用户去「API 中心」填写即可。"
            ),
        }
    result = await run_connector_test(key)
    return {"ok": result.ok, "key": key, "message": result.message}


async def _tool_test_all_connectors(args: dict, username: str) -> dict:
    """一次并发检测全部已配置连接器，替代逐个调用的几十轮往返。"""
    category = str(args.get("category") or "").strip()
    rows = [
        row
        for row in connector_rows()
        if bool(row.get("enabled"))
        and (bool(row.get("secret_enc")) or row.get("auth_type") == "cli")
        and (not category or row.get("category") == category)
    ]
    if not rows:
        return {
            "ok": True,
            "tested": 0,
            "results": [],
            "note": "没有已配置的连接器需要检测，先到 API 中心填写密钥。",
        }

    semaphore = asyncio.Semaphore(6)

    async def probe(row: dict) -> dict:
        async with semaphore:
            try:
                result = await run_connector_test(str(row["key"]))
            except Exception as exc:
                return {"key": row["key"], "ok": False, "message": f"检测异常：{exc}"}
            return {"key": row["key"], "name": row.get("name"), "ok": result.ok, "message": result.message}

    results = await asyncio.gather(*(probe(row) for row in rows))
    ok_count = sum(1 for item in results if item["ok"])
    failed_items = [
        {"key": item["key"], "message": str(item.get("message") or "")[:100]}
        for item in results
        if not item["ok"]
    ][:10]
    return {
        "ok": True,
        "tested": len(results),
        "passed": ok_count,
        "failed": len(results) - ok_count,
        "failed_detail": failed_items,
        "passed_keys": [item["key"] for item in results if item["ok"]],
        "note": (
            "一次调用已覆盖全部已配置连接器（含 ai/intel/recon/tool/vuln 各类），"
            "结果就是最终结论：failed_detail 之外的都是检测通过，无需再逐个 test_connector 复测。"
        ),
    }


def _scope_hint() -> list[dict[str, Any]]:
    """告诉模型有哪些目录可用，避免它以为没有读取权限。"""
    items = []
    for scope, label, base in allowed_roots():
        exists = base.exists()
        count = 0
        if scope == "memory":
            count = len(memory_files())
        elif exists and base.is_dir():
            try:
                count = len([i for i in base.iterdir() if i.is_file()])
            except OSError:
                count = 0
        elif exists and base.is_file():
            count = 1
        items.append({"scope": scope, "label": label, "path": str(base), "exists": exists, "files": count})
    return items


def _tool_list_dir(args: dict, username: str) -> dict:
    scope = str(args.get("scope") or "").strip().lower()
    raw_path = str(args.get("path") or "").strip()
    try:
        path, label = resolve_doc(raw_path, scope)
    except WorkspaceError as exc:
        return {"ok": False, "error": str(exc), "roots": _scope_hint()}
    if not path.exists():
        return {"ok": False, "error": f"路径不存在：{raw_path or path}", "roots": _scope_hint()}
    if path.is_file():
        return {"ok": True, "path": str(path), "scope": label, "type": "file"}
    entries = []
    try:
        for item in path.iterdir():
            is_dir = item.is_dir()
            try:
                size = 0 if is_dir else item.stat().st_size
            except OSError:
                size = 0
            entries.append(
                {
                    "name": item.name,
                    "type": "dir" if is_dir else "file",
                    "size": size,
                }
            )
    except OSError as exc:
        return {"ok": False, "error": f"读取目录失败：{exc}"}
    entries.sort(key=lambda entry: (entry["type"] != "dir", entry["name"].lower()))
    return {
        "ok": True,
        "path": str(path),
        "scope": label,
        "type": "dir",
        "count": len(entries),
        "entries": entries[:300],
        "roots": _scope_hint(),
    }


def _tool_read_file(args: dict, username: str) -> dict:
    raw_path = str(args.get("path") or "").strip()
    if not raw_path:
        return {"ok": False, "error": "path 不能为空", "roots": _scope_hint()}
    try:
        path, label = resolve_doc(raw_path)
    except WorkspaceError as exc:
        return {"ok": False, "error": str(exc), "roots": _scope_hint()}
    if not path.exists() or not path.is_file():
        return {
            "ok": False,
            "error": f"文件不存在：{raw_path}",
            "hint": "可以用 list_dir 先看目录里有什么（记忆目录传 scope=memory）",
            "roots": _scope_hint(),
        }
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return {"ok": False, "error": f"读取失败：{exc}"}
    offset = max(0, int(args.get("offset") or 0))
    limit = int(args.get("limit") or 0) or min(12000, READ_CHUNK_MAX)
    limit = max(1000, min(limit, READ_CHUNK_MAX))
    end = min(len(text), offset + limit)
    chunk = text[offset:end]
    payload = {
        "ok": True,
        "path": str(path),
        "scope": label,
        "chars": len(text),
        "offset": offset,
        "next_offset": end,
        "has_more": end < len(text),
        "truncated": end < len(text),
        "content": chunk,
    }
    if end < len(text):
        payload["hint"] = f"文件共 {len(text)} 字符，还有 {len(text) - end} 字符没读；带 offset={end} 继续读，读完再下结论。"
    elif label == "记忆目录":
        payload["hint"] = "这个文件已读完；如果还有别的记忆文件，逐个读完再动手。"
    return _fit_payload(payload)


def _fit_payload(payload: dict, budget: int = 0) -> dict:
    """保证 JSON 序列化后不超过工具结果预算。

    正文比分块上限还长、或者附加字段（文件清单）特别多时，JSON 会被上层压缩器截断，
    next_cursor 就与真实内容错位，模型以为读到了、其实少了尾巴。这里按实际序列化长度
    倒推可以留多少正文，宁可少给一点，也不让分页错位。
    """
    limit = budget or (LARGE_RESULT_CHARS - 600)
    text = json.dumps(payload, ensure_ascii=False)
    if len(text) <= limit:
        return payload
    content = str(payload.get("content") or "")
    keep = max(600, len(content) - (len(text) - limit) - 40)
    if keep >= len(content):
        return payload
    out = dict(payload)
    out["content"] = content[:keep]
    out["truncated"] = True
    if "next_cursor" in out:
        out["chars"] = keep
        out["next_cursor"] = int(out.get("cursor") or 0) + keep
        out["has_more"] = out["next_cursor"] < int(out.get("total_chars") or 0)
        out["hint"] = (
            f"本次返回 {keep} 字符（为避免分页错位已收窄），"
            f"再调 read_memory(cursor={out['next_cursor']}) 继续读。"
        )
    else:
        out["next_offset"] = int(out.get("offset") or 0) + keep
        out["has_more"] = out["next_offset"] < int(out.get("chars") or 0)
        out["hint"] = f"本次返回 {keep} 字符，带 offset={out['next_offset']} 继续读。"
    return out


def _tool_read_memory(args: dict, username: str) -> dict:
    """按游标分块读记忆：不限总量，has_more=false 才算读完。"""
    root = memory_path()
    if root is None:
        return {"ok": False, "error": "平台尚未配置记忆目录，请先在「目录配置」页面设置"}
    only = str(args.get("only") or "").strip()
    limit = int(args.get("limit") or 0) or min(12000, READ_CHUNK_MAX)
    data = memory_chunk(
        cursor=int(args.get("cursor") or 0),
        limit=max(1000, min(limit, READ_CHUNK_MAX)),
        only=only,
    )
    if data["total_chars"] == 0:
        return {
            "ok": True,
            "path": str(root),
            "exists": root.exists(),
            "files": data["files"],
            "total_chars": 0,
            "content": "（记忆目录里没有可读的文本文件，或文件内容为空）",
            "has_more": False,
            "next_cursor": 0,
        }
    payload = {
        "ok": True,
        "path": str(root),
        "exists": root.exists(),
        "files": data["files"],
        "chars": len(data["content"]),
        "total_chars": data["total_chars"],
        "cursor": data["cursor"],
        "next_cursor": data["next_cursor"],
        "has_more": data["has_more"],
        "content": data["content"],
    }
    if data["has_more"]:
        payload["hint"] = (
            f"记忆共 {data['total_chars']} 字符，本次到 {data['next_cursor']}；"
            f"再调 read_memory(cursor={data['next_cursor']}) 继续读，读完 has_more=false 再动手。"
        )
    else:
        payload["hint"] = "记忆已全部读完，可以据此执行任务。"
    return _fit_payload(payload)


def _tool_search_memory(args: dict, username: str) -> dict:
    keyword = str(args.get("keyword") or "").strip()
    if not keyword:
        return {"ok": False, "error": "keyword 不能为空"}
    if memory_path() is None:
        return {"ok": False, "error": "平台尚未配置记忆目录，请先在「目录配置」页面设置"}
    limit = max(1, min(int(args.get("limit") or 60), 200))
    hits = memory_search(keyword, limit=limit)
    return {
        "ok": True,
        "keyword": keyword,
        "count": len(hits),
        "matches": hits,
        "files": memory_manifest(),
        "hint": "只有命中片段不够时，再用 read_memory(only=文件名) 把该文件读完。",
    }


def _run_cwd(args: dict) -> Path:
    """命令落点：工作目录（或其中子目录）；越界一律退回工作目录根。"""
    base = exec_dir()
    sub = str(args.get("cwd") or "").strip()
    if not sub:
        return base
    candidate = (base / sub).expanduser()
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError:
        return base
    try:
        resolved = candidate.resolve()
        if resolved != base.resolve() and base.resolve() not in resolved.parents:
            return base
    except OSError:
        return base
    return candidate


# 渗透测试期间绝对不能真做的动作：改目标凭据、删账号、清表。
# 用户的红线是「不得对网站数据造成任何影响」，但模型为了证明「可造成实际危害」，
# 会真的去改口令再改回来——真出过一次：把 admin 口令改成新值，然后自己恢复。
# 一旦中途失败，用户的目标系统就进不去了，所以这件事由平台直接拦，不靠提示词自觉。
IRREVERSIBLE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "修改口令",
        re.compile(
            r"(new[_-]?password|new[_-]?pwd|confirm[_-]?password|change[_-]?password"
            r"|reset[_-]?password|改密|修改口令|重置口令|更改密码)",
            re.IGNORECASE,
        ),
    ),
    ("删除账号", re.compile(r"(delete|remove)\s+(the\s+)?(user|account|admin)", re.IGNORECASE)),
    ("清空数据表", re.compile(r"(drop\s+table|truncate\s+table|delete\s+from\s+\w+)", re.IGNORECASE)),
)

BLOCKED_WRITE_TEXT = (
    "【平台拦截】这一步会真的改动目标数据或凭据（{reason}），属于不可逆动作。"
    "渗透测试期间不允许改目标的数据：改口令、删账号、清表都可能让目标系统不可用，"
    "事后恢复也不等于没发生。请改用只读的等价证据来说明机制——"
    "例如：该接口未校验旧口令/旧会话即返回成功、未授权请求命中了写分支并回显变更结果，"
    "把请求包与响应包原样归档即可。需要实际改动数据时，让用户自己在界面上操作。"
)

# 平台自身的配置（连接器地址、平台设置）属于用户资产，不是被测对象：
# 实测里模型为了证明「base_url 可指向任意地址」，把用户的连接器改成了云元数据地址，
# 还改了一堆扫描器配置——测试结束这些改动不会自己回去，用户下次打开就懵了。
SELF_CONFIG_PATTERN = re.compile(
    r"^https?://(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(:\d+)?/api/(connectors|settings)",
    re.IGNORECASE,
)


def irreversible_write_reason(payload: str, method: str = "") -> str:
    """这一步会不会真的改动目标数据或凭据。返回原因，空串表示放行。"""
    text = str(payload or "")
    verb = str(method or "").upper()
    if verb in ("POST", "PUT", "PATCH", "DELETE") and SELF_CONFIG_PATTERN.search(text):
        return "修改平台自身配置"
    for label, pattern in IRREVERSIBLE_PATTERNS:
        if not pattern.search(text):
            continue
        # 读请求里出现这些词（比如读到的 JS 源码里有 new_password 字段）不算
        if verb and verb not in ("POST", "PUT", "PATCH", "DELETE"):
            continue
        return label
    return ""


def _script_write_reason(code: str) -> str:
    """脚本/命令里是不是真的要发写请求或改库。

    只出现 `new_password` 这个字符串不算（可能只是在读前端源码），
    必须同时看到发请求或写库的动作，才判定为「真改」。
    """
    text = str(code or "")
    if not text:
        return ""
    sends = re.search(
        r"(requests\.(post|put|patch|delete)|httpx\.(post|put|patch|delete)"
        r"|urllib\.request|curl\s+-X\s*(POST|PUT|PATCH|DELETE)|session\.(post|put|patch)"
        r"|UPDATE\s+\w+\s+SET)",
        text,
        re.IGNORECASE,
    )
    for index, (label, pattern) in enumerate(IRREVERSIBLE_PATTERNS):
        if not pattern.search(text):
            continue
        if index == 0 and not sends:
            continue
        return label
    return ""


SCRIPT_HTTP_HINT = (
    "这条命令 / 脚本没成功，里面既然在发 HTTP 请求，就别急着记成「打不通」："
    "先看报错是连接层还是响应层——连接层查端口、http/https、证书；响应层看状态码，"
    "换参数位置、类型、编码、方法或身份再试一次。说得出「为什么这条路走不通」再收手。"
)
SCRIPT_HTTP_WORDS = ("curl", "wget", "requests.", "httpx.", "urllib", "http://", "https://")


def script_http_hint(result: dict, source: str) -> str:
    """命令/脚本里发了 HTTP 又失败了，就给模型一句「换写法再试」的提示。"""
    if not isinstance(result, dict):
        return ""
    code = result.get("exit_code")
    if code in (0, None) and result.get("ok") is not False:
        return ""
    blob = str(source or "").lower()
    if not any(word in blob for word in SCRIPT_HTTP_WORDS):
        return ""
    return SCRIPT_HTTP_HINT


def _tool_run_shell(args: dict, username: str) -> dict:
    command = str(args.get("command") or "").strip()
    if not command:
        return {"ok": False, "error": "command 不能为空"}
    reason = _script_write_reason(command)
    if reason:
        return {"ok": False, "blocked": True, "error": BLOCKED_WRITE_TEXT.format(reason=reason)}
    cwd = _run_cwd(args)
    result = shell_run_command(command, cwd, timeout=int(args.get("timeout") or 0))
    result["cwd"] = str(cwd)
    audit(username, "shell_run", f"AI 执行命令：{command[:180]}（退出码 {result.get('exit_code', '-')}）")
    hint = script_http_hint(result, command)
    if hint:
        result = {**result, "retry_hint": hint}
    return result


def _tool_run_python(args: dict, username: str) -> dict:
    code = str(args.get("code") or "")
    if not code.strip():
        return {"ok": False, "error": "code 不能为空"}
    reason = _script_write_reason(code)
    if reason:
        return {"ok": False, "blocked": True, "error": BLOCKED_WRITE_TEXT.format(reason=reason)}
    cwd = _run_cwd(args)
    result = shell_run_script(code, cwd, timeout=int(args.get("timeout") or 0))
    result["cwd"] = str(cwd)
    first_line = code.strip().splitlines()[0][:120] if code.strip() else ""
    audit(username, "python_run", f"AI 运行脚本：{first_line}（退出码 {result.get('exit_code', '-')}）")
    hint = script_http_hint(result, code)
    if hint:
        result = {**result, "retry_hint": hint}
    return result


def _tool_http_request(args: dict, username: str) -> dict:
    url = str(args.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "url 不能为空"}
    headers = args.get("headers")
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except json.JSONDecodeError:
            headers = {}
    if not isinstance(headers, dict):
        headers = {}
    reason = irreversible_write_reason(f"{url}\n{args.get('body') or ''}", str(args.get("method") or "GET"))
    if reason:
        return {
            "ok": False,
            "blocked": True,
            "error": BLOCKED_WRITE_TEXT.format(reason=reason),
            "retry_hint": (
                "这一条被平台按「不做不可逆写操作」拦下了，不是接口打不通，也不要去改写绕过它。"
                "改用只读方式证明同样的事：把方法换成 GET/HEAD、只取列表或详情、用 OPTIONS 看允许的方法，"
                "或者只提交一个必然被校验拒绝的空参数，从报错里判断后端行为。"
            ),
        }
    # 超时跟着「平台设置」走：设置里写 5 秒就 5 秒，不再固定 30
    timeout = args.get("timeout")
    if not timeout:
        try:
            timeout = int(float(get_settings().get("request_timeout") or 30))
        except (TypeError, ValueError):
            timeout = 30
    result = shell_http_request(
        url=url,
        method=str(args.get("method") or "GET"),
        headers={str(k): str(v) for k, v in headers.items()},
        body=str(args.get("body") or ""),
        timeout=int(timeout),
        follow_redirects=bool(args.get("follow_redirects", True)),
        verify_cert=bool(args.get("verify_cert", False)),
        raw_body_is_json=bool(args.get("raw_body_is_json", False)),
    )
    audit(
        username,
        "http_request",
        f"AI 请求 {result.get('method', args.get('method') or 'GET')} {url[:160]} → {result.get('status', '失败')}",
    )
    # 这一轮实际发了包的域名，就是收尾时要摊开漏洞的域名
    _note_domain(url)
    # 用户硬性要求：结论要写清「怎么一步一步打出来的」。这一步连同报文一起记下来，
    # 归档时按时间顺序挂到那条漏洞上，收尾清单就能照着讲。
    _note_step(url, result, str(args.get("note") or ""))
    hint = retry_hint(result)
    if hint:
        # 放在结果里，模型下一次看工具结果就会被这句顶到眼前
        result = {**result, "retry_hint": hint}
    return result


# 请求没成功时，这段提示会跟着工具结果一起交给模型。
# 为什么写在这里而不是只写在系统提示词里：模型看提示词是「开跑前看一眼」，
# 看工具结果是「刚失败、正要不试了」的那一瞬——后者才是它真正会读的时候。
RETRY_HINT_BASE = (
    "这个请求没成功，别直接记成「走不通」。先判断原因，再换一种写法重发："
    "参数位置（query / body / header / path）、参数类型（字符串/数字/布尔/数组）、"
    "编码（URL / 双重 URL / Unicode / Base64）、请求方法（GET/POST/PUT/PATCH）、"
    "Content-Type（json / form / multipart）、鉴权头与必填字段/签名/时间戳、路径大小写。"
)

RETRY_HINT_BY_STATUS = {
    400: "400 多半是参数名、参数格式或 Content-Type 不对：把前端 JS 里读到的字段名与类型抄准，表单与 JSON 互换再试一次。",
    401: "401 是没认出来身份：补上 Cookie / Authorization，或换成另一个角色已登录的凭据再发；同一路径换 GET/POST 也常能绕开鉴权中间件。",
    403: "403 是认出来了但不让干：换一个权限更高的身份、把参数从 body 挪到 query、去掉多余的自定义头（有些 WAF 认头）、换等价路径（/api/v1/x ↔ /api/x、大小写、末尾斜杠）再试。",
    404: "404 多半是路径或方法不对：对照前端 JS 里的真实路由，试带/不带版本前缀、带/不带末尾斜杠、换请求方法。",
    405: "405 是方法不对：按前端实际用法换 GET/POST/PUT/DELETE，注意有些接口用 POST 模拟 GET。",
    415: "415 是 Content-Type 不认：在 application/json、x-www-form-urlencoded、multipart/form-data 之间换。",
    422: "422 是参数校验没过：补必填字段、修正类型（数字别写成字符串）、把嵌套对象拆平再试。",
    429: "429 是被限流：放慢节奏、换一个出口（如果有多个入口域名），不要继续高频打。",
    500: "500 可能是参数触发了异常分支：换一组更小/更规范的值，去掉可疑字符再试；仍然 500 说明这条路本身有问题。",
    502: "502/503/504 是网关或上游的问题：稍等重试一次，换 Host 头或换 http/https 再试。",
}

RETRY_STREAK_NOTE = (
    "【平台追问 · 连续第 {n} 个请求没成功】先停一下，逐条回答自己："
    "① 这次到底为什么失败（状态码与报错原文说的是什么）？"
    "② 还有哪些写法没试过——参数位置、参数类型、编码、请求方法、Content-Type、"
    "换个身份或换个路径版本？"
    "③ 这个方向是不是已经确实没有别的写法了？"
    "只要还答不出 ③，就不许把这一项记成「不可利用」或「不存在」，改包继续试。"
)


RETRY_HINT_TAIL = (
    "每换完一次都反问自己一句：「这个方向还有没有别的写法？我是不是已经把所有写法都试过了？」"
    "还有就接着试；只有能说出「为什么这条路确实走不通」的具体原因，才允许把这一项记成不可利用。"
    "说不出原因就说明还没试够。归档与上报时写清试过哪些变体、卡在哪一步。"
)


def retry_hint(result: dict) -> str:
    """给失败请求配一句「下一步怎么改」，成功就返回空串。"""
    if not isinstance(result, dict):
        return ""
    status = result.get("status")
    ok = bool(result.get("ok"))
    if ok and (status is None or 200 <= int(status) < 400):
        return ""
    if not result.get("ok") and status is None:
        # 连响应都没拿到：DNS / 端口 / TLS / 超时
        return (
            "这个请求连响应都没拿到（连接层就失败了），不是「接口不存在」。依次核对："
            "域名是否解析、端口是否开着、http 与 https 是否搞反、证书是否要跳过校验（verify_cert）、"
            "Host 头是否要改成内网域名、是否需要代理。换一种连法再试，别把连接失败当成结论。"
            + RETRY_HINT_TAIL
        )
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    specific = RETRY_HINT_BY_STATUS.get(code, "")
    if not specific and 300 <= code < 400:
        specific = "3xx 是跳转：注意是否被踢回登录页——如果是，说明这条路径需要身份，换成带凭据的请求再试。"
    if not specific and code >= 400:
        specific = "换参数位置、类型与编码各试一次，再决定这条路是不是真的走不通。"
    return f"{specific}{RETRY_HINT_BASE}{RETRY_HINT_TAIL}"


def _tool_write_file(args: dict, username: str) -> dict:
    relative = str(args.get("path") or "").strip()
    if not relative:
        return {"ok": False, "error": "path 不能为空"}
    try:
        path = resolve_path(relative)
    except WorkspaceError as exc:
        return {"ok": False, "error": str(exc)}
    if path.is_dir():
        return {"ok": False, "error": f"{relative} 是目录，不能写入"}
    content = str(args.get("content") or "")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        return {"ok": False, "error": f"写入失败：{exc}"}
    audit(username, "workspace_write", f"AI 写入文件 {relative}（{len(content)} 字符）")
    return {"ok": True, "path": relative, "chars": len(content)}


async def dispatch_tool(name: str, args: dict, username: str, trusted: bool = False) -> dict:
    handler = _HANDLERS.get(name)
    if not handler:
        return {"ok": False, "error": f"未知工具：{name}"}
    # __ 开头的是平台内部标记（点过确认后看敏感原文）。模型给的工具参数里出现这些键，
    # 一律当作它自己编的丢掉——否则它只要写一句 "__reveal_sensitive": true，
    # 敏感内容拦截就自己失效了。只有确认后重放这类平台内部调用才算可信。
    raw = dict(args or {})
    clean = {k: v for k, v in raw.items() if not str(k).startswith("__")}
    if trusted:
        clean.update({k: v for k, v in raw.items() if str(k).startswith("__")})
    args = clean
    # 工具本身是同步实现（起子进程、发 HTTP、读大文件、写报告）：丢到线程里跑，
    # 否则命令一跑几十秒、报告一出几万字，整个事件循环被占住，页面就像死了
    if inspect.iscoroutinefunction(handler):
        result = await handler(args, username)
    else:
        result = await asyncio.to_thread(handler, args, username)
    if inspect.isawaitable(result):
        result = await result
    return result


_HANDLERS = {
    "list_capabilities": _tool_list_capabilities,
    "platform_overview": _tool_platform_overview,
    "list_assets": _tool_list_assets,
    "create_asset": _tool_create_asset,
    "start_scan": _tool_start_scan,
    "list_scans": _tool_list_scans,
    "get_scan": _tool_get_scan,
    "cancel_scan": _tool_cancel_scan,
    "list_findings": _tool_list_findings,
    "update_finding_status": _tool_update_finding_status,
    "record_finding": _tool_record_finding,
    "report_capability": _tool_report_capability,
    "list_connectors": _tool_list_connectors,
    "test_connector": _tool_test_connector,
    "test_all_connectors": _tool_test_all_connectors,
    "list_dir": _tool_list_dir,
    "read_file": _tool_read_file,
    "read_memory": _tool_read_memory,
    "search_memory": _tool_search_memory,
    "write_file": _tool_write_file,
    "run_shell": _tool_run_shell,
    "run_python": _tool_run_python,
    "http_request": _tool_http_request,
}


def _compact(payload: dict, tool: str = "") -> str:
    """交给模型看的工具结果：普通查询够用即可，命令/文件/请求的结果不能砍。"""
    text = json.dumps(payload, ensure_ascii=False)
    cap = LARGE_RESULT_CHARS if tool in BIG_RESULT_TOOLS else TOOL_RESULT_CHARS
    if len(text) > cap:
        text = text[:cap] + "…（内容已截断，如需更多请缩小范围或分页读取）"
    return text


TRANSIENT_HINTS = (
    "502",
    "503",
    "504",
    "429",
    "proxyerror",
    "connecterror",
    "readtimeout",
    "connecttimeout",
    "timeout",
    "timed out",
    "连接",
    "temporarily",
    "overloaded",
)


HARD_ERROR_HINTS = ("http 400", "http 401", "http 403", "http 404", "http 422", "invalid api key", "unauthorized")


def _hard_error(message: str) -> bool:
    """鉴权或请求格式错误：重试与降级都不会成功，直接告诉用户。"""
    text = str(message or "").lower()
    return any(hint in text for hint in HARD_ERROR_HINTS)


def _transient_error(message: str) -> bool:
    """判断是否是值得重试一次的瞬时故障（网关、限流、超时）。"""
    text = str(message or "").lower()
    return any(hint in text for hint in TRANSIENT_HINTS)


def _token_limit_error(message: str) -> bool:
    """模型是不是在拒绝 max_tokens 这个值（而不是鉴权或网络问题）。

    国产/自建网关的 output 上限常常只有 4096 或 8192，请求 16000 会直接 400。
    这种情况换个参数就能成，值得自动降一档再试，而不是把错误码抛给用户。
    """
    text = str(message or "").lower()
    if "max_tokens" not in text and "max_output_tokens" not in text and "output token" not in text:
        return False
    return any(
        hint in text
        for hint in ("too", "exceed", "invalid", "less than", "maximum", "larger", "超出", "过大", "上限")
    )


# ---------------- 敏感操作确认 ----------------


def action_signature(tool: str, args: dict) -> str:
    raw = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(f"{tool}:{raw}".encode("utf-8")).hexdigest()[:16]


# ---- 这里区分「我自己的信息」和「目标的信息」 ----
# 用户的原话：查看目标敏感信息不需要询问，查看我的信息才需要询问，
# 而且同一处信息问过一次就不再问。所以先判断这份数据属于谁。
SELF_CREDENTIAL_HINTS: tuple[str, ...] = (
    ".ssh", ".aws", ".netrc", ".git-credentials", ".npmrc", ".kube",
    ".docker/config", "wallet.dat", ".config/gcloud",
)


def _norm_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip().lower()


def data_owner(path: str) -> str:
    """这份数据是谁的：self=用户自己的（记忆/平台库/本机凭据），target=目标侧的。"""
    text = _norm_path(path)
    if not text:
        return "unknown"
    # 工作目录里放的是目标物料，属于目标侧，读它不该打扰用户
    if _norm_path(WORKSPACE_DIR) and _norm_path(WORKSPACE_DIR) in text:
        return "target"
    for root in (MEMORY_DIR, DATA_DIR, BASE_DIR):
        root_text = _norm_path(root)
        if root_text and root_text in text:
            return "self"
    home = _norm_path(os.path.expanduser("~"))
    if home and text.startswith(home) and any(hint in text for hint in SELF_CREDENTIAL_HINTS):
        return "self"
    # 相对路径落在平台自己的工作目录/记忆目录里，按「我自己的信息」处理；
    # 绝对路径又不属于上面的目录，说明是目标侧物料或系统路径，不打扰用户
    if not text.startswith("/") and not re.match(r"^[a-z]:/", text):
        return "self"
    return "target"


def grant_key(tool: str, args: dict) -> str:
    """同一处信息只问一次的键：按「读哪个文件」算，不按偏移量和参数算。

    目标范围不再参与（授权已由免责声明覆盖），所以请求类工具不需要授权键，
    只有「读本机凭据」「删文件」这两类才记一次「已经问过了」。
    """
    clean = {k: v for k, v in (args or {}).items() if not str(k).startswith("__")}
    if tool in ("read_file", "read_memory", "search_memory"):
        target = clean.get("path") or clean.get("only") or clean.get("keyword") or ""
        return f"{tool}:{_norm_path(target)}"
    if tool in ("run_shell", "run_python"):
        command = str(clean.get("command") or clean.get("code") or "")
        paths = sorted({item for item in _sensitive_paths(command)})
        if paths:
            return f"{tool}:{'|'.join(paths)[:180]}"
    return action_signature(tool, clean)


def has_grant(session_id: int, key: str) -> bool:
    if not session_id or not key:
        return False
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT 1 FROM chat_grants WHERE session_id=? AND signature=?", (session_id, key)
            ).fetchone()
    except Exception:  # 授权表不可用时按未授权处理，宁可多问一次
        return False
    return bool(row)


def remember_grant(session_id: int, key: str, scope: str = "") -> None:
    if not session_id or not key:
        return
    try:
        with db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO chat_grants (session_id, signature, scope, created_at) VALUES (?,?,?,?)",
                (session_id, key, scope[:40], now_iso()),
            )
    except Exception:
        pass


def _sensitive_paths(command: str) -> list[str]:
    """从命令里挑出涉及敏感文件的路径片段，用于判断这份数据是谁的。

    只认「像文件名」的片段：`type .env`、`cat db.dump`、`~/.ssh/id_rsa` 都算；
    脚本里的 `json.dumps`、`token/localStorage`、`https://x/api` 这类代码/URL 片段
    只因为里面带了个关键字就被当成凭据文件，会让正常的测试每写一次脚本就弹一次确认，
    所以先按「最后一段是不是文件名」筛一遍。
    """
    text = str(command or "")
    found: list[str] = []
    for token in re.split(r"[\s\"'`|;&()<>=]+", text):
        item = token.strip().strip(",;:")
        if not _pathish(item):
            continue
        if _looks_sensitive(item):
            found.append(item)
    return found[:8]


CODEISH_HINTS: tuple[str, ...] = ("(", ")", "[", "]", "{", "}", "$", "#", "=>", "->", "==", "+", "\\n")
CREDENTIAL_FILENAMES: set[str] = {
    "id_rsa",
    "id_ed25519",
    "shadow",
    "wallet",
    "credentials",
    "htpasswd",
    "authorized_keys",
}


def _pathish(token: str) -> bool:
    """这个片段像不像一个真实文件路径（而不是代码里的标识符或 URL 片段）。"""
    item = str(token or "").strip()
    if not item or item in (".", "..", "/"):
        return False
    if any(hint in item for hint in CODEISH_HINTS):
        return False
    if "/" not in item and "\\" not in item and "." not in item:
        return False
    name = item.replace("\\", "/").rstrip("/").split("/")[-1].strip().lower()
    if not name:
        return False
    if name in CREDENTIAL_FILENAMES:
        return True
    # 文件名总得带个扩展名（.env / db.dump / app.conf），纯单词 + 斜杠的不算
    return "." in name


def _self_sensitive_hit(command: str) -> str:
    """命令是否在读「我自己的」敏感文件；读目标的敏感文件不拦。"""
    paths = _sensitive_paths(command)
    if not paths:
        # 命令里没写路径但提到了凭据类关键字（base64 里藏的命令等），按自己的信息处理
        return "命令可能读取凭据或密钥文件" if touch_sensitive_hint(command) else ""
    for item in paths:
        if data_owner(item) == "self":
            return f"{item} 属于你本机的凭据或密钥"
    return ""


def touch_sensitive_hint(command: str) -> bool:
    text = str(command or "").lower()
    return any(hint in text for hint in (".ssh/", "id_rsa", "id_ed25519", ".aws/", ".netrc", ".git-credentials"))


def _brief(value: Any, limit: int = 80) -> str:
    text = str(value if value is not None else "").replace("\n", " ").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _short_url(value: Any, limit: int = 38) -> str:
    """进度行里的地址：去掉协议头、压掉多余路径，留 host + 前段路径就够认了。"""
    text = str(value if value is not None else "").replace("\n", " ").strip()
    text = re.sub(r"^[a-z]+://", "", text, flags=re.IGNORECASE)
    text = re.sub(r"/{2,}", "/", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def _script_hint(args: dict) -> str:
    """脚本摘要：优先用模型给的 path，没有就取代码第一行的有效内容。"""
    path = str(args.get("path") or "").strip()
    if path:
        return _brief(path.split("/")[-1].split("\\")[-1], 16)
    code = str(args.get("code") or "").strip()
    for line in code.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        item = re.sub(r"^(import|from)\s+\S+.*$", "", item).strip()
        if item:
            return _brief(item, 18)
    return ""


def _ack_text(text: str, limit: int = 110) -> str:
    """插话后的第一句回应：只取开头一两句，不要整段独白。"""
    raw = str(text or "").strip()
    if not raw:
        return ""
    line = ""
    for candidate in raw.splitlines():
        item = candidate.strip().strip("*#>-·• 　")
        item = re.sub(r"^\d+[.、)]\s*", "", item)
        if item:
            line = item
            break
    if not line:
        return ""
    for sep in ("。", "！", "!", "；"):
        if sep in line:
            line = line.split(sep)[0] + sep
            break
    line = line.strip().rstrip("：:,，、* ")
    if len(line) > limit:
        line = line[: limit - 1] + "…"
    return line


def _strip_trailing_question(text: str) -> str:
    """去掉正文末尾重复的问句；只有问句、没有结论时原样保留。"""
    lines = str(text or "").split("\n")
    while len(lines) > 1 and lines[-1].strip().endswith(("？", "?")) and len(lines[-1].strip()) <= 60:
        lines.pop()
        while lines and not lines[-1].strip():
            lines.pop()
    cleaned = "\n".join(lines).rstrip()
    if cleaned.endswith(("？", "?")):
        cut = max(cleaned.rfind(mark) for mark in ("。", "！", "；"))
        if cut > 0:
            cleaned = cleaned[: cut + 1].rstrip()
    # 卡片自带选项，正文末尾的冒号、逗号没有意义
    return cleaned.rstrip(" \n:：,，、;；*")


LEAD_IN_WORDS = {
    "下一步", "下一步建议", "下一步怎么做", "下一步做什么", "后续建议", "接下来",
    "建议", "可选方案", "方案", "选项", "请选择", "选择", "做法", "方向", "怎么走",
}


def _strip_trailing_lead_in(text: str) -> str:
    """去掉「下一步建议」「可选方案：」这种悬空的引导标题——内容已经在选项卡片里了。"""
    lines = str(text or "").split("\n")
    while len(lines) > 1:
        raw = lines[-1].strip().strip("*# ").rstrip("：:，,、* ").strip("？?")
        if not raw:
            lines.pop()
            continue
        is_colon_lead = lines[-1].strip().endswith(("：", ":")) and len(raw) <= 12
        if is_colon_lead or (len(raw) <= 12 and raw in LEAD_IN_WORDS):
            lines.pop()
            while lines and not lines[-1].strip():
                lines.pop()
            continue
        break
    return "\n".join(lines).rstrip()


# ---------------- 用户插话（AI 思考期间用户补充输入） ----------------
_INTERJECT: dict[int, list[str]] = {}
_ACTIVE_SESSIONS: set[int] = set()

INTERJECT_MAX_ITEMS = 6


class RunToken:
    """一轮执行的取消凭据：用户点停止 / 换了会话，就把这一轮的标记置位。"""

    __slots__ = ("session_id", "cancelled", "reason")

    def __init__(self, session_id: int) -> None:
        self.session_id = int(session_id)
        self.cancelled = False
        self.reason = ""


_RUN_TOKENS: dict[int, set[RunToken]] = {}


def agent_running(session_id: int) -> bool:
    return bool(_RUN_TOKENS.get(int(session_id)))


def cancel_agent(session_id: int, reason: str = "已按你的要求停止这一轮") -> bool:
    """真正停掉一轮执行：标记取消、清空插话队列、杀掉还在跑的命令。

    返回 True 表示确实有任务在被中止。仅靠前端断开 SSE 是不够的——
    生成器可能已经进入下一个工具调用，命令也还在后台跑。
    """
    key = int(session_id)
    tokens = list(_RUN_TOKENS.get(key, set()))
    for token in tokens:
        token.cancelled = True
        token.reason = reason
    _INTERJECT.pop(key, None)
    # 用户点了「停止」：自动继续也一起停下，不然这一轮停了下一轮又被拉起来
    _AUTO_STOP.add(key)
    killed = shell_terminate_all()
    if killed:
        audit("system", "agent_cancel", f"会话 {key} 停止：已终止 {killed} 个在跑的命令")
    return bool(tokens)


# 用户主动停过的会话：自动继续不再接龙，直到他重新发消息或重新打开开关
_AUTO_STOP: set[int] = set()


def stop_auto(session_id: int, reason: str = "") -> None:
    _AUTO_STOP.add(int(session_id))
    if reason:
        audit("system", "auto_continue_stop", f"会话 {session_id} 停止自动继续：{reason}")


def auto_stopped(session_id: int) -> bool:
    return int(session_id) in _AUTO_STOP


def clear_auto_stop(session_id: int) -> None:
    _AUTO_STOP.discard(int(session_id))


def clear_auto_stops() -> None:
    """重新打开「自动继续」开关时调用：把之前点过停止留下的标记全清掉。

    不清的话会出现这种事：用户点过一次「停止生成」，之后再打开自动继续，
    平台仍然认为「这个会话被他叫停过」，于是第一轮结束就收手——看起来就是「开了也不跑」。
    """
    _AUTO_STOP.clear()


def push_interjection(session_id: int, text: str) -> bool:
    """把用户在 AI 思考期间的输入排队；没有正在跑的任务时返回 False。"""
    value = str(text or "").strip()
    key = int(session_id)
    if not value or key not in _ACTIVE_SESSIONS:
        return False
    bucket = _INTERJECT.setdefault(key, [])
    if len(bucket) >= INTERJECT_MAX_ITEMS:
        bucket.pop(0)
    bucket.append(value[:2000])
    return True


def take_interjections(session_id: int) -> list[str]:
    return _INTERJECT.pop(int(session_id), [])


def has_interjection(session_id: int) -> bool:
    return bool(_INTERJECT.get(int(session_id)))


def agent_busy(session_id: int) -> bool:
    return int(session_id) in _ACTIVE_SESSIONS


def _interjection_note(notes: list[str]) -> str:
    text = "\n".join(f"- {item}" for item in notes if str(item).strip())
    note = (
        "【用户补充要求，优先级高于原任务】\n"
        f"{text}\n"
        "处理要求：先满足这条补充——它可能改变了目标、范围、对象或输出形式；若与原任务冲突，一律以用户这次补充为准。"
        "已经拿到的只读结果可以复用，不要从头再来一遍；处理完直接用结论回应这条补充。\n"
        "**回应用户的要求**：先用一句话接住他这句话，结合你此刻的真实进度回答——"
        "做到哪一步了、这条补充你怎么处理、接下来会怎样（例如「收到，已经归档的 3 条结论保留，其余不再展开，我直接把报告收口」）。"
        "不要沉默着继续干活，也不要重复他的原话；这句话会直接显示在对话里。"
    )
    if any(question_turn(item) for item in notes):
        # 用户在干活途中问「测过没有 / 发现了没有」：这是要一句答案，不是改任务
        note += (
            "\n**他这句话是在问结果，不是让你换任务**：先用两句直接回答——做过没有、有没有发现、"
            "还差哪几项；答完再继续手上的活。不要用「已…，接下来…」的进度句代替回答。"
        )
    return note


# ---------------- 每一步的结论播报 ----------------
PROGRESS_MAX_CHARS = 60
# 值得用户抬头的关键节点：模型用这些词开头（或出现在句子前半段），平台就高亮 + 加粗 + 放大。
# 覆盖面故意做宽：书面词、变体说法、口语表达都算，别逼模型去背四个字的固定词。
HIGHLIGHT_MARKERS = (
    # 突破类
    "关键突破", "重大突破", "有突破", "突破了", "突破性进展", "突破口", "撕开口子", "打开缺口",
    # 发现类
    "重大发现", "新发现", "新的发现", "关键发现", "核心发现", "重要发现", "又发现",
    # 进展类
    "关键进展", "重大进展", "新的进展", "新进展", "有进展", "又有进展", "往前推了一步",
    # 确认 / 证明类
    "确认存在", "已确认存在", "确认可行", "已经证明", "已证明", "证实了", "实锤",
    "验证成功", "成功利用", "可利用", "能利用",
    # 结论 / 证据 / 风险类
    "关键结论", "关键证据", "关键线索", "有力证据", "关键风险", "重大风险",
    "高危确认", "严重风险",
)
HIGHLIGHT_MAX_CHARS = 120
# 固定词表只兜底用。真正的判定走下面的正则：关键说法长短不一，
# 「突破」「关键突破」「关键突破口」「重大安全发现」「已经确认存在」都得认，
# 不能只认四个字。徽标显示的也是命中的原话，不是写死的标签。
HIGHLIGHT_PATTERNS = tuple(
    re.compile(p) for p in (
        r"(?:关键|重大|核心|重要|突破性)(?:安全)?(?:突破口|突破|发现|进展|线索|结论|证据|风险)",
        r"(?:已经|已|经)?确认(?:了|出)?(?:确实)?(?:存在|可读|可访问|可绕过|能登|可行|成立)",
        r"(?:已经|已|经)?(?:证明|证实)(?:了)?",
        r"成功(?:利用|登录|绕过|读取|拿到|进入|执行|接管|越权)",
        r"(?:已经能|已能|能|可以)(?:利用|绕过|读到|拿到|进入|接管|越权|读取)",
        r"(?:撕开|打开|找到|发现)(?:了)?(?:口子|缺口|突破口)",
        r"突破口",
        r"(?:新的|新)(?:发现|进展|突破)",
        r"有(?:了)?(?:突破|进展|发现|收获)",
        r"验证成功|实锤",
        r"往前推了(?:一|1)步",
    )
)
# 口语化的说法同样算关键节点：「已经找到漏洞点，可以继续深入」这类句子比四个字的
# 书面词更像人话，模型自然会说，也值得让用户抬头看一眼
HIGHLIGHT_STRONG = (
    "漏洞点", "漏洞入口", "攻击点", "利用点", "有戏", "有料",
    "打得进去", "能打进去", "可以打", "能绕过", "绕过去了",
    "拿到了数据", "能读到数据", "兜出数据", "挖到东西", "挖到线索",
)
HIGHLIGHT_FINDINGS = (
    "可利用", "未授权", "越权", "口令", "弱口令", "密钥", "令牌", "敏感信息", "敏感数据",
    "高危", "严重", "接口", "入口", "注入点", "后台", "数据库", "堆栈", "身份证", "手机号",
)
HIGHLIGHT_FOLLOWUP = (
    "继续深入", "往下挖", "继续挖", "深挖", "跟进", "追下去", "继续验证", "接着验",
    "往下试", "扩面", "扩展", "继续测", "追一下",
)
# 否定说法不算突破：「没有突破」「未发现」不能点亮徽标
_NEGATIVE_BEFORE = ("没", "未", "无", "别", "不", "暂", "尚未")
DONE_MARKERS = ("已", "已经", "拿到", "读到", "取到", "完成", "跑完", "查完", "确认", "扫完", "理出", "看全")
# 模型有时写成「**【关键突破】**：…」，判定前把这些前后缀噪声去掉
_LEAD_NOISE = re.compile(r"^[\s　\-–—·•◆◇■□★☆*#>【】\[\]「」『』:：]+")


# 行首的关键说法前缀：「关键线索：」「重大发现：」——只有真正点亮的关键节点才配顶着它。
# 被冷却降级成普通进展时，这个帽子要摘掉，否则用户会看到「普通样式却写着关键线索」。
_KEY_PREFIX = re.compile(
    r"^(?:关键|重大|核心|重要|突破性)(?:安全)?(?:突破口|突破|发现|进展|线索|结论|证据|风险)"
    r"\s*[：:，,、\-–—]?\s*"
)


def strip_key_prefix(line: str) -> str:
    """摘掉行首的关键说法前缀，留给被降级的普通进展用。

    只在前缀后面还有实打实的内容时才摘，避免把「关键突破」这种整句摘成空。
    """
    text = str(line or "").strip()
    stripped = _KEY_PREFIX.sub("", text).strip()
    if len(stripped) < 6:
        return text
    return stripped


def _highlight_span(line: str) -> tuple[str, int]:
    """命中说法与位置（没命中返回 ("", -1)）。正则优先，长短都能认。"""
    value = _LEAD_NOISE.sub("", str(line or "").replace("*", "")).strip()
    if not value:
        return "", -1
    head = value[:40]
    best = ("", -1)
    for pattern in HIGHLIGHT_PATTERNS:
        match = pattern.search(head)
        if not match:
            continue
        index = match.start()
        before = head[max(0, index - 3) : index]
        if any(neg in before for neg in _NEGATIVE_BEFORE):
            continue
        # 同一位置命中多条时取更长的那个：「关键突破口」不能被截成「关键突破」
        if best[1] < 0 or index < best[1] or (index == best[1] and len(match.group(0)) > len(best[0])):
            best = (match.group(0), index)
    return best


def _highlight_marker(line: str) -> str:
    """命中的提醒词（没命中返回空串）：正则优先，固定词表兜底；开头优先，其次前 30 字内。"""
    phrase, _ = _highlight_span(line)
    if phrase:
        return phrase
    value = _LEAD_NOISE.sub("", str(line or "").replace("*", "")).strip()
    if not value:
        return ""
    heads = [word for word in HIGHLIGHT_MARKERS if value.startswith(word)]
    if heads:
        return max(heads, key=len)
    head = value[:30]
    for word in sorted(HIGHLIGHT_MARKERS, key=len, reverse=True):
        index = head.find(word)
        if index < 0:
            continue
        before = head[max(0, index - 3) : index]
        if any(neg in before for neg in _NEGATIVE_BEFORE):
            continue
        return word
    return ""


def _highlight_kind(line: str) -> str:
    """三档：key=关键节点（十个词及变体），focus=口语化的「有戏/值得深入」，info=普通进展。"""
    text = _LEAD_NOISE.sub("", str(line or "").replace("*", ""))
    if _highlight_marker(text):
        return "key"
    if any(word in text for word in HIGHLIGHT_STRONG):
        return "focus"
    hit = any(word in text for word in HIGHLIGHT_FINDINGS)
    return "focus" if hit and any(word in text for word in HIGHLIGHT_FOLLOWUP) else "info"


def _is_highlight(line: str) -> bool:
    return _highlight_kind(line) != "info"


# 关键节点要稀有才有分量：同一个任务里连着几步都点亮，满屏「关键突破」只会显得假。
# 两步以内再出现的关键说法，降级成普通进度（文字照常显示，只是不再放大）。
HIGHLIGHT_COOLDOWN_STEPS = 3


def highlight_allowed(step: int, last_key_step: int) -> bool:
    """这一步能不能点亮关键节点。"""
    return last_key_step < 0 or step - last_key_step >= HIGHLIGHT_COOLDOWN_STEPS


def progress_level(line: str) -> str:
    """这条进度是普通进展（info）、值得深入（focus）还是关键节点（highlight）。"""
    kind = _highlight_kind(line)
    return "highlight" if kind == "key" else kind


def _clean_progress(text: str, limit: int = PROGRESS_MAX_CHARS) -> str:
    """把模型这一步的开场白压成一句话结论：去掉列表符号、标题符号、多余换行。"""
    raw = str(text or "").strip()
    if not raw:
        return ""
    line = ""
    for candidate in raw.splitlines():
        item = candidate.strip().strip("*#>-·• 　")
        item = re.sub(r"^\d+[.、)]\s*", "", item)
        if item:
            line = item
            break
    if not line:
        return ""
    # 关键节点允许长一点，普通进度控制在 60 字
    if _is_highlight(line):
        limit = HIGHLIGHT_MAX_CHARS
    # 只取第一句，读起来像结论而不是独白
    for sep in ("。", "；", "!", "！"):
        if sep in line:
            line = line.split(sep)[0] + sep
            break
    line = line.strip().rstrip("：:,，、* ")
    if len(line) > limit:
        line = line[: limit - 1] + "…"
    return line


def _looks_done(line: str) -> bool:
    """判断这句话是不是"做完了"的结论；"我先去看…"这种意图不算。"""
    text = str(line or "").strip()
    return bool(text) and text.startswith(DONE_MARKERS)


def _payload(result: Any) -> dict:
    """工具结果不一定是 dict（脱敏、旧版工具都可能返回字符串），统一按空字典兜住。"""
    return result if isinstance(result, dict) else {}


def _auto_progress(results: list[dict], with_next: bool = True) -> str:
    """模型没给结论时，用执行结果拼一句：做了什么 + 下一步。"""
    if not results:
        return ""
    labels: list[str] = []
    for item in results:
        tool = str(item.get("tool") or "")
        args = item.get("args") or {}
        payload = _payload(item.get("result"))
        label = ""
        if tool == "http_request":
            status = payload.get("status")
            url = _short_url(args.get("url"), 38)
            label = f"已请求 {url}，回来了 {status}" if status else f"请求 {url} 没通"
        elif tool == "run_shell":
            code = payload.get("exit_code")
            cmd = _brief(str(args.get("command") or ""), 18)
            if payload.get("killed"):
                label = "命令已被停止"
            elif code is not None:
                lines = len(str(payload.get("stdout") or "").splitlines())
                head = f"已跑完「{cmd}」" if cmd else "已跑完一条命令"
                label = f"{head}（退出码 {code}，{lines} 行输出）"
            else:
                label = "命令没跑起来"
        elif tool == "run_python":
            code = payload.get("exit_code")
            hint = _script_hint(args)
            head = f"已跑完脚本 {hint}" if hint else "已跑完一段脚本"
            label = f"{head}（退出码 {code}）" if code is not None else f"{head}，没跑起来"
        elif tool == "read_memory":
            if payload.get("total_chars"):
                label = f"已读记忆 {payload.get('next_cursor', 0)}/{payload.get('total_chars')} 字符"
            else:
                label = "已确认记忆目录为空"
        elif tool == "read_file":
            label = f"已读 {_brief(args.get('path'), 30)}（{payload.get('chars', 0)} 字符）"
        elif tool == "search_memory":
            label = f"记忆里命中 {payload.get('count', 0)} 处"
        elif tool == "list_dir":
            label = f"已列目录（{payload.get('count', 0)} 项）"
        if not label:
            label = PROGRESS_DONE.get(tool, "已完成一步")
        if label not in labels:
            labels.append(label)
    # 一长串动作用顿号连起来会变成一大坨看不清，最多两条、用分号隔开
    head = "；".join(labels[:2])
    if len(labels) > 2:
        head += f"；等 {len(labels)} 项"
    return f"{head}，继续下一步" if with_next else head


# 目标回显里出现这些字样，说明这一步真的摸到东西了
EVIDENCE_HINTS = (
    "未授权", "越权", "泄露", "私钥", "BEGIN PRIVATE KEY", "SQL syntax",
    "CVE-", "vulnerable", "default password", "默认口令", "敏感信息", "身份证",
)


def _evidence_progress(results: list[dict], seen: set[str] | None = None) -> str:
    """命令或请求的回显里出现真凭实据时，提一句「这条值得顺着查」。

    注意这里**不点亮**：真正的关键节点必须来自模型自己的判断或已归档的结论，
    平台按关键字自动命中就高亮，会出现满屏「命令输出里出现「泄露」」这种机械播报。
    同一类证据一次任务只提一次（seen 传进来累积），避免同一句话反复刷。
    """
    for item in results:
        tool = str(item.get("tool") or "")
        payload = _payload(item.get("result"))
        if not payload or payload.get("ok") is False:
            continue
        text = ""
        where = ""
        if tool == "http_request":
            text = str(payload.get("body") or "")
            where = _short_url((item.get("args") or {}).get("url"), 32)
        elif tool in ("run_shell", "run_python"):
            text = str(payload.get("stdout") or "") + "\n" + str(payload.get("stderr") or "")
            where = "命令输出"
        if not text:
            continue
        for hint in EVIDENCE_HINTS:
            if hint.lower() not in text.lower():
                continue
            key = f"{tool}:{hint}"
            if seen is not None:
                if key in seen:
                    continue
                seen.add(key)
            place = f"{where} 里" if where != "命令输出" else "命令输出里"
            return f"{place}出现「{hint}」，这条记下了，接下来顺着它往下查"
    return ""


SEVERITY_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}


def _finding_progress(results: list[dict]) -> str:
    """刚归档了一条漏洞：这是用户最该抬头看一眼的时刻，直接给他一句关键突破。"""
    for item in results:
        if item.get("tool") != "record_finding":
            continue
        payload = _payload(item.get("result"))
        if not payload.get("ok"):
            continue
        title = str((item.get("args") or {}).get("title") or payload.get("title") or "").strip()
        severity = str((item.get("args") or {}).get("severity") or "").strip().lower()
        level = SEVERITY_CN.get(severity, "")
        if severity in ("critical", "high"):
            tail = f"（{level}）" if level else ""
            return f"关键突破：已确认并归档「{title}」{tail}，这条最值得先看，证据已留档"
        tail = f"（{level}）" if level else ""
        return f"关键结论：已归档「{title}」{tail}，证据已留档"
    return ""


def _finding_cards(results: list[dict]) -> list[dict]:
    """刚归档的漏洞做成卡片：查到一条就立刻推给前端，不用等任务跑完再刷页面。

    以前只在进度里说一句「已归档」，用户想看清是什么漏洞，还得等整轮结束、
    切到漏洞结果页再刷新——发现是实时的，展示却是滞后的。
    """
    cards: list[dict] = []
    for item in results:
        if item.get("tool") != "record_finding":
            continue
        payload = _payload(item.get("result"))
        if not payload.get("ok"):
            continue
        args = item.get("args") or {}
        url = str(args.get("url") or payload.get("url") or "").strip()
        severity = str(args.get("severity") or "info").strip().lower()
        if severity not in SEVERITY_CN:
            severity = "info"
        cards.append(
            {
                "finding_id": int(payload.get("finding_id") or 0),
                "title": str(args.get("title") or "").strip() or "未命名漏洞",
                "severity": severity,
                "severity_label": SEVERITY_CN.get(severity, ""),
                "url": url,
                "domain": host_of(url),
                "capability": str(args.get("capability") or "").strip(),
                "created_at": now_iso(),
            }
        )
    return cards


def _memory_loading_line(args: dict) -> str:
    """「正在读取记忆」：读之前就让用户看见，而不是读完了才知道。

    只保留这一句，不把游标、文件名塞进括号里——进度行是给眼睛扫的，
    细节留给读完之后那条结论。省略号由前端做成动态的，不再是静态三个点。
    """
    return "正在读取记忆"


def _memory_done_line(results: list[dict]) -> str:
    """「已完成记忆读取」：读完了/读完这一段，都说清楚。"""
    for item in reversed(results):
        if str(item.get("tool") or "") != "read_memory":
            continue
        payload = _payload(item.get("result"))
        if payload.get("ok") is False:
            continue
        total = int(payload.get("total_chars") or 0)
        if not total:
            return "已完成记忆读取：记忆目录里没有可读内容"
        if payload.get("has_more"):
            return (
                f"已读记忆 {payload.get('next_cursor', 0)}/{total} 字符，"
                "接着读下一段"
            )
        files = payload.get("files") or []
        return f"已完成记忆读取：{len(files)} 个文件、共 {total} 字符"
    return ""


def _progress_event(content: str, results: list[dict], seen_evidence: set[str] | None = None) -> str:
    """一步做完后的那句结论：优先用模型自己的总结，否则按真实结果生成。"""
    line = _clean_progress(content)
    if progress_level(line) == "highlight":
        return line
    # 刚归档了漏洞，比模型那句泛泛的总结更值得说
    finding = _finding_progress(results)
    if finding:
        return finding
    # 记忆读完了：先把「已读完」说清楚
    memory = _memory_done_line(results)
    if memory:
        return memory
    # 模型自己给了像样的结论就用它，别用平台的机械兜底覆盖掉
    if _looks_done(line):
        return line
    # 回显里出现了真凭实据（未授权 / 私钥 / SQL 报错…）：提一句，但不点亮
    evidence = _evidence_progress(results, seen_evidence)
    if evidence:
        return evidence
    return _auto_progress(results)


SELF_CHECK_PROMPT = (
    "【收尾自检·用户明确要求】在给出最终结论之前，把下面这些逐条对一遍：\n"
    "{notes}\n\n"
    "对照要求检查：\n"
    "1. 用户这一轮提的每一件事，是不是都有交代——做过的说结果，做不了的说明原因。\n"
    "2. 用户级记忆里写过的偏好、约定、待办，有没有被漏掉或违反。\n"
    "3. 已勾选的测试能力里，有没有哪一项完全没试过；有就现在补一次最小验证，不要跳。"
    "平台台账没满时（结论末尾会写明还差几项），这一轮就不算结束：不许写「测试完成」，直接开工补下一项。\n"
    "3.1 写了「用户提示」的能力，提示里点名的入口/参数/检查点是不是都照做了；漏的现在补测，"
    "并在 report_capability 的 note 里逐条说明结果。\n"
    "4. 确认存在的问题是否都已经归档、报告是否齐全（复现步骤 + 请求/响应包 + 50 字内修复方案）。\n"
    "5. 泄露类结论有没有过「正常用户看不到」这道门槛：如果这条信息在正常页面/自己的账号里本来就能看到，"
    "把它从漏洞里删掉或降到信息级，别让公开信息占着高危名额。\n"
    "6. 这一轮测的域名下，每一条漏洞是不是都写清了「怎么一步步打出来的」：标题、漏洞URL、成因与影响、"
    "步骤N（做了什么 / 看到什么 / 由此推出什么），以及**每一步自己的请求包N与响应包N**（```http 代码块原样贴），"
    "最后跟上 50 字内修复方案。只贴最后一对报文、或把几步压成一句的，现在补开。"
    "清单按域名给：只测一个域名就列该域名本次测试的全部漏洞，测了几个域名就每个域名各列一份，同一条不重复列举。"
    "这是每一轮都要做的事，不是只在最后一轮做；缺的现在就补进正文，别让用户自己去漏洞结果页翻。\n"
    "对得上就直接给最终结论；有缺口就直接补做完再说，不要只写「建议补充」。"
)

async def _final_self_check(username: str, used_tools: set[str]) -> tuple[str, str]:
    """收尾自检：再读一遍用户级记忆 + 当前能力清单，交给模型逐项核对。

    用户的要求是「任务完成前再读一次记忆，确保没有遗漏」以及「完成时核对记忆与能力，
    确保每一项都试过」。这两件事不该指望模型自己想起来，所以由平台在收尾前直接做掉，
    再把结果摆到它面前，让它对着清单收口。
    """
    notes: list[str] = []
    # 直接读底层分块，不走 dispatch_tool：这是一次平台自检，不该产生工具调用开销、
    # 也不该被外部替换的工具实现影响
    try:
        data = memory_chunk(cursor=0, limit=MEMORY_PRELOAD)
        body = str(data.get("content") or "").strip()
        total = int(data.get("total_chars") or 0)
    except Exception as exc:  # 读不到记忆不该阻断收口
        body, total = "", 0
        notes.append(f"- 用户级记忆：读取失败（{type(exc).__name__}: {exc}），按没有额外约定处理")
    else:
        if body:
            notes.append(f"- 用户级记忆（共 {total} 字符，节选）：\n{_brief(body, 3000)}")
        else:
            notes.append("- 用户级记忆：目录为空，没有额外的偏好或待办")
    caps = [str(item.get("name") or "").strip() for item in enabled_items()]
    caps = [item for item in caps if item]
    shown = "、".join(caps[:40]) + ("…" if len(caps) > 40 else "")
    notes.append(f"- 已勾选测试能力（{len(caps)} 项）：{shown or '（一项都没勾）'}")
    tried = "、".join(sorted(used_tools)) if used_tools else "（这一轮没调用任何工具）"
    notes.append(f"- 这一轮实际用过的工具：{tried}")
    if caps:
        line = f"已完成收尾核对：重读了一遍记忆，对着 {len(caps)} 项能力逐条对过，接下来给最终结论"
    else:
        line = "已完成收尾核对：重读了一遍记忆，能力清单里一项都没勾，接下来给最终结论"
    return SELF_CHECK_PROMPT.format(notes="\n".join(notes)), line


# 补测顺序与覆盖台账都在 coverage 里：勾了哪些、验了几项、还差哪些，由台账算，
# 不靠模型自己回忆「我测过没有」。
COVERAGE_ORDER: tuple[str, ...] = coverage.COVERAGE_ORDER


# 用户这句话是不是「去做一次渗透测试」——只有这类任务才适用「没验够不许收口」
ASSESSMENT_HINTS: tuple[str, ...] = (
    "测试",
    "评估",
    "渗透",
    "漏扫",
    "挖洞",
    "安全",
    "漏洞",
    "验一下",
    "测一下",
    "跑一遍",
    "风险",
    "攻击面",
    # 「继续测」「接着测」「把剩下的补完」这类催办话术：用户最常这么发，
    # 以前一个都认不出来，整轮就不算「在测」，台账再满也照样收口。
    "继续测",
    "接着测",
    "接着跑",
    "继续跑",
    "补测",
    "测完",
    "测一遍",
    "全测",
    "都测",
    "开测",
    "核查",
    "检查一下",
)


def assessment_task(text: str) -> bool:
    body = str(text or "").lower()
    return any(hint in body for hint in ASSESSMENT_HINTS)


# 三个方向是用户定下的硬指标：一轮渗透测试收尾时，这三条都必须有明确说法。
# 不是「随便扫扫看有没有洞」，而是奔着能落地的三类危害去。
AXIS_GOALS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "高敏感信息泄露",
        ("泄露", "敏感信息", "凭据", "密钥", "口令", "数据库", "源码", "备份", "身份证", "个人信息", "配置文"),
    ),
    (
        "控制权限",
        ("权限", "未授权", "越权", "后台", "登录", "接管", "控制", "上传", "命令执行", "rce", "提权"),
    ),
    (
        "可造成实际危害",
        ("危害", "影响", "读取", "写入", "篡改", "删除", "执行", "拿到", "可读", "可写", "数据"),
    ),
)


def missing_axes(text: str) -> list[str]:
    """结论里哪几个方向还没交代。

    判断依据是模型自己的结论——它必须逐个方向说清「有」还是「没有」，
    而不是用一句「未发现明显问题」把三个方向一起糊过去。
    """
    body = str(text or "").lower()
    return [name for name, hints in AXIS_GOALS if not any(hint.lower() in body for hint in hints)]


def pending_capabilities(session_id: int = 0, limit: int = 0) -> list[str]:
    """还没验的能力名，按补测优先级排。

    有会话就查覆盖台账（真的还差哪几项）；没有会话（比如纯提示词构造）退回按顺序列。
    """
    if session_id:
        todo = coverage.pending(int(session_id), limit=limit)
        return [item["name"] for item in todo]
    enabled = set(enabled_keys())
    names: list[str] = []
    for key in COVERAGE_ORDER:
        if key in enabled and key in CAPABILITY_BY_KEY:
            names.append(CAPABILITY_BY_KEY[key]["name"])
        if limit and len(names) >= limit:
            break
    return names


ARCHIVE_PROMPT = (
    "【平台判定：结论里已经确认了问题，但一条都没进漏洞结果页】\n"
    "你刚才的答复里已经给出了具体问题（有等级、有证据），可平台这边 findings 还是 0 条，"
    "用户打开「漏洞结果」看不到任何东西——这不算交付。\n"
    "现在逐条用 record_finding 归档，一条漏洞一次调用：\n"
    "1. url 填被测的完整地址；title 写清是什么漏洞；severity 只能是 critical/high/medium/low/info；\n"
    "2. description 写造成什么影响，remediation 控制在 50 字以内；\n"
    "3. request_packet / response_packet 用你已经拿到的原始报文原样填，不要重编、不要只写一句话摘要；\n"
    "4. capability 填命中的能力 key（没有就留空）。\n"
    "归档完再给最终答复；已经归档过的不要重复写。"
)


def _claims_findings(text: str) -> bool:
    """答复里是不是已经在报「有问题」了（用于逼它先归档再收尾）。"""
    body = str(text or "")
    if any(phrase in body for phrase in ("没有发现", "未发现", "不存在漏洞", "0 条", "无漏洞")):
        return False
    return bool(
        re.search(r"(高危|中危|严重|紧急|critical|high risk)", body, re.IGNORECASE)
        or re.search(r"(确认|已证实|实测)\S{0,6}(存在|可复现)", body)
    )


COVERAGE_CONTEXT = (
    "【能力覆盖台账·平台实算，不看你自己的回忆】{line}\n"
    "这本账只认 report_capability 的结果，用法：\n"
    "1. 每验完一项就调用一次 report_capability：capability 填 key，status 只能填 "
    "vulnerable（有漏洞）/ clean（验过没问题）/ blocked（被目标挡住）/ inconclusive（证据不足），"
    "note 写清测了哪个入口、看到什么；\n"
    "2. 验出问题的先 record_finding 归档（归档会自动把这一项记成「有漏洞」），再上报；\n"
    "3. 没上报的项一律算没验，平台会一直催；一项都不报，这轮就永远不会被认为做完；\n"
    "4. 不要问用户「先测哪一类」，顺序按台账给出的下一批往下走。"
)


NEXT_ROUND_PROMPT = (
    "【平台判定：这一轮还没做完，不能收口】你现在给出的结论是「只做了侦察、还没逐项验证」。"
    "这不是交付，是半成品。平台把这一轮的真实情况摆给你：\n"
    "{notes}\n\n"
    "这一轮必须奔着三个方向去，一个都不能落下：\n"
    "  ① 高敏感信息泄露——凭据、密钥、口令、身份证/个人信息、数据库、源码、备份文件有没有暴露；"
    "判定门槛是「正常用户看不到的才算」，页面上本来就能看到的不算泄露；\n"
    "  ② 控制权限——能不能未授权进后台、越权看别人的数据、上传拿到执行、命令执行、接管账号；\n"
    "  ③ 可造成实际危害——能不能真的读到/改掉/删掉业务数据、能不能打穿到内网或其他系统。\n"
    "三个方向无论有没有结果，最后都要各给一句明确说法（有：证据是什么；没有：测了哪些入口、为什么排除）。\n\n"
    "接下来照这个顺序继续动手，不要再问用户「先测哪一类」——顺序由你定，就按下面这个来：\n"
    "{order}\n"
    "要求：\n"
    "1. 每一类都要真的发出请求拿到响应，用 http_request 或 run_python 跑，不要只在正文里写「建议测」。\n"
    "2. 拿到的请求包与响应包原样留着；确认存在问题就用 record_finding 归档（带证据），没问题就往下走。\n"
    "3. 每做完一类播一句进展，写清楚验了什么、结果如何。\n"
    "4. 只有下面三种情况可以停：能力清单里该测的都测过、目标明确挡住了（401/403/WAF 统一拦截）、\n"
    "   或者三个方向都已经有结论（不是「还没验」，而是「验过，有/没有」）。除此之外都不算结束。\n"
    "红线不变：只做只读验证，不写改删数据、不压测、不爆破、不横向。"
)


def _looks_sensitive(path: str) -> bool:
    """这个路径片段是不是敏感文件。

    后缀型特征（.env / .key / .dump …）必须落在片段末尾或目录分隔处——
    否则脚本里的 `json.dumps` 会被 `.dump` 命中，模型每写一次脚本都要弹一次
    「json.dumps 属于你本机的凭据或密钥」，活生生把正常测试拦住。
    """
    text = str(path or "").lower()
    for hint in SENSITIVE_PATH_HINTS:
        position = text.find(hint)
        if position < 0:
            continue
        if hint.startswith(".") and not hint.endswith("."):
            after = text[position + len(hint) : position + len(hint) + 1]
            if after and after not in "/\\.":
                continue
        return True
    return False


def sensitive_kinds(payload: Any) -> list[str]:
    """探测任意工具结果里的敏感信息种类。"""
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return [name for name, pattern in SENSITIVE_PATTERNS if pattern.search(text)]


def _mask_text(text: str) -> str:
    for name, pattern in SENSITIVE_PATTERNS:
        if name == "凭据明文":
            text = pattern.sub(lambda m: m.group(0).replace(m.group(1), "***"), text)
        else:
            text = pattern.sub(f"[已脱敏:{name}]", text)
    return text


# 字段名本身就是凭据：这种键的值直接打码，不必等正则匹配
SECRET_KEY_HINT = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|cookie|session)"
)


def mask_sensitive(payload: Any) -> Any:
    """把敏感值就地抹掉，保留结构（dict/list 还是 dict/list），方便上层继续按字段取用。"""
    if isinstance(payload, str):
        return _mask_text(payload)
    if isinstance(payload, dict):
        masked: dict[Any, Any] = {}
        for key, value in payload.items():
            if (
                isinstance(value, str)
                and len(value) >= 6
                and SECRET_KEY_HINT.search(str(key))
                and "[已脱敏" not in value
            ):
                masked[key] = "[已脱敏]"
            else:
                masked[key] = mask_sensitive(value)
        return masked
    if isinstance(payload, list):
        return [mask_sensitive(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(mask_sensitive(item) for item in payload)
    return payload


def _setting_on(key: str, default: str = "true") -> bool:
    return str(get_settings().get(key, default) or "").lower() in ("1", "true", "yes", "on")


def confirmation_reason(tool: str, args: dict, session_id: int = 0) -> str:
    """返回"为什么需要用户确认"；空字符串表示可以直接执行。

    只有两类：读自己的敏感信息、删除类操作，各自听「操作询问」里的细分开关。
    目标范围不参与判断——登录时确认的免责声明就是授权，用户点名的目标直接跑。
    执行只读命令、向任何目标发请求、读目标侧的数据、登记资产、发起渗透测试都不问。
    同一处信息在同一会话里点过一次「确认」，后续直接放行（记在 chat_grants）。
    """
    if args.get("__reveal_sensitive"):
        return ""
    if session_id and has_grant(session_id, grant_key(tool, args)):
        return ""
    if tool in ("run_shell", "run_python"):
        command = str(args.get("command") or args.get("code") or "")
        if ask_enabled(ASK_DELETE_KEY):
            hit = shell_delete_reason(command, "python" if tool == "run_python" else "shell")
            if hit:
                return f"{hit}，属于不可逆操作"
        if ask_enabled(ASK_SENSITIVE_KEY):
            hit = _self_sensitive_hit(command)
            if hit:
                return hit
        return ""
    if tool == "http_request":
        # 安全模式：会改动目标数据的方法先问一声（GET/HEAD 这类只读的不问）
        if _setting_on("safe_mode", "true") and ask_enabled(ASK_DELETE_KEY):
            method = str(args.get("method") or "GET").strip().upper()
            if method in WRITE_METHODS:
                return f"{method} 会改动目标上的数据，安全模式开着时先问一声"
        return ""
    if tool in ("read_file", "read_memory", "search_memory") and ask_enabled(ASK_SENSITIVE_KEY):
        if not _setting_on("sensitive_path_checks", "true"):
            return ""
        target = str(args.get("path") or args.get("only") or args.get("keyword") or "")
        # 目标侧的数据（工作目录里的物料、目标的 .env）不打扰用户；只有我自己的凭据才问
        if _looks_sensitive(target) and data_owner(target) == "self":
            return f"{target} 是你本机的凭据或密钥"
        return ""
    return ""


def confirm_label(tool: str, reason: str = "") -> str:
    """确认卡片的标签：说清是哪一类确认，而不是一个泛泛的"需要确认"。"""
    if "删除" in reason or "删库" in reason or "清空" in reason:
        return "删除操作"
    if "凭据" in reason or "敏感" in reason:
        return "读取敏感文件"
    if "安全模式" in reason or "改动目标" in reason:
        return "写入确认"
    return CONFIRM_LABELS.get(tool, "需要确认")


def action_summary(tool: str, args: dict) -> str:
    """把工具调用翻译成一句人能看懂的话，用于确认卡片。"""
    if tool == "start_scan":
        targets = [str(item) for item in (args.get("targets") or [])]
        asset_ids = [item for item in (args.get("asset_ids") or []) if isinstance(item, int)]
        if not targets and asset_ids:
            placeholders = ",".join(["?"] * len(asset_ids))
            with db() as conn:
                rows = conn.execute(
                    f"SELECT name, target FROM assets WHERE id IN ({placeholders})", asset_ids
                ).fetchall()
            targets = [str(row["name"] or row["target"]) for row in rows]
        if isinstance(targets, list):
            targets = "、".join(targets[:6]) or "（按资产台账）"
        mode = {"active": "完整渗透测试", "passive": "情报测绘"}.get(str(args.get("mode") or "active"), "完整渗透测试")
        profile = {"quick": "快速", "standard": "标准", "deep": "深度"}.get(
            str(args.get("profile") or "standard"), "标准"
        )
        return f"发起渗透测试：目标 {_brief(targets, 120)} · 方式 {mode} · 强度 {profile}"
    if tool == "http_request":
        return f"向 {_brief(args.get('url'), 160)} 发送 {str(args.get('method') or 'GET').upper()} 请求"
    if tool == "run_shell":
        return f"执行命令：{_brief(args.get('command'), 160)}"
    if tool == "run_python":
        return f"运行 Python 脚本：{_brief(args.get('code'), 160)}"
    if tool == "cancel_scan":
        return f"终止测试任务 #{args.get('scan_id')}"
    if tool == "update_finding_status":
        return f"把风险 #{args.get('finding_id')} 的处置状态改为 {args.get('status')}"
    if tool == "record_finding":
        return f"归档检测结论「{_brief(args.get('title'), 60)}」到 {_brief(args.get('url'), 120)}"
    if tool == "write_file":
        content = str(args.get("content") or "")
        return f"写入报告文件 {_brief(args.get('path'), 120)}（{len(content)} 字符）"
    if tool == "read_file":
        return f"读取文件 {_brief(args.get('path'), 120)}"
    if tool == "read_memory":
        return f"读取用户级记忆 {_brief(args.get('only') or '全部文件', 120)}"
    return f"{CONFIRM_LABELS.get(tool, tool)}：{_brief(json.dumps(args, ensure_ascii=False), 120)}"


def create_action(
    session_id: int,
    username: str,
    tool: str,
    args: dict,
    reason: str = "",
    summary: str = "",
) -> dict[str, Any]:
    summary = summary or action_summary(tool, args)
    if reason:
        summary = f"{summary}｜{reason}"
    # 同一件事只留一张卡：模型重复发起同一个操作时复用待确认的那张，
    # 否则用户会看到「同一句话弹好几次」，点掉一张又来一张
    signature = action_signature(tool, args)
    with db() as conn:
        for row in conn.execute(
            "SELECT * FROM chat_actions WHERE session_id=? AND status='pending' ORDER BY id DESC",
            (session_id,),
        ).fetchall():
            try:
                old_args = json.loads(row["args_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                old_args = {}
            if str(row["tool_name"] or "") == tool and action_signature(tool, old_args) == signature:
                return {
                    "id": int(row["id"]),
                    "tool": tool,
                    "args": args,
                    "summary": row["summary"] or summary,
                    "status": "pending",
                    "reused": True,
                }
        cursor = conn.execute(
            """INSERT INTO chat_actions
               (session_id, username, tool_name, args_json, summary, status, created_at)
               VALUES (?,?,?,?,?,'pending',?)""",
            (session_id, username, tool, json.dumps(args, ensure_ascii=False)[:4000], summary, now_iso()),
        )
        action_id = cursor.lastrowid
    audit(username, "action_pending", f"等待确认：{summary}")
    return {"id": action_id, "tool": tool, "args": args, "summary": summary, "status": "pending"}


def get_action(action_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM chat_actions WHERE id=?", (action_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    try:
        data["args"] = json.loads(data.get("args_json") or "{}")
    except json.JSONDecodeError:
        data["args"] = {}
    return data


def decide_action(action_id: int, status: str) -> None:
    with db() as conn:
        row = conn.execute("SELECT * FROM chat_actions WHERE id=?", (action_id,)).fetchone()
        conn.execute(
            "UPDATE chat_actions SET status=?, decided_at=? WHERE id=?",
            (status, now_iso(), action_id),
        )
    # 用户点头后记住这处信息：同一会话里再遇到同一个人/同一个文件，不再重复打扰
    if status == "approved" and row:
        try:
            args = json.loads(row["args_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            args = {}
        session_id = int(row["session_id"] or 0)
        tool = str(row["tool_name"] or "")
        remember_grant(session_id, grant_key(tool, args), "approved")
        # 已经同意读这份文件，就别再为「结果里有凭据，要不要看原文」问第二次
        remember_grant(session_id, "reveal:" + grant_key(tool, args), "reveal")


def pending_actions(session_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM chat_actions WHERE session_id=? AND status='pending' ORDER BY id DESC",
            (session_id,),
        ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        try:
            data["args"] = json.loads(data.get("args_json") or "{}")
        except json.JSONDecodeError:
            data["args"] = {}
        items.append(data)
    return items


# ---------------- 选择题式提问 ----------------


def normalize_choices(raw: Any) -> list[dict[str, str]]:
    """把模型给的选项规范成 2-4 个 {label, hint, value}。"""
    items: list[dict[str, str]] = []
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, str):
                label, hint, value = entry.strip(), "", entry.strip()
            elif isinstance(entry, dict):
                label = str(entry.get("label") or entry.get("title") or "").strip()
                hint = str(entry.get("hint") or entry.get("description") or "").strip()
                value = str(entry.get("value") or label).strip()
            else:
                continue
            if not label:
                continue
            label = label[:28]
            items.append(
                {
                    "label": label,
                    "hint": _brief(hint, 60) if hint else "",
                    "value": (value or label)[:200],
                }
            )
            if len(items) >= 4:
                break
    return items


def create_choice(
    session_id: int,
    username: str,
    question: str,
    options: list[dict[str, str]],
    allow_custom: bool = False,
) -> dict[str, Any]:
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO chat_choices
               (session_id, username, question, options_json, allow_custom, status, created_at)
               VALUES (?,?,?,?,?,'pending',?)""",
            (
                session_id,
                username,
                _brief(question, 200),
                json.dumps(options, ensure_ascii=False)[:4000],
                1 if allow_custom else 0,
                now_iso(),
            ),
        )
        choice_id = cursor.lastrowid
    return {
        "id": choice_id,
        "question": _brief(question, 200),
        "options": options,
        "allow_custom": bool(allow_custom),
        "status": "pending",
    }


def get_choice(choice_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM chat_choices WHERE id=?", (choice_id,)).fetchone()
    if not row:
        return None
    return _choice_payload(dict(row))


def _choice_payload(row: dict[str, Any]) -> dict[str, Any]:
    data = dict(row)
    try:
        data["options"] = json.loads(data.get("options_json") or "[]")
    except json.JSONDecodeError:
        data["options"] = []
    data["allow_custom"] = bool(data.get("allow_custom"))
    return data


def decide_choice(choice_id: int, chosen: str, status: str = "chosen") -> None:
    with db() as conn:
        conn.execute(
            "UPDATE chat_choices SET status=?, chosen=?, decided_at=? WHERE id=?",
            (status, _brief(chosen, 200), now_iso(), choice_id),
        )


def pending_choices(session_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM chat_choices WHERE session_id=? AND status='pending' ORDER BY id DESC",
            (session_id,),
        ).fetchall()
    return [_choice_payload(dict(row)) for row in rows]


# ---------------- 单次模型调用 ----------------


async def _model_turn(
    llm: Any,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    max_tokens: int = MAX_OUTPUT_TOKENS,
) -> AsyncGenerator[tuple[str, Any], None]:
    """一次完整的模型调用：优先流式，失败回落非流式，瞬时故障自动重试一次。

    流式那一路套着看门狗：连续 ``STEP_STALL_SECONDS``（默认 300 秒）一片都不来，
    就判定这一步卡住，掐掉请求重发一次——模型调用没有副作用，重启是安全的。
    """
    streamer = getattr(llm, "stream_complete", None)
    last_error = ""
    tokens = max_tokens
    downgraded = False
    restarts = 0
    for attempt in range(4):
        text = ""
        message: dict[str, Any] | None = None
        finish = ""
        stalled = False
        if streamer is not None:
            stream = iter_with_watchdog(
                streamer(messages, tools=tools, max_tokens=tokens),
                STALL_SECONDS,
                "模型思考",
            )
            try:
                async for kind, data in stream:
                    if kind == "text":
                        text += str(data)
                        yield ("delta", str(data))
                    elif kind == "final":
                        message = (data or {}).get("message") or {}
                        finish = str((data or {}).get("finish_reason") or "")
                    elif kind == "error":
                        last_error = str(data)
                        if text:
                            # 已经输出一半，重来会导致正文重复
                            yield ("error", f"输出中断：{last_error}")
                            return
                        message = None
            except StepStalled as exc:
                stalled = True
                last_error = str(exc)
        if stalled:
            # 已经出了半截正文的话不能重来（会重复），如实报中断
            if text:
                yield ("error", f"输出中断：{last_error}")
                return
            if restarts >= 1:
                yield (
                    "error",
                    f"{last_error}；重启过一次仍然没有进展，已终止这一步（没有继续干等）。"
                    "可以再发一句话重试，或换一个模型。",
                )
                return
            restarts += 1
            yield (
                "status",
                f"{stall_message(STALL_SECONDS, '模型思考')}，已掐断这次请求，正在重新开始这一步…",
            )
            await asyncio.sleep(1.0)
            continue
        if message is None and last_error and _hard_error(last_error) and not _token_limit_error(last_error):
            # 鉴权 / 请求格式这类错误换个协议也一样失败，没必要再打一次
            # （max_tokens 过大的 400 例外：那是参数问题，降一档就能成）
            yield ("error", last_error)
            return
        if message is None:
            result = await llm.complete(messages, tools=tools, max_tokens=tokens)
            if result.ok:
                message = result.data.get("message") or {}
                finish = str(result.data.get("finish_reason") or "")
            else:
                last_error = result.message or "模型调用失败"
        if message is not None:
            yield ("final", {"message": message, "finish_reason": finish})
            return
        # 模型不认这么大的 max_tokens（部分自建/国产网关上限是 4096、8192）：减半再来，
        # 而不是把「参数非法」直接甩给用户
        if not downgraded and not text and _token_limit_error(last_error):
            downgraded = True
            tokens = max(2048, tokens // 2)
            yield ("status", f"该模型不支持 {max_tokens} 的输出长度，按 {tokens} 重新请求…")
            continue
        if attempt == 0 and not text and _transient_error(last_error):
            yield ("status", "上游临时故障，正在自动重试…")
            await asyncio.sleep(1.5)
            continue
        yield ("error", last_error or "模型没有返回内容")
        return


def _shrink_tool_history(messages: list[dict[str, Any]], budget: int = CONTEXT_CHAR_BUDGET) -> None:
    """上下文超标时压缩较早的工具结果，保证长任务不会把窗口吃满。"""

    def total() -> int:
        return sum(len(str(item.get("content") or "")) for item in messages)

    if total() <= budget:
        return
    tool_indexes = [i for i, item in enumerate(messages) if item.get("role") == "tool"]
    # 最近的 6 条工具结果保持完整，方便模型引用刚读到的记忆与命令输出
    for index in tool_indexes[:-6]:
        payload = str(messages[index].get("content") or "")
        if len(payload) > 400:
            messages[index] = {**messages[index], "content": payload[:400] + "…（较早的工具结果已压缩，需要时重新读取）"}
        if total() <= budget:
            return
    # 仍然超标，就压缩较早的助手正文
    for index, item in enumerate(messages):
        if item.get("role") != "assistant":
            continue
        payload = str(item.get("content") or "")
        if len(payload) > 240:
            messages[index] = {**item, "content": payload[:240] + "…（已压缩）"}
        if total() <= budget:
            return


async def _run_agent(
    session_id: int,
    username: str,
    provider: str = "",
    resume_note: str = "",
    approved: set[str] | None = None,
    token: "RunToken | None" = None,
    stats: dict[str, Any] | None = None,
) -> AsyncGenerator[dict[str, Any], None]:
    llm = pick_llm(provider)
    if llm is None:
        yield {
            "type": "error",
            "message": "尚未配置可用的大模型。请前往「API 中心」填写 DeepSeek、OpenAI、Claude、Gemini、通义、Kimi、智谱、豆包等任一大模型 API Key，并点击测试连接。",
        }
        return

    # 每轮开始前重新读取模型能力与开关，作为最新的工作边界
    # 漏洞清单按域名计：这一轮碰过哪些域名由本轮的发电/归档动作重新记；
    # 漏洞本身按对话累积，同一个域名要给用户一份完整清单，不能只列这一轮新发现的。
    _SESSION_FINDINGS[int(session_id)] = []
    _ROUND_DOMAINS[int(session_id)] = []
    # 这一轮开工时库里的最大消息 id：后面「不要重复上一轮」只跟它之前的比，
    # 免得把本轮刚写出来的内容当成「重复」删掉
    baseline_id = _max_message_id(session_id)
    history = _history(session_id)
    # 用户这一句是「问结果」而不是「派活」：答就行，不要再跑一遍
    user_text = _last_user_text(session_id)
    asking = not resume_note and question_turn(user_text)
    # 这句话是不是「去做一次渗透测试」：决定收尾时要不要按「没验够」把它推回去。
    # 认不出来的典型就是「继续测 xxx」这类催办话术——关键词表里已经补上，
    # 但不能再放宽到「句子里有 URL 就算」（用户让「看一下首页能不能打开」不能被按渗透测试推回）。
    testing_task = assessment_task(user_text) or bool(resume_note)
    messages: list[dict[str, Any]] = [
        # 自动渗透开着时，系统提示末尾追加一段「覆盖第 8 条」的口径：
        # 第 8 条写死了「清单之外一律不测」，只在开关关闭时才算数
        {"role": "system", "content": SYSTEM_PROMPT + (AUTO_PENTEST_SYSTEM_NOTE if auto_pentest_enabled() else "")},
        {"role": "system", "content": _context_message()},
        {"role": "system", "content": _workspace_context()},
        {"role": "system", "content": capabilities_context()},
    ]
    # 能力覆盖台账：勾了哪些、验了几项、还差哪些——每轮都摆出来，模型不用猜
    if not asking:
        messages.append(
            {"role": "system", "content": COVERAGE_CONTEXT.format(line=coverage.summary_line(session_id))}
        )
    if history:
        # 台账独立于历史预算：哪怕最早的结论被裁掉，做过什么也始终在上下文里
        messages.append({"role": "system", "content": _work_digest(session_id)})
    messages.extend(history)
    # 每轮开工前先把「已经知道的」收成一份交给模型：台账、已归档漏洞、做过的动作、
    # 上一轮写到哪。用户要求「以已知为基础往下做、不能重复之前的输出」，
    # 这份摘要就是那个「基础」；提问的轮次不塞，免得把答案挤掉。
    brief_line = ""
    if not asking and history:
        brief = _round_brief(session_id)
        if brief:
            messages.append({"role": "system", "content": ROUND_BRIEF.format(known=brief)})
            brief_line = _round_brief_line(session_id)
    if asking:
        # 必须先于「播报要求不变」：那一套是给干活的轮次用的，提问的轮次只会把答案挤掉
        messages.append(
            {
                "role": "system",
                "content": (
                    "【用户这句话是在提问，不是在派活】他要答案，不是要你动手。\n"
                    "怎么答：第一句先给判断——测过就答「测过」，没测过就答「没测」；"
                    "有发现就答「有，共 N 条」，没有就答「没有」。"
                    "然后按上面【本次会话已经做过的事】逐项说清：测了哪几类、各自结果、哪几项还没测。\n"
                    "两条硬约束：① 这一轮不要重新执行，不要跑脚本、不要重新发包、不要再扫一遍，"
                    "也不要为了「再确认一下」重复查询，记录里已经有的就是答案；"
                    "② 不要写「已…，接下来…」这种进度句，也不要用「继续下一步」收尾，用户在等答案。\n"
                    "记录里确实没有他问的那一项，就直接说「这一项我没有记录」，"
                    "再用 ask_choice 问要不要现在补测，不要假装测过。"
                    "如果你判断该补测哪几项，把选项放进 ask_choice 卡片，正文里不要写问句。"
                ),
            }
        )
    elif history:
        # 第一轮之后模型容易变懒：只调工具、不写结论。每轮都重新强调一次。
        messages.append(
            {
                "role": "system",
                "content": (
                    "【本轮是接着上面继续的对话】播报要求不变：每做完一步就给一句结论，"
                    "写清楚这一步拿到了什么、下一步做什么；出现新发现、确认存在、有突破、"
                    "已经证明时，直接用这些词开头（例如「重大发现：…」「确认存在：…」"
                    "「有突破：…」「新的进展：…」），平台会高亮给用户看。"
                    "不要因为已经聊过几轮就不再说，也不要整段沉默只调工具。"
                ),
            }
        )
    if resume_note:
        messages.append({"role": "user", "content": resume_note})
    yield {"type": "status", "message": "正在思考…"}
    if brief_line:
        # 让用户也看见「这一轮从哪接」：不是黑箱再跑一遍
        _save_message(session_id, "progress", brief_line, "step")
        yield {"type": "progress", "content": brief_line, "level": "step"}

    approved_sigs = set(approved or ())
    cache: dict[str, str] = {}
    covered_connectors: set[str] = set()
    executed_calls = 0
    choice_used = False
    answer_retried = False
    hard_stop = False
    last_progress = ""
    # 同一句话一次任务里只播一次：模型绕圈、反复跑同一个脚本时，
    # 「脚本跑完（退出码 0），继续下一步」会一条条刷屏，看着像卡进了循环
    seen_progress: set[str] = set()
    seen_evidence: set[str] = set()
    used_tools: set[str] = set()
    # 动手次数：只数真正朝目标发请求 / 跑脚本的调用，用来说明「到底验了多少」
    test_actions = 0
    tested_hosts: set[str] = set()
    # 连续多少个请求没打成功：到 3 的倍数就追问一次「这个方向是不是没路了」
    http_fail_streak = 0
    # 判「干完没干完」用：允许平台把模型推回去几次
    coverage_pushes = 0
    # 自动渗透开着时，台账清空后再补一次「清单外」的广度检查（只推一次，不能无限拖）
    breadth_pushed = False
    findings_recorded = 0
    archive_pushed = False
    # 连续几步没有任何新结果（全被缓存挡回、或者只重复同一句话）就提前收口
    stall_steps = 0
    last_key_step = -99
    progress_log: list[str] = []
    # 收尾自检：模型想收尾时先核对一遍记忆与能力清单，再真正结束
    self_checked = False
    held_content = ""

    def stopped() -> bool:
        return bool(token and token.cancelled)

    def _pending_left() -> int:
        """能力台账里还有几项没结论；没勾能力、或这轮只是提问，都算 0。

        平台用它决定「这一轮给多少步、跑到多久」：台账没满就不许按固定预算收口。
        """
        if asking:
            return 0
        try:
            if not coverage.selected_keys():
                return 0
            return int(coverage.summary(session_id).get("pending") or 0)
        except Exception:
            # 台账读不出来不能把整轮带死：退回固定预算
            return 0

    budget = 3 if asking else round_step_budget(_pending_left())
    max_calls = max(30, budget * 2)
    step_tools = QUESTION_TOOLS if asking else TOOL_SPECS

    def finish_gap(conclusion: str = "") -> str:
        """收尾前的完成度判定。

        只看了两眼页面、跑个脚本就写「尚未逐项验证」的，不算做完——平台把它推回去补测。
        判定只看客观事实：朝目标动手了几次、归档了几条、三个方向有没有各有说法；
        不看模型自己怎么措辞，也不接受「未发现明显问题」这种一句话糊过去。
        用户定死的规矩：能力台账没满就不能收口——这一条不看推回次数，推到有结论为止。
        """
        nonlocal breadth_pushed
        # 勾选的能力还没验完：这是最硬的判据，先算出来，后面的「推几次就放弃」对它不生效
        ledger_gap = bool(coverage.selected_keys()) and not coverage.all_done(session_id)
        if coverage_pushes >= MAX_COVERAGE_PUSHES and not ledger_gap:
            return ""
        # 判据三条，命中任一条就要补完再收口：
        #   ① 勾了能力却没验完（最硬）；② 只动手了几次、一条没归档（结论太薄）；
        #   ③ 三个方向缺两个以上（只在一个面上打转）。
        # 用户只是让看一眼、查个状态，不该被按「渗透测试没做够」推回去
        if not testing_task:
            return ""
        # 没打过任何目标地址（本地统计、看平台状态这类活）不适用：别把普通任务也推回去。
        # 但「勾了能力还没验完」是例外：一项都没动手恰恰是必须推回去的情况——
        # 只写结论、连包都没发的，不能因为「没打过目标」就放它收口。
        if not ledger_gap and (not tested_hosts or test_actions <= 0):
            return ""
        missing = missing_axes(conclusion)
        thin = not findings_recorded and test_actions < MIN_TEST_ACTIONS
        # 三个方向缺两个以上，说明这一轮只在一个面上打转，同样不算做完
        axes_gap = len(missing) >= 2
        if not thin and not axes_gap and not ledger_gap:
            # 台账已清空、结论也不薄：自动渗透开着的话，再补一次「清单外」的广度检查。
            # 只推一次——用户开这个开关要的是「多看一眼清单外」，不是无限往下挖。
            if (
                auto_pentest_enabled()
                and not breadth_pushed
                and test_actions > 0
            ):
                breadth_pushed = True
                return (
                    "【平台提醒：自动渗透已开启，清单外的漏洞类型还没过一遍】\n"
                    "上面勾选的能力确实都有结论了，但这一轮到此为止只完成了「清单内」的部分。\n"
                    "现在花一轮做广度检查，做完就可以收尾：\n"
                    "1. 回看你已经抓到的前端 JS、响应头、接口清单，找出清单没覆盖但明显有入口的东西——\n"
                    "   GraphQL 内省与批量查询、文件上传、反序列化、缓存投毒、业务逻辑/金额越权、\n"
                    "   JWT/OAuth/SAML 配置、Actuator / Swagger / Druid 这类管理面未授权、组件已知漏洞入口；\n"
                    "2. 每个有入口的点真的发一次请求确认，别只写「建议测」；\n"
                    "3. 验出问题用 record_finding 归档（标题写清类别），没有问题的也在结论里写一句「看过、无问题」；\n"
                    "4. 这一轮确实没有清单外的入口可测，就直接说「清单外未发现可测入口」并收尾。\n"
                    "红线不变：只做只读验证，不写改删数据、不压测、不爆破、不横向。"
                )
            return ""
        if ledger_gap:
            text = coverage.next_batch_prompt(session_id, batch=3)
            if text:
                if missing:
                    text += f"\n结论里还差这几个方向的说法：{'、'.join(missing)}。"
                if coverage_pushes >= MAX_COVERAGE_PUSHES:
                    # 推了这么多次还在收尾：把「不许结束」说透，并给出下一步的具体动作
                    text += (
                        f"\n这是第 {coverage_pushes + 1} 次被推回：平台不会因为你写了结论就算测完。"
                        "现在不要写总结，直接调用 http_request 开始测上面点名的第一项。"
                    )
                return text
        notes = [
            f"- 朝目标动手 {test_actions} 次（http_request / 脚本 / 渗透测试任务），"
            f"覆盖 {len(tested_hosts) or 0} 个目标"
            + (f"：{'、'.join(sorted(tested_hosts)[:5])}" if tested_hosts else ""),
            f"- 已归档漏洞 {findings_recorded} 条",
            f"- 判定基准：没确认到漏洞时至少动手 {MIN_TEST_ACTIONS} 次，且三个方向各有结论",
        ]
        if missing:
            notes.append(
                f"- 结论里还没交代的方向：{'、'.join(missing)}"
                "（每个方向都要说清：有就带证据，没有就说明测了哪些入口、为什么排除）"
            )
        names = pending_capabilities(session_id, limit=8)
        order = "\n".join(f"   {index + 1}. {name}" for index, name in enumerate(names))
        return NEXT_ROUND_PROMPT.format(
            notes="\n".join(notes),
            order=order or "   （能力清单里一项都没勾，先把目标的高价值接口跑一遍）",
        )

    digest_done = False

    def with_findings(text: str) -> str:
        """每一轮收尾都要带上「标题 + 请求包 + 响应包」三件套，并说明能力台账测完没有。

        用户把这条定成硬性要求：一轮工作完成就要能直接核对，不能只在最后一轮写。
        正常收尾、轮次用尽、超时收口、输出被截断——所有出口都走这里，避免某条路径
        悄悄把漏洞清单漏掉（以前只有正常收尾那条路补，轮次跑满的场次恰好最容易漏）。
        同一轮只贴一次：后面因为插话补的那段结论不再重复贴同一份清单。
        """
        nonlocal digest_done
        # 出门前先过一遍「不要重复上一轮」：一字不差的长段落去掉，报文与代码块不动
        if not asking and text:
            text, _ = _strip_repeated_paragraphs(session_id, text, baseline_id)
        if digest_done:
            return text
        digest_done = True
        # 不再用「本轮有没有新归档」当开关：清单口径是域名，这一轮即使没有新发现，
        # 只要该域名在本次对话里已有漏洞，也要把完整清单给出来——用户的要求是
        # 每一轮工作完成之后都能直接核对。没有可列的内容时 findings_digest 原样返回。
        body = findings_digest(session_id, text)
        # 能力台账没满就不许说「测完了」：这行由平台算，不靠模型自觉。
        # 提问的轮次不贴（用户在问结果，不是要开工），普通看一眼的任务也不贴。
        if testing_task and not asking:
            line = coverage.gate_line(session_id)
            if line and line not in body:
                body = f"{body.rstrip()}\n\n{line}" if body.strip() else line
        return body

    async def flush_text(text: str):
        """把这一轮的正文分批推给前端：有打字机观感，又不会泄露过程独白。"""
        if not text:
            return
        total = len(text)
        # 短回答按字吐，长回答（报告、清单、大段结论）按块推：
        # 一段两万字的报告如果按 24 字一个事件推，就是 800 多次渲染，浏览器必卡
        if total <= 400:
            chunk, pause = 24, 0.012
        elif total <= 3000:
            chunk, pause = 80, 0.008
        else:
            chunk, pause = max(240, total // 40), 0.006
        for index in range(0, total, chunk):
            if stopped():
                return
            yield {"type": "delta", "content": text[index:index + chunk]}
            await asyncio.sleep(pause)

    async def consume(tools_arg: list[dict[str, Any]] | None, holder: dict[str, Any], watch: bool = False):
        """跑一次模型调用，把增量推给前端，结果写进 holder。

        watch=True 时监听用户插话：一旦有新的输入就中止本轮（本轮内容作废），
        由主循环把用户的话插进上下文后重新决策，避免"用户已经改主意、AI 还在按老目标跑"。
        """
        holder.update({"text": "", "message": None, "finish": "", "error": "", "interject": [], "cancelled": False})
        async for kind, data in _model_turn(llm, messages, tools_arg, MAX_OUTPUT_TOKENS):
            if stopped():
                holder["cancelled"] = True
                return
            if watch:
                pending = take_interjections(session_id)
                if pending:
                    holder["interject"] = pending
                    return
            if kind == "delta":
                # 先攒着：这一轮如果只是要调工具，这些过程独白就不该出现在对话里
                holder["text"] += str(data)
            elif kind == "final":
                holder["message"] = (data or {}).get("message") or {}
                holder["finish"] = str((data or {}).get("finish_reason") or "")
            elif kind == "status":
                yield {"type": "status", "message": str(data)}
            elif kind == "error":
                holder["error"] = str(data)

    def cancel_event() -> dict[str, Any]:
        return {"type": "cancelled", "message": (token.reason if token and token.reason else "已按你的要求停止这一轮")}

    ack_pending = False
    turn_started = time.monotonic()
    turn_cap = TURN_MAX_SECONDS
    for step in range(budget):
        if stopped():
            yield cancel_event()
            return
        # 单轮跑太久就先收口：用户要的是结论，不是无限往下挖。
        # 例外：台账里还有没验的项——这时候收口就是「把活推给下一轮」，用户不接受，
        # 所以按 15 分钟一段往后延，直到验完或到兜底时长。
        if time.monotonic() - turn_started > turn_cap:
            left_now = _pending_left()
            if left_now and turn_cap < LEDGER_HARD_SECONDS:
                turn_cap = min(turn_cap + TURN_MAX_SECONDS, LEDGER_HARD_SECONDS)
                yield {
                    "type": "status",
                    "message": f"台账还剩 {left_now} 项没验，这一轮不按时间收口，接着按顺序测…",
                }
            else:
                yield {"type": "status", "message": "这一轮已经跑了一段时间，正在按已有结果收口…"}
                messages.append(
                    {
                        "role": "system",
                        "content": (
                            f"【平台提示】本轮已连续运行超过 {TURN_MAX_SECONDS // 60} 分钟，平台现在收口。"
                            "不要再调用任何工具，直接基于已拿到的结果给结论：三个方向分别有/没有、"
                            "证据是什么、还差什么。已归档的漏洞不用重复写。"
                        ),
                    }
                )
                hard_stop = True
                break
        # 用户在你干活时插话：先按他的新要求来，再回到原任务
        queued = take_interjections(session_id)
        if queued:
            messages.append({"role": "user", "content": _interjection_note(queued)})
            yield {"type": "status", "message": "收到你的补充，正在按新要求调整…"}
            ack_pending = True
        _shrink_tool_history(messages)
        last_step = step >= budget - 1
        if step == budget - 5:
            messages.append(
                {
                    "role": "system",
                    "content": (
                        "【提醒】工具轮次只剩最后 4 轮：不要再开新的探索方向，"
                        "用剩下的轮次把最关键的 1-2 个验证补完（带上请求包/响应包），"
                        "然后直接给结论。不要因为轮次快用完就停下来问用户要不要继续。"
                    ),
                }
            )
        holder: dict[str, Any] = {}
        async for event in consume(None if last_step else step_tools, holder, watch=True):
            yield event

        if holder.get("interject"):
            # 这一轮作废，把用户的新输入作为最高优先级指令插进上下文
            messages.append({"role": "user", "content": _interjection_note(holder["interject"])})
            yield {"type": "status", "message": "收到你的补充，正在按新要求调整…"}
            ack_pending = True
            continue

        if holder["message"] is None:
            if holder["text"]:
                yield {"type": "error", "message": f"输出中断：{holder['error'] or '连接异常'}"}
                return
            yield {"type": "error", "message": f"模型调用失败：{holder['error'] or '没有返回内容'}"}
            return

        message: dict[str, Any] = holder["message"]
        finish_reason = holder["finish"]
        total_text = holder["text"]

        # 输出被长度上限截断时自动续写，而不是直接丢弃
        continuations = 0
        while (
            finish_reason == "length"
            and not (message.get("tool_calls") or [])
            and continuations < CONTINUE_ROUNDS
        ):
            # 用累计文本判断有没有写过东西：有的模型把额度全花在 reasoning 上，
            # 单轮 message.content 是空的，但前面几段正文其实已经写出来了
            partial = total_text or str(message.get("content") or "")
            if not partial.strip():
                break
            messages.append({"role": "assistant", "content": partial})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "接着上面中断的位置继续写完，不要重复已经输出的内容，也不要重新开场；"
                        "剩下没写完的部分尽量紧凑，把结论、证据和修复建议写完整。"
                    ),
                }
            )
            yield {"type": "status", "message": f"输出较长，正在接着写（第 {continuations + 1} 段）…"}
            previous = total_text
            async for event in consume(None, holder):
                yield event
            continuations += 1
            if holder["message"] is None:
                message["content"] = previous
                finish_reason = "stop"
                break
            message = holder["message"]
            finish_reason = holder["finish"]
            total_text = previous + holder["text"]
            message["content"] = total_text

        # 只接受结构完整的 tool_call：极少数模型会塞进 None / 空对象，
        # 一旦原样回传，下一轮就会出现「请求里的 tool_call 和结果对不上」的 400
        calls = [item for item in (message.get("tool_calls") or []) if isinstance(item, dict)]
        content = str(message.get("content") or "").strip()

        # 用户刚插过话：先把模型那句回应放出来（这一步要继续调工具，独白本来会被丢掉，
        # 但"你说的话我听到了、现在这么处理"必须让用户看见）
        if calls and ack_pending:
            ack_pending = False
            ack = _ack_text(content)
            if ack:
                _save_message(session_id, "assistant", ack)
                async for event in flush_text(ack):
                    yield event
                yield {"type": "message", "role": "assistant", "content": ack}

        if calls:
            # 调工具的这一轮：模型的操作独白一律丢弃，用户只看结果。
            # 例外是选择题——提问前的结论必须留下，否则用户只看到一张卡片。
            has_choice = any(
                isinstance(item, dict) and (item.get("function") or {}).get("name") == "ask_choice"
                for item in calls
            )
            if has_choice and content:
                # 问题已经放进选项卡片，末尾重复的问句去掉，但结论必须留下
                pre_text = _strip_trailing_lead_in(_strip_trailing_question(content))
                if pre_text:
                    _save_message(session_id, "assistant", pre_text)
                    async for event in flush_text(pre_text):
                        yield event
                    yield {"type": "message", "role": "assistant", "content": pre_text}
            messages.append(
                {
                    "role": "assistant",
                    "content": message.get("content") or "",
                    "tool_calls": calls,
                }
            )
            step_results: list[dict[str, Any]] = []
            parallel_batch: list[dict[str, Any]] = []
            # 每个 tool_call 必须恰好对应一条 role=tool 的结果，而且要紧跟在
            # assistant 的 tool_calls 后面、顺序一致、中间不能夹别的角色。
            # 所以先按位置占坑，全部跑完再一次性按顺序补进消息里：
            # 去重跳过、参数非法、超过单轮上限这些「不发结果」的分支也有了兜底结果。
            slots: list[str | None] = [None] * len(calls)
            step_notes: list[str] = []
            step_auto_decided = False
            for slot_index, call in enumerate(calls):
                if stopped():
                    yield cancel_event()
                    return
                function = call.get("function") or {}
                tool_name = str(function.get("name") or "")
                raw_args = function.get("arguments") or "{}"
                try:
                    tool_args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except (json.JSONDecodeError, TypeError, ValueError):
                    tool_args = {}
                if not isinstance(tool_args, dict):
                    tool_args = {}
                # __ 开头是平台内部标记（点过确认后看敏感原文）。模型在参数里自己写一个
                # "__force_scope": true 就等于给自己发许可证，所以解析这一层就清掉，
                # 后面的确认判定和工具执行都看不到它。真正的放行标记只由确认流程注入。
                tool_args = {k: v for k, v in tool_args.items() if not str(k).startswith("__")}

                # 提问的轮次：执行类工具一律不落地。工具清单已经收窄，但个别模型
                # 会无视清单硬发工具名，这里再挡一道，否则又变成"重新跑一遍"。
                if asking and tool_name not in QUESTION_TOOL_NAMES:
                    slots[slot_index] = (
                        f"用户这一轮是在提问，不是派活，{tool_name} 现在不提供。"
                        "不要重新执行任何东西，直接用【本次会话已执行的步骤】回答他问的问题："
                        "测过没有、发现没有、哪几项还没测。"
                    )
                    continue

                # 批量检测已经覆盖过的连接器，不必再逐个复测
                if tool_name == "test_connector":
                    key = str(tool_args.get("key") or "").strip()
                    if key and key in covered_connectors:
                        slots[slot_index] = f"{key} 已在本次批量检测中测过，结论见上一条结果，不需要复测。"
                        continue

                # 同一轮里完全相同的调用只真正执行一次，避免模型绕圈
                dedupe_key = tool_name if tool_name in SINGLE_SHOT_TOOLS else action_signature(tool_name, tool_args)
                if dedupe_key in cache:
                    # 结果原样复用（模型可能按 JSON 解析，不能拼脏），提示单独攒起来，
                    # 等这一批 tool 消息都发完再补一条，否则会破坏「tool 紧跟 tool_calls」的结构
                    slots[slot_index] = cache[dedupe_key]
                    step_notes.append(
                        "【平台提示】本次运行中已经执行过相同的调用，结果就是上面那条，"
                        "不要再重复调用它；没有新信息就往下走或直接给结论。"
                    )
                    continue

                # 只有两类会打断用户：读敏感信息、删除类操作（各自听开关）
                signature = action_signature(tool_name, tool_args)
                reason = confirmation_reason(tool_name, tool_args, session_id)
                if reason and signature not in approved_sigs:
                    action_args = dict(tool_args)
                    action = create_action(session_id, username, tool_name, action_args, reason)
                    # 卡片本身就是提问，不再额外说一段话，避免同一件事说两遍
                    yield {
                        "type": "confirm",
                        "action_id": action["id"],
                        "tool": tool_name,
                        "args": tool_args,
                        "summary": action["summary"],
                        "label": confirm_label(tool_name, reason),
                    }
                    yield {"type": "done"}
                    return

                # 选择题式提问：不执行实际操作，把问题做成可点选项交给前端
                if tool_name == "ask_choice":
                    options = normalize_choices(tool_args.get("options"))
                    if not options:
                        slots[slot_index] = json.dumps(
                            {"ok": False, "error": "options 为空，请给出 2-4 个具体选项"},
                            ensure_ascii=False,
                        )
                        continue
                    # 用户说过「你自己决定 / 全测」：这一类优先级问题根本不该问他。
                    # 平台替他拍板，把选择结果当工具结果还回去，接着干。
                    if autonomy_granted(session_id):
                        picked = _auto_choice(options)
                        label_text = str(picked.get("label") or "").strip() or str(options[0]["label"])
                        slots[slot_index] = json.dumps(
                            {
                                "ok": True,
                                "chosen": label_text,
                                "note": (
                                    "用户已经明确授权你自己决定，平台已按这一项继续。"
                                    "不要再为同一件事抛选择题，直接往下执行。"
                                ),
                            },
                            ensure_ascii=False,
                        )
                        step_auto_decided = True
                        line = f"已按你的授权自己定：「{_brief(label_text, 18)}」，这一类不用你选，接着做"
                        if line not in seen_progress:
                            seen_progress.add(line)
                            progress_log.append(line)
                            _save_message(session_id, "progress", line, "step")
                            yield {"type": "progress", "content": line, "level": "step"}
                        continue
                    choice_used = True
                    question = str(tool_args.get("question") or "").strip() or "请选择下一步"
                    choice = create_choice(
                        session_id,
                        username,
                        question,
                        options,
                        bool(tool_args.get("allow_custom")),
                    )
                    # 存下问题，保证下一轮模型仍能看到上下文；前端会用选项卡片替代这条气泡
                    _save_message(session_id, "assistant", question)
                    yield {
                        "type": "choice",
                        "choice_id": choice["id"],
                        "question": choice["question"],
                        "options": options,
                        "allow_custom": choice["allow_custom"],
                    }
                    yield {"type": "done"}
                    return

                # 过程只在后台执行：给用户一句"在做什么"就够了，不推工具卡、不写进会话
                if tool_name not in QUIET_TOOLS:
                    yield {"type": "status", "message": ACTIVITY_HINTS.get(tool_name, "正在处理…")}
                # 读记忆前后各播一条：先「正在读取记忆」，读完再「已完成记忆读取」
                if tool_name == "read_memory":
                    loading = _memory_loading_line(tool_args)
                    if loading and loading != last_progress:
                        last_progress = loading
                        _save_message(session_id, "progress", loading, "loading")
                        yield {"type": "progress", "content": loading, "level": "loading"}
                # 能并发的先攒着，等这一批都校验完再一起发出去
                if tool_name in PARALLEL_SAFE_TOOLS:
                    # 并发批次里的重复也要挡：两条一模一样的请求没必要打两次
                    if any(item["dedupe"] == dedupe_key for item in parallel_batch):
                        slots[slot_index] = (
                            "这一条与同一批里的另一条调用完全相同，结果就是那一条，不需要再打一次。"
                        )
                        step_notes.append(
                            "【平台提示】同一批里有完全相同的调用，已经只执行了一次，"
                            "结果见对应的那条 tool 结果。"
                        )
                        continue
                    parallel_batch.append(
                        {
                            "call": call,
                            "slot": slot_index,
                            "tool": tool_name,
                            "args": tool_args,
                            "dedupe": dedupe_key,
                        }
                    )
                    continue
                try:
                    tool_result = await dispatch_tool(tool_name, tool_args, username)
                except Exception as exc:  # 单个工具异常不应中断整轮对话
                    tool_result = {"ok": False, "error": f"工具执行异常：{type(exc).__name__}: {exc}"}
                # 敏感信息不止文件：结果里出现凭据/私钥/令牌/连接串，先脱敏再问是否看原文。
                # 只对「我自己的数据」这么做：目标侧返回的敏感内容就是这次渗透测试要看的东西，不必反复请示。
                if tool_name in CONTENT_GATE_TOOLS and not tool_args.get("__reveal_sensitive"):
                    source = str(tool_args.get("path") or tool_args.get("only") or "")
                    owner = data_owner(source) if source else "self"
                    if owner == "self" and not has_grant(session_id, f"reveal:{grant_key(tool_name, tool_args)}"):
                        kinds = sensitive_kinds(tool_result)
                        if kinds:
                            reveal_args = dict(tool_args)
                            reveal_args["__reveal_sensitive"] = True
                            action = create_action(
                                session_id,
                                username,
                                tool_name,
                                reveal_args,
                                summary=f"结果中发现「{'、'.join(kinds)}」，平台已脱敏；是否允许查看原文？",
                            )
                            yield {
                                "type": "confirm",
                                "action_id": action["id"],
                                "tool": tool_name,
                                "args": tool_args,
                                "summary": action["summary"],
                                "label": "查看敏感内容",
                            }
                            yield {"type": "done"}
                            return
                    elif owner == "self":
                        tool_result = mask_sensitive(tool_result)

                if tool_name == "test_all_connectors" and tool_result.get("ok"):
                    covered_connectors.update(tool_result.get("passed_keys") or [])
                    covered_connectors.update(
                        item.get("key") for item in tool_result.get("failed_detail") or [] if item.get("key")
                    )
                executed_calls += 1
                if tool_name in TEST_TOOLS:
                    test_actions += 1
                if stats is not None:
                    stats["tool_calls"] = int(executed_calls)
                    stats["test_actions"] = int(test_actions)
                used_tools.add(tool_name)
                if stats is not None:
                    stats["tools"] = sorted(used_tools)
                if tool_name == "http_request":
                    if isinstance(tool_result, dict) and tool_result.get("ok"):
                        http_fail_streak = 0
                    else:
                        http_fail_streak += 1
                        if http_fail_streak % 3 == 0:
                            step_notes.append(RETRY_STREAK_NOTE.format(n=http_fail_streak))
                step_results.append({"tool": tool_name, "args": tool_args, "result": tool_result})
                compact = _compact(tool_result, tool_name)
                cache[dedupe_key] = compact
                slots[slot_index] = compact
                if executed_calls >= max_calls:
                    hard_stop = True
                    break
            if parallel_batch:
                async def _run_one(item: dict[str, Any]) -> Any:
                    try:
                        return await dispatch_tool(item["tool"], item["args"], username)
                    except Exception as exc:  # 单个工具异常不应中断整轮对话
                        return {"ok": False, "error": f"工具执行异常：{type(exc).__name__}: {exc}"}

                # 并发发出，按原来的顺序收结果：既快，又不打乱模型看到的先后
                batch_results = await asyncio.gather(*[_run_one(item) for item in parallel_batch])
                for item, result in zip(parallel_batch, batch_results):
                    name = item["tool"]
                    if name == "test_all_connectors" and isinstance(result, dict) and result.get("ok"):
                        covered_connectors.update(result.get("passed_keys") or [])
                        covered_connectors.update(
                            row.get("key") for row in result.get("failed_detail") or [] if row.get("key")
                        )
                    if name in CONTENT_GATE_TOOLS and not item["args"].get("__reveal_sensitive"):
                        result = mask_sensitive(result)
                    executed_calls += 1
                    if name in TEST_TOOLS:
                        test_actions += 1
                    if stats is not None:
                        stats["tool_calls"] = int(executed_calls)
                        stats["test_actions"] = int(test_actions)
                    used_tools.add(name)
                    if stats is not None:
                        stats["tools"] = sorted(used_tools)
                    if name == "http_request":
                        if isinstance(result, dict) and result.get("ok"):
                            http_fail_streak = 0
                        else:
                            http_fail_streak += 1
                            if http_fail_streak % 3 == 0:
                                step_notes.append(RETRY_STREAK_NOTE.format(n=http_fail_streak))
                    step_results.append({"tool": name, "args": item["args"], "result": result})
                    compact = _compact(result, name)
                    cache[item["dedupe"]] = compact
                    slots[item["slot"]] = compact

            # 按 tool_call 的原始顺序补齐结果：缺的那几条也要有一条，
            # 否则下一轮请求里「有调用没结果」，服务端会直接 400 拒绝
            for slot_index, call in enumerate(calls):
                payload = slots[slot_index]
                if payload is None:
                    payload = (
                        "本次没有执行这一条调用"
                        + ("（本轮调用次数已达上限）" if hard_stop else "（被平台跳过或参数不合法）")
                        + "，需要的话下一步再做，不要重复提交同样的调用。"
                    )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id") or f"call_{step}_{slot_index}",
                        "content": payload,
                    }
                )
            if step_notes:
                messages.append({"role": "system", "content": "\n".join(step_notes)})
            for item in step_results:
                args = item["args"]
                target = str(args.get("url") or args.get("target") or "").strip()
                if not target:
                    # 脚本/命令里 curl 的目标也算：不然「只用 run_shell 打」会被误判成没动手
                    blob = " ".join(
                        str(args.get(key) or "") for key in ("command", "script", "code")
                    )
                    found = URL_IN_TEXT.search(blob)
                    target = found.group(0) if found else ""
                if target:
                    tested_hosts.add(host_of(target))

            # 这一步做完了：把结论说给用户听（"已…，接下来…"），再往下走
            if stopped():
                yield cancel_event()
                return
            if step_results:
                cards = _finding_cards(step_results)
            else:
                cards = []
            # 刚归档的漏洞：当场推一张卡片出去，这就是「实时输出漏洞信息」
            if cards:
                findings_recorded += len(cards)
                for card in cards:
                    _save_message(
                        session_id,
                        "finding",
                        json.dumps(card, ensure_ascii=False),
                        card["severity"],
                        "record_finding",
                    )
                    yield {"type": "finding", "finding": card}
                    progress_log.append(
                        f"关键突破：已确认并归档「{card['title']}」（{card['severity_label']}）"
                    )
                # 卡片本身已经把「发现了什么」说清楚了，不再补一句进度重复它；
                # 但关键节点要让位：紧跟着的关键说法照样走冷却，不能刷屏
                last_key_step = step
                stall_steps = 0
            elif step_results:
                line = _progress_event(content, step_results, seen_evidence)
                level = progress_level(line) if line else ""
                if level == "highlight" and line:
                    if highlight_allowed(step, last_key_step):
                        last_key_step = step
                    else:
                        # 冷却期内：降级成普通进展，同时把这个帽子摘掉，
                        # 否则会出现「普通小字却写着关键线索」这种自相矛盾的样子
                        level = "step"
                        line = strip_key_prefix(line)
                if line and line not in seen_progress:
                    seen_progress.add(line)
                    progress_log.append(line)
                    _save_message(session_id, "progress", line, level)
                    yield {"type": "progress", "content": line, "level": level}
                    stall_steps = 0
                else:
                    # 播报词重复不等于空转：这一步的工具确实执行了（可能就是又登记了一项能力）。
                    # 以前这里算一次空转，连报几项结论就被判「没有新结果」直接收口，
                    # 表现出来就是台账才 6/58 就收尾。
                    stall_steps = 0
            else:
                # 一个工具都没真跑（全部被去重缓存挡回）：这一步是空转
                # 平台替用户拍板的那一步不算空转——它本来就不执行工具
                if not step_auto_decided:
                    stall_steps += 1
            if stall_steps >= 5:
                # 已经确认了问题、却一条都没进漏洞结果：别急着收口，先给它一轮把漏洞写进去。
                # 轮次耗尽那条路上再想归档就晚了（那时已经不允许调工具），所以在这里补。
                claims = _claims_findings(content) or any(
                    _claims_findings(item) for item in progress_log[-6:]
                )
                if claims and not archive_pushed and findings_recorded == 0:
                    archive_pushed = True
                    stall_steps = 0
                    line = "已经确认了问题，先把它们逐条归档到漏洞结果，再收尾"
                    progress_log.append(line)
                    _save_message(session_id, "progress", line, "step")
                    yield {"type": "progress", "content": line, "level": "step"}
                    yield {"type": "status", "message": "正在把确认的问题归档到漏洞结果…"}
                    messages.append({"role": "system", "content": ARCHIVE_PROMPT})
                    continue
                # 台账还没验完：不许按「没有新结果」收口——那是把剩下的项丢给下一轮
                left_stall = _pending_left()
                if left_stall:
                    stall_steps = 0
                    yield {"type": "status", "message": f"台账还剩 {left_stall} 项，接着测下一项…"}
                    messages.append(
                        {
                            "role": "system",
                            "content": (
                                f"【平台提示】能力清单里还剩 {left_stall} 项没有结论，平台不会在这里收口。"
                                "不要重复已经做过的那几步：直接换下一个没验的项，先调用 http_request "
                                "打出真实响应，再调用 report_capability 登记结论。"
                            ),
                        }
                    )
                    continue
                # 连转三步没有任何新东西：别再让它原地画圈，直接进收尾
                yield {"type": "status", "message": "这一步没有新结果，正在按已有信息收口…"}
                messages.append(
                    {
                        "role": "system",
                        "content": (
                            "【平台提示】你连续几步都在重复已经做过的操作，没有拿到任何新结果。"
                            "不要再调用工具，直接基于已有信息给出结论：已经确认了什么、"
                            "还缺什么、建议下一步做什么。"
                        ),
                    }
                )
                hard_stop = True
            if hard_stop:
                break
            continue

        if stopped():
            yield cancel_event()
            return
        # 深度轮把中间结论吃掉了：万一最后一轮空手而归，至少把它放出来
        if not content and held_content:
            content = held_content
        # 再判「结论里说有漏洞、结果一条没归档」：用户要的是漏洞结果页里有东西，不是正文里说说
        if content and not asking and testing_task and not archive_pushed and findings_recorded == 0:
            if _claims_findings(content):
                archive_pushed = True
                held_content = held_content or content
                line = "已经确认了问题，先把它们逐条归档到漏洞结果，再收尾"
                progress_log.append(line)
                _save_message(session_id, "progress", line, "step")
                yield {"type": "progress", "content": line, "level": "step"}
                yield {"type": "status", "message": "正在把确认的问题归档到漏洞结果…"}
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "system", "content": ARCHIVE_PROMPT})
                continue
        # 先判「到底做完没有」：只发了一两个请求就写结论的，连深度轮都不用等，直接推回去
        if content and not asking:
            gap = finish_gap(content)
            if gap:
                coverage_pushes += 1
                held_content = held_content or content
                detail = "还没验完"
                if len(missing_axes(content)) >= 2:
                    detail = "还没验完，三个方向还没各有结论"
                line = (
                    f"这一轮动手 {test_actions} 次、覆盖 {len(tested_hosts) or '—'} 个目标，"
                    f"{detail}，接着按优先级补测"
                )
                progress_log.append(line)
                _save_message(session_id, "progress", line, "step")
                yield {"type": "progress", "content": line, "level": "step"}
                yield {"type": "status", "message": "还没验完，继续按优先级补测…"}
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "system", "content": gap})
                continue
        # 模型准备收尾：先做一次「收尾自检」，再真正结束。
        # 只对真正干过活的回合做——问一句话、看一眼状态这种短任务不值得多跑一轮模型。
        if content and not asking and executed_calls >= 2:
            if not self_checked:
                self_checked = True
                held_content = held_content or content
                yield {"type": "status", "message": "正在读记忆与能力清单，核对有没有遗漏…"}
                check_prompt, check_line = await _final_self_check(username, used_tools)
                progress_log.append(check_line)
                _save_message(session_id, "progress", check_line, "step")
                yield {"type": "progress", "content": check_line, "level": "step"}
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "system", "content": check_prompt})
                continue
        if content:
            ack_pending = False
            # 提问的轮次里，模型有时把「已…，接下来…」当回答：这不是答案，再要一次
            if asking and not answer_retried and _looks_like_progress_report(content):
                answer_retried = True
                messages.append({"role": "assistant", "content": content})
                messages.append(
                    {
                        "role": "system",
                        "content": (
                            "你刚才回的是执行过程播报，但用户是在问「做没做过、有没有发现」。"
                            "去掉「已…，接下来…」这种句式，直接回答他问的那几点："
                            "测过没有、发现没有、测了哪几类、哪几项还没测。不要再调工具。"
                        ),
                    }
                )
                retry_holder: dict[str, Any] = {}
                async for event in consume(None, retry_holder):
                    yield event
                retry_text = str(
                    ((retry_holder.get("message") or {}).get("content")) or retry_holder.get("text") or ""
                ).strip()
                if retry_text:
                    content = retry_text
                    total_text = retry_text
            # 没给选择卡却用问句收尾，等于把决定权扔回给用户：裁掉问句，让回答落在结论上
            if not choice_used:
                content = _strip_trailing_lead_in(_strip_trailing_question(content)) or content
            # 用户硬性要求：每一轮工作完成后，都要把每个漏洞的标题、请求包、响应包写出来。
            # 模型写全了就不动，漏了哪条由平台补在末尾——不能只留一句「已归档」。
            content = with_findings(content)
            _save_message(session_id, "assistant", content)
            async for event in flush_text(total_text or content):
                yield event
            yield {"type": "message", "role": "assistant", "content": content}
        elif finish_reason == "length":
            body = (total_text or "").strip()
            if body:
                # 已经写出来的部分不能再丢：截断时把正文给用户，末尾说明怎么接着写
                content = body + (
                    f"\n\n（到这里已经写到第 {CONTINUE_ROUNDS + 1} 段，仍未写完。回复「继续」我接着往下写。）"
                )
                # 截断也不能把漏洞三件套截掉：先在末尾补齐再交付
                content = with_findings(content)
                _save_message(session_id, "assistant", content)
                async for event in flush_text(body):
                    yield event
                yield {"type": "message", "role": "assistant", "content": content}
            else:
                notice = (
                    "这次模型把输出额度全用在思考过程上了，正文一个字都没留下。"
                    "回复「继续」我再写一次；如果反复如此，说明这个模型的输出上限偏小，"
                    "可以换一个上限更大的模型，或在启动前把 `K7so_MAX_OUTPUT_TOKENS` 调大。"
                )
                notice = with_findings(notice)
                _save_message(session_id, "assistant", notice)
                yield {"type": "message", "role": "assistant", "content": notice}
        else:
            notice = "模型没有返回内容，请重试一次；若连续为空，请检查该模型的接口额度与参数配置。"
            # 正文丢了也不要紧：本轮归档的漏洞照样逐条摊给用户
            notice = with_findings(notice)
            _save_message(session_id, "assistant", notice)
            yield {"type": "message", "role": "assistant", "content": notice}

        # 收尾前再看一眼：用户在最后几秒说的话也不能吞掉，补一轮结论再结束
        tail = take_interjections(session_id)
        if tail:
            messages.append({"role": "user", "content": _interjection_note(tail)})
            yield {"type": "status", "message": "收到你的补充，正在按新要求补一轮…"}
            extra_holder: dict[str, Any] = {}
            async for event in consume(None, extra_holder):
                yield event
            extra = str(
                ((extra_holder.get("message") or {}).get("content")) or extra_holder.get("text") or ""
            ).strip()
            if extra:
                extra = with_findings(extra)
                _save_message(session_id, "assistant", extra)
                async for event in flush_text(extra):
                    yield event
                yield {"type": "message", "role": "assistant", "content": extra}
        yield {"type": "done"}
        return

    # 轮次用完（或连续空转被提前拦下）不等于失败：不再调工具，强制基于已有结果收口
    if hard_stop:
        yield {"type": "status", "message": "正在按执行记录整理答案…"}
    else:
        yield {
            "type": "status",
            "message": "正在按执行记录整理答案…" if asking else "工具轮次已用完，正在汇总已有结果…",
        }
    messages.append(
        {
            "role": "system",
            "content": (
                "【工具轮次已用完】不要再调用任何工具，直接基于上面已经拿到的信息给出结论："
                "已经确认了什么、还缺什么、建议用户下一步做什么。"
            ),
        }
    )
    # 用户要求「任务完成前再读一遍记忆」：强制收口这条路上也要做，不能只在正常收尾时做
    if not asking and not self_checked:
        self_checked = True
        check_prompt, _ = await _final_self_check(username, used_tools)
        messages.append({"role": "system", "content": check_prompt})
    holder = {}
    async for event in consume(None, holder):
        yield event
    if stopped():
        yield cancel_event()
        return

    def _final_text(h: dict[str, Any]) -> str:
        """收口用的文字：还在发工具调用的那一轮，独白不算结论。"""
        msg = h.get("message") or {}
        if msg.get("tool_calls"):
            return ""
        return str(msg.get("content") or h.get("text") or "").strip()

    final_text = _final_text(holder)
    # 少数模型会无视「不再调用工具」的约束，再明确要求一次
    retry_rounds = 0
    while not final_text and retry_rounds < 2:
        messages.append({"role": "user", "content": "请直接用文字给出结论，不要再调用任何工具。"})
        async for event in consume(None, holder):
            yield event
        final_text = _final_text(holder)
        retry_rounds += 1
    if not final_text:
        # 别把「没收敛」甩回给用户：把这一轮真正做过的事摊开，让他知道停在哪、怎么接上
        done = [item for item in progress_log[-4:] if item]
        tail = "；".join(done) if done else "只做了基础核对，还没拿到可用的结果"
        final_text = (
            f"这一轮我执行了 {max(executed_calls, len(progress_log))} 步，做到这里：{tail}。\n\n"
            "还没到能下结论的程度，我不会凭空编一个。要接着往下推，直接说「继续」，"
            "我从断点接着走，不用从头再来。"
        )
    # 轮次用尽 / 空转收口同样是「这一轮完成」：漏洞三件套照样要摊开
    final_text = with_findings(final_text)
    _save_message(session_id, "assistant", final_text)
    async for event in flush_text(final_text):
        yield event
    yield {"type": "message", "role": "assistant", "content": final_text}

    # 同样地：收尾前补上用户最后时刻的插话
    tail = take_interjections(session_id)
    if tail:
        messages.append({"role": "user", "content": _interjection_note(tail)})
        yield {"type": "status", "message": "收到你的补充，正在按新要求补一轮…"}
        tail_holder: dict[str, Any] = {}
        async for event in consume(None, tail_holder):
            yield event
        tail_text = str(
            ((tail_holder.get("message") or {}).get("content")) or tail_holder.get("text") or ""
        ).strip()
        if tail_text:
            tail_text = with_findings(tail_text)
            _save_message(session_id, "assistant", tail_text)
            async for event in flush_text(tail_text):
                yield event
            yield {"type": "message", "role": "assistant", "content": tail_text}
    yield {"type": "done"}


def round_step_budget(pending: int = 0) -> int:
    """这一轮给多少步工具轮次。

    默认就是 step_budget()（50）。但用户定死「第一轮要勾选的能力全测完」，
    所以台账里还剩 pending 项时按「一项 8 步」往上加，上限 1200 步兜底。
    以前这里是写死 50 步：58 项根本跑不完，第一轮必然在台账 0/58 的时候被收口，
    活全落到下一轮——用户看到的就是「第一轮什么都没测」。
    """
    budget = step_budget()
    if int(pending or 0) > 0:
        budget = min(max(budget, 12 + int(pending) * LEDGER_STEPS_PER_ITEM), LEDGER_HARD_STEPS)
    return budget


async def run_agent(
    session_id: int,
    username: str,
    provider: str = "",
    resume_note: str = "",
    approved: set[str] | None = None,
    stats: dict[str, Any] | None = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """对外入口：登记活跃会话与取消凭据，使用户在 AI 思考期间也能插话、随时能停。"""
    key = int(session_id)
    token = RunToken(key)
    _ACTIVE_SESSIONS.add(key)
    _RUN_TOKENS.setdefault(key, set()).add(token)
    session_ctx = set_tool_session(key)
    try:
        async for event in _run_agent(
            session_id, username, provider, resume_note, approved, token, stats
        ):
            yield event
    finally:
        _TOOL_SESSION.reset(session_ctx)
        _SESSION_FINDINGS.pop(key, None)
        _ROUND_DOMAINS.pop(key, None)
        # _SESSION_ALL_FINDINGS / _SESSION_DOMAINS 故意不在这里清：
        # 自动继续是「每轮调一次 run_agent」，一轮结束就清会让下一轮看不到本次对话
        # 已经归档的漏洞，清单就退化回「只列这一轮」。它们留到会话删除时再清。
        _ACTIVE_SESSIONS.discard(key)
        bucket = _RUN_TOKENS.get(key)
        if bucket is not None:
            bucket.discard(token)
            if not bucket:
                _RUN_TOKENS.pop(key, None)
        _INTERJECT.pop(key, None)
