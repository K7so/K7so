"""测试能力目录：用户在「模型能力」页勾选后，AI 只在勾选的范围内执行对应测试。

目录共 64 项测试能力，按攻击面分为 7 组，覆盖注入、执行、认证与访问控制、
业务逻辑、云与组件、客户端与传输、信息泄露等主流漏洞类型。
同一类漏洞的多种手法不再拆成多张卡片：SQL 注入的盲注/报错/UNION/堆叠合并为一项，
IDOR 与水平越权合并为一项，任意文件读取与路径穿越合并为一项，云配置与元数据合并为一项，
源码泄露与备份文件泄露合并为一项，组件漏洞与 Nday 合并为一项——勾一项即覆盖该类的全部常规手法。
「绕过 / 变形」类手法同样不单列条目：勾选某项探测能力，即视为允许它的常规绕过手法
（编码、大小写、注释、重复写等），需要时直接使用，不必再单独勾选。

每一项能力另有一个 1-5 的测试权重（默认 5，5 最优先）：用户在「模型能力」页用方块控件设定，
AI 先抓目标首页与前端 JS 分析技术栈、路由与接口，再按权重从高到低安排测试顺序。

「操作询问」保留两个平级的子开关（读敏感信息 / 删除类操作）——各自管各自的一类动作。
「自动迭代」不再单设开关：自动继续（把预设那句话一直发下去）本身就是自动迭代，
两者是同一件事，只留一个入口。
"""
from __future__ import annotations

import json

from ..db import get_settings, set_settings

CAPABILITIES: list[dict[str, str]] = [
    # ---------- 注入攻击 ----------
    {"key": "xss_reflected", "name": "反射型 XSS", "group": "注入攻击", "description": "在参数中注入脚本并验证是否原样反射到响应。"},
    {"key": "xss_stored", "name": "存储型 XSS", "group": "注入攻击", "description": "在写入点提交脚本后重新读取页面，验证持久化输出。"},
    {"key": "xss_dom", "name": "DOM 型 XSS", "group": "注入攻击", "description": "检查前端对 location/hash 等可控输入的不安全拼接。"},
    {"key": "sqli", "name": "SQL 注入", "group": "注入攻击", "description": "字符型/整型/报错/UNION/堆叠/时间盲注一并验，按注入点实际形态选手法。"},
    {"key": "nosql", "name": "NoSQL 注入", "group": "注入攻击", "description": "针对 Mongo 等文档数据库的参数对象注入测试。"},
    {"key": "orm_injection", "name": "ORM / HQL 注入", "group": "注入攻击", "description": "测试 Hibernate、MyBatis 等 ORM 拼接点的注入面。"},
    {"key": "ssti", "name": "模板注入 SSTI", "group": "注入攻击", "description": "在模板参数中注入表达式并观察渲染结果。"},
    {"key": "expression_injection", "name": "表达式注入", "group": "注入攻击", "description": "针对 SpEL、OGNL、MVEL 等表达式引擎的求值测试。"},
    {"key": "cmd_injection", "name": "命令注入", "group": "注入攻击", "description": "在系统命令拼接点注入无副作用命令并验证回显。"},
    {"key": "deserialization", "name": "反序列化", "group": "注入攻击", "description": "识别不安全的反序列化入口与可探测特征。"},
    {"key": "ssrf", "name": "SSRF", "group": "注入攻击", "description": "测试服务端请求伪造，确认是否可访问内网或元数据地址。"},
    {"key": "xxe", "name": "XXE", "group": "注入攻击", "description": "在 XML 解析点注入外部实体，验证文件读取或外带。"},
    {"key": "ldap_injection", "name": "LDAP 注入", "group": "注入攻击", "description": "在目录服务查询点注入过滤器语法，验证鉴权绕过。"},
    {"key": "xpath_injection", "name": "XPath 注入", "group": "注入攻击", "description": "在 XPath 查询点构造表达式，验证查询逻辑被改写。"},
    {"key": "crlf_injection", "name": "CRLF 注入", "group": "注入攻击", "description": "在头部拼接点注入换行，验证响应头与缓存被污染。"},
    {"key": "graphql_abuse", "name": "GraphQL 内省与注入", "group": "注入攻击", "description": "检查内省开放、批量查询与字段级越权读取。"},
    # ---------- 执行与文件 ----------
    {"key": "rce", "name": "远程代码执行 RCE", "group": "执行与文件", "description": "针对已知执行入口做最小化验证，只运行无副作用命令。"},
    {"key": "code_eval", "name": "动态代码执行", "group": "执行与文件", "description": "检查 eval、表达式求值与插件加载等动态执行面。"},
    {"key": "file_upload", "name": "任意文件上传", "group": "执行与文件", "description": "测试类型校验与解析绕过，使用无害测试文件。"},
    {"key": "file_download", "name": "任意文件读取", "group": "执行与文件", "description": "路径穿越、编码绕过与敏感文件读取一并验，读到即停。"},
    {"key": "file_write", "name": "任意文件写入", "group": "执行与文件", "description": "验证写入路径是否可控，仅在可回滚位置写入无害文件。"},
    {"key": "file_include", "name": "文件包含 LFI/RFI", "group": "执行与文件", "description": "测试 include 类参数与伪协议包含。"},
    {"key": "zip_slip", "name": "压缩包路径穿越", "group": "执行与文件", "description": "提交含穿越路径的压缩包，验证解压落点是否越界。"},
    {"key": "source_leak", "name": "源码与备份泄露", "group": "执行与文件", "description": "查 .bak/.old/.zip 备份、编辑器残留与未编译源码暴露。"},
    {"key": "dir_bruteforce", "name": "目录爆破", "group": "执行与文件", "description": "按字典探测隐藏目录、备份与调试入口，限制并发。"},
    {"key": "dir_listing", "name": "目录索引", "group": "执行与文件", "description": "检查服务器是否开启目录浏览导致文件清单泄露。"},
    # ---------- 认证与访问控制 ----------
    {"key": "unauthorized", "name": "未授权访问", "group": "认证与访问控制", "description": "在无凭据下访问管理接口、中间件与数据接口。"},
    {"key": "idor", "name": "越权访问（IDOR）", "group": "认证与访问控制", "description": "替换对象 ID 验证水平越权：能不能看/改别人的数据。"},
    {"key": "privilege_escalation", "name": "权限提升", "group": "认证与访问控制", "description": "验证低权限账号能否触达高权限功能（垂直越权）。"},
    {"key": "mass_assignment", "name": "批量赋值", "group": "认证与访问控制", "description": "在注册/更新接口注入高权限字段，验证是否被接受。"},
    {"key": "weak_password", "name": "弱口令", "group": "认证与访问控制", "description": "对登录入口做低频率常见口令验证，避免锁定账号。"},
    {"key": "default_cred", "name": "默认凭据", "group": "认证与访问控制", "description": "检查产品默认账号口令是否仍可登录。"},
    {"key": "login_bruteforce", "name": "登录防爆破缺失", "group": "认证与访问控制", "description": "检查失败锁定、验证码与频率限制是否缺位。"},
    {"key": "password_reset", "name": "密码重置缺陷", "group": "认证与访问控制", "description": "检查重置令牌可预测、可复用与响应差异泄露。"},
    {"key": "account_takeover", "name": "任意用户接管", "group": "认证与访问控制", "description": "验证令牌伪造、绑定缺陷导致的账号接管路径。"},
    {"key": "register_abuse", "name": "任意用户注册", "group": "认证与访问控制", "description": "检查注册接口是否可绕过校验批量建号。"},
    {"key": "jwt_weak", "name": "JWT 弱密钥", "group": "认证与访问控制", "description": "测试空签名、算法混淆与弱密钥导致的令牌伪造。"},
    {"key": "session_fixation", "name": "会话固定", "group": "认证与访问控制", "description": "检查登录前后会话标识是否更新。"},
    {"key": "oauth_misconfig", "name": "OAuth / SSO 配置", "group": "认证与访问控制", "description": "检查 redirect_uri 校验缺失与 state 参数缺位。"},
    {"key": "csrf", "name": "CSRF", "group": "认证与访问控制", "description": "检查敏感操作的令牌与来源校验。"},
    {"key": "open_redirect", "name": "开放重定向", "group": "认证与访问控制", "description": "验证跳转参数是否可指向任意外部域。"},
    # ---------- 业务逻辑 ----------
    {"key": "business_logic", "name": "业务逻辑缺陷", "group": "业务逻辑", "description": "检查价格、数量与权限校验在流程中的缺失点。"},
    {"key": "payment_tamper", "name": "支付与金额篡改", "group": "业务逻辑", "description": "验证前端金额、负数与币种是否被服务端信任。"},
    {"key": "race_condition", "name": "并发竞态", "group": "业务逻辑", "description": "以低并发窗口验证重复提交、超卖与幂等缺失。"},
    {"key": "api_rate_limit", "name": "接口限流缺失", "group": "业务逻辑", "description": "核查高频调用是否被限制，只做低频探测不压测。"},
    {"key": "data_mass_export", "name": "数据批量导出", "group": "业务逻辑", "description": "检查列表接口是否可全量拉取，取证后立即停止。"},
    # ---------- 云与组件 ----------
    {"key": "cloud_vuln", "name": "云配置与元数据", "group": "云与组件", "description": "查云控制台暴露面与元数据地址可达性，只取非凭据字段。"},
    {"key": "cloud_storage", "name": "对象存储权限", "group": "云与组件", "description": "验证 OSS / S3 桶是否允许匿名列举或下载。"},
    {"key": "component_vuln", "name": "组件已知漏洞", "group": "云与组件", "description": "按指纹匹配中间件/框架 Nday，并对确认存在的做无破坏验证。"},
    {"key": "middleware_exposed", "name": "中间件管理端暴露", "group": "云与组件", "description": "检查 Tomcat / WebLogic / Nacos 等管理端可达性。"},
    {"key": "container_api", "name": "容器 API 暴露", "group": "云与组件", "description": "检查 Docker / containerd 接口是否未授权可达。"},
    {"key": "k8s_api", "name": "Kubernetes API 暴露", "group": "云与组件", "description": "检查 apiserver、kubelet 与 dashboard 暴露面。"},
    {"key": "ci_cd_exposure", "name": "CI/CD 配置泄露", "group": "云与组件", "description": "检查流水线配置与仓库凭据泄露。"},
    # ---------- 客户端与传输 ----------
    {"key": "prototype_pollution", "name": "原型链污染", "group": "客户端与传输", "description": "检查合并、反序列化与参数解析造成的原型污染。"},
    {"key": "postmessage_misconfig", "name": "postMessage 校验缺失", "group": "客户端与传输", "description": "检查消息监听是否校验来源与数据类型。"},
    {"key": "clickjacking", "name": "点击劫持", "group": "客户端与传输", "description": "检查关键页面是否缺少 Frame 防护与 CSP 策略。"},
    {"key": "cache_deception", "name": "Web 缓存欺骗", "group": "客户端与传输", "description": "验证路径混淆是否导致私有页面被缓存。"},
    # ---------- 信息泄露 ----------
    {"key": "sensitive_info", "name": "敏感信息泄露", "group": "信息泄露", "description": "检查接口与静态资源中泄露的密钥、内网地址与账号。"},
    {"key": "api_doc_leak", "name": "接口文档泄露", "group": "信息泄露", "description": "检查 swagger / openapi / graphql 等文档端点暴露。"},
    {"key": "error_leak", "name": "详细报错泄露", "group": "信息泄露", "description": "检查堆栈、SQL 语句与调试信息回显。"},
    {"key": "pii_leak", "name": "个人数据泄露", "group": "信息泄露", "description": "检查响应中未脱敏的手机号、证件号与地址。"},
    {"key": "log_exposure", "name": "日志文件暴露", "group": "信息泄露", "description": "探测 access.log、debug.log 等日志文件可读性。"},
    {"key": "vcs_leak", "name": "版本库泄露", "group": "信息泄露", "description": "检查 .git / .svn / .hg 目录可读导致源码还原。"},
    {"key": "debug_endpoint", "name": "调试端点暴露", "group": "信息泄露", "description": "检查 debug、test、console 等调试入口开放。"},
]

# ---------- 开关 ----------
# 「自动迭代」已整体下线：它和「自动继续」是同一件事，只保留后者，避免两个开关打架。
# 旧库里写在 capability_switches 里的 auto_iterate 不再读取，下次保存开关时顺手丢掉。
CONFIRM_ACTIONS_KEY = "confirm_actions"
ASK_SENSITIVE_KEY = "ask_sensitive"
ASK_DELETE_KEY = "ask_delete"
# 自动渗透：开了就不受「勾选清单」限制，清单外的漏洞类型也照测；默认关。
AUTO_PENTEST_KEY = "auto_pentest"

# ---------- 测试权重 ----------
# 1-5 级，越大越优先。用户逐项设定，AI 按它排测试顺序；默认满格 5，装好即按最高优先级排。
WEIGHT_KEY = "capability_weights"
WEIGHT_MIN = 1
WEIGHT_MAX = 5
DEFAULT_WEIGHT = 5

# ---------- 用户提示 ----------
# 用户给某一项能力写的「必须怎么做」：例如「只测 /api/order 的越权，必须换别人的订单号」。
# 这是硬性要求，不是建议：模型执行该项前必须逐字读完并照做，漏做就等于这项没测。
HINT_KEY = "capability_hints"
HINT_MAX_CHARS = 600

SWITCHES: list[dict] = [
    {
        "key": AUTO_PENTEST_KEY,
        "name": "自动渗透",
        "tag": "AUTO PENTEST",
        "group": "scope",
        "default": "false",
        "description": (
            "关闭（默认）：只测下面勾选并启用的漏洞类型，清单外的一律不扩张。"
            "开启：清单只是底线，模型会按目标实际暴露面自己找清单外的漏洞类型一起测，"
            "清单里勾选的每一项仍然必须有结论。"
        ),
    },
    {
        "key": ASK_SENSITIVE_KEY,
        "name": "读取敏感信息",
        "tag": "SENSITIVE",
        "group": "confirm",
        "default": "true",
        "description": "要读凭据、私钥、令牌、连接串、身份证号这类内容时先问一次，不论它出现在文件、日志、命令输出还是接口返回里。",
    },
    {
        "key": ASK_DELETE_KEY,
        "name": "删除类操作",
        "tag": "DELETE",
        "group": "confirm",
        "default": "true",
        "description": "命令或脚本里要删文件、删目录、清库这类不可逆动作时先问一次；格式化、删根目录、关机仍然直接拒绝。",
    },
]

SWITCH_BY_KEY = {item["key"]: item for item in SWITCHES}
DEFAULT_SWITCHES = {item["key"]: item["default"] == "true" for item in SWITCHES}

CAPABILITY_BY_KEY = {item["key"]: item for item in CAPABILITIES}
CAPABILITY_KEYS = tuple(CAPABILITY_BY_KEY)

GROUP_ORDER = [
    "注入攻击",
    "执行与文件",
    "认证与访问控制",
    "业务逻辑",
    "云与组件",
    "客户端与传输",
    "信息泄露",
]

# 合并掉的旧 key → 合并后的新 key。老库里存着的勾选与权重按这张表迁过去，
# 免得升级后用户之前勾的项凭空消失。
MERGED_KEYS: dict[str, str] = {
    "sqli_char": "sqli",
    "sqli_int": "sqli",
    "sqli_time": "sqli",
    "sqli_error": "sqli",
    "sqli_union": "sqli",
    "sqli_stacked": "sqli",
    "horizontal_escalation": "idor",
    "path_traversal": "file_download",
    "cloud_metadata": "cloud_vuln",
    "backup_file": "source_leak",
    "cve_nday": "component_vuln",
}


def _load_json(raw: str | None, fallback):
    try:
        value = json.loads(raw or "")
    except (json.JSONDecodeError, TypeError):
        return fallback
    return value if isinstance(value, type(fallback)) else fallback


def _migrate_key(key: str) -> str:
    return MERGED_KEYS.get(key, key)


def enabled_keys() -> list[str]:
    values = _load_json(get_settings().get("capabilities", "[]"), [])
    merged: list[str] = []
    for item in values:
        key = _migrate_key(str(item))
        if key in CAPABILITY_BY_KEY and key not in merged:
            merged.append(key)
    return merged


def enabled_items() -> list[dict[str, str]]:
    return [CAPABILITY_BY_KEY[key] for key in enabled_keys()]


def get_switches() -> dict[str, bool]:
    """读取开关；未落库时用默认值（两个询问开关默认全开）。"""
    raw = _load_json(get_settings().get("capability_switches", ""), {})
    values = dict(DEFAULT_SWITCHES)
    for key in SWITCH_BY_KEY:
        if key in raw:
            values[key] = bool(raw[key])
    # 兼容旧版：总开关曾经一关全关。老配置里它是关的、子项又没单独存过，
    # 就按他当时的意思保持「都不问」，别让升级把确认卡又弹回来。
    if isinstance(raw, dict) and raw.get(CONFIRM_ACTIONS_KEY) is False:
        for key in (ASK_SENSITIVE_KEY, ASK_DELETE_KEY):
            if key not in raw:
                values[key] = False
    return values


def set_switches(values: dict[str, bool]) -> dict[str, bool]:
    merged = get_switches()
    for key, value in values.items():
        if key in SWITCH_BY_KEY:
            merged[key] = bool(value)
    # 只写还活着的键：老库里残留的 auto_iterate 之类顺手丢掉，
    # 免得回显时又冒出来一个已经不存在的开关
    merged = {key: bool(merged[key]) for key in SWITCH_BY_KEY}
    set_settings({"capability_switches": json.dumps(merged, ensure_ascii=False)})
    return merged


def confirm_actions_enabled() -> bool:
    """子开关里还有没有开着的（不再有总开关）。"""
    switches = get_switches()
    return any(
        switches.get(key, True) for key in (ASK_SENSITIVE_KEY, ASK_DELETE_KEY)
    )


def ask_enabled(kind: str) -> bool:
    """某个询问是否生效：子开关平级，各管各的。"""
    return bool(get_switches().get(kind, True))


def auto_pentest_enabled() -> bool:
    """自动渗透开关：默认关闭——只测勾选的那几类，不自己扩张。

    开的时候返回 True，调用方据此放开「只能测清单内」的约束。
    """
    return bool(get_switches().get(AUTO_PENTEST_KEY, False))


def save_enabled(keys: list[str]) -> list[str]:
    cleaned: list[str] = []
    for key in keys:
        target = _migrate_key(str(key))
        if target in CAPABILITY_BY_KEY and target not in cleaned:
            cleaned.append(target)
    set_settings({"capabilities": json.dumps(cleaned, ensure_ascii=False)})
    return cleaned


# ---------- 权重 ----------


def _clamp_weight(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return max(WEIGHT_MIN, min(WEIGHT_MAX, number))


def get_weights() -> dict[str, int]:
    """每一项能力的权重（1-5）；没设过的按默认 5。"""
    raw = _load_json(get_settings().get(WEIGHT_KEY, "{}"), {})
    values = {key: DEFAULT_WEIGHT for key in CAPABILITY_KEYS}
    if isinstance(raw, dict):
        # 先只收「真的存过」的值，再覆盖默认值：
        # 若拿默认值参与比较，用户把权重从 5 调到 1 会被 max() 顶回 5，永远降不下来。
        explicit: dict[str, int] = {}
        for key, value in raw.items():
            number = _clamp_weight(value)
            if number is None:
                continue
            target = _migrate_key(str(key))
            if target not in values:
                continue
            # 合并项（几个旧 key 指向同一项）取其中最高的一个，别把用户设过的 5 盖成 3
            explicit[target] = max(explicit.get(target, number), number)
        values.update(explicit)
    return values


def save_weights(values: dict) -> dict[str, int]:
    """保存权重：只认目录里的 key，越界值夹到 1-5，其余键忽略。"""
    merged = get_weights()
    changed = 0
    for key, value in (values or {}).items():
        target = _migrate_key(str(key))
        if target not in merged:
            continue
        number = _clamp_weight(value)
        if number is None:
            continue
        merged[target] = number
        changed += 1
    if changed:
        set_settings({WEIGHT_KEY: json.dumps(merged, ensure_ascii=False)})
    return merged


def weighted_items() -> list[dict[str, object]]:
    """已勾选能力，按「权重降序 + 目录顺序」排好，供提示词直接排测试顺序。"""
    weights = get_weights()
    order = {key: index for index, key in enumerate(CAPABILITY_KEYS)}
    items = [
        {**item, "weight": weights.get(item["key"], DEFAULT_WEIGHT)}
        for item in enabled_items()
    ]
    items.sort(key=lambda item: (-int(item["weight"]), order.get(str(item["key"]), 0)))
    return items


# ---------- 用户提示 ----------


def get_hints() -> dict[str, str]:
    """每一项能力的用户提示（只留目录里认得的 key，空内容不占位）。"""
    raw = _load_json(get_settings().get(HINT_KEY, "{}"), {})
    out: dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        target = _migrate_key(str(key))
        text = str(value or "").strip()
        if target in CAPABILITY_BY_KEY and text:
            out[target] = text[:HINT_MAX_CHARS]
    return out


def save_hints(values: dict) -> dict[str, str]:
    """整表替换：传进来的就是最终结果（空串＝删掉这条提示）。

    不跟旧值合并，否则用户在界面上清空一条提示永远删不掉——留着会让模型
    继续按一条已经作废的要求去测，比没写更糟。
    """
    cleaned: dict[str, str] = {}
    for key, value in (values or {}).items():
        target = _migrate_key(str(key))
        if target not in CAPABILITY_BY_KEY:
            continue
        text = str(value or "").strip()[:HINT_MAX_CHARS]
        if text:
            cleaned[target] = text
    set_settings({HINT_KEY: json.dumps(cleaned, ensure_ascii=False)})
    return cleaned


def hint_of(key: str) -> str:
    return get_hints().get(str(key), "")


def catalog() -> list[dict[str, str]]:
    """全部可勾选的专项能力（不含开关）。"""
    return list(CAPABILITIES)


def step_budget() -> int:
    """工具轮次预算：一次任务通常要「侦察→核对→试探→归档」多轮，给足余量。

    自动继续会把预设话一直发下去，每一轮都要真的能往深里走；
    40 轮就到顶会让模型在快摸到东西的时候被迫收手，所以给 50。
    """
    return 50


def snapshot() -> dict[str, object]:
    """当前能力快照，供 API 与每轮对话注入使用。"""
    return {
        "capabilities": enabled_items(),
        "weights": get_weights(),
        "hints": get_hints(),
        "order": [item["key"] for item in weighted_items()],
        "switches": get_switches(),
        "auto_pentest": auto_pentest_enabled(),
        "steps": step_budget(),
    }


def context_text() -> str:
    items = weighted_items()
    switches = get_switches()
    hints = get_hints()
    auto = auto_pentest_enabled()
    if not items and auto:
        # 一项没勾但开了自动渗透：按目标实际暴露面自己定范围（等价常规渗透流程）
        head = (
            "【测试能力快照 · 本轮开始前重新读取】\n"
            "自动渗透已开启，且用户没有勾选具体能力：按目标实际暴露面自己决定测什么，"
            "把常见的注入、越权、未授权、文件读取、认证绕过、云与组件问题都过一遍，"
            "验出问题立刻 record_finding 归档。红线不变：只做只读验证。"
        )
    else:
        head = (
            "【测试能力快照 · 本轮开始前重新读取】\n"
            "用户未勾选任何测试能力：只执行平台默认的被动侦察与配置面检查，"
            "不要主动发起注入、爆破、文件上传等专项探测。"
        )
    if items:
        lines = []
        for item in items:
            line = f"- [权重 {item['weight']}] {item['name']}（{item['group']}）：{item['description']}"
            hint = hints.get(str(item["key"]), "")
            if hint:
                # 用户提示挂在它自己那一行下面：模型读能力清单时一定会读到，
                # 不用它自己想起来「还有一段提示没看」
                line += (
                    "\n    【用户提示 · 硬性要求】"
                    + hint.replace("\n", "\n    ")
                )
            lines.append(line)
        if auto:
            scope = (
                f"已勾选 {len(items)} 项测试能力——**这 {len(items)} 项是底线，不是上限**："
                "每一项都必须有结论，同时清单之外的漏洞类型也要测（自动渗透已开启）。\n"
            )
        else:
            scope = (
                f"已勾选 {len(items)} 项测试能力，**只能在这些范围内工作**；"
                "未勾选的能力一律不执行，清单之外的漏洞类型也不主动扩张（自动渗透已关闭）。\n"
            )
        head = (
            "【测试能力快照 · 本轮开始前重新读取】\n"
            + scope
            + "下面按权重从高到低排好了（5 最优先、1 最靠后），这就是默认的测试顺序：\n"
            + "\n".join(lines)
        )
        head += (
            "\n\n【先看前端代码，再按权重排顺序】动手测之前，先用 http_request 把目标的首页、登录页"
            "和它加载的 JS 抓下来（优先主入口与 app.*.js / chunk / vendor 这类打包文件），"
            "从中读出路由表、接口路径、参数名、鉴权方式与技术栈，先在脑子里（或用一句话在正文里）"
            "落实「这个站有哪些入口、每个入口对应哪类测试」。然后按上面的权重从高到低开测；"
            "权重相同的，先测前端代码里真的能看到入口的那一项。"
            "前端代码里明显用不上的高权重项不要硬凑——跳过它，把时间放到真有入口的能力上，"
            "并在正文里说一句为什么跳过。"
        )
        if hints:
            listed = "、".join(
                CAPABILITY_BY_KEY[key]["name"] for key in hints if key in CAPABILITY_BY_KEY
            )
            head += (
                "\n\n【用户提示 · 强制执行，不是建议】上面带「用户提示」的项："
                f"{listed}。\n"
                "这些是用户亲手写的要求，测试该项之前必须先逐字读完，然后严格照它执行：\n"
                "1. 提示里点名的接口、参数、账号、检查点，一个都不能少——漏掉任何一条，这一项就算没测，"
                "平台会把结论退回并继续催；\n"
                "2. 提示里明确说「不要测 / 不要碰」的，一律不碰，哪怕你认为那里可能有问题；\n"
                "3. 不许把提示当成一句口号复述；要按它真的发出请求、拿到响应；\n"
                "4. 用 report_capability 上报该项时，note 里要写清提示里每处要求各自的结果（照做了看到什么 / "
                "为什么没做）。平台要求先读提示再上报：第一次上报会返回 hint_required 和提示原文，"
                "读完把同一结论再报一次即可，不用重新测。"
            )
    if auto:
        head += (
            "\n\n【自动渗透已开启：清单是底线，不是边界】\n"
            "1. 上面勾选的每一项仍然必须有结论（vulnerable / clean / blocked），这一条不放宽；\n"
            "2. 之外还要按目标真实暴露面自己找别的类型：前端代码里看到的、响应头暴露的、"
            "接口形态暗示的（GraphQL、WebSocket、文件上传、反序列化、SSRF 回调、缓存投毒、"
            "批量导出越权、第三方组件已知漏洞等），都可以直接测；\n"
            "3. 清单外的类型验出问题：一律用 record_finding 归档，标题里写清属于哪一类；"
            "如果正好是清单里存在但没勾选的项，也可以 report_capability 上报（平台照收，"
            "只是不计入本次交付门槛）；\n"
            "4. 不许把「不在清单里」「用户没勾」当成不测的理由；也不许只测清单就宣布收工。\n"
            "红线不变：只做只读验证，不写改删数据、不压测、不爆破、不横向。"
        )
    else:
        head += (
            "\n\n【自动渗透已关闭：只测清单内】\n"
            "只测上面勾选的能力，清单之外的漏洞类型不主动扩张；"
            "顺手看到别的线索时，在正文里记一句「另外发现某某入口值得单独测」即可，不要展开测试。"
            "用户在能力页把这个开关打开后，才允许超出清单。"
        )
    head += (
        "\n\n开关状态：操作询问（两个平级开关，无总开关）"
        "读取敏感信息={sensitive}、删除类操作={delete}。"
        "自动继续（跑完一轮把预设话原样发出去，即自动迭代）由用户在对话页控制，不在能力页设开关。"
        "每次处理用户输入前都已重新读取本快照，请以此为准；若不确定，调用 list_capabilities 再确认一次。"
        "另外：绕过与变形手法（编码、大小写、注释、重复写、分块等）不需要单独开关——"
        "勾选了某类探测能力，它的常规绕过方式就已经默认允许，直接用，不要因为「没勾选绕过项」而放弃验证。"
    ).format(
        sensitive="询问" if ask_enabled(ASK_SENSITIVE_KEY) else "不询问",
        delete="询问" if ask_enabled(ASK_DELETE_KEY) else "不询问",
    )
    active = []
    if ask_enabled(ASK_SENSITIVE_KEY):
        active.append("读取敏感信息（凭据、私钥、令牌、连接串、个人身份信息）")
    if ask_enabled(ASK_DELETE_KEY):
        active.append("删除类操作（删文件、删目录、清库等不可逆动作）")
    if active:
        head += (
            "\n\n【操作询问已开启】以下操作会先经用户确认，未确认前不得执行："
            + "；".join(active)
            + "。平台会自动弹确认卡，你只需把要做的事讲清楚并等待用户决定；"
            "用户拒绝后不要重试同一操作，改用只读手段或给出替代方案。"
            "其余操作（执行只读命令、向任何目标发请求、登记资产、发起/终止评估、流转风险、归档结论、写报告）一律直接执行。"
            "目标范围不需要任何授权确认：用户登录时已确认免责声明，他点名的目标就是已授权目标。"
        )
    else:
        head += "\n\n【询问开关都已关闭】所有操作直接执行，平台不再打断用户。"
    return head
