import os
from pathlib import Path


def env(name: str, default: str | None = None) -> str | None:
    """读环境变量：优先 K7so_ 前缀，兼容早期的 MONO_ 前缀。"""
    for prefix in ("K7so_", "MONO_"):
        value = os.getenv(prefix + name)
        if value is not None:
            return value
    return default


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(env("DATA_DIR", str(BASE_DIR / "data")))
DB_PATH = DATA_DIR / "mono.db"
REPORTS_DIR = DATA_DIR / "reports"
MEMORY_DIR = DATA_DIR / "memory"
WORKSPACE_DIR = DATA_DIR / "workspace"
STATIC_DIR = Path(__file__).resolve().parent / "static"
SECRET_PATH = DATA_DIR / ".secret"

APP_NAME = "K7so"
APP_SUBTITLE = "Agent 渗透测试平台"
APP_VERSION = "3.7.4"

# 默认用普通浏览器 UA：目标是业务系统时，非浏览器指纹容易被 WAF 直接拦掉
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_ADMIN = env("ADMIN_USER", "admin")
# 初始口令不写死在代码里：留空就表示「首次启动随机生成一个」，
# 生成的口令写进 data/初始口令.txt，同时打到启动日志里。
# 想用固定口令（自动化部署、自己图省事）就设 K7so_ADMIN_PASSWORD。
DEFAULT_ADMIN_PASSWORD = env("ADMIN_PASSWORD", "") or ""
INITIAL_PASSWORD_FILE = DATA_DIR / "初始口令.txt"

SESSION_COOKIE = "mono_session"
SESSION_TTL = 12 * 3600

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


MEMORY_README = """# 用户级记忆目录

把希望 AI 长期记住的偏好、约定、历史决策写在这个目录下的文本文件里（.md / .txt / .json / .yaml / .csv …，也可以建子目录）。
每次对话开始前，平台会把记忆预载给模型；AI 还会按需继续读——不论文件多大、有多少个，都能用分页把整份记忆读完。
所以这里可以放心写长文档，不需要自己压缩成摘要。

本文件（README.md）只是目录说明，不会被当作记忆内容读取。
"""


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    readme = MEMORY_DIR / "README.md"
    if not readme.exists():
        try:
            readme.write_text(MEMORY_README, encoding="utf-8")
        except OSError:
            pass
