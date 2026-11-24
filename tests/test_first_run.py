"""首次启动的口令：仓库里不留固定口令，随机生成且只在数据目录里。

这一组是「上传前检查」的固化版本：只要有人图省事把口令写回源码或登录页，
这里就会红。所有断言都不打印口令本身，只打印布尔与长度。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


PROBE = r"""
import json, os, sys
sys.path.insert(0, r"{root}")
from mono.db import init_db, db
from mono.config import INITIAL_PASSWORD_FILE
from mono.security import verify_password
init_db()
pwd = ""
if INITIAL_PASSWORD_FILE.exists():
    for line in INITIAL_PASSWORD_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("口令"):
            pwd = line.split("：", 1)[1].strip()
with db() as conn:
    row = conn.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()
hashed = row["password_hash"]
print("PROBE" + json.dumps({{
    "file": INITIAL_PASSWORD_FILE.exists(),
    "name": INITIAL_PASSWORD_FILE.name,
    "len": len(pwd),
    "matches_db": bool(pwd) and verify_password(pwd, hashed),
    "default_works": verify_password("admin123", hashed),
    "fixed_works": verify_password("FixedPass_2026", hashed),
}}, ensure_ascii=False))
"""


def probe(env_extra: dict[str, str] | None = None) -> dict:
    data = tempfile.mkdtemp(prefix="k7so-firstrun-")
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith("ADMIN_PASSWORD")}
    env["MONO_DATA_DIR"] = data
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("K7so_ADMIN_PASSWORD", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [PY, "-c", PROBE.format(root=str(ROOT))],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(ROOT),
    )
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("PROBE")), "")
    if not line:
        return {"error": (proc.stderr or proc.stdout)[-300:]}
    return json.loads(line[5:])


def test_random_first_run() -> None:
    info = probe()
    check("首次启动没有失败", "error" not in info, str(info.get("error")))
    if "error" in info:
        return
    check("首次启动会生成口令文件", info["file"] is True)
    check("口令文件就叫「初始口令.txt」", info["name"] == "初始口令.txt", str(info["name"]))
    check("生成的口令长度够用", info["len"] >= 10, str(info["len"]))
    check("文件里的口令就是数据库里的口令", info["matches_db"] is True)
    check("旧的固定口令 admin123 已失效", info["default_works"] is False)
    check("随机口令不是写死值", info["fixed_works"] is False)


def test_env_override() -> None:
    info = probe({"K7so_ADMIN_PASSWORD": "FixedPass_2026"})
    check("指定口令时首次启动成功", "error" not in info, str(info.get("error")))
    if "error" in info:
        return
    check("环境变量指定的口令能登录", info["fixed_works"] is True)
    check("指定口令时不覆盖口令文件", info["file"] is False)


def test_repo_has_no_credential() -> None:
    cfg = (ROOT / "mono/config.py").read_text(encoding="utf-8")
    check("配置里不再写死默认口令", 'env("ADMIN_PASSWORD", "") or ""' in cfg)
    check("配置里没有口令字面量", '"admin123"' not in cfg and "'admin123'" not in cfg)

    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
    check("登录页不预告口令", "admin123" not in html)
    check("登录页指路口令文件", "初始口令.txt" in html)

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    check("README 不提固定口令", "admin123" not in readme)
    check("README 说明随机口令", "随机口令" in readme and "初始口令.txt" in readme)

    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    check("数据目录整体不进仓库", "data/" in ignore)

    db_py = (ROOT / "mono/db.py").read_text(encoding="utf-8")
    check("建库时走随机口令入口", "_initial_admin_password()" in db_py)
    check("随机口令用 secrets 生成", "secrets.token_urlsafe" in db_py)


def main() -> int:
    test_random_first_run()
    test_env_override()
    test_repo_has_no_credential()
    failed = [name for name, ok, _ in RESULTS if not ok]
    print("\n" + "=" * 56)
    print(f"共 {len(RESULTS)} 项，通过 {len(RESULTS) - len(failed)} 项，失败 {len(failed)} 项")
    if failed:
        print("失败项：" + "、".join(failed))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
