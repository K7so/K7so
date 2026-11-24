"""一键跑完所有回归测试。

用法：
    python tests/run_all.py
任意一组失败则退出码非 0。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    ("智能工作循环", "tests/test_agent_flow.py"),
    ("设置项是否真的生效", "tests/test_settings_effect.py"),
    ("泄露门槛与提问导航", "tests/test_leak_and_outline.py"),
    ("工具层冒烟", "tests/test_tools_smoke.py"),
    ("资产监管与 K7so工具", "tests/test_asset_kits.py"),
    ("步骤看门狗与能力方块", "tests/test_watchdog.py"),
    ("承上摘要与自定义模型", "tests/test_round_brief.py"),
    ("首次启动不写死口令", "tests/test_first_run.py"),
    ("接口层冒烟", "tests/test_api_smoke.py"),
    ("记忆联调（按记忆干活）", "tests/test_memory_worker.py"),
]


def main() -> int:
    failed = []
    for name, path in CASES:
        print("=" * 66)
        print(f"▶ {name}  ({path})")
        print("=" * 66)
        proc = subprocess.run([sys.executable, str(ROOT / path)], cwd=ROOT)
        if proc.returncode != 0:
            failed.append(name)
        print()

    print("=" * 66)
    if failed:
        print("失败：" + "、".join(failed))
        return 1
    print("全部测试通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
