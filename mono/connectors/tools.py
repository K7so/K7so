"""本地安全工具连接器：Nmap / Nuclei / HTTPX。"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .base import BaseConnector, ConnectorResult

NMAP_WINDOWS_CANDIDATES = [
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
]


def resolve_binary(config: dict[str, Any], names: list[str], extra_paths: list[str] | None = None) -> str:
    configured = str(config.get("path") or "").strip()
    if configured and Path(configured).exists():
        return configured
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for candidate in extra_paths or []:
        if Path(candidate).exists():
            return candidate
    return ""


async def run_command(cmd: list[str], timeout: float = 180) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        return -1, "", f"命令执行超时（{int(timeout)}s）"
    return (
        process.returncode if process.returncode is not None else -1,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


class CLIBaseConnector(BaseConnector):
    binary_names: list[str] = []
    version_args: list[str] = ["-version"]
    version_markers: tuple[str, ...] = ()

    def binary(self) -> str:
        return resolve_binary(
            self.config,
            self.binary_names,
            NMAP_WINDOWS_CANDIDATES if "nmap" in self.binary_names else None,
        )

    async def test(self) -> ConnectorResult:
        path = self.binary()
        if not path:
            return ConnectorResult(
                False,
                f"未检测到 {self.binary_names[0]}，请安装后重试或填写可执行文件路径",
            )
        code, stdout, stderr = await run_command([path, *self.version_args], timeout=20)
        text = (stdout + "\n" + stderr).strip()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        first = lines[0] if lines else ""
        if code != 0:
            return ConnectorResult(False, f"工具无法正常执行（退出码 {code}）：{first[:160] or path}")
        if self.version_markers and not any(marker.lower() in text.lower() for marker in self.version_markers):
            return ConnectorResult(
                False,
                f"检测到的可执行文件不是预期工具（{first[:120] or path}），请填写正确路径",
            )
        return ConnectorResult(True, f"已检测到工具：{first or path}", {"path": path})

    def available(self) -> bool:
        return bool(self.binary())


class NmapConnector(CLIBaseConnector):
    key = "nmap"
    category = "tool"
    binary_names = ["nmap"]
    version_args = ["--version"]
    version_markers = ("nmap version",)

    async def scan_ports(
        self, targets: list[str], profile: str = "standard", timeout: float = 240
    ) -> ConnectorResult:
        path = self.binary()
        if not path:
            return ConnectorResult(False, "未安装 Nmap")
        top_ports = {"quick": "100", "standard": "500", "deep": "1000"}.get(profile, "500")
        cmd = [path, "-Pn", "-T4", "--top-ports", top_ports, "-oX", "-", *targets]
        code, stdout, stderr = await run_command(cmd, timeout=timeout)
        if code != 0 or not stdout.strip().startswith("<?xml"):
            return ConnectorResult(False, f"Nmap 执行失败：{stderr.strip()[:200] or '无输出'}")
        ports: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(stdout)
            for host in root.findall("host"):
                addr_node = host.find("address")
                addr = addr_node.get("addr") if addr_node is not None else ""
                for port in host.findall("./ports/port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    service = port.find("service")
                    ports.append(
                        {
                            "host": addr,
                            "port": int(port.get("portid", 0)),
                            "protocol": port.get("protocol", "tcp"),
                            "service": service.get("name", "") if service is not None else "",
                            "product": service.get("product", "") if service is not None else "",
                            "version": service.get("version", "") if service is not None else "",
                        }
                    )
        except ET.ParseError:
            return ConnectorResult(False, "Nmap XML 解析失败")
        return ConnectorResult(True, f"发现 {len(ports)} 个开放端口", {"ports": ports})


class NucleiConnector(CLIBaseConnector):
    key = "nuclei"
    category = "tool"
    binary_names = ["nuclei"]
    version_args = ["-version"]

    async def scan(
        self,
        targets: list[str],
        profile: str = "standard",
        output_path: str | None = None,
        timeout: float = 900,
        safe_mode: bool = True,
    ) -> ConnectorResult:
        path = self.binary()
        if not path:
            return ConnectorResult(False, "未安装 Nuclei")
        severity = str(self.config.get("severity") or "critical,high,medium,low")
        cmd = [path, "-jsonl", "-silent", "-severity", severity]
        if output_path:
            cmd += ["-o", output_path]
        if safe_mode:
            cmd += ["-etags", "dos,fuzz,intrusive,brute-force"]
        if profile == "quick":
            cmd += ["-tags", "exposure,misconfig,tech,panel"]
        if profile == "deep":
            cmd += ["-stats"]
        cmd += list(targets)
        code, _, stderr = await run_command(cmd, timeout=timeout)
        items: list[dict[str, Any]] = []
        if output_path and os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if code != 0 and not items:
            return ConnectorResult(False, f"Nuclei 执行失败：{stderr.strip()[:200] or '无输出'}")
        return ConnectorResult(True, f"Nuclei 命中 {len(items)} 条", {"items": items})


class HttpxConnector(CLIBaseConnector):
    key = "httpx"
    category = "tool"
    binary_names = ["httpx"]
    version_args = ["-version"]
    version_markers = ("projectdiscovery", "current version")
