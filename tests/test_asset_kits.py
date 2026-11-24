"""资产监管 + K7so工具：解析、提取、子域收集、模块对比、工具导入与运行。

用法：
    python tests/test_asset_kits.py
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp(prefix="mono-assets-")
os.environ["MONO_DATA_DIR"] = TMP
sys.path.insert(0, str(ROOT))

from mono.db import init_db, set_settings  # noqa: E402
from mono.engine import asset_registry as ar  # noqa: E402
from mono.engine import kits  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))


# ---------------------------------------------------------------- 造文档
def make_xlsx(rows: list[list[str]]) -> bytes:
    shared: list[str] = []
    index: dict[str, int] = {}
    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for col_index, value in enumerate(row):
            if value not in index:
                index[value] = len(shared)
                shared.append(value)
            col = chr(ord("A") + col_index)
            cells.append(f'<c r="{col}{row_index}" t="s"><v>{index[value]}</v></c>')
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("xl/sharedStrings.xml",
                    '<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    + "".join(f"<si><t>{v}</t></si>" for v in shared) + "</sst>")
        zf.writestr("xl/worksheets/sheet1.xml",
                    '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>')
    return buf.getvalue()


def make_docx(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )
    return buf.getvalue()


def make_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/Contents 4 0 R>>endobj\n"
            b"4 0 obj<</Length " + str(len(stream)).encode() + b">>stream\n" + stream + b"\nendstream endobj\n"
            b"trailer<</Root 1 0 R>>\n%%EOF\n")


# ---------------------------------------------------------------- 解析
def test_parse() -> None:
    text, note = ar.parse_document("a.txt", "主站 www.example.com 与 10.1.2.3".encode("utf-8"))
    check("txt 能读出原文", "www.example.com" in text and not note, f"{text!r} {note}")

    text, _ = ar.parse_document("a.md", b"# head\n- api.example.com\n")
    check("md 能读出原文", "api.example.com" in text, text[:80])

    text, note = ar.parse_document("a.xlsx", make_xlsx([["www.example.com", "93.184.216.34"]]))
    check("xlsx 能读出单元格", "www.example.com" in text and "93.184.216.34" in text, f"{text!r} {note}")

    text, note = ar.parse_document("a.docx", make_docx("内网 oa.example.com 10.1.2.3"))
    check("docx 能读出正文", "oa.example.com" in text, f"{text!r} {note}")

    text, note = ar.parse_document("a.pdf", make_pdf("cdn.example.com 8.8.8.8"))
    check("pdf 能抽出文本", "cdn.example.com" in text, f"{text!r} {note}")

    text, note = ar.parse_document("a.doc", b"\x00\x01binary")
    check("老式 doc 给出明确提示", not text and "doc" in note.lower(), f"{text!r} {note}")

    text, note = ar.parse_document("a.xyz", b"")
    check("空文件不炸", text == "", f"{text!r} {note}")


def test_extract() -> None:
    got = ar.extract_targets("访问 https://a.example.com/x 和 b.example.com.cn，还有 10.0.0.1 与 1.2.3.4:8080")
    check("抽出域名", "a.example.com" in got["domains"] and "b.example.com.cn" in got["domains"], str(got))
    check("抽出 IP", "10.0.0.1" in got["ips"] and "1.2.3.4" in got["ips"], str(got))

    noise = "logo.png main.js app.css v1.2.3 user@mail.example.com readme.md"
    got = ar.extract_targets(noise)
    check("文件名不算域名", "logo.png" not in got["domains"] and "main.js" not in got["domains"], str(got))
    check("邮箱主机不算独立域名", "mail.example.com" in got["domains"], str(got))
    check("版本号不算域名", "v1.2.3" not in got["domains"], str(got))

    got = ar.extract_targets("999.1.1.1 与 10.0.0.256 都不是 IP")
    check("非法 IP 被剔除", got["ips"] == [], str(got))

    check("多级后缀识别", ar.root_domain("deep.a.example.co.uk") == "example.co.uk")
    check("com.cn 识别", ar.root_domain("x.example.com.cn") == "example.com.cn")
    check("裸域识别", ar.root_domain("example.com") == "example.com")
    check("ip 不当作域", not ar._valid_domain("10.0.0.1"))


def test_dns_name() -> None:
    """DNS 名字是「长度前缀标签」，还带 0xC0 压缩指针，解错了 MX/NS 全是乱码。"""
    raw = b"\x04mail\x06python\x03org\x00"
    name, end = ar._dns_name(raw, 0)
    check("解普通名字", name == "mail.python.org", name)
    check("返回正确的下一个位置", end == len(raw), str(end))

    # 压缩指针：前面放好名字，后面用一个指针指回去（真实报文就是这么省的）
    base = b"\x04mail\x06python\x03org\x00"
    data = base + b"\x03api\xc0\x00"
    name, end = ar._dns_name(data, len(base))
    check("前半段标签 + 指针", name == "api.mail.python.org", name)
    check("指针解完位置正确", end == len(data), str(end))

    name, _ = ar._dns_name(b"\xc0\x00", 0)
    check("指向自己的指针不进入死循环", name == "", name)

    check("空串不出错", ar._dns_name(b"\x00", 0)[0] == "")
    check("越界不出错", ar._dns_name(b"\x05ab", 0)[0] in ("", "ab"))


def test_parse_answers() -> None:
    """构造一段真实格式的 MX 响应，确认 preference 被跳过、主机名被解出来。"""
    qname = b"\x06python\x03org\x00"
    header = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    question = qname + b"\x00\x0f\x00\x01"
    answer_name = b"\xc0\x0c"
    rdata = b"\x00\x32" + b"\x04mail\xc0\x0c"
    answer = answer_name + b"\x00\x0f\x00\x01\x00\x00\x0e\x10" + len(rdata).to_bytes(2, "big") + rdata
    got = ar._parse_dns_answers(header + question + answer, 15)
    check("MX 解析出主机名", got == [b"mail.python.org"], str(got))


def test_records() -> None:
    """真查一次记录，只为确认「查询能跑通、不抛异常」；内容随网络变化不做硬断言。"""
    t0 = time.time()
    hosts, notes = ar.record_subdomains("qq.com")
    used = time.time() - t0
    check("记录查询能在 15 秒内返回", used < 15, f"{used:.1f}s")
    check("记录线索里都是合法域名", all(ar._valid_domain(h) for h in hosts), str(hosts[:5]))
    check("只保留同根域", all(h == "qq.com" or h.endswith(".qq.com") for h in hosts), str(hosts[:5]))
    check("SPF 原文能留证", all(isinstance(n, str) for n in notes))


# ---------------------------------------------------------------- 模块
def test_modules() -> None:
    m = ar.create_module("第一批-2026-11-17", "admin", "从资产清单导入")
    check("模块能建", bool(m.get("id")), str(m))
    check("模块名带日期", m["name"] == "第一批-2026-11-17", str(m.get("name")))
    check("建模块记了创建时间", bool(m.get("created_at")), str(m))

    mid = m["id"]
    added = ar.save_hosts(mid, [
        {"host": "www.example.com", "kind": "domain", "source": "document"},
        {"host": "api.example.com", "kind": "domain", "source": "document"},
        {"host": "10.0.0.5", "kind": "ip", "source": "document"},
    ])
    check("批量写入 3 条", added == 3, str(added))

    again = ar.save_hosts(mid, [{"host": "www.example.com", "kind": "domain", "source": "document"}])
    check("同一条不重复入库", again == 0, str(again))

    rows = ar.host_rows(mid)
    check("模块里能查到 3 条", rows["total"] == 3, str(rows["total"]))
    got = ar.host_rows(mid, query="api")
    check("按关键字搜", got["total"] == 1 and got["items"][0]["host"] == "api.example.com", str(got))

    detail = ar.get_module(mid)
    check("模块详情带上数量", detail and detail["host_count"] == 3, str(detail))

    mods = ar.list_modules()
    check("模块列表能列出来", any(item["id"] == mid for item in mods), str(len(mods)))
    check("删模块成功", ar.delete_module(mid) is True)
    check("删完查不到", ar.get_module(mid) is None)


def test_compare() -> None:
    left = ar.create_module("九月-2026-09-01", "admin")["id"]
    right = ar.create_module("十月-2026-10-01", "admin")["id"]
    ar.save_hosts(left, [
        {"host": "www.example.com"}, {"host": "api.example.com"}, {"host": "old.example.com"},
    ])
    ar.save_hosts(right, [
        {"host": "www.example.com"}, {"host": "api.example.com"}, {"host": "new.example.com"},
        {"host": "vpn.example.com"},
    ])
    got = ar.compare_modules(left, right)
    check("对比标记成功", got.get("ok") is True, str(got)[:200])
    # added / removed 是域名列表（前端要用它渲染清单），不是计数
    check("新增两个域名", got["added"] == ["new.example.com", "vpn.example.com"], str(got.get("added")))
    check("消失一个域名", got["removed"] == ["old.example.com"], str(got.get("removed")))
    check("共有两个", got["common_count"] == 2, str(got.get("common_count")))
    check("列表前 200 条另给一份", got["sample_added"] == got["added"][:200], str(got.get("sample_added")))
    check("两边条数各自带上", got["left_count"] == 3 and got["right_count"] == 4, str(got)[:160])

    bad = ar.compare_modules(left, 99999)
    check("比不存在的模块给错误", bad.get("ok") is False, str(bad))


def test_import_document() -> None:
    mid = ar.create_module("导入测试", "admin")["id"]
    result = ar.import_document(mid, "资产.xlsx", make_xlsx([["www.example.com", "1.1.1.1"], ["api.example.com", ""]]), "admin")
    check("导入 xlsx 成功", result.get("ok") is True, str(result)[:200])
    check("导入后落库", result.get("added", 0) >= 2, str(result))
    detail = ar.get_module(mid)
    check("模块数量同步", detail["host_count"] >= 2, str(detail))
    rows = ar.host_rows(mid)
    hosts = {item["host"] for item in rows["items"]}
    check("文件里的域名都在", {"www.example.com", "api.example.com"} <= hosts, str(hosts))

    bad = ar.import_document(mid, "a.exe", b"MZ\x90\x00", "admin")
    check("不支持的格式被拒", bad.get("ok") is False and "不支持" in str(bad.get("error", "")), str(bad)[:160])


# ---------------------------------------------------------------- 工具
def test_kits() -> None:
    check("识别 python", kits.detect_kind("poc.py") == "python")
    check("识别 exe", kits.detect_kind("scan.exe") == "exe")
    check("识别 jar", kits.detect_kind("tool.jar") == "jar")
    check("未知扩展名默认可执行", kits.detect_kind("scan.bin") == "exe")

    check("文件名去路径", kits.safe_filename("C:\\x\\y\\poc.py") == "poc.py", kits.safe_filename("C:\\x\\y\\poc.py"))
    cleaned = kits.safe_filename('a<b>c:d"e|f?.exe')
    check("清掉非法字符", not any(ch in cleaned for ch in '<>:"|?*'), cleaned)

    script = Path(TMP) / "hello.py"
    script.write_text("print('k7so-tool-ok')\n", encoding="utf-8")
    data = script.read_bytes()

    sink = kits.make_sink("hello.py")
    sink.write(data)
    sink.close()
    info = kits.create_kit("hello.py", "python", sink.path, sink.size, sink.sha256, "admin")
    check("工具能入库", bool(info.get("id")), str(info))
    check("记录了摘要", len(info.get("sha256") or "") == 64, str(info.get("sha256")))

    same = kits.make_sink("hello.py")
    check("重名不覆盖原文件", same.path != sink.path, f"{same.path} vs {sink.path}")
    same.abort()   # 空文件 + 已打开的句柄，abort 会先关再删

    listed = kits.list_kits()
    check("工具列表能列出来", any(item["id"] == info["id"] for item in listed), str(len(listed)))

    run = kits.launch(kits.get_kit(info["id"]))
    check("python 工具能启动", run.get("ok") is True, str(run)[:200])
    output = ""
    for _ in range(60):
        state = kits.run_state(run["run_id"]) if run.get("ok") else None
        if state and state["status"] != "running":
            output = state.get("output") or ""
            break
        time.sleep(0.1)
    check("运行输出被收回来", "k7so-tool-ok" in output, output[:200])

    latest = kits.latest_run(info["id"])
    check("能查最近一次运行", latest and latest["status"] == "finished", str(latest)[:160])

    stopped = kits.stop(info["id"])
    check("停一个没在跑的工具如实说明", stopped.get("ok") is False and "没在跑" in str(stopped.get("error")), str(stopped))
    check("删工具", kits.delete_kit(info["id"], delete_file=True).get("ok") is True)
    check("删完查不到", kits.get_kit(info["id"]) is None)


def test_kit_kinds_error() -> None:
    """jar 没装 java 时要给出可操作的提示，而不是抛异常。"""
    fake = Path(TMP) / "x.jar"
    fake.write_bytes(b"PK\x03\x04")
    sink = kits.make_sink("x.jar")
    with open(sink.path, "wb") as handle:
        handle.write(fake.read_bytes())
    info = kits.create_kit("x.jar", "jar", sink.path, sink.size, sink.sha256, "admin")
    run = kits.launch(kits.get_kit(info["id"]))
    if run.get("ok"):
        check("有 java 时能启动 jar", True)
        kits.stop(info["id"])
    else:
        check("没 java 时给中文提示", "java" in str(run.get("error", "")).lower(), str(run))
    kits.delete_kit(info["id"])

    missing = kits.get_kit(99999)
    check("查不存在的工具返回 None", missing is None)
    check("运行不存在的工具给错误", kits.launch({"id": 99999, "filename": "nope.py", "kind": "python"}).get("ok") is False)


def test_prompt_and_nav() -> None:
    """导航与页面上该改的文案都改了，别留旧名字。"""
    html = (ROOT / "mono/static/index.html").read_text(encoding="utf-8")
    check("导航里有 K7so工具", "K7so工具" in html)
    check("导航里有资产监管", "资产监管" in html)
    check("旧「安全评估」导航已去掉", 'data-page="scans"><span class="idx">03</span>安全评估' not in html)
    check("旧「资产台账」导航已去掉", 'data-page="assets"><span class="idx">02</span>资产台账' not in html)
    for elem in ("kit-grid", "asset-module-table", "asset-compare", "kit-output-panel"):
        check(f"页面元素 {elem} 存在", elem in html)

    js = (ROOT / "mono/static/app.js").read_text(encoding="utf-8")
    check("工具页有导入与运行", "data-kit-run" in js and "api/kits/upload" in js)
    check("资产页有导入与对比", "data-module-import" in js and "api/asset-modules/compare" in js)
    check("来源标签覆盖新来源", '"DNS 记录"' in js or "DNS 记录" in js)
    check("收集时按钮置灰防重复点", "收集中…" in js)

    # v3.2 文案与交互：导航不再有旧写法，卡片别整块点击运行
    check("导航 K7so 不带空格", "K7so 工具" not in html and "K7so 工具" not in js)
    check("API 中心保留空格的包裹层", 'class="nav-label">API 中心' in html)
    check("导航文字包一层，空格不被 flex 吞掉", "nav-label" in (ROOT / "mono/static/style.css").read_text(encoding="utf-8"))
    check("资产页头部不再写那段长说明", "每个模块自己命名" not in html and "再顺着 DNS 收集三级子域名" not in html)
    check("卡片不再整块点击运行", '$$(".kit-card").forEach((card) => card.addEventListener("click"' not in js)
    check("卡片不显示导入时间", "导入 ${esc(kit.created_at)}" not in js)
    check("卡片不显示运行次数", "跑过 ${kit.run_count" not in js)
    check("卡片鼠标不再是手型", "cursor: default" in (ROOT / "mono/static/style.css").read_text(encoding="utf-8").split(".kit-card {")[1][:200])


def main() -> int:
    init_db()
    set_settings({"work_dir": str(Path(TMP) / "work")})
    (Path(TMP) / "work").mkdir(parents=True, exist_ok=True)

    test_parse()
    test_extract()
    test_dns_name()
    test_parse_answers()
    test_records()
    test_modules()
    test_compare()
    test_import_document()
    test_kits()
    test_kit_kinds_error()
    test_prompt_and_nav()

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n共 {len(RESULTS)} 项，通过 {passed} 项")
    failed = [name for name, ok, _ in RESULTS if not ok]
    if failed:
        print("失败：" + "、".join(failed))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
