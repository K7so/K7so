"""K7so 自动化渗透测试平台启动入口。

用法:
    python run.py                # 监听 127.0.0.1:8000
    python run.py --host 0.0.0.0 --port 9000
"""
import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="K7so auto pentest platform")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    uvicorn.run("mono.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
