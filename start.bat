@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] 创建虚拟环境...
  python -m venv .venv
  if errorlevel 1 (
    echo 创建虚拟环境失败，请确认已安装 Python 3.10+ 并加入 PATH。
    pause
    exit /b 1
  )
)

echo [2/3] 安装依赖...
".venv\Scripts\python.exe" -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo 依赖安装失败，尝试不带版本约束安装...
  ".venv\Scripts\python.exe" -m pip install -q fastapi uvicorn httpx cryptography
  if errorlevel 1 (
    echo 依赖安装失败，请检查网络后重试。
    pause
    exit /b 1
  )
)

echo [3/3] 启动 K7so...
echo 打开 http://127.0.0.1:8000  默认账号 admin / admin123
".venv\Scripts\python.exe" run.py
pause
