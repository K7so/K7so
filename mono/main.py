from __future__ import annotations

import asyncio
import contextlib

from fastapi import Depends, FastAPI, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import (
    asset_modules,
    assets,
    auth,
    capabilities,
    chat,
    connectors,
    dashboard,
    findings,
    kits,
    memory,
    reports,
    scans,
    settings,
)
from .api.deps import get_current_user
from .config import APP_NAME, APP_SUBTITLE, APP_VERSION, STATIC_DIR
from .db import db, init_db
from .engine.scanner import scan_worker


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with db() as conn:
        conn.execute(
            "UPDATE scans SET status='failed', stage='服务重启中断', finished_at=datetime('now','localtime') "
            "WHERE status='running'"
        )
    workers = [asyncio.create_task(scan_worker()) for _ in range(2)]
    try:
        yield
    finally:
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


app = FastAPI(
    title=f"{APP_NAME} {APP_SUBTITLE}",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.include_router(auth.router)

for module in (
    dashboard, chat, assets, asset_modules, kits, scans, findings,
    connectors, capabilities, reports, settings, memory,
):
    app.include_router(module.router, dependencies=[Depends(get_current_user)])

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def revalidate_frontend(request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.get("/api/health")
async def health():
    return {"ok": True, "name": APP_NAME, "version": APP_VERSION}
