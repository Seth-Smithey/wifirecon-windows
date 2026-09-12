"""The optional web server.

The desktop application is the interface. This exists so a running survey can
be reached from another machine, which the desktop application cannot do on
its own. It is built on demand rather than at import, so a machine without
FastAPI installed still runs the application normally.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from . import runtime, scanner, updater
from .config import config, data_dir
from .services import ServiceError, lifecycle

log = logging.getLogger("wifirecon")

# In a packaged build the assets are unpacked beside the code, not next to
# this source file.
STATIC_DIR = (
    runtime.resource_dir() / "app" / "static"
    if runtime.is_frozen()
    else Path(__file__).resolve().parent / "static"
)
if runtime.is_frozen() and not STATIC_DIR.exists():
    # onedir layouts put them one level up.
    alternative = runtime.resource_dir() / "static"
    if alternative.exists():
        STATIC_DIR = alternative


def available() -> tuple[bool, str]:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        return False, (
            "Remote access needs fastapi and uvicorn, which are not installed. "
            "Run: pip install fastapi uvicorn[standard]"
        )
    return True, ""


def create_app():
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles

    from .api.routes import router

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        log.info("wifirecon-win %s serving", updater.version())
        log.info("Data directory: %s", data_dir())
        lifecycle.bootstrap()
        # Scanning is opt-in. The engine thread comes up so the interface can
        # talk to it, but it stays idle unless autostart was asked for.
        if not config.get("scan", "autostart_on_launch", default=False):
            config.set(False, "scan", "enabled")
        scanner.engine.start()
        if config.get("updates", "check_on_start", default=True):
            updater.checker.start(
                config.get("updates", "channel", default="main"),
                float(config.get("updates", "check_interval_hours", default=24)),
            )
        try:
            yield
        finally:
            log.info("Shutting down")
            updater.checker.stop()
            lifecycle.teardown()

    application = FastAPI(
        title="wifirecon-win",
        description="Passive wireless reconnaissance for Windows using the "
                    "Native Wifi API.",
        version=updater.version(),
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1", "http://localhost"],
        allow_origin_regex=r"http://(127\.0\.0\.1|localhost)(:\d+)?",
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(router)

    @application.exception_handler(ServiceError)
    async def service_error(request, exc: ServiceError):
        # The service layer writes its messages for a person, so they are
        # carried through rather than replaced with something vaguer.
        return JSONResponse(status_code=exc.status, content={"detail": exc.message})

    @application.exception_handler(Exception)
    async def unhandled(request, exc):  # pragma: no cover - safety net
        log.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Something went wrong. Check Diagnostics or the log."},
        )

    if STATIC_DIR.exists():
        application.mount(
            "/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @application.get("/", include_in_schema=False)
    async def index():
        page = STATIC_DIR / "index.html"
        if not page.exists():
            return JSONResponse(
                status_code=500,
                content={"detail": "The web interface files are missing. "
                                   "Reinstall, or use the desktop application."},
            )
        return FileResponse(str(page), headers={"Cache-Control": "no-store"})

    @application.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        icon = STATIC_DIR / "favicon.svg"
        if icon.exists():
            return FileResponse(str(icon), media_type="image/svg+xml")
        return JSONResponse(status_code=404, content={"detail": "No icon"})

    return application
