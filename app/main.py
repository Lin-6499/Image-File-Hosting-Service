"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import settings
from .db import db
from .routers import access, files

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("host")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    added = db.init()
    if added:
        log.info("schema migrated, columns added: %s", ", ".join(added))
    # The cause of link instability is an empty SECRET_KEY, not debug mode.
    # Saying "debug mode" sent people looking in the wrong place: the reloader
    # restarting on every save is what makes the churn visible, but a fixed
    # SECRET_KEY keeps links valid across those restarts.
    if settings.secret_key_ephemeral:
        log.warning(
            "SECRET_KEY is empty: a random signing key was generated for this "
            "process, so links issued before this start are invalid and links "
            "issued now will die on the next restart. Set SECRET_KEY in .env "
            "to keep links stable across restarts."
        )
    log.info("data dir: %s", settings.data_dir)
    log.info("base url: %s", settings.base_url)

    # Report the antivirus posture at startup. Scanning being off is a
    # legitimate configuration, but it should never be a surprise.
    from .scanservice import get_scanner

    scanner = get_scanner()
    if scanner is None:
        log.warning(
            "antivirus scanning DISABLED (AV_BACKEND=%s); "
            "uploads are recorded as 'skipped'",
            settings.av_backend,
        )
    else:
        log.info("antivirus scanning enabled via %s", scanner.name)

    yield
    log.info("shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Image & Text Hosting Service",
        version="1.0.0",
        description=(
            "Self-hosted file and image hosting with time-limited signed "
            "download links and public image display links."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        # Wide-open CORS is acceptable for a link-hosting service whose
        # access routes are unauthenticated anyway; the API routes remain
        # protected by API keys. Narrow this if the API is browser-exposed.
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(files.router)
    app.include_router(access.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_exc_handler(request: Request, exc: StarletteHTTPException):
        code = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            410: "gone",
            413: "too_large",
            415: "unsupported_media_type",
            429: "rate_limited",
            507: "insufficient_storage",
        }.get(exc.status_code, "error")
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": code, "message": str(exc.detail)}},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "request validation failed",
                    "details": exc.errors(),
                }
            },
        )

    @app.get("/healthz", tags=["ops"], summary="Liveness probe")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"], summary="Readiness probe")
    async def readyz():
        writable = settings.data_dir.exists() and settings.blobs_dir.exists()
        return {"status": "ready" if writable else "not_ready", "storage_writable": writable}

    return app


app = create_app()
