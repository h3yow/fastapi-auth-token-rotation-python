"""Application factory wiring stores, limiter and routes together."""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import Settings
from .errors import AuthError
from .ratelimit import FixedWindowRateLimiter
from .routes import router
from .store import RefreshTokenStore, UserStore


def configure_logging(level: str | None = None) -> None:
    level = level or os.environ.get("AUTHAPP_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    logger = logging.getLogger("authapp")
    if not any(getattr(h, "_authapp", False) for h in logger.handlers):
        handler._authapp = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging()

    app = FastAPI(title="authapp", version="0.1.0")
    app.state.settings = settings
    app.state.user_store = UserStore()
    app.state.refresh_store = RefreshTokenStore()
    app.state.rate_limiter = FixedWindowRateLimiter(
        limit=settings.rate_limit_per_subject,
        window_seconds=settings.rate_limit_window_seconds,
        clock=settings.clock,
    )
    app.include_router(router)

    @app.exception_handler(AuthError)
    async def _on_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
            headers=exc.headers,
        )

    return app
