"""应用工厂：组装认证、授权、限流与受有识路由。"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .config import Settings, load_settings
from .dependencies import rate_limited, require_scopes
from .errors import AuthError, ErrorCode
from .models import TokenPair, User
from .ratelimit import RateLimiter
from .tokens import TokenService

logger = logging.getLogger("auth")


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


# 演示用资源：归属不同主体，用于验证「不泄露资源是否存在」。
_ITEMS: dict[int, dict] = {
    1: {"id": 1, "owner": "admin", "name": "admin-item"},
    2: {"id": 2, "owner": "editor", "name": "editor-item"},
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="auth-token-rotation-demo")
    app.state.settings = settings
    app.state.token_service = TokenService(settings)
    app.state.rate_limiter = RateLimiter(
        max_requests=settings.rate_limit_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        headers = {}
        if exc.status_code == 401:
            headers["WWW-Authenticate"] = f'Bearer error="{exc.code}"'
        if exc.status_code == 429 and exc.retry_after:
            headers["Retry-After"] = str(exc.retry_after)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": str(exc.code), "message": exc.message}},
            headers=headers,
        )

    # ---------------- 认证端点 ---------------- #
    @app.post("/auth/token", response_model=TokenPair)
    def login(body: LoginRequest) -> TokenPair:
        user = settings.users.get(body.username)
        if user is None or user.password != body.password:
            logger.info("登录失败: username=%s 原因=用户名或密码错误", body.username)
            raise AuthError(401, ErrorCode.INVALID_CREDENTIALS, "用户名或密码错误")
        logger.info("登录成功: username=%s", user.username)
        return app.state.token_service.issue(user)

    @app.post("/auth/refresh", response_model=TokenPair)
    def refresh(body: RefreshRequest) -> TokenPair:
        pair = app.state.token_service.rotate(body.refresh_token)
        logger.info("令牌轮换成功: refresh_token 前缀=%s", body.refresh_token[:10])
        return pair

    @app.post("/auth/logout")
    def logout(body: RefreshRequest) -> dict:
        app.state.token_service.revoke_chain(body.refresh_token)
        logger.info("令牌链已撤销: refresh_token 前缀=%s", body.refresh_token[:10])
        return {"revoked": True}

    # ---------------- 受保护资源 ---------------- #
    @app.get("/api/profile", dependencies=[Depends(rate_limited)])
    def profile(user: User = Depends(require_scopes("read"))) -> dict:
        return {"username": user.username, "roles": sorted(user.roles),
                "scopes": sorted(user.scopes)}

    @app.post("/api/items", dependencies=[Depends(rate_limited)])
    def create_item(user: User = Depends(require_scopes("write"))) -> dict:
        return {"created": True, "by": user.username}

    @app.delete("/api/admin/users/{username}", dependencies=[Depends(rate_limited)])
    def delete_user(username: str, user: User = Depends(require_scopes("admin"))) -> dict:
        return {"deleted": username, "by": user.username}

    @app.get("/api/items/{item_id}")
    def get_item(item_id: int, user: User = Depends(require_scopes("read"))) -> dict:
        item = _ITEMS.get(item_id)
        # 资源不存在与「存在但无权访问」返回完全相同的 404，
        # 拒绝方式不泄露资源是否存在。
        if item is None or (item["owner"] != user.username and "admin" not in user.scopes):
            logger.info(
                "资源访问拒绝: subject=%s item_id=%s 存在=%s 判定=404(不泄露存在性)",
                user.username, item_id, item is not None,
            )
            raise AuthError(404, ErrorCode.INSUFFICIENT_SCOPE, "资源不存在")
        return item

    return app
