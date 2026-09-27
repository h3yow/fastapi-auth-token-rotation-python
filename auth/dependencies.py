"""FastAPI 依赖：凭据提取、认证、按作用域授权与按主体限流。

所有关键判定都写日志（令牌状态、所需权限与实际权限、限流计数），
便于测试与排障时区分失败原因。
"""

from __future__ import annotations

import logging
from typing import Callable

from fastapi import Request

from .errors import AuthError, ErrorCode
from .models import User

logger = logging.getLogger("auth")


def get_current_user(request: Request) -> User:
    """从 Authorization: Bearer 头提取并校验访问令牌。"""
    header = request.headers.get("authorization")
    if header is None:
        logger.info("认证失败: 缺少 Authorization 头")
        raise AuthError(401, ErrorCode.MISSING_CREDENTIALS, "缺少访问凭据")
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.info("认证失败: Authorization 头格式不合法 header=%r", header)
        raise AuthError(401, ErrorCode.MALFORMED_TOKEN, "Authorization 头格式不合法")

    token = parts[1]
    token_service = request.app.state.token_service
    try:
        user = token_service.authenticate_access_token(token)
    except AuthError as exc:
        logger.info("认证失败: 令牌状态=%s 原因=%s", exc.code, exc.message)
        raise
    logger.info("认证成功: subject=%s scopes=%s", user.username, sorted(user.scopes))
    return user


def require_scopes(*required: str) -> Callable:
    """生成一个要求指定作用域的授权依赖。

    凭据有效但权限不足时返回 403 + insufficient_scope，
    与「完全没有凭据」的 401 明确区分。
    """
    required_set = frozenset(required)

    def checker(request: Request) -> User:
        user = get_current_user(request)
        missing = required_set - user.scopes
        if missing:
            logger.info(
                "授权拒绝: subject=%s 所需权限=%s 实际权限=%s 缺少=%s",
                user.username, sorted(required_set), sorted(user.scopes), sorted(missing),
            )
            raise AuthError(403, ErrorCode.INSUFFICIENT_SCOPE, "权限不足")
        logger.info("授权通过: subject=%s 所需权限=%s", user.username, sorted(required_set))
        return user

    return checker


def rate_limited(request: Request) -> User:
    """按调用主体（用户名）限流，超过阈值返回 429 并携带重试提示。"""
    user = get_current_user(request)
    limiter = request.app.state.rate_limiter
    allowed, remaining, retry_after = limiter.check(user.username)
    logger.info(
        "限流判定: subject=%s allowed=%s remaining=%s retry_after=%s",
        user.username, allowed, remaining, retry_after,
    )
    if not allowed:
        raise AuthError(
            429, ErrorCode.RATE_LIMITED,
            "请求过于频繁，请稍后重试", retry_after=retry_after,
        )
    return user
