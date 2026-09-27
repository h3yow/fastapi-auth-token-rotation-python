"""FastAPI dependencies: authentication, authorization, rate limiting."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Depends, Request

from .errors import (
    AuthError,
    ERR_FORBIDDEN,
    ERR_RATE_LIMITED,
    ERR_TOKEN_BAD_SIGNATURE,
    ERR_TOKEN_EXPIRED,
    ERR_TOKEN_FAMILY_REVOKED,
    ERR_TOKEN_MALFORMED,
    ERR_TOKEN_MISSING,
    ERR_TOKEN_NOT_RECOGNIZED,
    ERR_TOKEN_REUSE,
    ERR_TOKEN_REVOKED,
    ERR_WRONG_TOKEN_TYPE,
)
from .tokens import TokenClaims, decode_token

logger = logging.getLogger("authapp.authz")

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    scopes: frozenset[str]
    family_id: str
    jti: str


def _bearer_claims(request: Request) -> TokenClaims:
    """Extract and cryptographically verify the Bearer token.

    Distinguishes: missing -> malformed -> bad signature -> expired.
    """
    settings = request.app.state.settings
    header = request.headers.get("authorization")
    if header is None or not header:
        raise AuthError(ERR_TOKEN_MISSING, "missing credentials", status_code=401)
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthError(
            ERR_TOKEN_MALFORMED,
            "authorization header must be 'Bearer <token>'",
            status_code=401,
        )
    token = parts[1].strip()
    return decode_token(token, settings.secret, settings.clock())


def authenticate(request: Request) -> Principal:
    """Resolve the caller to a Principal or raise with a distinct code."""
    claims = _bearer_claims(request)
    if claims.token_type != ACCESS_TOKEN_TYPE:
        raise AuthError(
            ERR_WRONG_TOKEN_TYPE,
            f"an access token is required, got type {claims.token_type!r}",
            status_code=401,
        )

    refresh_store = request.app.state.refresh_store
    if refresh_store.is_family_revoked(claims.family_id):
        family = refresh_store.family(claims.family_id)
        reason = family.revoke_reason if family else "family not found"
        revoke_code = family.revoke_code if family else None
        # Reuse-driven revocation is reported distinctly from explicit logout.
        code = (
            ERR_TOKEN_FAMILY_REVOKED
            if revoke_code == ERR_TOKEN_REUSE
            else ERR_TOKEN_REVOKED
        )
        logger.info(
            "authz.deny reason=%s sub=%s fid=%s jti=%s family_reason=%s",
            code, claims.sub, claims.family_id, claims.jti, reason,
        )
        raise AuthError(code, f"token family is revoked: {reason}", status_code=401)

    principal = Principal(
        username=claims.sub,
        role=claims.role,
        scopes=frozenset(claims.scopes),
        family_id=claims.family_id,
        jti=claims.jti,
    )
    logger.info(
        "authz.allow sub=%s role=%s scopes=%s fid=%s jti=%s",
        principal.username, principal.role, sorted(principal.scopes),
        principal.family_id, principal.jti,
    )
    return principal


def require_scopes(*required: str):
    """Dependency factory enforcing that all ``required`` scopes are present."""
    required_set = frozenset(required)

    def _checker(request: Request, principal: Principal = Depends(authenticate)) -> Principal:
        missing = required_set - principal.scopes
        if missing:
            logger.info(
                "authz.forbidden sub=%s role=%s scopes=%s required=%s missing=%s",
                principal.username, principal.role, sorted(principal.scopes),
                sorted(required_set), sorted(missing),
            )
            raise AuthError(
                ERR_FORBIDDEN,
                "credential lacks one or more required permissions",
                status_code=403,
            )
        return principal

    return _checker


def rate_limit(request: Request, principal: Principal = Depends(authenticate)) -> Principal:
    """Per-subject fixed-window limit; runs after authentication."""
    limiter = request.app.state.rate_limiter
    result = limiter.check(principal.username)
    logger.info(
        "ratelimit.check sub=%s count=%s/%s allowed=%s window_start=%.3f retry_after=%s",
        principal.username, result.count, result.limit, result.allowed,
        result.window_start,
        result.retry_after_seconds if not result.allowed else 0,
    )
    if not result.allowed:
        raise AuthError(
            ERR_RATE_LIMITED,
            "rate limit exceeded for subject; retry later",
            status_code=429,
            headers={"Retry-After": str(result.retry_after_seconds)},
        )
    return principal

