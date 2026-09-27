"""HTTP routes: login, refresh rotation, logout, protected resources."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from .deps import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    Principal,
    _bearer_claims,
    rate_limit,
    require_scopes,
)
from .errors import AuthError, ERR_WRONG_TOKEN_TYPE
from .tokens import encode_token

logger = logging.getLogger("authapp.routes")

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def _issue_pair(
    request: Request,
    username: str,
    role: str,
    scopes: tuple[str, ...],
    family_id: str,
    refresh_jti: str,
) -> TokenPair:
    settings = request.app.state.settings
    now = settings.clock()
    access_claims = {
        "jti": f"at-{refresh_jti[:12]}",
        "sub": username,
        "role": role,
        "scopes": list(scopes),
        "fid": family_id,
        "typ": ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": now + settings.access_token_ttl_seconds,
    }
    refresh_claims = {
        "jti": refresh_jti,
        "sub": username,
        "role": role,
        "scopes": list(scopes),
        "fid": family_id,
        "typ": REFRESH_TOKEN_TYPE,
        "iat": now,
        "exp": now + settings.refresh_token_ttl_seconds,
    }
    return TokenPair(
        access_token=encode_token(access_claims, settings.secret),
        refresh_token=encode_token(refresh_claims, settings.secret),
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/auth/login", response_model=TokenPair)
def login(body: LoginRequest, request: Request) -> TokenPair:
    settings = request.app.state.settings
    user_store = request.app.state.user_store
    refresh_store = request.app.state.refresh_store

    user = user_store.verify(body.username, body.password)
    if user is None:
        logger.info("auth.login.deny username=%s reason=bad_credentials", body.username)
        raise AuthError("invalid_credentials", "invalid username or password", status_code=401)

    now = settings.clock()
    entry = refresh_store.issue_family(
        user.username, user.role, user.scopes, now, settings.refresh_token_ttl_seconds
    )
    logger.info(
        "auth.login.allow sub=%s role=%s scopes=%s fid=%s",
        user.username, user.role, list(user.scopes), entry.family_id,
    )
    return _issue_pair(request, user.username, user.role, user.scopes, entry.family_id, entry.jti)


@router.post("/auth/refresh", response_model=TokenPair)
def refresh(request: Request) -> TokenPair:
    """Rotate a refresh token; reuse is detected and revokes the family."""
    settings = request.app.state.settings
    refresh_store = request.app.state.refresh_store

    claims = _bearer_claims(request)
    if claims.token_type != REFRESH_TOKEN_TYPE:
        raise AuthError(
            ERR_WRONG_TOKEN_TYPE,
            f"a refresh token is required, got type {claims.token_type!r}",
            status_code=401,
        )

    result = refresh_store.rotate(
        claims.jti, settings.clock(), settings.refresh_token_ttl_seconds
    )
    if result.outcome != "ok":
        logger.info(
            "auth.refresh.deny sub=%s jti=%s outcome=%s reason=%s",
            claims.sub, claims.jti, result.outcome, result.error.message,
        )
        raise result.error

    entry = result.new_entry
    family = refresh_store.family(result.family_id)
    logger.info(
        "auth.refresh.allow sub=%s old_jti=%s new_jti=%s fid=%s",
        claims.sub, claims.jti, entry.jti, result.family_id,
    )
    return _issue_pair(
        request, family.subject, family.role, family.scopes, result.family_id, entry.jti
    )


@router.post("/auth/logout")
def logout(request: Request, principal: Principal = Depends(require_scopes())) -> dict:
    """Revoke the caller's whole token family (all chained tokens die)."""
    refresh_store = request.app.state.refresh_store
    refresh_store.revoke_family(principal.family_id)
    logger.info(
        "auth.logout sub=%s fid=%s jti=%s",
        principal.username, principal.family_id, principal.jti,
    )
    return {"revoked": True, "family_id": principal.family_id}


@router.get("/public/ping")
def public_ping() -> dict:
    return {"pong": True}


@router.get("/api/profile")
def profile(principal: Principal = Depends(rate_limit)) -> dict:
    return {
        "username": principal.username,
        "role": principal.role,
        "scopes": sorted(principal.scopes),
    }


@router.get("/api/reports")
def reports(principal: Principal = Depends(require_scopes("read"))) -> dict:
    return {"reports": ["q1", "q2"], "viewer": principal.username}


@router.post("/api/reports")
def create_report(principal: Principal = Depends(require_scopes("write"))) -> dict:
    return {"created": True, "by": principal.username}


@router.get("/api/admin/users")
def admin_users(request: Request, principal: Principal = Depends(require_scopes("admin"))) -> dict:
    user_store = request.app.state.user_store
    return {"users": user_store.all_usernames(), "by": principal.username}


@router.get("/api/admin/reports/{report_id}")
def admin_report(report_id: str, principal: Principal = Depends(require_scopes("admin"))) -> dict:
    # Authorization runs before the existence check so that a low-privilege
    # caller cannot probe whether a given report_id exists.
    known = {"rpt-001": {"title": "Quarterly revenue"}, "rpt-002": {"title": "Ops incidents"}}
    if report_id not in known:
        raise AuthError("not_found", "report not found", status_code=404)
    return {"report_id": report_id, **known[report_id]}


@router.post("/api/admin/ratelimit/reset")
def reset_rate_limit(
    request: Request,
    principal: Principal = Depends(require_scopes("admin")),
    subject: str | None = None,
) -> dict:
    limiter = request.app.state.rate_limiter
    limiter.reset(subject)
    logger.info(
        "ratelimit.reset by=%s subject=%s", principal.username, subject or "<all>"
    )
    return {"reset": True, "subject": subject}
