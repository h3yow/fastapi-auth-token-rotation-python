"""令牌生命周期：签发、轮换、并发复用、过期、撤销、签名 / 格式不合法。

每个失败场景断言可区分的 error code，并通过 caplog 检查关键判定依据。
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

import httpx
import jwt
import pytest

from auth.config import Settings
from auth.errors import AuthError, ErrorCode
from auth.tokens import TokenService

from .conftest import auth_header, login


class FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_service(**overrides) -> tuple[TokenService, FakeClock]:
    clock = FakeClock()
    settings = Settings(**overrides)
    return TokenService(settings, now=clock), clock


# ---------------- 服务级：轮换与复用 ---------------- #

def test_refresh_rotation_invalidates_old_token():
    svc, _ = make_service()
    user = svc._settings.users["viewer"]
    pair1 = svc.issue(user)
    pair2 = svc.rotate(pair1.refresh_token)
    assert pair2.refresh_token != pair1.refresh_token

    # 旧刷新令牌再次使用 → 复用，整条链失效
    with pytest.raises(AuthError) as exc:
        svc.rotate(pair1.refresh_token)
    assert exc.value.code == ErrorCode.TOKEN_REUSE_DETECTED

    # 链上新的访问令牌也随之失效，且原因可区分
    with pytest.raises(AuthError) as exc2:
        svc.authenticate_access_token(pair2.access_token)
    assert exc2.value.code == ErrorCode.TOKEN_REUSE_DETECTED


def test_concurrent_refresh_reuse_only_one_succeeds(caplog):
    svc, _ = make_service()
    user = svc._settings.users["editor"]
    pair = svc.issue(user)

    def attempt(_):
        try:
            svc.rotate(pair.refresh_token)
            return "success"
        except AuthError as e:
            return str(e.code)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))

    logging.getLogger("auth").info(
        "并发复用判定: 输入=同一刷新令牌x16 结果=%s", sorted(set(results)))
    assert results.count("success") == 1
    assert results.count(str(ErrorCode.TOKEN_REUSE_DETECTED)) == 15


def test_concurrent_refresh_over_http_only_one_succeeds(client):
    pair = login(client, "viewer", "viewer-pass")

    async def run():
        transport = httpx.ASGITransport(app=client.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
            return await asyncio.gather(*[
                ac.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
                for _ in range(8)
            ])

    responses = asyncio.run(run())
    codes = [r.status_code for r in responses]
    errors = {r.json()["error"]["code"] for r in responses if r.status_code != 200}
    logging.getLogger("auth").info(
        "HTTP 并发轮换: 状态码=%s 错误码=%s", sorted(codes), sorted(errors))
    assert codes.count(200) == 1
    assert errors == {str(ErrorCode.TOKEN_REUSE_DETECTED)}


# ---------------- 服务级：过期 / 撤销 / 不合法 ---------------- #

def test_expired_access_token():
    svc, clock = make_service(access_token_ttl_seconds=10)
    pair = svc.issue(svc._settings.users["viewer"])
    clock.advance(11)
    with pytest.raises(AuthError) as exc:
        svc.authenticate_access_token(pair.access_token)
    assert exc.value.code == ErrorCode.TOKEN_EXPIRED


def test_expired_refresh_token():
    svc, clock = make_service(refresh_token_ttl_seconds=10)
    pair = svc.issue(svc._settings.users["viewer"])
    clock.advance(11)
    with pytest.raises(AuthError) as exc:
        svc.rotate(pair.refresh_token)
    assert exc.value.code == ErrorCode.TOKEN_EXPIRED


def test_invalid_signature():
    svc, _ = make_service()
    forged = jwt.encode(
        {"sub": "viewer", "scopes": ["read"], "typ": "access",
         "iat": 1, "exp": 9_999_999_999},
        "wrong-secret-wrong-secret-wrong!!", algorithm="HS256")
    with pytest.raises(AuthError) as exc:
        svc.authenticate_access_token(forged)
    assert exc.value.code == ErrorCode.INVALID_SIGNATURE


def test_malformed_token():
    svc, _ = make_service()
    with pytest.raises(AuthError) as exc:
        svc.authenticate_access_token("not-a-jwt")
    assert exc.value.code == ErrorCode.MALFORMED_TOKEN


def test_revoked_chain():
    svc, _ = make_service()
    pair = svc.issue(svc._settings.users["viewer"])
    svc.revoke_chain(pair.refresh_token)

    with pytest.raises(AuthError) as exc:
        svc.rotate(pair.refresh_token)
    assert exc.value.code == ErrorCode.TOKEN_REVOKED

    with pytest.raises(AuthError) as exc2:
        svc.authenticate_access_token(pair.access_token)
    assert exc2.value.code == ErrorCode.TOKEN_REVOKED


def test_unknown_refresh_token():
    svc, _ = make_service()
    with pytest.raises(AuthError) as exc:
        svc.rotate("rt_doesnotexist")
    assert exc.value.code == ErrorCode.UNKNOWN_TOKEN


def test_rejection_reasons_are_distinguishable():
    """所有拒绝原因的错误码互不相同。"""
    codes = {
        ErrorCode.TOKEN_EXPIRED, ErrorCode.TOKEN_REVOKED,
        ErrorCode.TOKEN_REUSE_DETECTED, ErrorCode.INVALID_SIGNATURE,
        ErrorCode.MALFORMED_TOKEN, ErrorCode.UNKNOWN_TOKEN,
        ErrorCode.MISSING_CREDENTIALS, ErrorCode.INSUFFICIENT_SCOPE,
        ErrorCode.RATE_LIMITED,
    }
    assert len(codes) == 9


# ---------------- HTTP 级：端到端 ---------------- #

def test_http_refresh_rotation_and_reuse(client, caplog):
    pair = login(client, "viewer", "viewer-pass")
    r1 = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r1.status_code == 200
    r2 = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == str(ErrorCode.TOKEN_REUSE_DETECTED)
    # 新访问令牌也因链失效而被拒
    r3 = client.get("/api/profile", headers=auth_header(r1.json()))
    assert r3.status_code == 401
    assert r3.json()["error"]["code"] == str(ErrorCode.TOKEN_REUSE_DETECTED)
    assert "WWW-Authenticate" in r3.headers


def test_http_logout_revokes_chain(client):
    pair = login(client, "editor", "editor-pass")
    r = client.post("/auth/logout", json={"refresh_token": pair["refresh_token"]})
    assert r.status_code == 200
    r2 = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r2.json()["error"]["code"] == str(ErrorCode.TOKEN_REVOKED)
    r3 = client.get("/api/profile", headers=auth_header(pair))
    assert r3.json()["error"]["code"] == str(ErrorCode.TOKEN_REVOKED)


def test_http_bad_login(client):
    r = client.post("/auth/token", json={"username": "viewer", "password": "wrong"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"
