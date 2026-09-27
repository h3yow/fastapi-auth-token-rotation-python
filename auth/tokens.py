"""令牌服务：JWT 访问令牌 + 不透明刷新令牌链。

设计要点：
- 每次刷新必须轮换：旧刷新令牌被标记为 rotated，立即失效。
- 同一刷新令牌被再次使用（含并发）视为复用攻击：整条令牌链
  （family）被标记为 compromised，链上所有刷新令牌与访问令牌
  一律拒绝，且错误码与「主动撤销」「过期」等情形可区分。
- 所有状态变更在单把锁内完成，check-and-set 原子，并发下
  同一刷新令牌最多只有一次轮换成功。
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Literal

import jwt

from .config import Settings
from .errors import AuthError, ErrorCode
from .models import TokenPair, User

# 令牌链状态：active 正常 / revoked 主动撤销 / compromised 检测到复用
FamilyStatus = Literal["active", "revoked", "compromised"]

# 刷新令牌个体状态
TokenStatus = Literal["active", "rotated", "revoked"]


@dataclass
class _RefreshRecord:
    token: str
    username: str
    family_id: str
    expires_at: float
    status: TokenStatus = "active"


class TokenService:
    """并发安全的令牌服务。"""

    def __init__(self, settings: Settings, now: Callable[[], float] | None = None) -> None:
        self._settings = settings
        self._now = now or time.time
        self._lock = threading.Lock()
        self._refresh_tokens: dict[str, _RefreshRecord] = {}
        self._families: dict[str, FamilyStatus] = {}

    # ------------------------------------------------------------------ #
    # 签发
    # ------------------------------------------------------------------ #
    def issue(self, user: User) -> TokenPair:
        """为用户开启一条新的令牌链并签发首个令牌对。"""
        family_id = uuid.uuid4().hex
        with self._lock:
            self._families[family_id] = "active"
            return self._issue_pair_locked(user, family_id)

    def _issue_pair_locked(self, user: User, family_id: str) -> TokenPair:
        now = self._now()
        access_ttl = self._settings.access_token_ttl_seconds
        refresh_ttl = self._settings.refresh_token_ttl_seconds

        access_token = jwt.encode(
            {
                "sub": user.username,
                "roles": sorted(user.roles),
                "scopes": sorted(user.scopes),
                "fid": family_id,
                "jti": uuid.uuid4().hex,
                "iat": int(now),
                "exp": int(now) + access_ttl,
                "typ": "access",
            },
            self._settings.jwt_secret,
            algorithm=self._settings.jwt_algorithm,
        )

        refresh_token = f"rt_{uuid.uuid4().hex}"
        self._refresh_tokens[refresh_token] = _RefreshRecord(
            token=refresh_token,
            username=user.username,
            family_id=family_id,
            expires_at=now + refresh_ttl,
        )
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=access_ttl,
        )

    # ------------------------------------------------------------------ #
    # 访问令牌校验
    # ------------------------------------------------------------------ #
    def authenticate_access_token(self, token: str) -> User:
        """校验访问令牌，失败时抛出带可区分错误码的 AuthError。"""
        try:
            payload = jwt.decode(
                token,
                self._settings.jwt_secret,
                algorithms=[self._settings.jwt_algorithm],
                # exp 由下方基于注入时钟手动判定，保证测试与重启行为确定。
                options={"require": ["exp", "iat", "sub"], "verify_exp": False},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError(401, ErrorCode.TOKEN_EXPIRED, "访问令牌已过期") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthError(401, ErrorCode.INVALID_SIGNATURE, "令牌签名不合法") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError(401, ErrorCode.MALFORMED_TOKEN, "令牌格式不合法") from exc

        if float(payload["exp"]) <= self._now():
            raise AuthError(401, ErrorCode.TOKEN_EXPIRED, "访问令牌已过期")

        if payload.get("typ") != "access":
            raise AuthError(401, ErrorCode.MALFORMED_TOKEN, "令牌类型不正确")

        family_id = payload.get("fid", "")
        with self._lock:
            family_status = self._families.get(family_id, "active")
        if family_status == "compromised":
            raise AuthError(
                401, ErrorCode.TOKEN_REUSE_DETECTED,
                "检测到刷新令牌复用，所属令牌链已失效",
            )
        if family_status == "revoked":
            raise AuthError(401, ErrorCode.TOKEN_REVOKED, "令牌链已被撤销")

        username = payload["sub"]
        user = self._settings.users.get(username)
        if user is None:
            raise AuthError(401, ErrorCode.UNKNOWN_TOKEN, "令牌对应的主体不存在")
        return user

    # ------------------------------------------------------------------ #
    # 刷新轮换（核心：复用检测 + 并发安全）
    # ------------------------------------------------------------------ #
    def rotate(self, refresh_token: str) -> TokenPair:
        """用刷新令牌轮换新令牌对。

        同一令牌只允许成功一次；再次使用（含并发）即判定为复用，
        整条令牌链立即失效。
        """
        with self._lock:
            record = self._refresh_tokens.get(refresh_token)
            if record is None:
                raise AuthError(401, ErrorCode.UNKNOWN_TOKEN, "刷新令牌不存在或格式不合法")

            family_status = self._families.get(record.family_id, "active")
            if family_status == "compromised":
                raise AuthError(
                    401, ErrorCode.TOKEN_REUSE_DETECTED,
                    "检测到刷新令牌复用，所属令牌链已失效",
                )
            if family_status == "revoked":
                raise AuthError(401, ErrorCode.TOKEN_REVOKED, "令牌链已被撤销")

            if record.status == "rotated":
                # 已轮换过的令牌被再次使用 → 复用攻击，熔断整条链。
                self._families[record.family_id] = "compromised"
                raise AuthError(
                    401, ErrorCode.TOKEN_REUSE_DETECTED,
                    "刷新令牌被重复使用，所属令牌链已失效",
                )
            if record.status == "revoked":
                raise AuthError(401, ErrorCode.TOKEN_REVOKED, "刷新令牌已被撤销")

            if self._now() >= record.expires_at:
                raise AuthError(401, ErrorCode.TOKEN_EXPIRED, "刷新令牌已过期")

            # 原子地完成「标记旧令牌已轮换 + 签发新令牌对」。
            record.status = "rotated"
            user = self._settings.users.get(record.username)
            if user is None:
                raise AuthError(401, ErrorCode.UNKNOWN_TOKEN, "令牌对应的主体不存在")
            return self._issue_pair_locked(user, record.family_id)

    # ------------------------------------------------------------------ #
    # 撤销
    # ------------------------------------------------------------------ #
    def revoke_chain(self, refresh_token: str) -> None:
        """撤销该刷新令牌所属的整条令牌链（幂等）。"""
        with self._lock:
            record = self._refresh_tokens.get(refresh_token)
            if record is None:
                raise AuthError(401, ErrorCode.UNKNOWN_TOKEN, "刷新令牌不存在或格式不合法")
            # 已 compromised 的链保持 compromised，保证错误原因仍可区分。
            if self._families.get(record.family_id) == "active":
                self._families[record.family_id] = "revoked"
