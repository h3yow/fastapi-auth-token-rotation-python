"""In-process, thread-safe user directory and refresh-token family store.

Refresh-token rotation safety model
-----------------------------------
Each successful login starts a *token family*. Every rotation marks the
presented refresh token ``used`` and appends a fresh token to the same family.
``rotate`` performs lookup -> state checks -> state mutation inside a single
lock-held critical section, so when the same JTI is presented concurrently
exactly one caller wins; every loser is classified as reuse and the whole
family is revoked. Expired / already-revoked / unknown tokens get distinct
outcomes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from typing import Literal

from .errors import (
    AuthError,
    ERR_TOKEN_EXPIRED,
    ERR_TOKEN_FAMILY_REVOKED,
    ERR_TOKEN_NOT_RECOGNIZED,
    ERR_TOKEN_REUSE,
    ERR_TOKEN_REVOKED,
)

RotateOutcome = Literal["ok", "reuse", "expired", "family_revoked", "not_recognized"]


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """PBKDF2-HMAC-SHA256, 200k iterations; returns ``pbkdf2$iter$salt$hash``."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"pbkdf2$200000${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_hex, hash_hex = encoded.split("$")
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class UserRecord:
    username: str
    password_hash: str
    role: str
    scopes: tuple[str, ...]


@dataclass
class RefreshEntry:
    jti: str
    family_id: str
    subject: str
    issued_at: float
    expires_at: float
    used: bool = False


@dataclass
class RefreshFamily:
    family_id: str
    subject: str
    role: str
    scopes: tuple[str, ...]
    revoked: bool = False
    revoke_code: str | None = None      # machine-readable, e.g. ERR_TOKEN_REUSE
    revoke_reason: str | None = None    # human-readable detail
    entries: dict[str, RefreshEntry] = field(default_factory=dict)


@dataclass
class RotateResult:
    outcome: RotateOutcome
    family_id: str | None = None
    new_entry: RefreshEntry | None = None
    error: AuthError | None = None


class UserStore:
    def __init__(self, users: list[UserRecord] | None = None) -> None:
        self._users: dict[str, UserRecord] = {}
        for user in users or self._demo_users():
            self._users[user.username] = user

    @staticmethod
    def _demo_users() -> list[UserRecord]:
        # Demo credentials for local/offline use only.
        return [
            UserRecord("admin", hash_password("admin-pass"), "admin", ("read", "write", "admin")),
            UserRecord("editor", hash_password("editor-pass"), "editor", ("read", "write")),
            UserRecord("viewer", hash_password("viewer-pass"), "viewer", ("read",)),
        ]

    def verify(self, username: str, password: str) -> UserRecord | None:
        user = self._users.get(username)
        if user is None:
            # Still perform a dummy derivation to reduce timing side channel.
            verify_password(password, hash_password("dummy-password"))
            return None
        return user if verify_password(password, user.password_hash) else None

    def get(self, username: str) -> UserRecord | None:
        return self._users.get(username)

    def all_usernames(self) -> list[str]:
        return sorted(self._users)


class RefreshTokenStore:
    def __init__(self) -> None:
        self._families: dict[str, RefreshFamily] = {}
        self._jti_index: dict[str, str] = {}  # jti -> family_id
        self._lock = threading.Lock()

    def issue_family(
        self, subject: str, role: str, scopes: tuple[str, ...], now: float, ttl: int
    ) -> RefreshEntry:
        """Open a brand-new family and return its first refresh entry."""
        with self._lock:
            family_id = uuid.uuid4().hex
            family = RefreshFamily(
                family_id=family_id, subject=subject, role=role, scopes=tuple(scopes)
            )
            self._families[family_id] = family
            return self._append_entry(family, now, ttl)

    def _append_entry(self, family: RefreshFamily, now: float, ttl: int) -> RefreshEntry:
        entry = RefreshEntry(
            jti=secrets.token_urlsafe(24),
            family_id=family.family_id,
            subject=family.subject,
            issued_at=now,
            expires_at=now + ttl,
        )
        family.entries[entry.jti] = entry
        self._jti_index[entry.jti] = family.family_id
        return entry

    def rotate(self, jti: str, now: float, ttl: int) -> RotateResult:
        """Atomically consume ``jti`` and append a successor token.

        Outcomes are mutually distinguishable:
        ``not_recognized`` < ``reuse`` < ``family_revoked`` < ``expired`` < ``ok``.

        ``reuse`` is checked before the revoked-family flag so that every
        loser of a concurrent replay of the *same* token is classified as
        reuse (an attack on this credential), while a caller presenting a
        never-used token of an already-dead chain gets ``family_revoked``.
        """
        with self._lock:
            family_id = self._jti_index.get(jti)
            if family_id is None:
                return RotateResult(
                    outcome="not_recognized",
                    error=AuthError(
                        ERR_TOKEN_NOT_RECOGNIZED,
                        "refresh token is not recognized",
                        status_code=401,
                    ),
                )
            family = self._families[family_id]

            entry = family.entries.get(jti)
            assert entry is not None  # index invariant

            if entry.used:
                self._revoke_locked(family, ERR_TOKEN_REUSE, "refresh token reuse detected")
                return RotateResult(
                    outcome="reuse",
                    family_id=family_id,
                    error=AuthError(
                        ERR_TOKEN_REUSE,
                        "refresh token reuse detected; token family revoked",
                        status_code=401,
                    ),
                )
            if family.revoked:
                return RotateResult(
                    outcome="family_revoked",
                    family_id=family_id,
                    error=AuthError(
                        ERR_TOKEN_FAMILY_REVOKED,
                        f"token family revoked: {family.revoke_reason}",
                        status_code=401,
                    ),
                )
            if now >= entry.expires_at:
                # Expiry does not by itself revoke the family; other live
                # tokens issued earlier in the chain remain usable.
                return RotateResult(
                    outcome="expired",
                    family_id=family_id,
                    error=AuthError(
                        ERR_TOKEN_EXPIRED,
                        f"refresh token expired at {entry.expires_at} (now={now})",
                        status_code=401,
                    ),
                )

            entry.used = True
            successor = self._append_entry(family, now, ttl)
            return RotateResult(outcome="ok", family_id=family_id, new_entry=successor)

    def revoke_family(self, family_id: str, reason: str = ERR_TOKEN_REVOKED) -> bool:
        with self._lock:
            family = self._families.get(family_id)
            if family is None or family.revoked:
                return False
            self._revoke_locked(family, reason, reason)
            return True

    def _revoke_locked(
        self, family: RefreshFamily, code: str, human_reason: str
    ) -> None:
        family.revoked = True
        family.revoke_code = code
        family.revoke_reason = human_reason

    def is_family_revoked(self, family_id: str) -> bool:
        with self._lock:
            family = self._families.get(family_id)
            return family is None or family.revoked

    def family(self, family_id: str) -> RefreshFamily | None:
        with self._lock:
            return self._families.get(family_id)


