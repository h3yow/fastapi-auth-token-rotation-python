"""Distinguishable authentication/authorization/rate-limit error codes."""

from __future__ import annotations

# --- Token verification rejection reasons (mutually distinct) ---
ERR_TOKEN_MISSING = "token_missing"
ERR_TOKEN_MALFORMED = "token_malformed"
ERR_TOKEN_BAD_SIGNATURE = "bad_signature"
ERR_TOKEN_EXPIRED = "token_expired"
ERR_TOKEN_REVOKED = "token_revoked"
ERR_TOKEN_REUSE = "refresh_token_reuse_detected"
ERR_TOKEN_FAMILY_REVOKED = "token_family_revoked"
ERR_TOKEN_NOT_RECOGNIZED = "refresh_token_not_recognized"
ERR_WRONG_TOKEN_TYPE = "wrong_token_type"

# --- Authorization rejection reasons ---
ERR_FORBIDDEN = "forbidden"

# --- Rate limiting ---
ERR_RATE_LIMITED = "rate_limited"


class AuthError(Exception):
    """Base application error carrying a distinct machine-readable code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 401,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.headers = headers or {}
