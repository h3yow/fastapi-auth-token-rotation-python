"""Stateless HMAC-signed access/refresh token encode/decode primitives.

Wire format::

    base64url(payload_json) . base64url(hmac_sha256(secret, payload_segment))

Decode failures map to *distinct* rejection reasons:

* malformed structure / undecodable payload  -> token_malformed
* signature mismatch                         -> bad_signature
* expiry claim in the past                   -> token_expired
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from .errors import AuthError, ERR_TOKEN_BAD_SIGNATURE, ERR_TOKEN_EXPIRED, ERR_TOKEN_MALFORMED


@dataclass(frozen=True)
class TokenClaims:
    jti: str
    sub: str
    role: str
    scopes: tuple[str, ...]
    family_id: str
    token_type: str
    issued_at: float
    expires_at: float


_REQUIRED_CLAIM_KEYS = {
    "jti", "sub", "role", "scopes", "fid", "typ", "iat", "exp",
}


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    # urlsafe_b64decode tolerates missing padding but rejects junk chars.
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(secret: str, payload_segment: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_segment.encode("ascii"), hashlib.sha256)
    return _b64encode(mac.digest())


def encode_token(claims: dict[str, Any], secret: str) -> str:
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True)
    payload_segment = _b64encode(payload.encode("utf-8"))
    signature_segment = _sign(secret, payload_segment)
    return f"{payload_segment}.{signature_segment}"


def _malformed(detail: str) -> AuthError:
    return AuthError(ERR_TOKEN_MALFORMED, f"malformed token: {detail}", status_code=401)


def decode_token(token: str, secret: str, now: float) -> TokenClaims:
    if not isinstance(token, str) or token.count(".") != 1:
        raise _malformed("expected payload.signature")
    payload_segment, signature_segment = token.split(".")
    if not payload_segment or not signature_segment:
        raise _malformed("empty segment")

    expected_signature = _sign(secret, payload_segment)
    if not hmac.compare_digest(expected_signature, signature_segment):
        raise AuthError(
            ERR_TOKEN_BAD_SIGNATURE,
            "token signature does not match",
            status_code=401,
        )

    try:
        payload_bytes = _b64decode(payload_segment)
        raw = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:  # binascii.Error / UnicodeDecodeError / JSON errors
        raise _malformed(f"payload not decodable: {type(exc).__name__}") from exc

    if not isinstance(raw, dict) or not _REQUIRED_CLAIM_KEYS.issubset(raw):
        raise _malformed("missing required claims")

    try:
        claims = TokenClaims(
            jti=str(raw["jti"]),
            sub=str(raw["sub"]),
            role=str(raw["role"]),
            scopes=tuple(raw["scopes"]),
            family_id=str(raw["fid"]),
            token_type=str(raw["typ"]),
            issued_at=float(raw["iat"]),
            expires_at=float(raw["exp"]),
        )
    except (TypeError, ValueError) as exc:
        raise _malformed(f"invalid claim types: {exc}") from exc

    if now >= claims.expires_at:
        raise AuthError(
            ERR_TOKEN_EXPIRED,
            f"token expired at {claims.expires_at} (now={now})",
            status_code=401,
        )
    return claims
