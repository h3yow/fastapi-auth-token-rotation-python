"""错误码与异常骨架：定义可区分的拒绝原因枚举，实现后续填充。"""

from enum import StrEnum


class ErrorCode(StrEnum):
    """所有认证 / 授权 / 限流失败原因的可区分错误码。"""

    MISSING_CREDENTIALS = "missing_credentials"
    INVALID_CREDENTIALS = "invalid_credentials"
    MALFORMED_TOKEN = "malformed_token"
    INVALID_SIGNATURE = "invalid_signature"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_REUSE_DETECTED = "token_reuse_detected"
    UNKNOWN_TOKEN = "unknown_token"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    RATE_LIMITED = "rate_limited"


class AuthError(Exception):
    """认证 / 授权失败，携带 HTTP 状态码与可区分错误码。"""

    def __init__(self, status_code: int, code: ErrorCode, message: str,
                 retry_after: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retry_after = retry_after
