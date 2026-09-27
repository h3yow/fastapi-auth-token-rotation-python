"""配置：密钥、令牌有效期、限流阈值与内置用户。

所有项都可通过环境变量覆盖，默认值仅供本地开发 / 测试使用，
不包含任何真实凭据，完全离线可复现。
"""

from dataclasses import dataclass, field
import os

from .models import User

# 内置演示用户：不同角色 / 作用域，便于本地验证授权矩阵。
# 密码为明文演示值，仅用于离线自包含场景。
_DEFAULT_USERS: dict[str, User] = {
    "admin": User(
        username="admin",
        password="admin-pass",
        roles=frozenset({"admin"}),
        scopes=frozenset({"read", "write", "admin"}),
    ),
    "editor": User(
        username="editor",
        password="editor-pass",
        roles=frozenset({"editor"}),
        scopes=frozenset({"read", "write"}),
    ),
    "viewer": User(
        username="viewer",
        password="viewer-pass",
        roles=frozenset({"viewer"}),
        scopes=frozenset({"read"}),
    ),
}


@dataclass(frozen=True)
class Settings:
    """服务配置，全部可用环境变量或测试注入覆盖。"""

    jwt_secret: str = "dev-only-secret-0123456789abcdef-32bytes"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 3600
    rate_limit_max_requests: int = 5
    rate_limit_window_seconds: int = 60
    users: dict[str, User] = field(default_factory=lambda: dict(_DEFAULT_USERS))


def load_settings() -> Settings:
    """从环境变量加载配置，缺省使用本地开发默认值。"""
    return Settings(
        jwt_secret=os.environ.get("AUTH_JWT_SECRET", "dev-only-secret-0123456789abcdef-32bytes"),
        jwt_algorithm=os.environ.get("AUTH_JWT_ALGORITHM", "HS256"),
        access_token_ttl_seconds=int(os.environ.get("AUTH_ACCESS_TTL", "900")),
        refresh_token_ttl_seconds=int(os.environ.get("AUTH_REFRESH_TTL", "3600")),
        rate_limit_max_requests=int(os.environ.get("AUTH_RATE_LIMIT_MAX", "5")),
        rate_limit_window_seconds=int(os.environ.get("AUTH_RATE_LIMIT_WINDOW", "60")),
    )
