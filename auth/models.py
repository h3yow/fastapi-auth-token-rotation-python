"""数据模型骨架：用户、令牌对、令牌链等类型定义。"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    """调用主体：用户名、角色与作用域集合。"""

    username: str
    password: str
    roles: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class TokenPair:
    """一次签发 / 轮换得到的访问令牌 + 刷新令牌。"""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
