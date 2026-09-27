"""自包含的身份认证与访问控制包。"""

from .app import create_app
from .config import Settings

__all__ = ["create_app", "Settings"]
