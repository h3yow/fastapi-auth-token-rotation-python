"""Application settings and injectable clock (deterministic in tests)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Settings:
    secret: str = "dev-only-secret-do-not-use-in-prod"
    issuer: str = "authapp"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 7
    rate_limit_per_subject: int = 10
    rate_limit_window_seconds: int = 60
    clock: Callable[[], float] = field(default=time.time)


def get_settings() -> Settings:
    """Default settings; tests build their own Settings with a fake clock."""
    return Settings()
