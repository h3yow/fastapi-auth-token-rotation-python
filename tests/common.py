"""Shared test helpers: controllable clock + fresh app/client factory."""

from __future__ import annotations

from fastapi.testclient import TestClient

from authapp.app import create_app
from authapp.config import Settings


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_client(
    *,
    rate_limit: int = 1000,
    rate_window: int = 60,
    access_ttl: int = 900,
    refresh_ttl: int = 3600,
    clock: FakeClock | None = None,
) -> tuple[TestClient, FakeClock]:
    clock = clock or FakeClock()
    settings = Settings(
        clock=clock,
        rate_limit_per_subject=rate_limit,
        rate_limit_window_seconds=rate_window,
        access_token_ttl_seconds=access_ttl,
        refresh_token_ttl_seconds=refresh_ttl,
    )
    return TestClient(create_app(settings)), clock


def login(client: TestClient, username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
