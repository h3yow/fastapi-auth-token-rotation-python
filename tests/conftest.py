import logging

import pytest
from fastapi.testclient import TestClient

from auth.app import create_app
from auth.config import Settings


@pytest.fixture
def settings() -> Settings:
    # 小阈值便于触发限流；其它用默认值。
    return Settings(rate_limit_max_requests=5, rate_limit_window_seconds=60)


@pytest.fixture
def client(settings) -> TestClient:
    return TestClient(create_app(settings))


def login(client: TestClient, username: str, password: str) -> dict:
    resp = client.post("/auth/token", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(pair: dict) -> dict:
    return {"Authorization": f"Bearer {pair['access_token']}"}


@pytest.fixture(autouse=True)
def enable_auth_logs(caplog):
    # 测试中打开 auth 日志，便于断言关键判定依据。
    with caplog.at_level(logging.INFO, logger="auth"):
        yield
