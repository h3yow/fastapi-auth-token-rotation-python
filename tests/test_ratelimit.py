"""限流：触发、重试提示、并发计数准确性、重置与重启后的确定行为。"""

import logging
from concurrent.futures import ThreadPoolExecutor

from auth.errors import ErrorCode
from auth.ratelimit import RateLimiter

from .conftest import auth_header, login


def test_rate_limit_triggers_with_retry_hint(client, caplog):
    pair = login(client, "viewer", "viewer-pass")
    headers = auth_header(pair)

    codes = [client.get("/api/profile", headers=headers).status_code
             for _ in range(5)]
    assert codes == [200] * 5

    r = client.get("/api/profile", headers=headers)
    logging.getLogger("auth").info(
        "限流触发: subject=viewer 阈值=5 第6次请求状态=%s retry_after=%s",
        r.status_code, r.headers.get("Retry-After"))
    assert r.status_code == 429
    assert r.json()["error"]["code"] == str(ErrorCode.RATE_LIMITED)
    assert int(r.headers["Retry-After"]) >= 1

    # 429 与 401 / 403 可区分
    assert r.status_code not in (401, 403)
    assert any("限流判定" in rec.message for rec in caplog.records)


def test_rate_limit_is_per_subject(client):
    viewer = auth_header(login(client, "viewer", "viewer-pass"))
    editor = auth_header(login(client, "editor", "editor-pass"))
    for _ in range(5):
        client.get("/api/profile", headers=viewer)
    assert client.get("/api/profile", headers=viewer).status_code == 429
    # 其它主体不受影响
    assert client.get("/api/profile", headers=editor).status_code == 200


def test_rate_limit_reset_restores_access(client):
    headers = auth_header(login(client, "viewer", "viewer-pass"))
    for _ in range(6):
        client.get("/api/profile", headers=headers)
    assert client.get("/api/profile", headers=headers).status_code == 429

    client.app.state.rate_limiter.reset()
    assert client.get("/api/profile", headers=headers).status_code == 200


def test_concurrent_counting_is_exact():
    """高并发下计数不因竞态失准：放行数必须恰好等于阈值。"""
    limiter = RateLimiter(max_requests=10, window_seconds=60)
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: limiter.check("subject")[0], range(100)))
    allowed = results.count(True)
    logging.getLogger("auth").info(
        "并发限流: 阈值=10 请求数=100 放行=%s", allowed)
    assert allowed == 10


def test_window_rollover_recovers():
    t = [0.0]
    limiter = RateLimiter(max_requests=2, window_seconds=60, now=lambda: t[0])
    assert [limiter.check("k")[0] for _ in range(3)] == [True, True, False]
    t[0] = 61.0  # 进入下一窗口
    assert limiter.check("k")[0] is True


def test_restart_is_deterministic():
    """重启（新建限流器、状态清零）后行为确定：等价于当前窗口计数清零。"""
    t = [100.0]
    clock = lambda: t[0]
    limiter = RateLimiter(max_requests=2, window_seconds=60, now=clock)
    limiter.check("k")
    limiter.check("k")
    assert limiter.check("k")[0] is False

    # 模拟服务重启：全新实例、无任何持久化状态
    restarted = RateLimiter(max_requests=2, window_seconds=60, now=clock)
    assert restarted.check("k")[0] is True
    assert restarted.check("k")[0] is True
    assert restarted.check("k")[0] is False
