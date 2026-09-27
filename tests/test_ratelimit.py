"""Per-subject rate limiting: threshold, recovery, reset, concurrency."""

from __future__ import annotations

import threading
import unittest

from fastapi.testclient import TestClient

from authapp.config import Settings
from authapp.app import create_app
from tests.common import FakeClock, auth_header, login


def make_app(clock: FakeClock, limit: int = 3, window: int = 60) :
    return create_app(
        Settings(
            clock=clock,
            rate_limit_per_subject=limit,
            rate_limit_window_seconds=window,
        )
    )


class RateLimitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.app = make_app(self.clock)
        self.client = TestClient(self.app)
        self.viewer = login(self.client, "viewer", "viewer-pass")["access_token"]
        self.editor = login(self.client, "editor", "editor-pass")["access_token"]

    def test_threshold_returns_distinct_429_with_retry_after(self) -> None:
        for i in range(1, 4):
            resp = self.client.get("/api/profile", headers=auth_header(self.viewer))
            self.assertEqual(resp.status_code, 200, f"request {i}")

        blocked = self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(blocked.status_code, 429)
        body = blocked.json()["error"]
        self.assertEqual(body["code"], "rate_limited")
        self.assertEqual(blocked.headers["retry-after"], "60")
        self.assertIn("retry", body["message"].lower())

    def test_limit_is_per_subject(self) -> None:
        for _ in range(3):
            self.assertEqual(
                self.client.get("/api/profile", headers=auth_header(self.viewer)).status_code,
                200,
            )
        self.assertEqual(
            self.client.get("/api/profile", headers=auth_header(self.viewer)).status_code, 429
        )
        # A different subject has its own independent counter.
        self.assertEqual(
            self.client.get("/api/profile", headers=auth_header(self.editor)).status_code, 200
        )

    def test_window_recovery_is_deterministic(self) -> None:
        for _ in range(3):
            self.client.get("/api/profile", headers=auth_header(self.viewer))
        blocked = self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["retry-after"], "60")

        # 59.9s in: still blocked, retry-after rounds up to 1.
        self.clock.advance(59.9)
        blocked = self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["retry-after"], "1")

        # Exactly at window boundary: new window starts deterministically.
        self.clock.advance(0.1)
        resp = self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(resp.status_code, 200)

    def test_admin_reset_restores_access_immediately(self) -> None:
        admin = login(self.client, "admin", "admin-pass")["access_token"]
        # Give admin enough headroom (limit applies to admin too); exhaust viewer.
        for _ in range(3):
            self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(
            self.client.get("/api/profile", headers=auth_header(self.viewer)).status_code, 429
        )

        reset = self.client.post(
            "/api/admin/ratelimit/reset?subject=viewer", headers=auth_header(admin)
        )
        self.assertEqual(reset.status_code, 200, reset.text)

        recovered = self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(recovered.status_code, 200)

    def test_restart_resets_state_deterministically(self) -> None:
        for _ in range(3):
            self.client.get("/api/profile", headers=auth_header(self.viewer))
        self.assertEqual(
            self.client.get("/api/profile", headers=auth_header(self.viewer)).status_code, 429
        )
        # Simulate a process restart: same clock, brand-new in-memory state.
        restarted_app = make_app(self.clock)
        restarted = TestClient(restarted_app)
        # Login establishes the same demo subject; the counter restarts at zero.
        token = login(restarted, "viewer", "viewer-pass")["access_token"]
        resp = restarted.get("/api/profile", headers=auth_header(token))
        self.assertEqual(resp.status_code, 200)

    def test_concurrent_count_is_exact(self) -> None:
        # 30 simultaneous requests with limit 10: exactly 10 allowed.
        app = make_app(FakeClock(), limit=10)
        client = TestClient(app)
        token = login(client, "viewer", "viewer-pass")["access_token"]
        statuses: list[int] = []
        barrier = threading.Barrier(30)

        def hit() -> None:
            c = TestClient(app)
            barrier.wait()
            statuses.append(c.get("/api/profile", headers=auth_header(token)).status_code)

        threads = [threading.Thread(target=hit) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(statuses).count(200), 10, statuses)
        self.assertEqual(sorted(statuses).count(429), 20, statuses)


if __name__ == "__main__":
    unittest.main()
