"""Token lifecycle: issuance, rotation, reuse, expiry, revocation, validity."""

from __future__ import annotations

import threading
import unittest

from fastapi.testclient import TestClient

from tests.common import FakeClock, auth_header, login, make_client


class TokenLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client, self.clock = make_client(refresh_ttl=3600, access_ttl=300)

    # ---- issuance / basic validation -------------------------------------
    def test_login_issues_pair_and_access_token_works(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        self.assertEqual(pair["token_type"], "bearer")
        self.assertEqual(pair["expires_in"], 300)

        resp = self.client.get("/api/profile", headers=auth_header(pair["access_token"]))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["username"], "viewer")

    def test_bad_credentials_rejected_distinctly(self) -> None:
        resp = self.client.post(
            "/auth/login", json={"username": "viewer", "password": "wrong"}
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"]["code"], "invalid_credentials")

    # ---- rotation ----------------------------------------------------------
    def test_normal_chain_can_rotate_many_times(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        current = pair["refresh_token"]
        for _ in range(5):
            resp = self.client.post("/auth/refresh", headers=auth_header(current))
            self.assertEqual(resp.status_code, 200, resp.text)
            current = resp.json()["refresh_token"]

        # Access tokens minted along the healthy chain all belong to one family.
        headers_ok = auth_header(current)
        # Final refresh token still accepted on the next rotation (chain alive).
        resp = self.client.post("/auth/refresh", headers=headers_ok)
        self.assertEqual(resp.status_code, 200)

    def test_reuse_kills_access_tokens_of_the_family_too(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        rotated = self.client.post(
            "/auth/refresh", headers=auth_header(pair["refresh_token"])
        ).json()
        # Replay the old refresh token -> family revoked.
        replay = self.client.post("/auth/refresh", headers=auth_header(pair["refresh_token"]))
        self.assertEqual(replay.json()["error"]["code"], "refresh_token_reuse_detected")

        # The new access token (issued to the one-time winner) is dead at once.
        blocked = self.client.get("/api/profile", headers=auth_header(rotated["access_token"]))
        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(blocked.json()["error"]["code"], "token_family_revoked")

    def test_refresh_rotates_and_old_token_becomes_invalid(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        r1 = self.client.post("/auth/refresh", headers=auth_header(pair["refresh_token"]))
        self.assertEqual(r1.status_code, 200, r1.text)
        new_pair = r1.json()
        self.assertNotEqual(new_pair["refresh_token"], pair["refresh_token"])

        # The previous refresh token must not be usable again.
        r2 = self.client.post("/auth/refresh", headers=auth_header(pair["refresh_token"]))
        self.assertEqual(r2.status_code, 401)
        self.assertEqual(r2.json()["error"]["code"], "refresh_token_reuse_detected")

        # The whole chain is dead: even the just-issued successor is rejected.
        r3 = self.client.post("/auth/refresh", headers=auth_header(new_pair["refresh_token"]))
        self.assertEqual(r3.status_code, 401)
        self.assertEqual(r3.json()["error"]["code"], "token_family_revoked")

    def test_concurrent_reuse_exactly_one_success(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        results: list[dict] = []
        barrier = threading.Barrier(20)

        def attempt() -> None:
            # Separate client per thread, all sharing one app (and thus one
            # RefreshTokenStore); the barrier maximizes overlap.
            client = TestClient(self.client.app)
            barrier.wait()
            resp = client.post("/auth/refresh", headers=auth_header(pair["refresh_token"]))
            results.append(
                resp.json() if resp.status_code == 200
                else {"error_code": resp.json()["error"]["code"]}
            )

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if "access_token" in r]
        codes = [r["error_code"] for r in results if "error_code" in r]
        self.assertEqual(len(successes), 1, results)
        # Every loser presented the *same* credential, so each must be
        # classified as reuse itself (not just as a revoked family).
        self.assertEqual(codes, ["refresh_token_reuse_detected"] * 19)
        self.assertEqual(len(results), 20)

        # The single winner's successor is unusable because the family was
        # revoked when the losers replayed the old token.
        winner = successes[0]
        followup = self.client.post(
            "/auth/refresh", headers=auth_header(winner["refresh_token"])
        )
        self.assertEqual(followup.status_code, 401)
        self.assertEqual(followup.json()["error"]["code"], "token_family_revoked")

    # ---- expiry ------------------------------------------------------------
    def test_expired_refresh_token_has_distinct_code(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        self.clock.advance(3601)  # past refresh TTL
        resp = self.client.post("/auth/refresh", headers=auth_header(pair["refresh_token"]))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"]["code"], "token_expired")

    def test_expired_access_token_has_distinct_code(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        self.clock.advance(301)
        resp = self.client.get("/api/profile", headers=auth_header(pair["access_token"]))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"]["code"], "token_expired")

    # ---- revocation ---------------------------------------------------------
    def test_logout_revokes_family_access_and_refresh_tokens(self) -> None:
        pair = login(self.client, "viewer", "viewer-pass")
        logout = self.client.post("/auth/logout", headers=auth_header(pair["access_token"]))
        self.assertEqual(logout.status_code, 200, logout.text)

        access = self.client.get("/api/profile", headers=auth_header(pair["access_token"]))
        self.assertEqual(access.status_code, 401)
        self.assertEqual(access.json()["error"]["code"], "token_revoked")

        refresh = self.client.post("/auth/refresh", headers=auth_header(pair["refresh_token"]))
        self.assertEqual(refresh.status_code, 401)
        self.assertEqual(refresh.json()["error"]["code"], "token_family_revoked")

    # ---- token validity matrix ---------------------------------------------
    def test_invalid_token_shapes_give_distinct_codes(self) -> None:
        # 1) no credentials
        self.assertEqual(
            self.client.get("/api/profile").json()["error"]["code"], "token_missing"
        )
        # 2) malformed structure
        resp = self.client.get("/api/profile", headers=auth_header("not-a-token"))
        self.assertEqual(resp.json()["error"]["code"], "token_malformed")
        # 3) bad signature
        pair = login(self.client, "viewer", "viewer-pass")
        payload, sig = pair["access_token"].split(".")
        forged = f"{payload}.{sig[:-2]}xx"
        resp = self.client.get("/api/profile", headers=auth_header(forged))
        self.assertEqual(resp.json()["error"]["code"], "bad_signature")
        # 4) wrong token type: refresh token used on an access endpoint
        resp = self.client.get("/api/profile", headers=auth_header(pair["refresh_token"]))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"]["code"], "wrong_token_type")
        # 5) unknown (valid signature, unrecognized jti)
        other, _ = make_client(clock=self.clock)
        other_pair = login(other, "viewer", "viewer-pass")
        resp = self.client.post(
            "/auth/refresh", headers=auth_header(other_pair["refresh_token"])
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"]["code"], "refresh_token_not_recognized")


if __name__ == "__main__":
    unittest.main()
