"""Role/scope based access control and non-disclosure on forbidden paths."""

from __future__ import annotations

import unittest

from tests.common import auth_header, login, make_client

CREDS = {
    "admin": "admin-pass",
    "editor": "editor-pass",
    "viewer": "viewer-pass",
}


class RBACTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client, self.clock = make_client()
        self.tokens = {
            name: login(self.client, name, pw)["access_token"] for name, pw in CREDS.items()
        }

    def _get(self, user: str | None, path: str):
        headers = auth_header(self.tokens[user]) if user else {}
        return self.client.get(path, headers=headers)

    def _post(self, user: str | None, path: str):
        headers = auth_header(self.tokens[user]) if user else {}
        return self.client.post(path, headers=headers)

    def test_scope_matrix(self) -> None:
        # GET /api/reports requires "read"
        self.assertEqual(self._get("viewer", "/api/reports").status_code, 200)
        self.assertEqual(self._get("editor", "/api/reports").status_code, 200)
        self.assertEqual(self._get("admin", "/api/reports").status_code, 200)

        # POST /api/reports requires "write": viewer is denied
        self.assertEqual(self._post("editor", "/api/reports").status_code, 200)
        denied = self._post("viewer", "/api/reports")
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["error"]["code"], "forbidden")

        # admin-only endpoints
        self.assertEqual(self._get("admin", "/api/admin/users").status_code, 200)
        for low in ("viewer", "editor"):
            denied = self._get(low, "/api/admin/users")
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.json()["error"]["code"], "forbidden")

    def test_missing_vs_forbidden_are_distinguishable(self) -> None:
        # No credentials at all
        no_cred = self._get(None, "/api/admin/users")
        self.assertEqual(no_cred.status_code, 401)
        self.assertEqual(no_cred.json()["error"]["code"], "token_missing")

        # Valid credential but insufficient privilege
        forbidden = self._get("viewer", "/api/admin/users")
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(forbidden.json()["error"]["code"], "forbidden")

    def test_forbidden_does_not_reveal_resource_existence(self) -> None:
        # A low-privilege caller gets 403 for BOTH existing and non-existing
        # admin resources; existence is only evaluated after authorization.
        existing = self._get("viewer", "/api/admin/reports/rpt-001")
        missing = self._get("viewer", "/api/admin/reports/does-not-exist")
        self.assertEqual(existing.status_code, 403)
        self.assertEqual(missing.status_code, 403)
        self.assertEqual(existing.json(), missing.json())

        # The admin sees the real distinction once authorized.
        ok = self._get("admin", "/api/admin/reports/rpt-001")
        gone = self._get("admin", "/api/admin/reports/does-not-exist")
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(gone.status_code, 404)
        self.assertEqual(gone.json()["error"]["code"], "not_found")

    def test_public_endpoint_needs_no_credentials(self) -> None:
        self.assertEqual(self.client.get("/public/ping").status_code, 200)


if __name__ == "__main__":
    unittest.main()
