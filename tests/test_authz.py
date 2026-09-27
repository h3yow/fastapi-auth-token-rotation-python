"""授权：角色 / 作用域矩阵、无凭据与越权的区分、资源存在性不泄露。"""

import logging

from auth.errors import ErrorCode

from .conftest import auth_header, login


def test_no_credentials_is_401_and_distinguishable(client):
    r = client.get("/api/profile")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == str(ErrorCode.MISSING_CREDENTIALS)
    assert r.headers["WWW-Authenticate"].startswith("Bearer")


def test_malformed_authorization_header(client):
    r = client.get("/api/profile", headers={"Authorization": "Token abc"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == str(ErrorCode.MALFORMED_TOKEN)


def test_scope_matrix(client, caplog):
    """viewer/editor/admin 对读、写、管理三类接口的权限矩阵。"""
    viewer = auth_header(login(client, "viewer", "viewer-pass"))
    editor = auth_header(login(client, "editor", "editor-pass"))
    admin = auth_header(login(client, "admin", "admin-pass"))

    cases = [
        # (描述, 方法, 路径, 头, 期望状态)
        ("viewer 可读", "GET", "/api/profile", viewer, 200),
        ("viewer 不可写", "POST", "/api/items", viewer, 403),
        ("viewer 不可管理", "DELETE", "/api/admin/users/x", viewer, 403),
        ("editor 可读", "GET", "/api/profile", editor, 200),
        ("editor 可写", "POST", "/api/items", editor, 200),
        ("editor 不可管理", "DELETE", "/api/admin/users/x", editor, 403),
        ("admin 可读", "GET", "/api/profile", admin, 200),
        ("admin 可写", "POST", "/api/items", admin, 200),
        ("admin 可管理", "DELETE", "/api/admin/users/x", admin, 200),
    ]
    for desc, method, path, headers, expected in cases:
        r = client.request(method, path, headers=headers)
        logging.getLogger("auth").info(
            "授权矩阵: %s -> %s %s 状态=%s", desc, method, path, r.status_code)
        assert r.status_code == expected, desc
        if r.status_code == 403:
            assert r.json()["error"]["code"] == str(ErrorCode.INSUFFICIENT_SCOPE)

    # 日志中应包含所需权限与实际权限的判定依据
    assert any("所需权限" in rec.message and "实际权限" in rec.message
               for rec in caplog.records)


def test_valid_token_but_forbidden_is_distinct_from_no_token(client):
    """「有效凭据但越权」403 与「无凭据」401 必须可区分。"""
    viewer = auth_header(login(client, "viewer", "viewer-pass"))
    forbidden = client.post("/api/items", headers=viewer)
    anonymous = client.post("/api/items")
    assert forbidden.status_code == 403
    assert anonymous.status_code == 401
    assert forbidden.json()["error"]["code"] != anonymous.json()["error"]["code"]


def test_resource_existence_is_not_leaked(client):
    """资源不存在 vs 存在但无权访问：响应必须完全一致。"""
    viewer = auth_header(login(client, "viewer", "viewer-pass"))
    missing = client.get("/api/items/999", headers=viewer)      # 不存在
    not_owned = client.get("/api/items/2", headers=viewer)      # 存在但属 editor
    assert missing.status_code == 404
    assert not_owned.status_code == 404
    assert missing.json() == not_owned.json()

    # 所有者可访问，admin 可访问任意资源
    editor = auth_header(login(client, "editor", "editor-pass"))
    admin = auth_header(login(client, "admin", "admin-pass"))
    assert client.get("/api/items/2", headers=editor).status_code == 200
    assert client.get("/api/items/2", headers=admin).status_code == 200
