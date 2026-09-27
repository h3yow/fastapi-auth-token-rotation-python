# FastAPI 身份认证与访问控制（自包含演示）

在现有 FastAPI 服务上叠加的一套**完全离线、自包含**的认证 / 授权 / 限流实现：
JWT 访问令牌 + 不透明刷新令牌（强制轮换 + 复用检测）、按作用域的接口授权、
按调用主体的并发安全限流。不依赖任何外部服务、真实凭据或付费资源。

## 快速开始

```bash
uv sync                 # 离线可复现：uv sync --offline
uv run pytest tests/ -v # 运行全部测试（24 个）
uv run python main.py   # 启动服务，监听 127.0.0.1:8000
```

手动验证：

```bash
# 登录（内置用户：admin/editor/viewer，密码分别为 *-pass，仅本地演示）
curl -s -X POST localhost:8000/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pass"}'

# 访问受保护接口
curl -s localhost:8000/api/profile -H "Authorization: Bearer <access_token>"

# 轮换刷新令牌（旧令牌立即失效，再用即触发复用检测）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<refresh_token>"}'

# 注销：撤销整条令牌链
curl -s -X POST localhost:8000/auth/logout \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<refresh_token>"}'
```

## 令牌生命周期与失效规则

```
登录 /auth/token ──► 签发令牌对（访问令牌 JWT + 不透明刷新令牌，属同一令牌链 family）
        │
        ▼
访问接口：校验访问令牌（签名 / 格式 / 过期 / 链状态）
        │
        ▼
刷新 /auth/refresh ──► 必须轮换：旧刷新令牌标记为 rotated 并立即失效，
        │               签发同一条链上的新令牌对
        ├─ 旧刷新令牌被再次使用（含并发）──► 判定为复用攻击：
        │     整条链置为 compromised，链上所有刷新令牌与访问令牌一律拒绝
        ├─ /auth/logout ──► 整条链置为 revoked（幂等）
        └─ 刷新令牌到期 ──► 拒绝，需重新登录
```

- **并发安全**：轮换的「检查旧令牌状态 + 标记 + 签发新令牌」在同一把锁内原子完成，
  同一刷新令牌并发提交 N 次时**恰好只有一次成功**，其余全部判定为复用并熔断整条链。
- **时钟可注入**：`TokenService` / `RateLimiter` 接受 `now` 参数，测试用假时钟
  确定性覆盖过期场景；访问令牌的 `exp` 按注入时钟判定。

### 可区分的失败原因

所有失败响应为 `{"error": {"code": ..., "message": ...}}`，`code` 互不相同：

| 场景 | HTTP | code |
|---|---|---|
| 缺少 Authorization 头 | 401 | `missing_credentials` |
| 用户名或密码错误 | 401 | `invalid_credentials` |
| 令牌格式不合法 / 头格式错误 | 401 | `malformed_token` |
| 签名不合法 | 401 | `invalid_signature` |
| 访问 / 刷新令牌过期 | 401 | `token_expired` |
| 令牌链被主动撤销 | 401 | `token_revoked` |
| 刷新令牌复用（链已熔断） | 401 | `token_reuse_detected` |
| 刷新令牌不存在 | 401 | `unknown_token` |
| 凭据有效但权限不足 | 403 | `insufficient_scope` |
| 触发限流 | 429 | `rate_limited`（带 `Retry-After` 头） |

401 响应均带 `WWW-Authenticate: Bearer error="<code>"` 头。

## 授权模型

- 主体（用户）持有**作用域集合**，角色只是作用域的命名分组：
  `viewer={read}`、`editor={read,write}`、`admin={read,write,admin}`。
- 接口通过 `require_scopes(...)` 声明所需作用域：

| 接口 | 所需作用域 |
|---|---|
| `GET /api/profile` | `read` |
| `POST /api/items` | `write` |
| `DELETE /api/admin/users/{username}` | `admin` |
| `GET /api/items/{id}` | `read` + 资源归属 |

- 三种情形明确区分：**无凭据** → 401 `missing_credentials`；
  **凭据有效但越权** → 403 `insufficient_scope`；**低权限凭据执行高权限操作**必被拒。
- **不泄露资源存在性**：`GET /api/items/{id}` 中「资源不存在」与「存在但无权访问」
  返回完全相同的 404 响应体。

## 限流语义

- **固定窗口**，按调用主体（用户名）计数；默认 5 次 / 60 秒
  （`AUTH_RATE_LIMIT_MAX` / `AUTH_RATE_LIMIT_WINDOW` 可配）。
- 窗口起点按 wall-clock 对齐（`floor(now / window)`），**不随请求漂移**。
- 计数与判定在同一把锁内完成，高并发下放行数恰好等于阈值，不因竞态失准。
- 超限返回 429 + `rate_limited` + `Retry-After`（到下一窗口起点的秒数）。
- **重置 / 重启行为确定**：`reset()` 或服务重启等价于「当前窗口计数清零」，
  窗口边界不变；无需任何持久化状态。

## 本地验证

```bash
uv run pytest tests/ -v
```

- `tests/test_tokens.py`：轮换、并发复用（线程池 + HTTP 两级）、过期（假时钟）、
  撤销、签名 / 格式不合法、未知令牌，以及所有错误码互不相同。
- `tests/test_authz.py`：权限矩阵、401/403 区分、资源存在性不泄露。
- `tests/test_ratelimit.py`：触发与 `Retry-After`、按主体隔离、并发计数精确、
  reset 恢复、窗口滚动恢复、重启后行为确定。
- 关键判定（令牌状态、所需 vs 实际权限、限流计数）都写入 `auth` logger，
  测试用 `caplog` 断言日志中的判定依据。

## 配置

均可用环境变量覆盖（默认值仅供本地开发）：
`AUTH_JWT_SECRET`、`AUTH_JWT_ALGORITHM`、`AUTH_ACCESS_TTL`、`AUTH_REFRESH_TTL`、
`AUTH_RATE_LIMIT_MAX`、`AUTH_RATE_LIMIT_WINDOW`。
