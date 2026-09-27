# FastAPI 身份认证与访问控制（自包含示例）

本项目在 FastAPI 上实现了一套**完全离线、无外部依赖**的身份认证 / 授权 / 限流
组件，覆盖以下确定性语义：

- 访问令牌（access token）+ 刷新令牌（refresh token），刷新时**强制轮换**；
- 刷新令牌**并发重复使用**时恰好一次成功，其余请求被识别为复用并使整条
  令牌链（token family）失效；
- 过期、撤销、签名错误、格式错误、未知令牌、令牌类型错误等场景返回
  **互不相同的错误码**；
- 基于角色 / 作用域（role/scope）的接口授权，区分“无凭据（401）”、
  “凭据有效但权限不足（403）”，且 403 不泄露资源是否存在；
- 按调用主体（subject）的并发安全固定窗口限流，超限返回可区分的 `429`
  与 `Retry-After` 提示；窗口恢复、管理员重置、服务重启后的行为都是确定的。

## 目录结构

```
authapp/
  config.py     # Settings：密钥、TTL、限流阈值、可注入时钟
  errors.py     # 可区分错误码与统一异常类型
  tokens.py     # HMAC-SHA256 自签名令牌的编码 / 解码 / 过期判定
  store.py      # 线程安全的用户目录与刷新令牌族存储（轮换核心）
  ratelimit.py  # 线程安全的按主体固定窗口限流器
  deps.py       # FastAPI 依赖：认证、作用域授权、限流
  routes.py     # 登录 / 刷新 / 登出 / 受保护接口
  app.py        # 应用工厂与统一错误响应
tests/          # stdlib unittest + FastAPI TestClient（可离线重复运行）
main.py         # 入口：uvicorn 运行
```

## 令牌生命周期与失效规则

### 令牌格式

令牌为无状态的自包含结构，不依赖任何外部服务或数据库：

```
base64url(payload_json) "." base64url(HMAC_SHA256(secret, payload_segment))
```

载荷字段：`jti`（唯一 id）、`sub`（主体）、`role`、`scopes`、`fid`（令牌族 id）、
`typ`（`access` / `refresh`）、`iat`、`exp`。签名校验使用
`hmac.compare_digest` 做常量时间比较。

### 令牌族（Token Family）与轮换

- 每次登录开启一个新的**令牌族**（`fid`），签发一对 access / refresh 令牌；
- `POST /auth/refresh` 必须携带 refresh 令牌：服务端在**单个锁临界区**内
  完成「查找 → 状态检查 → 标记已用 → 追加后继令牌」，然后签发新的一对令牌；
- refresh 令牌**用过即失效**，下一次必须使用新返回的 refresh 令牌；
- 同一个 refresh 令牌再次出现（无论顺序还是并发）即判定为**复用**：
  该次请求得到 `refresh_token_reuse_detected`，且整个令牌族立即被撤销；
  此后该族中任何 refresh 令牌返回 `token_family_revoked`，任何 access 令牌
  也立即无法通过认证；
- `POST /auth/logout` 显式撤销令牌族（登出），其 access / refresh 令牌分别
  返回 `token_revoked` / `token_family_revoked`，与复用场景可区分；
- 过期本身不撤销令牌族：某一条 refresh 令牌过期返回 `token_expired`，
  族内其他未过期的令牌仍可使用。

### 拒绝原因（错误码互不相同）

统一响应体：`{"error": {"code": ..., "message": ...}}`

| 场景 | HTTP | code |
| --- | --- | --- |
| 没有 `Authorization` 头 | 401 | `token_missing` |
| 头格式错误 / 载荷不可解析 / 缺字段 | 401 | `token_malformed` |
| 签名不匹配 | 401 | `bad_signature` |
| 已过期（access 或 refresh） | 401 | `token_expired` |
| 登出撤销后继续使用 access 令牌 | 401 | `token_revoked` |
| 复用检测后使用该族 access 令牌 | 401 | `token_family_revoked` |
| 重复使用 refresh 令牌的当次请求 | 401 | `refresh_token_reuse_detected` |
| 族已撤销后再去刷新 | 401 | `token_family_revoked` |
| 签名合法但 jti 在服务端不存在（如重启后、别的实例签发） | 401 | `refresh_token_not_recognized` |
| 用 refresh 令牌访问受保护接口（或反之） | 401 | `wrong_token_type` |
| 凭据有效但缺少所需作用域 | 403 | `forbidden` |
| 超出主体限流阈值 | 429 | `rate_limited`（带 `Retry-After`） |

> 刷新校验顺序固定为：格式 → 签名 → 过期（密码学层）→ 服务端状态
> （未识别 → 该令牌已使用即复用 → 族已撤销 → 已过期），因此上述结果可确定
> 区分；并发复用时每个输家都会得到 `refresh_token_reuse_detected`，而族内
> 其他未使用令牌的持有者得到 `token_family_revoked`。

## 授权模型

- 本地演示账号（仅用于本地验证，密码使用 PBKDF2-HMAC-SHA256 存储）：

  | 用户名 | 密码 | role | scopes |
  | --- | --- | --- | --- |
  | `admin` | `admin-pass` | `admin` | `read, write, admin` |
  | `editor` | `editor-pass` | `editor` | `read, write` |
  | `viewer` | `viewer-pass` | `viewer` | `read` |

- 接口与所需权限：

  | 接口 | 要求 |
  | --- | --- |
  | `GET /public/ping` | 无凭据 |
  | `POST /auth/login` / `POST /auth/refresh` | 对应凭据 |
  | `GET /api/profile` | 有效 access 令牌（并受限流） |
  | `GET /api/reports` | scope `read` |
  | `POST /api/reports` | scope `write` |
  | `GET /api/admin/users` | scope `admin` |
  | `GET /api/admin/reports/{id}` | scope `admin`（授权通过后才查存在性） |
  | `POST /api/admin/ratelimit/reset?subject=...` | scope `admin` |

- **不泄露资源存在性**：授权依赖在资源查找之前执行。低权限凭据访问
  `/api/admin/reports/{存在的id}` 与 `{不存在的id}` 都得到完全相同的 403；
  只有授权通过后，不存在的资源才返回 404 `not_found`。

## 限流语义

- 维度：**按认证主体**（`sub`）计数，不同主体互不影响；
- 算法：**固定窗口**。某主体的窗口从它的第一个请求开始，长度
  `rate_limit_window_seconds`（默认 60s），窗口内最多
  `rate_limit_per_subject` 次（默认 10 次）；
- 计数自增与放行判定在同一把锁内完成，高并发下不会丢失计数或越过阈值；
- 超限时返回 `429 {"code":"rate_limited"}`，并带
  `Retry-After: <剩余整秒数>`（向上取整，可据此重试）；
- 窗口到达边界后自动开启新窗口；管理员可立即重置单个 / 全部主体；
- **重启确定性**：状态仅保存在进程内存中，服务重启后下一次请求必然从
  count=1 的新窗口开始（测试中通过同一时钟下重建 app 精确验证）。

## 本地验证方法（全程离线）

需要 Python 3.14 与项目锁定的依赖（FastAPI / httpx，测试仅用标准库
`unittest`）。

```bash
# 1) 运行全部测试（令牌轮换 / 并发复用 / 越权 / 限流触发与恢复）
uv run python -m unittest discover -s tests -v

# 2) 启动服务
uv run python main.py
# 另一个终端手工演练：
curl -s -X POST http://127.0.0.1:<port>/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pass"}'
```

测试使用可注入的假时钟（`tests/common.py:FakeClock`），因此过期、窗口
滑动、重启等场景无需真实等待，结果可重复。关键判定会打印到日志，例如：
令牌状态（`auth.refresh.deny ... outcome=reuse`）、所需权限与实际权限
（`authz.forbidden ... required=[...] missing=[...]`）、限流计数
（`ratelimit.check sub=... count=4/3 allowed=False retry_after=60`）。
可用环境变量 `AUTHAPP_LOG_LEVEL=DEBUG` 调整日志级别。

## 安全说明

示例密钥为开发用途的固定值（见 `config.Settings.secret`）；生产环境应通过
`create_app(Settings(secret=...))` 注入强随机密钥。用户数据与令牌状态均
保存在内存中，进程退出即清空，这也是“重启后限流 / 刷新状态确定重置”语义的
一部分。
