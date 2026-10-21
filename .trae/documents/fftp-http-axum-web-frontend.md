# fftp-http：axum Web 管理前端实施计划

## Context

fftps 已有 iced GUI（fftp-gui）作为前端，经 fftp-ipc 管理 fftpd。用户要求新增平行的 Web 管理前端 `fftp-http`（axum），API 与界面一起交付。已确认决策：

- fftpd 与 fftp-http 保持隔离；fftp-http **独立配置文件**（监听地址/端口、TLS、IP 黑白名单、管理员用户，全部在同一个 `fftp-http.toml`）
- 允许绑定 `0.0.0.0`，但非回环绑定强制要求 TLS 或 api_token（启动时 fail fast）
- API 与 Web UI 一起做（内嵌静态 vanilla JS SPA，无构建工具链）

架构定位：fftp-http 只依赖 `fftp-common` + `fftp-ipc`，与 fftp-gui 平级，fftpd 零改动（除共享层两处可见性/路径小改）。

## 已验证的关键事实

- `ipc::Client` 为 `Clone`（Arc 内部），按 id 多路复用支持并发请求（ipc/src/client.rs L19-96）
- **SSE 必须每流专用 IPC 连接**：`SubscribeLogs`/`UnsubscribeLogs` 按 IPC 连接记账（ipc/src/server.rs L108-158 `log_forward: Option<JoinHandle>`），共享 Client 会互相杀推送；连接关闭时服务端自动 abort 推送任务
- 订阅顺序必须"先 `subscribe_events()` 再发 `SubscribeLogs`"（对齐 fftp-gui/src/app.rs L380-383，防历史丢失）
- `Config::is_ip_allowed_for(allowed, denied, ip)` 已公开（common/src/config.rs L377，CIDR 支持），HTTP IP 过滤直接复用
- `UserManager::hash_password`/`verify_password` 当前私有（common/src/users.rs L210/L222），GUI 侧已重复实现 hash；本次在 common 公开，fftp-http 直接复用（GUI 的重复实现不在本次范围）
- rustls 0.23 将同时编入 aws-lc-rs（libunftp 传递）与 ring，**必须显式 `builder_with_provider(ring)`**，不能依赖进程默认 provider
- rand 0.10 已在 Cargo.lock（传递依赖）；token 用 `u128` 生成，避免数组 Distribution API
- axum 0.8：路径参数 `{name}` 语法（非 `:name`）；`Router` 实现 Service，手写 accept loop 需 `tower::ServiceExt::oneshot` + `req.map(Body::new)`

## 一、现有文件修改（2 处）

### 1. common/src/users.rs
- `hash_password`（L210）、`verify_password`（L222）改为 `pub fn`（doc 注明供 fftp-http 使用）

### 2. common/src/paths.rs
- 新增跨平台 `pub fn http_config_path() -> PathBuf`：环境变量 `FFTPD_HTTP_CONFIG` 覆盖 > `config_path().with_file_name("fftp-http.toml")`（天然复用 exe 目录 vs XDG/ProgramData 解析）；补一条 `ends_with("fftp-http.toml")` 测试

## 二、workspace Cargo.toml

- `members` 追加 `"fftp-http"`
- `[workspace.dependencies]` 追加：

```toml
axum = "0.8"
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "server-auto", "service"] }
tower = { version = "0.5", features = ["util"] }
tokio-stream = { version = "0.1", features = ["sync"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "logging", "tls12"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12"] }
rustls-pemfile = "2"
rand = "0.10"
```

## 三、新 crate `fftp-http/`

Cargo.toml 仿 fftp-gui 格式：workspace 继承字段 + `[lints] workspace = true` + `[[bin]] name = "fftp-http"`。

### 模块结构

| 文件 | 职责 |
|---|---|
| `src/main.rs` | `std::env::args` 分发：`hash <password>` 子命令（调 `UserManager::hash_password` 打印 PHC）与默认 serve；serve 流程：日志初始化 → 加载 HttpConfig（缺失写默认模板）→ 启动校验（非回环必须有 TLS 或 api_token、TLS 文件存在、admin_users 非空）→ AppState → daemon 重连任务 → 统一 accept loop → Ctrl-C 退出 |
| `src/config.rs` | `HttpConfig`（ListenConfig/TlsConfig/IpFilterConfig/AuthConfig/AdminUser），serde 全 `#[serde(default)]`；`load()`（缺失生成模板）、`validate()`（错误信息含修复指引）、`is_loopback_only()` |
| `src/state.rs` | `AppState`：`Arc<HttpConfig>` + `Daemon` + `SessionStore` + `audit()` 辅助（封装 WriteAuditLog，失败仅 warn） |
| `src/daemon.rs` | 守护进程连接管理器（移植 fftp-gui/src/ipc_service.rs 状态机）：`watch::channel<Option<Client>>` + 每 5s `GetStatus` 心跳 + 断开后指数退避重连（1s 起上限 10s）；`request(cmd)` 辅助，None 时返回 503 语义 |
| `src/error.rs` | `ApiError` 实现 IntoResponse，JSON `{"error":{"code","message"}}`；`From<ClientError>`：Disconnected→503、Validation→400、NotFound→404、Conflict→409、Io/Protocol/Internal→502 |
| `src/auth.rs` | `SessionStore`（Mutex<HashMap<token,(username, Instant)>>，TTL 默认 43200s，惰性淘汰+小时清扫）；token `format!("{:032x}{:032x}", u128, u128)`（256bit）；Cookie `fftp_session`（HttpOnly/SameSite=Strict，TLS 时 Secure）手工拼/解析；`AdminSession` extractor（axum 0.8 原生 async trait，`FromRequestParts<Arc<AppState>>`），认证 = Cookie 或 `Authorization: Bearer <api_token>`；token 比较用常量时间 XOR |
| `src/ip_filter.rs` | `axum::middleware::from_fn`：从 extensions 取 `ConnectInfo<SocketAddr>` 对端 IP → `Config::is_ip_allowed_for` → 拒绝 403；**不**信任 X-Forwarded-For（防伪造） |
| `src/routes.rs` | Router 组装 + 全部 IPC 代理 handler；DTO 复刻 fftp-gui/src/ipc_service.rs L183-234 形状，用 `fftp_ipc::client::parse_data` |
| `src/sse.rs` | SSE 日志流（见关键设计） |
| `src/tls.rs` | `builder_with_provider(ring)` 构建ServerConfig + `TlsAcceptor`（rustls_pemfile 读证书链/私钥） |
| `ui/index.html` `ui/app.js` `ui/style.css` | 中文 SPA，`include_str!` 嵌入，无外部 CDN |

### 配置文件（config.rs 生成模板）

```toml
[listen]
address = "127.0.0.1"   # 非回环（0.0.0.0）必须启用 TLS 或 api_token
port = 8080
[tls]
enabled = false
cert_path = ""
key_path = ""
[ip_filter]
whitelist = []          # 空=不限制；支持单 IP 与 CIDR
blacklist = []
[auth]
session_ttl_secs = 43200
api_token = ""          # 可选；Bearer 程序化访问
[[admin_users]]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
```

### 路由表（中间件顺序：ip_filter 最外层 → auth → handler）

| 方法 | 路径 | IPC 命令 |
|---|---|---|
| POST | `/api/login` | 本地校验 + 审计（成功/失败均写 WriteAuditLog） |
| POST | `/api/logout` | — |
| GET | `/api/status` | GetStatus |
| GET | `/api/daemon` | —（`{connected:bool}`，UI 离线横幅） |
| POST | `/api/service/{action}` | Start/Stop/RestartService（body `{which}`，审计） |
| POST | `/api/shutdown` | Shutdown（审计 + UI 二次确认） |
| GET/PUT | `/api/config` | GetConfig / SaveConfig（审计） |
| GET/PUT | `/api/users` | GetUsers / SaveUsers（审计） |
| GET | `/api/initial` | GetInitialState |
| POST | `/api/user-directories/ensure` | EnsureUserDirectories |
| POST | `/api/user-directory` | CreateUserDirectory |
| POST | `/api/directory-permissions` | SetupDirectoryPermissions |
| GET | `/api/logs?count=` | GetRecentLogs |
| GET | `/api/logs/files` | GetLogFiles |
| POST | `/api/logs/content` | GetLogFileContent（路径放 body 免 URL 编码） |
| GET | `/api/fileop/files` | GetFileOpLogFiles |
| POST | `/api/fileop/content` | GetFileOpLogContent |
| PUT | `/api/log-config` | SaveLogConfig（审计） |
| GET | `/api/logs/stream?tail=` | **SSE**（SubscribeLogs/UnsubscribeLogs） |
| GET | `/`、`/static/{file}` | index.html、app.js/style.css（match mime） |

### 关键设计

**SSE（sse.rs）**：
1. 每流 `Client::connect()` 专用连接（按连接记账，已验证）
2. 先 `subscribe_events()` 再 `request(SubscribeLogs{tail_count})`
3. `BroadcastStream` 处理 `Lagged`（转发一条 notice 事件）与 `Closed`
4. 浏览器断开 → Client drop → 连接关闭 → 服务端自动 abort 推送；收尾 best-effort 发一次 UnsubscribeLogs
5. EventSource 自动重连 → 新连接 → 重新补推历史

**统一 accept loop（main.rs）**：明文/TLS 同一路径；手动 `extensions_mut().insert(ConnectInfo(peer))` 供 ip_filter 使用；`hyper_util::server::conn::auto::Builder...serve_connection_with_upgrades`。

**Router 组装**：protected 路由先 `.layer(auth_middleware)`，public（login/logout）单独，最后 `.layer(ip_filter)` 覆盖全部（axum layer 只包住此前注册的路由）。

**安全**：SameSite=Strict Cookie + 变更端点要求 `Content-Type: application/json`（基础 CSRF 防线）；启动校验 fail fast；登录失败审计；每 IP 登录失败限流列为可选加固项。

**UI**：登录遮罩 → tab 切换（服务状态/启停、配置编辑、用户管理+目录辅助、实时日志 SSE+暂停/清屏、日志文件、文件操作日志、关于）；fetch 封装：401→登录遮罩、503/502→离线横幅；对齐 GUI 各 tab 交互。

## 四、实施顺序（每步 workspace 可编译）

1. common 两处修改 + paths 测试 → `cargo test -p fftp-common`
2. workspace deps + member；fftp-http 骨架 → `cargo check -p fftp-http`
3. config.rs 全量 + `hash` 子命令 → `cargo run -p fftp-http -- hash test1234`
4. daemon.rs + state.rs → 单测仿 ipc client.rs 的 `tokio::io::duplex` 法
5. error.rs + ip_filter.rs → `cargo check`
6. auth.rs + routes.rs 骨架（status/daemon）+ 明文 accept loop → 起 fftpd 后 curl 首验
7. routes.rs 补全全部代理路由 + 审计 → curl 全路由冒烟
8. sse.rs → `curl -N` 验证
9. tls.rs 接入 → 自签证书测试 TLS 模式
10. UI 三文件 → 浏览器手测
11. 收尾：clippy pedantic 清零；（可选）scripts/build.sh 矩阵、debian 打包、docs/design.md 补章节

## 五、验证

1. 静态：`cargo check/clippy/test --workspace`、`cargo build --release --workspace`
2. 启动负例：无 admin_users 拒启；`0.0.0.0` 且无 TLS 无 token 拒启；TLS 文件缺失拒启；黑名单 IP 返回 403（含 `/`）
3. curl 流程：login（-c jar）→ status → config → PUT config 观察校验 400 回显 → `curl -N` SSE → 无 cookie 401
4. 浏览器（TRAE-browseruse）：登录/登出、各 tab 动作、SSE 滚动与断流自愈（重启 fftpd 自动重连补历史）、双标签页 SSE 互不干扰
5. 交叉编译冒烟：`./scripts/build.sh x86_64-pc-windows-gnu`（rustls+ring 与 zigbuild 管线无冲突）

## 六、风险

1. rustls 双 provider 必须全程显式 `builder_with_provider`（tls.rs 单测锁定）
2. SSE 禁止图省事共享 Client（code review 重点）
3. axum 0.8 细节：`{name}` 语法、不依赖 `Option<T>` extractor（query 用 `#[serde(default)]`）
4. panic=abort release：handler 不 panic，SSE 错误路径显式处理
5. 心跳探活 5s 延迟内 `/api/status` 可能 502（stale client），UI 以 502/503 一并显示离线横幅
6. 打包（build.sh/debian）不在首版阻塞路径，列为步骤 11 可选
