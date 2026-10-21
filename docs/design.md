# fftps（f-ftp suite）整合设计

> 目标：将 wftpd-linux 与 wftpd-windows 两个长期独立迭代的项目合并为单一跨平台代码库。
> 服务端命名 **fftpd**，前端管理程序命名 **fftp-gui**。
>
> 既定决策（用户确认）：
> 1. **逐模块择优**：不设全局基线，每个模块比较两边实现后择优合并；
> 2. **轻量 JSON 帧协议**：4 字节长度前缀 + serde_json，统一运行在平台传输上；
> 3. **分阶段可编译交付**：每阶段结束均能编译、可验证；
> 4. **GUI 用 iced 重写**：弃 GTK3（Linux）/ egui（Windows）双实现。

---

## 1. 总体架构

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│  fftp-gui (iced, 跨平台)      │        │  fftpd (守护进程/服务)        │
│  配置/用户/日志/服务管理 UI   │        │  FTP(FTPS) + SFTP 服务端     │
└──────────────┬──────────────┘        └──────────────┬──────────────┘
               │  fftp-ipc（JSON 帧协议）              │
               │  Linux: Unix socket (0600)           │
               │  Windows: Named Pipe (本地会话 ACL)   │
               └──────────────┬───────────────────────┘
                              │
                     fftp-common（共享）
                     配置/用户/路径/日志/配额/限速/防护/指标
```

- 前后端**物理分离**（独立二进制），仅通过 fftp-ipc 通信；fftpd 是配置与用户数据的唯一写入者（沿用 wftpd.proto 的 "backend is the single writer" 原则），GUI 经 IPC 读写。
- 平台差异**集中在三处**，其余代码全部跨平台：
  1. `fftp-ipc::transport`：UDS ↔ Named Pipe；
  2. `fftp-common::paths`：XDG ↔ ProgramData；
  3. 服务生命周期控制：systemd --user ↔ Windows Service（GUI 侧 `platform` 模块）。

## 2. 目录与 crate 划分

```
fftps/
├── Cargo.toml              # workspace（resolver=3, edition=2024）
├── common/                 # fftp-common：配置/用户/路径/日志/配额/限速/防护/指标
│   └── src/{config,users,paths,logging,quota,rate_limit,fail2ban,metrics}.rs
├── ipc/                    # fftp-ipc：协议 + 传输 + client/server 骨架
│   └── src/{protocol,framing,transport/{unix,named_pipe},client,server}.rs
├── ftp/                    # fftp-ftp：FTP(FTPS) 服务端（libunftp 组装）
├── sftp/                   # fftp-sftp：SFTP 服务端（russh + 手写协议层）
├── fftpd/                  # 服务端二进制 fftpd（组装 + IPC dispatch + 服务入口）
├── fftp-gui/                # iced GUI 二进制 fftp-gui
├── docs/design.md
├── debian/                 # [阶段3] deb + systemd 单元
├── scripts/                # [阶段3] 交叉编译/打包脚本
└── .github/workflows/      # [阶段3] CI 矩阵
```

内部依赖：`fftpd → fftp-common, fftp-ipc, fftp-ftp, fftp-sftp`；`fftp-gui → fftp-common, fftp-ipc`。GUI 不依赖任何服务端协议实现 crate。

## 3. IPC 设计（fftp-ipc）

### 3.1 帧格式

每帧 = `u32 BE 长度` + UTF-8 JSON。对称用于请求、响应与服务端推送。

```jsonc
// 请求
{ "type": "request", "id": 1, "cmd": "save_config", "content": "..." }
// 响应（成功）
{ "type": "response", "id": 1, "status": "ok", "data": { ... } }
// 响应（失败）
{ "type": "response", "id": 1, "status": "error", "code": "validation", "message": "..." }
// 服务端推送（日志订阅等），id 恒为 0
{ "type": "notification", "event": "log", "entry": { ... } }
```

- `Command` 为内部 tagged 枚举（`#[serde(tag="cmd", rename_all="snake_case")]`），命令与参数一次定义、两端复用；
- 帧长上限 4 MiB（防止恶意/损坏帧导致 OOM）；
- 无外部 schema（不引 prost/tonic），依赖仅 serde_json + tokio。

### 3.2 命令面（wftpd.proto 的并集 + Windows reload，均为 JSON 命令）

| 类别 | 命令 |
|---|---|
| 生命周期 | `get_status` `start_service{which}` `stop_service{which}` `restart_service{which}` `shutdown` |
| 配置/用户 | `get_config` `save_config{content}` `get_users` `save_users{content}` `get_initial_state` |
| 目录辅助 | `ensure_user_directories` `create_user_directory{path}` `setup_directory_permissions{path}` |
| 日志 | `get_recent_logs{count}` `subscribe_logs{tail_count}` `unsubscribe_logs` `get_log_files` `get_log_file_content{path,count}` `get_file_op_log_files` `get_file_op_log_content{path,count}` `save_log_config{...}` `write_audit_log{user,action,target,details}` |

配置/用户以**原文字符串**（TOML/JSON）传输、由共享类型解析校验——保证前后端对 schema 的理解必然一致（沿用 wftpd.proto 策略）。

### 3.3 传输抽象

```rust
// 两端共用的抽象：任何 AsyncRead + AsyncWrite + Unpin + Send 的双工流
pub trait Transport { type Stream; async fn accept(); async fn connect(); }
```

- **Linux (`transport::unix`)**：`$XDG_RUNTIME_DIR/fftpd/fftpd.sock`（回退 `/tmp/fftpd-$UID`），bind 前清残留，权限 0600，进程退出 unlink；
- **Windows (`transport::named_pipe`)**：`\\.\pipe\fftpd`，`first_pipe_instance` 防多实例，accept 循环持续创建新实例，connect 侧 `WaitNamedPipe` 重试 + 超时（移植 wftpd-windows/windows_ipc.rs 的重试逻辑）；
- 连接建立后协议层完全一致（framing/dispatch/订阅不感知平台）。

## 4. 逐模块择优结论

| 模块 | 取舍 | 依据 |
|---|---|---|
| 工程结构 | **Linux** workspace 多 crate | 依赖面清晰、编译隔离，天然容纳平台传输抽象 |
| 配置 schema | **Windows** config_types.rs 为基础 + Linux logging 增量字段 | Windows 字段更全（FTPS/ConnectionMode/masquerade/pooled listener/fail2ban/per-IP 连接/allow_symlinks/host key 轮换）；补 Linux 的 `max_log_size/enable_json/enable_gui_logging` |
| 用户存储 | 两边**几乎一致，取 Linux** users.rs + Windows argon2 参数 | 字段相同（Permissions 10 字段）；密码哈希统一 Argon2id `Params::new(65536,3,4,Some(32))`（Windows 参数），保留 Linux 的哈希升级/迁移测试 |
| 路径布局 | **拆平台实现**：Linux paths.rs（XDG + 二进制同目录测试友好策略）为源，新增 Windows 分支（ProgramData/config 同目录） | Linux 的路径解析策略更精细（env 覆盖、测试友好）；Windows 侧归一化/防逃逸逻辑（path_utils）并入 SFTP/FTP 存储层的路径解析 |
| FTP 服务端 | **Windows** 组装路线（unftp-sbe-fs + rooter + restrict + cert_gen + active/passive + UPnP + ip_utils） | 功能显著更全（认证链含 IP 安全/连接数/Fail2Ban/会话注册/失败锁定，rcgen 证书生成）；Linux 的自研 StorageBackend 逻辑并入 restrict/rooter 的封装层 |
| SFTP 服务端 | **Windows** 手写协议实现（cmd_dispatch + ops 全家桶） | russh-sftp 仅覆盖 v3 基础 + 少量扩展；手写版多出 `copy-file/hardlink@openssh.com`、`LOCK/UNLOCK`(v5+)、link/lock ops。功能并集优先于"库优先"原则（库不满足场景） |
| 日志 | **Linux** tracing_logger 架构（JSON/文本 + 按天轮转 + file-ops 审计分离 + 内存环形缓冲） | 环形缓冲 + IPC 订阅推送给 GUI，比 Windows "GUI 自己 tail 文件" 的耦合更干净；Windows 的 LogEntry 字段并入 |
| 防护 | **Windows** fail2ban.rs（含持久化）+ 连接数治理（ServerConfig 计数器） | 比 Linux login_tracker 功能全；Linux 的登录统计字段并入 |
| 限速/配额 | **Windows** rate_limiter.rs / quota.rs 为基础，吸收 Linux speed_limiter 的接口 | Windows 实现更完整（383/496 行，多层级） |
| 指标 | **Windows** metrics.rs（prometheus） | Linux 无此模块 |
| 服务集成 | **两套并存**，平台 gating：Linux debian/ + systemd --user；Windows windows-service + 安装脚本 | 无法互相替代 |
| GUI | **iced 重写**，功能面取并集：Windows 的 tab 集 + i18n(en/zh) + log_watcher 思路 + Linux 的 suggested_dirs/user_dialog 完整性 | 两边 UI 框架均弃用 |
| 集成测试 | **Windows** wftpd-test-go 移植为 `tests/`（或保留 Go 套件跨平台跑） | 覆盖 FTP/SFTP/边界/安全/性能；Linux 单元测试随模块并入 |

## 5. 统一数据 schema

### 5.1 config.toml（Windows 字段为基础 + Linux logging 增量）

```toml
[ftp]
enabled = true
bind_ip = "0.0.0.0"
port = 21
welcome_message = "Welcome to fftpd"
encoding = "UTF-8"
default_transfer_mode = "binary"
connection_mode = "passive_only"        # passive_only | active_only | active_and_passive
allow_anonymous = false
anonymous_home = ""
passive_ports = [50000, 51000]          # 由 (u16,u16) 改为元组兼容两侧格式
max_speed_kbps = 0
masquerade_address = ""
connection_timeout = 15
idle_timeout = 15
hide_version_info = false
pooled_listener_mode = true
allow_nat_clients = true
ftp_root = ""                           # 空 = 各用户 home
[ftp.ftps]
enabled = false
require_ssl = false
cert_path = ""
key_path = ""                           # 空 = 自动生成（rcgen）

[sftp]
enabled = true
bind_ip = "0.0.0.0"
port = 2222
host_key_path = ""                      # 空 = paths::default_host_key_path()
max_auth_attempts = 3
auth_timeout = 60
log_level = "info"
max_sessions_per_user = 5
host_key_rotation_days = 0

[security]
max_connections = 100
max_connections_per_ip = 10
allowed_ips = ["0.0.0.0/0"]
denied_ips = []
fail2ban_enabled = false
fail2ban_threshold = 5
fail2ban_ban_time = 3600
allow_symlinks = false
max_login_attempts = 5

[logging]
log_dir = ""                            # 空 = paths::default_log_dir()
log_level = "info"
max_log_files = 10
max_log_size = 10485760
enable_json = false
enable_gui_logging = true
```

### 5.2 users.json（两侧一致，取 Linux 定义 + Windows argon2 参数）

`{ "users": { "<username>": { username, password_hash, home_dir, permissions{can_read..can_append, quota_mb, speed_limit_kbps}, created_at, last_login, enabled, is_admin } } }`
密码哈希：Argon2id PHC 字符串，`m=65536,t=3,p=4,len=32`；加载时对旧参数哈希惰性升级（Linux password_hash_upgrade 测试保留）。

### 5.3 路径（fftp-common::paths）

| 用途 | Linux | Windows |
|---|---|---|
| 配置 | `config.toml`（env 覆盖 > 二进制同目录 > `~/.config/fftpd`） | 同策略，回退 `%ProgramData%\\fftpd` |
| 持久状态 | `~/.local/state/fftpd`（日志、SSH host key） | `%ProgramData%\\fftpd` |
| 运行时 | `$XDG_RUNTIME_DIR/fftpd/fftpd.sock` | `\\.\pipe\fftpd` |
| env 覆盖 | `FFTPD_CONFIG_DIR` `FFTPD_STATE_DIR` | 同名 |

## 6. GUI（fftp-gui, iced）

- tab 并集：**服务器**（FTP/SFTP/FTPS 开关、监听、被动端口、证书）、**用户**（含 Linux user_dialog 的完整编辑）、**安全**（fail2ban/IP 名单/连接数）、**日志**（实时订阅 + 历史文件）、**文件日志**（审计）、**服务**（生命周期 + 安装/卸载/开机自启，平台分支）、**其他/关于**；
- i18n：en/zh JSON（沿用 wftpd-windows/wftpg/i18n 结构）；
- 日志实时性：`subscribe_logs` 通知推送（iced Subscription/subscription channel）；
- 连接管理：启动时连 IPC，失联自动重连 + 状态栏提示（不可见时禁用写操作）。

## 7. 交叉编译

- 目标矩阵：`x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、`x86_64-unknown-linux-musl`、`x86_64-pc-windows-gnu`（可选 `x86_64-pc-windows-msvc`）；
- 工具：`cargo-zigbuild`（linux 全目标 + windows-gnu），windows-gnu 需 mingw 链接器；本机已装 rustup 目标与 cargo-zigbuild；
- `scripts/build.sh <target>`：统一入口，产物落 `dist/<target>/{fftpd,fftp-gui}`；
- 阶段3：debian/（fftpd.service、postinst）+ Windows 服务安装脚本沿用旧项目的成熟脚本改名适配；CI 走 GitHub Actions 矩阵。

## 8. 分阶段实施与验收

| 阶段 | 内容 | 验收 |
|---|---|---|
| **1a** | workspace 骨架 + fftp-common（paths/config/users 全量 schema） | `cargo test` 过（含哈希升级测试） |
| **1b** | fftp-ipc（协议+framing+UDS/NamedPipe 传输+client/server）+ fftpd 骨架（IPC dispatch：status/config/users/日志占位） | Linux 实机：fftpd 启动、IPC 往返通 |
| **1c** | fftp-gui iced 壳（全部 tab 框架 + 状态/配置/用户页可用 + 订阅日志） | Linux 实机运行，与 fftpd 联通 |
| **2** | 功能迁移：FTP(Windows 组装线)、SFTP(手写实现)、日志、fail2ban/限速/配额/指标、完整命令面 | 两侧单测 + Go 集成测试通过 |
| **3** | 交叉编译脚本、debian/systemd、Windows 服务与安装器、CI | 全目标矩阵产物可构建 |

阶段 1 结束后旧项目（wftpd-linux/、wftpd-windows/）保留为迁移参照，全部迁移完成后删除。
