//! 平台传输层：Linux Unix domain socket ↔ Windows Named Pipe
//!
//! 连接一经建立即为普通双工流，协议层（[`crate::framing`]）对平台无感知。

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// 双工连接抽象：`AsyncRead + AsyncWrite` 的对象安全组合
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> DuplexStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type Duplex = Box<dyn DuplexStream>;

/// 平台端点描述（日志/状态展示用）
#[must_use]
pub fn endpoint_display() -> String {
    #[cfg(unix)]
    {
        fftp_common::paths::socket_path().display().to_string()
    }
    #[cfg(windows)]
    {
        named_pipe::PIPE_PATH.to_string()
    }
}

/// 服务端监听器
pub struct Listener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(windows)]
    first_instance: bool,
}

/// 建立服务端监听
///
/// # Errors
/// 绑定失败（Unix socket 创建/权限设置）或管道创建失败时返回错误
pub async fn listen() -> Result<Listener> {
    #[cfg(unix)]
    {
        unix::listen().await
    }
    #[cfg(windows)]
    {
        Ok(Listener {
            first_instance: true,
        })
    }
}

impl Listener {
    /// 接受下一个连接
    ///
    /// # Errors
    /// 接受失败时返回错误
    pub async fn accept(&mut self) -> Result<Duplex> {
        #[cfg(unix)]
        {
            let (stream, _addr) = self.inner.accept().await?;
            Ok(Box::new(stream))
        }
        #[cfg(windows)]
        {
            named_pipe::accept_one(&mut self.first_instance).await
        }
    }
}

/// 连接服务端（带有限重试，覆盖 Windows 管道 busy 场景）
///
/// # Errors
/// 重试耗尽仍无法连接时返回错误
pub async fn connect() -> Result<Duplex> {
    const RETRIES: u32 = 20;
    const INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

    let mut last_err = None;
    for _ in 0..RETRIES {
        match try_connect().await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(INTERVAL).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("连接 IPC 端点失败")))
}

async fn try_connect() -> Result<Duplex> {
    #[cfg(unix)]
    {
        unix::connect().await
    }
    #[cfg(windows)]
    {
        named_pipe::connect().await
    }
}

/// 进程退出时清理 Unix socket 残留（Windows 管道随进程消亡，无需清理）
pub fn cleanup() {
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(fftp_common::paths::socket_path());
    }
}

#[cfg(unix)]
mod unix {
    use super::{Duplex, Listener};
    use anyhow::{Context, Result};
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    pub(super) async fn listen() -> Result<Listener> {
        let path = fftp_common::paths::socket_path();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("创建运行时目录失败")?;
        }

        // 清理上次异常退出的残留套接字；若已有存活实例则让 bind 失败暴露冲突
        if path.exists() {
            let _ = tokio::fs::remove_file(&path).await;
        }

        let inner = UnixListener::bind(&path).context("绑定 Unix socket 失败")?;

        // 仅同用户可连（前后端以同一桌面用户运行）
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .context("设置套接字权限失败")?;

        Ok(Listener { inner })
    }

    pub(super) async fn connect() -> Result<Duplex> {
        let path = fftp_common::paths::socket_path();
        let stream = UnixStream::connect(&path)
            .await
            .with_context(|| format!("连接 {} 失败", path.display()))?;
        Ok(Box::new(stream))
    }

}

#[cfg(windows)]
pub mod named_pipe {
    //! Named Pipe 传输：`\\.\pipe\fftpd`
    //!
    //! accept 侧沿用「每次 accept 创建新实例」的 tokio 管道模式；
    //! connect 侧重试由 [`super::connect`] 统一提供。

    use super::Duplex;
    use anyhow::{Context, Result};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    pub const PIPE_NAME: &str = "fftpd";
    pub const PIPE_PATH: &str = r"\\.\pipe\fftpd";

    fn create_instance(first: bool) -> Result<NamedPipeServer> {
        let mut opts = ServerOptions::new();
        if first {
            opts.first_pipe_instance(true);
        }
        opts.create(PIPE_NAME)
            .context("创建命名管道实例失败（可能已有 fftpd 实例在运行）")
    }

    pub(super) async fn accept_one(first_instance: &mut bool) -> Result<Duplex> {
        let server = create_instance(*first_instance)?;
        *first_instance = false;
        server.connect().await.context("等待命名管道连接失败")?;
        Ok(Box::new(server))
    }

    pub(super) async fn connect() -> Result<Duplex> {
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(PIPE_NAME)
            .with_context(|| format!("打开命名管道 {PIPE_PATH} 失败"))?;
        Ok(Box::new(client))
    }
}
