//! FTP 存储封装层：路径防护（jail）+ 配额 + 限速
//!
//! 存储栈组合（docs/design.md §4，Windows 组装路线）：
//!
//! ```text
//! RestrictingVfs<JailFilesystem<RooterVfs<Filesystem, FtpUser, Meta>>, FtpUser, Meta>
//! ```
//!
//! [`JailFilesystem`] 位于 rooter 之上，职责：
//! - 虚拟路径净化（[`crate::path_safety::normalize_virtual_path`]，杜绝 `..` 越界与
//!   非法成分进入 rooter——`unftp-sbe-rooter` 对异常路径存在 unwrap/下溢 panic 分支）；
//! - 真实路径防逃逸（canonicalize 越界检查 + 符号链接策略，
//!   策略取 [`fftp_common::config::SecurityConfig::allow_symlinks`]）；
//! - 配额：写入前预留、成功后按实际字节结算、失败回滚、删除/删目录扣减
//!   （对接 [`fftp_common::quota::QuotaManager`]）；
//! - 限速：上传/下载套 [`fftp_common::rate_limit::RateLimitedReader`]，
//!   限速取全局 `ftp.max_speed_kbps` 与用户 `speed_limit_kbps` 的有效值。
//!
//! 路径解析语义：rooter 把会话根（`FtpUser::session_root`）拼到虚拟路径前，
//! 因此本层校验的真实根 = `base_root`（unftp-sbe-fs 的 Filesystem 根）+ 会话根。

use std::fmt::Debug;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, ReadBuf};
use unftp_core::storage::{Error, ErrorKind, Fileinfo, Metadata, Result, StorageBackend};

use fftp_common::rate_limit::{RateLimitedReader, effective_speed_limit_kbps};
use fftp_common::{Config, QuotaManager};

use crate::auth::FtpUser;
use crate::path_safety::{PathError, normalize_virtual_path, resolve_in_root};

/// 上传读取包装：每读到一批数据即按增量预留配额，超限立即中止传输
///
/// 旧实现固定按 100MB 预留，既会误拒小配额用户的小文件，也无法阻止
/// 超过预留值的超大上传；按实际流经字节预留可精确控制上限。
struct QuotaReservingReader<R> {
    inner: R,
    quota: Arc<QuotaManager>,
    username: String,
    quota_mb: Option<u64>,
    /// 已成功预留的字节数（供传输失败/结算时回滚）
    reserved: Arc<AtomicU64>,
    /// 是否因配额超限中止（用于映射为配额错误）
    denied: Arc<AtomicBool>,
}

impl<R: AsyncRead + Unpin> AsyncRead for QuotaReservingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len().saturating_sub(before) as u64;
                if read > 0
                    && let Some(quota_mb) = this.quota_mb
                {
                    if !this
                        .quota
                        .try_reserve_quota(&this.username, read, quota_mb)
                    {
                        this.denied.store(true, Ordering::Relaxed);
                        return Poll::Ready(Err(std::io::Error::other("配额超限")));
                    }
                    this.reserved.fetch_add(read, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// 路径防护 + 配额 + 限速的存储封装层
#[derive(Debug)]
pub struct JailFilesystem<Delegate> {
    inner: Delegate,
    /// 存储根（unftp-sbe-fs `Filesystem` 的根，canonical 形态）
    base_root: PathBuf,
    quota: Arc<QuotaManager>,
    config: Arc<StdRwLock<Config>>,
}

impl<Delegate> JailFilesystem<Delegate> {
    /// 创建封装层
    ///
    /// - `base_root`：存储栈底层 `Filesystem` 的根目录；
    /// - `quota`：共享配额管理器；
    /// - `config`：共享配置（热重载后限速/符号链接策略即时生效）。
    #[must_use]
    pub fn new(
        inner: Delegate,
        base_root: PathBuf,
        quota: Arc<QuotaManager>,
        config: Arc<StdRwLock<Config>>,
    ) -> Self {
        JailFilesystem {
            inner,
            base_root,
            quota,
            config,
        }
    }

    /// 用户真实会话根 = 存储根 + 会话根（跳过 `.` 成分）
    fn real_root(&self, user: &FtpUser) -> PathBuf {
        let mut root = self.base_root.clone();
        for component in user.session_root().components() {
            if let Component::Normal(name) = component {
                root.push(name);
            }
        }
        root
    }

    /// 全局单连接限速（KB/s，0 = 不限速）
    fn global_speed_kbps(&self) -> u64 {
        self.config.read().unwrap().ftp.max_speed_kbps
    }

    /// 符号链接策略
    fn allow_symlinks(&self) -> bool {
        self.config.read().unwrap().security.allow_symlinks
    }

    /// 净化虚拟路径并做真实路径防逃逸检查
    ///
    /// 返回 `(净化后的虚拟路径, 真实路径)`：虚拟路径交给内层 rooter/Filesystem，
    /// 真实路径用于配额目录统计等需要落盘位置的场景。
    fn guard(&self, user: &FtpUser, path: &Path) -> Result<(PathBuf, PathBuf)> {
        let virtual_str = path.to_string_lossy();
        let normalized = normalize_virtual_path(&virtual_str).map_err(map_path_error)?;
        let real = resolve_in_root(&self.real_root(user), &normalized, self.allow_symlinks())
            .map_err(map_path_error)?;
        Ok((PathBuf::from(normalized), real))
    }
}

/// 路径错误 → unftp 存储错误
fn map_path_error(e: PathError) -> Error {
    let kind = match e {
        PathError::NotFound => ErrorKind::PermanentFileNotAvailable,
        PathError::NotADirectory => ErrorKind::PermanentDirectoryNotAvailable,
        PathError::PathEscape | PathError::PathNotUnderRoot | PathError::SymlinkNotAllowed => {
            ErrorKind::PermissionDenied
        }
        PathError::InvalidPath | PathError::PathTooDeep => ErrorKind::FileNameNotAllowedError,
        PathError::RootNotFound | PathError::CanonicalizeFailed => ErrorKind::LocalError,
    };
    Error::new(kind, std::io::Error::other(e.to_string()))
}

/// 配额超限错误
fn quota_exceeded() -> Error {
    Error::new(
        ErrorKind::InsufficientStorageSpaceError,
        std::io::Error::other("配额超限"),
    )
}

#[async_trait]
impl<Delegate> StorageBackend<FtpUser> for JailFilesystem<Delegate>
where
    Delegate: StorageBackend<FtpUser> + Send + Sync + Debug + 'static,
{
    type Metadata = Delegate::Metadata;

    fn supported_features(&self) -> u32 {
        self.inner.supported_features()
    }

    async fn metadata<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &FtpUser,
        path: P,
    ) -> Result<Self::Metadata> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        self.inner.metadata(user, &virt).await
    }

    async fn list<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &FtpUser,
        path: P,
    ) -> Result<Vec<Fileinfo<PathBuf, Self::Metadata>>> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        self.inner.list(user, &virt).await
    }

    async fn get<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &FtpUser,
        path: P,
        start_pos: u64,
    ) -> Result<Box<dyn AsyncRead + Send + Sync + Unpin>> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        let reader = self.inner.get(user, &virt, start_pos).await?;

        let limit = effective_speed_limit_kbps(
            self.global_speed_kbps(),
            user.permissions.speed_limit_kbps.unwrap_or(0),
        );
        if limit > 0 {
            tracing::debug!(username = %user.username, limit_kbps = limit, "下载限速生效");
            Ok(Box::new(RateLimitedReader::new(reader, limit)))
        } else {
            Ok(reader)
        }
    }

    async fn put<P: AsRef<Path> + Send + Debug, R: AsyncRead + Send + Sync + Unpin + 'static>(
        &self,
        user: &FtpUser,
        input: R,
        path: P,
        start_pos: u64,
    ) -> Result<u64> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        let username = user.username.as_str();
        let quota_mb = user.permissions.quota_mb;

        // 配额预检：已耗尽时直接拒绝，避免传输到一半才失败
        if let Some(quota) = quota_mb
            && !self.quota.check_quota(username, quota, 0)
        {
            tracing::warn!(username, "上传被配额超限拦截");
            return Err(quota_exceeded());
        }

        // REST 偏移落在文件末尾之后会通过 set_len 直接占盘，先按空洞增量预留
        let existing_size = self
            .inner
            .metadata(user, &virt)
            .await
            .map_or(0, |meta| meta.len());
        let seek_growth = start_pos.saturating_sub(existing_size);
        if seek_growth > 0
            && let Some(quota) = quota_mb
            && !self
                .quota
                .try_reserve_quota(username, seek_growth, quota)
        {
            tracing::warn!(username, "上传被配额超限拦截（REST 偏移）");
            return Err(quota_exceeded());
        }
        let upfront_reserved = if quota_mb.is_some() {
            seek_growth
        } else {
            0
        };

        // 流式预留：每读取一批数据就按增量检查配额
        let streamed = Arc::new(AtomicU64::new(0));
        let denied = Arc::new(AtomicBool::new(false));
        let quota_reader = QuotaReservingReader {
            inner: input,
            quota: Arc::clone(&self.quota),
            username: username.to_string(),
            quota_mb,
            reserved: Arc::clone(&streamed),
            denied: Arc::clone(&denied),
        };

        let limit = effective_speed_limit_kbps(
            self.global_speed_kbps(),
            user.permissions.speed_limit_kbps.unwrap_or(0),
        );
        let upload_result = if limit > 0 {
            tracing::debug!(username, limit_kbps = limit, "上传限速生效");
            self.inner
                .put(
                    user,
                    RateLimitedReader::new(quota_reader, limit),
                    &virt,
                    start_pos,
                )
                .await
        } else {
            self.inner.put(user, quota_reader, &virt, start_pos).await
        };

        let streamed_bytes = streamed.load(Ordering::Relaxed);
        let total_reserved = upfront_reserved.saturating_add(streamed_bytes);

        match upload_result {
            Ok(bytes_written) => {
                if quota_mb.is_some() {
                    // 按最终文件大小二次复核增量，避免恢复/覆盖场景多计
                    let final_size = existing_size.max(start_pos.saturating_add(bytes_written));
                    let actual_growth = final_size.saturating_sub(existing_size);
                    self.quota
                        .commit_usage(username, total_reserved, actual_growth);
                } else {
                    // 未设配额的用户同样记账用量（供统计与前端展示）
                    self.quota.add_usage(username, bytes_written);
                }
                Ok(bytes_written)
            }
            Err(e) => {
                if total_reserved > 0 {
                    self.quota.rollback_reservation(username, total_reserved);
                }
                if denied.load(Ordering::Relaxed) {
                    tracing::warn!(username, "上传因配额超限中途终止");
                    Err(quota_exceeded())
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn del<P: AsRef<Path> + Send + Debug>(&self, user: &FtpUser, path: P) -> Result<()> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        let username = user.username.as_str();
        let file_size = self.inner.metadata(user, &virt).await?.len();

        self.inner.del(user, &virt).await?;

        if file_size > 0 {
            self.quota.subtract_usage(username, file_size);
        }
        Ok(())
    }

    async fn mkd<P: AsRef<Path> + Send + Debug>(&self, user: &FtpUser, path: P) -> Result<()> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        self.inner.mkd(user, &virt).await
    }

    async fn rename<P: AsRef<Path> + Send + Debug>(
        &self,
        user: &FtpUser,
        from: P,
        to: P,
    ) -> Result<()> {
        let (from_virt, _) = self.guard(user, from.as_ref())?;
        let (to_virt, _) = self.guard(user, to.as_ref())?;
        self.inner.rename(user, &from_virt, &to_virt).await
    }

    async fn rmd<P: AsRef<Path> + Send + Debug>(&self, user: &FtpUser, path: P) -> Result<()> {
        let (virt, real) = self.guard(user, path.as_ref())?;
        let username = user.username.as_str();

        // 目录体积按真实路径统计（旧实现误用会话虚拟路径，迁移时修正）
        let total_size = tokio::task::spawn_blocking(move || {
            fftp_common::quota::dir_size(&real).unwrap_or(0)
        })
        .await
        .map_err(|e| Error::new(ErrorKind::LocalError, std::io::Error::other(e)))?;

        self.inner.rmd(user, &virt).await?;

        if total_size > 0 {
            self.quota.subtract_usage(username, total_size);
        }
        Ok(())
    }

    async fn cwd<P: AsRef<Path> + Send + Debug>(&self, user: &FtpUser, path: P) -> Result<()> {
        let (virt, _) = self.guard(user, path.as_ref())?;
        self.inner.cwd(user, &virt).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use unftp_sbe_fs::Meta;
    use unftp_sbe_rooter::RooterVfs;

    use fftp_common::Permissions;

    type Delegate = RooterVfs<unftp_sbe_fs::Filesystem, FtpUser, Meta>;

    fn make_user(base: &Path, session_root: &str) -> FtpUser {
        FtpUser::new(
            "alice".to_string(),
            base.join(session_root),
            PathBuf::from(session_root),
            true,
            Permissions {
                can_read: true,
                can_write: true,
                can_delete: true,
                can_list: true,
                can_mkdir: true,
                can_rmdir: true,
                can_rename: true,
                can_append: true,
                quota_mb: None,
                speed_limit_kbps: None,
            },
        )
    }

    fn make_fs(base: &Path, quota_dir: &Path) -> JailFilesystem<Delegate> {
        let filesystem = unftp_sbe_fs::Filesystem::new(base).unwrap();
        let rooter: Delegate = RooterVfs::new(filesystem);
        JailFilesystem::new(
            rooter,
            base.canonicalize().unwrap(),
            Arc::new(QuotaManager::new(quota_dir)),
            Arc::new(StdRwLock::new(Config::default())),
        )
    }

    #[tokio::test]
    async fn test_put_get_roundtrip_and_quota_accounting() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let user = make_user(base.path(), ".");

        fs.mkd(&user, Path::new("/dir")).await.unwrap();
        let written = fs
            .put(&user, &b"hello ftp"[..], Path::new("/dir/file.txt"), 0)
            .await
            .unwrap();
        assert_eq!(written, 9);
        assert_eq!(fs.quota.get_usage("alice"), 9);

        let mut reader = fs.get(&user, Path::new("/dir/file.txt"), 0).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"hello ftp");

        // 删除后配额扣减
        fs.del(&user, Path::new("/dir/file.txt")).await.unwrap();
        assert_eq!(fs.quota.get_usage("alice"), 0);
    }

    #[tokio::test]
    async fn test_quota_exceeded_rejects_upload() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let mut user = make_user(base.path(), ".");
        user.permissions.quota_mb = Some(1);
        // 先占满 1MB 配额，上传前预检应直接拒绝
        fs.quota.add_usage("alice", 1024 * 1024);

        let err = fs
            .put(&user, &b"x"[..], Path::new("/big.bin"), 0)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InsufficientStorageSpaceError);
    }

    #[tokio::test]
    async fn test_small_quota_allows_small_upload() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let mut user = make_user(base.path(), ".");
        user.permissions.quota_mb = Some(1);

        // 剩余配额不足 100MB 也不应误拒小文件
        let written = fs
            .put(&user, &b"small"[..], Path::new("/small.txt"), 0)
            .await
            .unwrap();
        assert_eq!(written, 5);
        assert_eq!(fs.quota.get_usage("alice"), 5);
    }

    #[tokio::test]
    async fn test_quota_exceeded_midstream_rolls_back() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let mut user = make_user(base.path(), ".");
        user.permissions.quota_mb = Some(1);

        // 2MB 数据超过 1MB 配额：流式预留失败，预留在错误后回滚
        let data = std::io::Cursor::new(vec![0u8; 2 * 1024 * 1024]);
        let err = fs
            .put(&user, data, Path::new("/oversize.bin"), 0)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InsufficientStorageSpaceError);
        assert_eq!(fs.quota.get_usage("alice"), 0);
        assert_eq!(fs.quota.get_reserved("alice"), 0);
    }

    #[tokio::test]
    async fn test_jail_blocks_parent_escape() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let user = make_user(base.path(), ".");

        let err = fs.metadata(&user, Path::new("/../etc/passwd")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);

        let err = fs.metadata(&user, Path::new("/..")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_jail_blocks_invalid_component() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let user = make_user(base.path(), ".");

        let err = fs.metadata(&user, Path::new("/bad:name")).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileNameNotAllowedError);
    }

    #[tokio::test]
    async fn test_rename_and_mkdir() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        let fs = make_fs(base.path(), quota_dir.path());
        let user = make_user(base.path(), ".");

        fs.mkd(&user, Path::new("/work")).await.unwrap();
        fs.put(&user, &b"data"[..], Path::new("/work/a.txt"), 0)
            .await
            .unwrap();
        fs.rename(&user, Path::new("/work/a.txt"), Path::new("/work/b.txt"))
            .await
            .unwrap();

        let meta = fs.metadata(&user, Path::new("/work/b.txt")).await.unwrap();
        assert_eq!(meta.len(), 4);

        // 目录非空时 rmd 由底层报错；删除文件后可删
        assert!(fs.rmd(&user, Path::new("/work")).await.is_err());
        fs.del(&user, Path::new("/work/b.txt")).await.unwrap();
        fs.rmd(&user, Path::new("/work")).await.unwrap();
    }

    #[tokio::test]
    async fn test_session_root_isolation() {
        let base = tempfile::tempdir().unwrap();
        let quota_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(base.path().join("homes/alice")).unwrap();
        std::fs::create_dir_all(base.path().join("homes/bob")).unwrap();
        std::fs::write(base.path().join("homes/bob/secret.txt"), b"s").unwrap();

        let fs = make_fs(base.path(), quota_dir.path());
        let alice = make_user(base.path(), "homes/alice");
        let bob = make_user(base.path(), "homes/bob");

        // alice 的会话根之外不可见
        assert!(fs.metadata(&alice, Path::new("/secret.txt")).await.is_err());
        assert!(fs.metadata(&bob, Path::new("/secret.txt")).await.is_ok());
    }
}
