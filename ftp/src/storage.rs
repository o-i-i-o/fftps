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
use std::sync::{Arc, RwLock as StdRwLock};

use async_trait::async_trait;
use tokio::io::AsyncRead;
use unftp_core::storage::{Error, ErrorKind, Fileinfo, Metadata, Result, StorageBackend};

use fftp_common::rate_limit::{RateLimitedReader, effective_speed_limit_kbps};
use fftp_common::{Config, QuotaManager};

use crate::auth::FtpUser;
use crate::path_safety::{PathError, normalize_virtual_path, resolve_in_root};

/// 写入配额预留估算值（迁移自 wftpd-windows `QuotaFilesystem`）：
/// 上传大小未知，先按 100MB 预留，完成后按实际字节结算
const ESTIMATED_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

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

        // 配额：先预留估算值，完成后按实际字节结算
        let reserved = user.permissions.quota_mb.and_then(|quota_mb| {
            if self
                .quota
                .try_reserve_quota(username, ESTIMATED_MAX_FILE_SIZE, quota_mb)
            {
                Some(ESTIMATED_MAX_FILE_SIZE)
            } else {
                None
            }
        });
        if user.permissions.quota_mb.is_some() && reserved.is_none() {
            tracing::warn!(username, "上传被配额超限拦截");
            return Err(quota_exceeded());
        }

        let limit = effective_speed_limit_kbps(
            self.global_speed_kbps(),
            user.permissions.speed_limit_kbps.unwrap_or(0),
        );
        let upload_result = if limit > 0 {
            tracing::debug!(username, limit_kbps = limit, "上传限速生效");
            self.inner
                .put(user, RateLimitedReader::new(input, limit), &virt, start_pos)
                .await
        } else {
            self.inner.put(user, input, &virt, start_pos).await
        };

        match upload_result {
            Ok(bytes_written) => {
                if let Some(reserved) = reserved {
                    self.quota.commit_usage(username, reserved, bytes_written);
                } else {
                    // 未设配额的用户同样记账用量（供统计与前端展示）
                    self.quota.add_usage(username, bytes_written);
                }
                Ok(bytes_written)
            }
            Err(e) => {
                if let Some(reserved) = reserved {
                    self.quota.rollback_reservation(username, reserved);
                }
                Err(e)
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
        // 预留估算值 100MB > 1MB 配额 → 直接拒绝
        user.permissions.quota_mb = Some(1);

        let err = fs
            .put(&user, &b"x"[..], Path::new("/big.bin"), 0)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InsufficientStorageSpaceError);
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
