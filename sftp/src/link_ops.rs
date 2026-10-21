//! SFTP 链接操作命令：READLINK / SYMLINK
//!
//! 符号链接创建按平台分化：Unix 走 `std::os::unix::fs::symlink`，
//! Windows 按目标类型选 `symlink_file`/`symlink_dir` 并拒绝 junction/reparse 目标。
//! 链接路径与目标都必须落在 home 之内（jail）。

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::protocol::{
    build_attrs, build_packet, build_status_packet, parse_string, parse_string_with_len, parse_u32,
};
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

impl SftpState {
    /// `SSH_FXP_READLINK`：读取符号链接目标（应答 `SSH_FXP_NAME`，单条目）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_readlink(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        if !self.check_permission(|p| p.can_read || p.can_list) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        // 不跟随符号链接：末段文件名保留，读取链接自身的目标
        let full_path = match self.resolve_path_no_follow_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        match tokio::fs::read_link(&full_path).await {
            Ok(target) => {
                let target_str = target.to_string_lossy().to_string();
                let mut payload = vec![SSH_FXP_NAME];
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&1u32.to_be_bytes());
                // filename
                payload.extend_from_slice(&(target_str.len() as u32).to_be_bytes());
                payload.extend_from_slice(target_str.as_bytes());
                // longname（无 ls 风格长名，重复文件名）
                payload.extend_from_slice(&(target_str.len() as u32).to_be_bytes());
                payload.extend_from_slice(target_str.as_bytes());
                payload.extend_from_slice(&build_attrs(false, 0));
                Ok(build_packet(&payload))
            }
            Err(e) => {
                tracing::debug!("SFTP READLINK failed for {full_path:?}: {e}");
                let (code, msg) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (SSH_FX_PERMISSION_DENIED, "Permission denied")
                } else {
                    (SSH_FX_NO_SUCH_FILE, "No such file")
                };
                Ok(build_status_packet(id, code, msg, ""))
            }
        }
    }

    /// `SSH_FXP_SYMLINK`：创建符号链接（请求体：target 字符串 + linkpath 字符串）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub fn handle_symlink(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (target, target_len) = parse_string_with_len(data, 5)?;
        let link_pos = 5 + 4 + target_len;
        let link_path = parse_string(data, link_pos)?;

        if !self.check_permission(|p| p.can_write) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let full_link = match self.resolve_path_checked(id, &link_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        // home 规范路径作为 jail 基准（链接路径已经 resolve_path_checked 落在其内）
        let home_canon = PathBuf::from(&self.home_dir)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(&self.home_dir));

        // 目标必须解析到 home 之内（相对目标按链接父目录拼接）
        let link_parent = full_link.parent().unwrap_or(Path::new(&self.home_dir));
        let resolved_target = if Path::new(&target).is_absolute() {
            match self.resolve_path_checked(id, &target) {
                Ok(p) => p,
                Err(resp) => return Ok(resp),
            }
        } else {
            link_parent.join(&target)
        };

        // 词法校验：`..` 归一化后仍须落在 home 内（悬空链接目标也必须安全）
        if crate::path_resolve::build_safe_path(&home_canon, &resolved_target, "symlink target")
            .is_err()
        {
            tracing::warn!(
                "SFTP SYMLINK denied: target path outside home - {} -> {:?}",
                full_link.display(),
                resolved_target
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied: target path outside home",
                "",
            ));
        }

        // 目标已存在时再做 canonicalize 校验（防符号链接目标指向 home 之外）
        if let Ok(canon_target) = resolved_target.canonicalize()
            && !crate::path_resolve::path_starts_with_ignore_case(&canon_target, &home_canon)
        {
            tracing::warn!(
                "SFTP SYMLINK denied: canonicalized target outside home - {} -> {:?}",
                full_link.display(),
                canon_target
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied: target path outside home",
                "",
            ));
        }

        // Windows：拒绝指向 junction/reparse point 的目标（旧版防护）
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if resolved_target.exists()
                && let Ok(metadata) = std::fs::metadata(&resolved_target)
                && metadata.file_attributes() & 0x400 != 0
            {
                tracing::warn!(
                    "SFTP SYMLINK denied: target is a junction/reparse point - {:?}",
                    resolved_target
                );
                return Ok(build_status_packet(
                    id,
                    SSH_FX_PERMISSION_DENIED,
                    "Permission denied: junction points not allowed",
                    "",
                ));
            }
        }

        match create_symlink(&target, &full_link, &resolved_target) {
            Ok(()) => {
                self.audit_file_op_pair(
                    "SYMLINK",
                    &full_link.to_string_lossy(),
                    &resolved_target.to_string_lossy(),
                    0,
                    "Symlink created successfully",
                );
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Err(e) => {
                tracing::warn!("SFTP SYMLINK failed for {full_link:?}: {e}");
                let msg = if e.raw_os_error() == Some(1314) {
                    // ERROR_PRIVILEGE_NOT_HELD：Windows 创建符号链接需要特权/开发者模式
                    "Symlink requires administrator privileges on Windows"
                } else {
                    "Failed to create symlink"
                };
                Ok(build_status_packet(id, SSH_FX_FAILURE, msg, ""))
            }
        }
    }
}

/// 跨平台创建符号链接
///
/// Windows 按已知目标类型选 file/dir 链接（目标不存在时按后缀猜测为文件链接）；
/// Unix 统一走 `std::os::unix::fs::symlink`。
fn create_symlink(
    target: &str,
    link_path: &Path,
    resolved_target: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let _ = resolved_target;
        std::os::unix::fs::symlink(target, link_path)
    }
    #[cfg(windows)]
    {
        let is_dir = if resolved_target.exists() {
            resolved_target.is_dir()
        } else {
            false
        };
        if is_dir {
            std::os::windows::fs::symlink_dir(target, link_path)
        } else {
            std::os::windows::fs::symlink_file(target, link_path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{self, setup, setup_with_perms};

    fn symlink_req(id: u32, target: &str, linkpath: &str) -> Vec<u8> {
        let mut v = vec![SSH_FXP_SYMLINK];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(target));
        v.extend_from_slice(&test_util::str_field(linkpath));
        v
    }

    fn readlink_req(id: u32, path: &str) -> Vec<u8> {
        let mut v = vec![SSH_FXP_READLINK];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(path));
        v
    }

    #[tokio::test]
    async fn test_symlink_and_readlink_roundtrip() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("target.txt"), b"t").unwrap();

        let resp = env
            .state
            .dispatch_packet(&symlink_req(1, "target.txt", "/link.txt"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert!(env.dir.path().join("link.txt").is_symlink());

        let resp = env
            .state
            .dispatch_packet(&readlink_req(2, "/link.txt"))
            .await
            .unwrap();
        let payload = test_util::payload(&resp);
        assert_eq!(payload[0], SSH_FXP_NAME);
        // NAME 报文体：id(4) + count(4) + 首条 filename
        let (target, _) = parse_string_with_len(payload, 9).unwrap();
        assert_eq!(target, "target.txt");
    }

    #[tokio::test]
    async fn test_readlink_nonexistent_fails() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&readlink_req(1, "/nope"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_NO_SUCH_FILE);
    }

    #[tokio::test]
    async fn test_symlink_denied_without_write_permission() {
        let mut env = setup_with_perms(|p| p.can_write = false);
        let resp = env
            .state
            .dispatch_packet(&symlink_req(1, "t.txt", "/link.txt"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_PERMISSION_DENIED);
    }

    #[tokio::test]
    async fn test_symlink_target_outside_home_denied() {
        let mut env = setup();
        // 相对目标越出 home：link_parent/../../outside
        let resp = env
            .state
            .dispatch_packet(&symlink_req(1, "../../outside", "/link.txt"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_PERMISSION_DENIED);
        assert!(!env.dir.path().join("link.txt").exists());
    }
}
