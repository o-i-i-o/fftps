//! SFTP 文件区间锁定：BLOCK / UNBLOCK（v3 draft §6.6，LOCK 扩展）
//!
//! advisory 锁语义：会话级标记 + 全局 `locked_files` 集合防重入，
//! 阻塞锁不支持。参数为协议层解析后的强类型字段。

use crate::protocol::{Status, StatusReply, StatusCode};
use crate::state::{SftpState, status_err, status_ok};
use crate::types::SftpFileHandle;

/// BLOCK 请求 flags：低 3 位为锁类型（0 读 / 1 写 / 2 解锁），0x8 为阻塞
const LOCK_TYPE_MASK: u32 = 0x7;
const LOCK_FLAG_BLOCKING: u32 = 0x8;

impl SftpState {
    /// `SSH_FXP_BLOCK`：对已打开文件句柄加 advisory 锁
    ///
    /// # Errors
    /// 权限不足、句柄无效、锁冲突或不支持的锁类型时返回错误应答
    pub fn block(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        length: u64,
        flags: u32,
    ) -> Result<Status, StatusReply> {
        if !self.check_permission(|p| p.can_write) {
            return Err(status_err(StatusCode::PermissionDenied, "Permission denied"));
        }

        let file_handle = self
            .handles
            .get_mut(&handle)
            .filter(|h| matches!(h, SftpFileHandle::File { .. }));
        let Some(SftpFileHandle::File {
            path,
            locked,
            last_access,
            ..
        }) = file_handle
        else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "LOCK_INVALID_HANDLE",
                handle = %handle,
                "SFTP LOCK: handle not found or invalid type"
            );
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        let lock_type = flags & LOCK_TYPE_MASK;
        let blocking = (flags & LOCK_FLAG_BLOCKING) != 0;

        if blocking {
            return Err(status_err(
                StatusCode::Failure,
                "Blocking locks not supported",
            ));
        }

        *last_access = std::time::Instant::now();

        match lock_type {
            0 | 1 => {
                if *locked {
                    return Err(status_err(StatusCode::Failure, "File already locked"));
                }

                tracing::debug!(
                    "SFTP LOCK: {} lock requested on {path:?} at offset {offset} length {length}",
                    if lock_type == 0 { "read" } else { "write" }
                );

                if self.locked_files.contains(path) {
                    return Err(status_err(StatusCode::Failure, "Lock conflict"));
                }

                *locked = true;
                self.locked_files.insert(path.clone());

                tracing::debug!("SFTP LOCK: advisory lock acquired on {path:?}");
                Ok(status_ok(id))
            }
            2 => {
                // LOCK 类型 2 即解锁（对已锁/未锁文件均幂等成功）
                tracing::debug!(
                    "SFTP LOCK: unlock requested on {path:?} at offset {offset} length {length}"
                );
                *locked = false;
                self.locked_files.remove(path);
                Ok(status_ok(id))
            }
            _ => Err(status_err(StatusCode::Failure, "Invalid lock type")),
        }
    }

    /// `SSH_FXP_UNBLOCK`：释放句柄上的 advisory 锁
    ///
    /// # Errors
    /// 句柄无效时返回错误应答
    pub fn unblock(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        length: u64,
    ) -> Result<Status, StatusReply> {
        let file_handle = self
            .handles
            .get_mut(&handle)
            .filter(|h| matches!(h, SftpFileHandle::File { .. }));
        let Some(SftpFileHandle::File {
            path,
            locked,
            last_access,
            ..
        }) = file_handle
        else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "UNLOCK_INVALID_HANDLE",
                handle = %handle,
                "SFTP UNLOCK: handle not found or invalid type"
            );
            return Err(status_err(StatusCode::Failure, "Invalid handle"));
        };

        *last_access = std::time::Instant::now();

        tracing::debug!(
            "SFTP UNLOCK: releasing lock on {path:?} at offset {offset} length {length}"
        );

        if *locked {
            *locked = false;
            self.locked_files.remove(path);
            tracing::debug!("SFTP UNLOCK: lock released on {path:?}");
        } else {
            tracing::debug!("SFTP UNLOCK: no lock to release on {path:?}");
        }
        Ok(status_ok(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FileAttributes, OpenFlags};
    use crate::test_util::setup;

    /// 打开文件句柄的辅助
    async fn open_file(state: &mut SftpState, id: u32) -> String {
        state
            .open(id, "/f.txt".to_string(), OpenFlags::WRITE | OpenFlags::CREATE, FileAttributes::default())
            .await
            .unwrap()
            .handle
    }

    /// BLOCK → UNBLOCK 回环；锁期间二次 BLOCK 冲突
    #[tokio::test]
    async fn block_unblock_roundtrip() {
        let mut env = setup();
        let handle = open_file(&mut env.state, 1).await;

        env.state
            .block(2, handle.clone(), 0, 100, 1)
            .unwrap();
        assert_eq!(env.state.locked_files.len(), 1);

        // 已锁文件再次加锁 → File already locked（FAILURE）
        let err = env
            .state
            .block(3, handle.clone(), 0, 100, 1)
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        env.state
            .unblock(4, handle.clone(), 0, 100)
            .unwrap();
        assert!(env.state.locked_files.is_empty());

        // 释放后可重新加锁
        env.state
            .block(5, handle.clone(), 0, 100, 0)
            .unwrap();
        env.state
            .unblock(6, handle, 0, 100)
            .unwrap();
    }

    /// BLOCK flags=2（解锁语义）幂等释放
    #[tokio::test]
    async fn block_type_two_unlocks() {
        let mut env = setup();
        let handle = open_file(&mut env.state, 1).await;

        env.state
            .block(2, handle.clone(), 0, 10, 1)
            .unwrap();
        env.state
            .block(3, handle.clone(), 0, 10, 2)
            .unwrap();
        assert!(env.state.locked_files.is_empty());
    }

    /// 阻塞锁（flags & 0x8）不支持
    #[tokio::test]
    async fn blocking_lock_rejected() {
        let mut env = setup();
        let handle = open_file(&mut env.state, 1).await;
        let err = env
            .state
            .block(2, handle, 0, 10, 0x8 | 0x1)
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
        assert!(env.state.locked_files.is_empty());
    }

    /// 无效句柄（不存在 / 目录句柄）拒绝
    #[tokio::test]
    async fn lock_invalid_handles() {
        let mut env = setup();

        let err = env
            .state
            .block(1, "ghost".to_string(), 0, 10, 1)
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        let err = env
            .state
            .unblock(2, "ghost".to_string(), 0, 10)
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);

        let dir_handle = env.state.opendir(3, "/".to_string()).unwrap().handle;
        let err = env
            .state
            .block(4, dir_handle.clone(), 0, 10, 1)
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
        let err = env
            .state
            .unblock(5, dir_handle, 0, 10)
            .unwrap_err();
        assert_eq!(err.status_code, StatusCode::Failure);
    }
}
