//! SFTP 文件区间锁定命令：LOCK / UNBLOCK（SFTP v5+，draft 中的 BLOCK/UNBLOCK）
//!
//! advisory 锁语义（与旧版一致）：会话级标记 + 全局 `locked_files` 集合防重入，
//! 阻塞锁不支持。旧代码 LOCK/UNLOCK 从未被 `cmd_dispatch` 路由（死代码），
//! 本迁移在 [`crate::cmd_dispatch`] 中按报文码 22/23 正确路由。

use anyhow::Result;

use crate::protocol::{build_status_packet, parse_string_with_len, parse_u32, parse_u64};
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

/// LOCK 请求 flags：低 3 位为锁类型（0 读 / 1 写 / 2 解锁），0x8 为阻塞
const LOCK_TYPE_MASK: u32 = 0x7;
const LOCK_FLAG_BLOCKING: u32 = 0x8;

impl SftpState {
    /// `SSH_FXP_BLOCK`（LOCK）：对已打开文件句柄加 advisory 锁
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub fn handle_lock(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (handle_str, handle_len) = parse_string_with_len(data, 5)?;

        let offset_pos = 5 + 4 + handle_len;
        let offset = parse_u64(data, offset_pos)?;
        let length_pos = offset_pos + 8;
        let length = parse_u64(data, length_pos)?;
        let flags_pos = length_pos + 8;
        let flags = parse_u32(data, flags_pos)?;

        if !self.check_permission(|p| p.can_write) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let handle = self.handles.get_mut(&handle_str);
        match handle {
            Some(SftpFileHandle::File {
                path,
                locked,
                last_access,
                ..
            }) => {
                let lock_type = flags & LOCK_TYPE_MASK;
                let blocking = (flags & LOCK_FLAG_BLOCKING) != 0;

                if blocking {
                    return Ok(build_status_packet(
                        id,
                        SSH_FX_FAILURE,
                        "Blocking locks not supported",
                        "",
                    ));
                }

                *last_access = std::time::Instant::now();

                match lock_type {
                    0 | 1 => {
                        if *locked {
                            return Ok(build_status_packet(
                                id,
                                SSH_FX_FAILURE,
                                "File already locked",
                                "",
                            ));
                        }

                        tracing::debug!(
                            "SFTP LOCK: {} lock requested on {:?} at offset {offset} length {length}",
                            if lock_type == 0 { "read" } else { "write" },
                            path
                        );

                        if self.locked_files.contains(path) {
                            return Ok(build_status_packet(id, SSH_FX_FAILURE, "Lock conflict", ""));
                        }

                        *locked = true;
                        self.locked_files.insert(path.clone());

                        tracing::debug!("SFTP LOCK: advisory lock acquired on {:?}", path);
                        Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
                    }
                    2 => {
                        // LOCK 类型 2 即解锁（对已锁/未锁文件均幂等成功）
                        tracing::debug!(
                            "SFTP LOCK: unlock requested on {:?} at offset {offset} length {length}",
                            path
                        );
                        *locked = false;
                        self.locked_files.remove(path);
                        Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
                    }
                    _ => Ok(build_status_packet(
                        id,
                        SSH_FX_FAILURE,
                        "Invalid lock type",
                        "",
                    )),
                }
            }
            Some(SftpFileHandle::Dir { .. }) => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "LOCK_INVALID_TYPE",
                    handle = %handle_str,
                    "SFTP LOCK on directory handle (expected file)"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle type", ""))
            }
            None => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "LOCK_INVALID_HANDLE",
                    handle = %handle_str,
                    "SFTP LOCK: handle not found"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""))
            }
        }
    }

    /// `SSH_FXP_UNBLOCK`（UNLOCK）：释放句柄上的 advisory 锁
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub fn handle_unlock(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (handle_str, handle_len) = parse_string_with_len(data, 5)?;

        let offset_pos = 5 + 4 + handle_len;
        let offset = parse_u64(data, offset_pos)?;
        let length_pos = offset_pos + 8;
        let length = parse_u64(data, length_pos)?;

        let handle = self.handles.get_mut(&handle_str);
        match handle {
            Some(SftpFileHandle::File {
                path,
                locked,
                last_access,
                ..
            }) => {
                *last_access = std::time::Instant::now();

                tracing::debug!(
                    "SFTP UNLOCK: releasing lock on {:?} at offset {offset} length {length}",
                    path
                );

                if *locked {
                    *locked = false;
                    self.locked_files.remove(path);
                    tracing::debug!("SFTP UNLOCK: lock released on {:?}", path);
                } else {
                    tracing::debug!("SFTP UNLOCK: no lock to release on {:?}", path);
                }
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Some(SftpFileHandle::Dir { .. }) => {
                tracing::warn!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "UNLOCK_INVALID_TYPE",
                    handle = %handle_str,
                    "SFTP UNLOCK on directory handle (expected file)"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle type", ""))
            }
            None => {
                tracing::debug!(
                    client_ip = %self.client_ip,
                    username = ?self.username,
                    action = "UNLOCK_INVALID_HANDLE",
                    handle = %handle_str,
                    "SFTP UNLOCK: handle not found"
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::parse_string;
    use crate::test_util::{self, setup};

    async fn open_file(env: &mut crate::test_util::TestEnv, name: &str) -> String {
        let mut req = vec![SSH_FXP_OPEN];
        req.extend_from_slice(&1u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field(name));
        req.extend_from_slice(&(SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_CREAT).to_be_bytes());
        req.extend_from_slice(&0u32.to_be_bytes());
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        parse_string(test_util::payload(&resp), 5).unwrap()
    }

    fn lock_req(id: u32, handle: &str, flags: u32) -> Vec<u8> {
        let mut v = vec![SSH_FXP_BLOCK];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(handle));
        v.extend_from_slice(&0u64.to_be_bytes()); // offset
        v.extend_from_slice(&0u64.to_be_bytes()); // length
        v.extend_from_slice(&flags.to_be_bytes());
        v
    }

    fn unlock_req(id: u32, handle: &str) -> Vec<u8> {
        let mut v = vec![SSH_FXP_UNBLOCK];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(handle));
        v.extend_from_slice(&0u64.to_be_bytes());
        v.extend_from_slice(&0u64.to_be_bytes());
        v
    }

    #[tokio::test]
    async fn test_lock_unlock_roundtrip() {
        let mut env = setup();
        let handle = open_file(&mut env, "l.txt").await;

        // 写锁（类型 1）
        let resp = env
            .state
            .dispatch_packet(&lock_req(2, &handle, 1))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);

        // 重复加锁 → 冲突
        let resp = env
            .state
            .dispatch_packet(&lock_req(3, &handle, 1))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);

        // 解锁
        let resp = env
            .state
            .dispatch_packet(&unlock_req(4, &handle))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);

        // 解锁后可再次加锁
        let resp = env
            .state
            .dispatch_packet(&lock_req(5, &handle, 1))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
    }

    #[tokio::test]
    async fn test_lock_type_unlock_via_block() {
        let mut env = setup();
        let handle = open_file(&mut env, "l2.txt").await;
        env.state
            .dispatch_packet(&lock_req(1, &handle, 1))
            .await
            .unwrap();
        // LOCK 类型 2 = 解锁
        let resp = env
            .state
            .dispatch_packet(&lock_req(2, &handle, 2))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
    }

    #[tokio::test]
    async fn test_lock_blocking_rejected() {
        let mut env = setup();
        let handle = open_file(&mut env, "l3.txt").await;
        // 0x8 = 阻塞锁，不支持
        let resp = env
            .state
            .dispatch_packet(&lock_req(1, &handle, 1 | 0x8))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }

    #[tokio::test]
    async fn test_lock_invalid_handle() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&lock_req(1, "ghost", 1))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }

    #[tokio::test]
    async fn test_lock_on_dir_handle_rejected() {
        let mut env = setup();
        std::fs::create_dir(env.dir.path().join("d")).unwrap();
        let mut req = vec![SSH_FXP_OPENDIR];
        req.extend_from_slice(&1u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field("/d"));
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        let handle = parse_string(test_util::payload(&resp), 5).unwrap();

        let resp = env
            .state
            .dispatch_packet(&lock_req(2, &handle, 1))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_FAILURE);
    }
}
