//! SFTP 目录操作命令：OPENDIR / READDIR / REMOVE / MKDIR / RMDIR / RENAME / REALPATH

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::path_resolve::{path_starts_with_ignore_case, to_ftp_path};
use crate::protocol::{build_attrs, build_packet, build_status_packet, parse_string, parse_string_with_len, parse_u32};
use crate::state::SftpState;
// types 是本 crate 的协议常量/句柄类型聚合模块（等价内部预导入），逐项列举反而降低可读性
#[allow(clippy::wildcard_imports)]
use crate::types::*;

impl SftpState {
    /// `SSH_FXP_OPENDIR`：打开目录句柄
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub fn handle_opendir(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        if !self.check_permission(|p| p.can_list) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        if self.handles.len() >= MAX_HANDLES {
            tracing::warn!(
                "SFTP OPENDIR denied: too many open handles ({})",
                self.handles.len()
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Too many open handles",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        if !full_path.exists() {
            return Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, "No such directory", ""));
        }

        if !full_path.is_dir() {
            return Ok(build_status_packet(id, SSH_FX_FAILURE, "Not a directory", ""));
        }

        let handle = self.generate_handle();
        self.handles.insert(
            handle.clone(),
            SftpFileHandle::Dir {
                path: full_path,
                entries: Vec::new(),
                index: 0,
                last_access: std::time::Instant::now(),
            },
        );

        Ok(crate::protocol::build_handle_packet(id, &handle))
    }

    /// `SSH_FXP_READDIR`：分批枚举目录（每批 [`MAX_READDIR_ENTRIES`] 条）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn handle_readdir(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let handle_str = parse_string(data, 5)?;

        let entries_result = {
            let handle = self.handles.get_mut(&handle_str);
            match handle {
                Some(SftpFileHandle::Dir {
                    path,
                    entries,
                    index,
                    last_access,
                }) => {
                    if entries.is_empty() && *index == 0 {
                        let mut read_entries = Vec::new();
                        match tokio::fs::read_dir(path).await {
                            Ok(mut dir) => {
                                while let Ok(Some(entry)) = dir.next_entry().await {
                                    let name = entry.file_name().to_string_lossy().to_string();
                                    let is_dir = entry
                                        .file_type()
                                        .await
                                        .is_ok_and(|t| t.is_dir());
                                    let (size, mtime) = entry.metadata().await.map_or((0, 0), |m| {
                                        let mt = m
                                            .modified()
                                            .ok()
                                            .and_then(|t| {
                                                t.duration_since(std::time::UNIX_EPOCH).ok()
                                            })
                                            .and_then(|d| u32::try_from(d.as_secs()).ok())
                                            .unwrap_or(0);
                                        (m.len(), mt)
                                    });
                                    read_entries.push(DirEntry {
                                        name,
                                        is_dir,
                                        size,
                                        mtime,
                                    });
                                }
                            }
                            Err(e) => {
                                return Ok(build_status_packet(
                                    id,
                                    SSH_FX_FAILURE,
                                    &format!("Failed to read directory: {e}"),
                                    "",
                                ));
                            }
                        }
                        *entries = read_entries;
                    }

                    if *index >= entries.len() {
                        return Ok(build_status_packet(id, SSH_FX_EOF, "End of directory", ""));
                    }

                    let count = (entries.len() - *index).min(MAX_READDIR_ENTRIES);
                    let result_entries: Vec<DirEntry> = entries[*index..*index + count].to_vec();
                    *index += count;
                    *last_access = std::time::Instant::now();
                    Some(result_entries)
                }
                _ => None,
            }
        };

        if let Some(dir_entries) = entries_result {
            let mut payload = vec![SSH_FXP_NAME];
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&(dir_entries.len() as u32).to_be_bytes());

            for entry in &dir_entries {
                payload.extend_from_slice(&(entry.name.len() as u32).to_be_bytes());
                payload.extend_from_slice(entry.name.as_bytes());

                let mtime_str = chrono::DateTime::from_timestamp(
                    i64::from(entry.mtime),
                    0,
                )
                .map_or_else(
                    || "Jan 01 00:00".to_string(),
                    |dt| dt.format("%b %d %H:%M").to_string(),
                );

                let long_name = format!(
                    "{} 1 user user {:>10} {} {}",
                    if entry.is_dir {
                        "drwxr-xr-x"
                    } else {
                        "-rw-r--r--"
                    },
                    entry.size,
                    mtime_str,
                    entry.name
                );
                payload.extend_from_slice(&(long_name.len() as u32).to_be_bytes());
                payload.extend_from_slice(long_name.as_bytes());

                payload.extend_from_slice(&build_attrs(entry.is_dir, entry.size));
            }

            Ok(build_packet(&payload))
        } else {
            tracing::debug!(
                client_ip = %self.client_ip,
                username = ?self.username,
                action = "READDIR_INVALID_HANDLE",
                handle = %handle_str,
                "SFTP READDIR: handle not found or invalid type"
            );
            Ok(build_status_packet(id, SSH_FX_FAILURE, "Invalid handle", ""))
        }
    }

    /// `SSH_FXP_REMOVE`：删除文件（结算配额 + 审计）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_remove(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        if !self.check_permission(|p| p.can_delete) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        let file_size = tokio::fs::metadata(&full_path)
            .await
            .map_or(0, |m| m.len());

        if tokio::fs::remove_file(&full_path).await.is_ok() {
            if file_size > 0
                && let Some(username) = &self.username
            {
                self.quota_manager.subtract_usage(username, file_size);
            }
            self.audit_file_op("DELETE", &full_path.to_string_lossy(), 0);
            Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
        } else {
            Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Failed to remove file",
                "",
            ))
        }
    }

    /// `SSH_FXP_MKDIR`：创建目录
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_mkdir(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        if !self.check_permission(|p| p.can_mkdir) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        if full_path.exists() {
            return Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Directory already exists",
                "",
            ));
        }

        match tokio::fs::create_dir(&full_path).await {
            Ok(()) => {
                self.audit_file_op("MKDIR", &full_path.to_string_lossy(), 0);
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, "Parent directory not found", ""))
            }
            Err(_) => Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Failed to create directory",
                "",
            )),
        }
    }

    /// `SSH_FXP_RMDIR`：删除空目录（回收目录占用配额 + 审计）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub async fn handle_rmdir(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        if !self.check_permission(|p| p.can_rmdir) {
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let full_path = match self.resolve_path_checked(id, &path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        let dir_size = calculate_dir_size(&full_path).await;

        match tokio::fs::remove_dir(&full_path).await {
            Ok(()) => {
                if dir_size > 0
                    && let Some(username) = &self.username
                {
                    self.quota_manager.subtract_usage(username, dir_size);
                }
                self.audit_file_op("RMDIR", &full_path.to_string_lossy(), 0);
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Directory not empty",
                "",
            )),
            Err(_) => Ok(build_status_packet(
                id,
                SSH_FX_FAILURE,
                "Failed to remove directory",
                "",
            )),
        }
    }

    /// `SSH_FXP_RENAME`：重命名/移动（目标存在则拒绝，双路径审计）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    // 命令主流程（权限 → 路径解析 → fs 操作 → 审计）保持单函数内联，拆分会割裂协议语义
    #[allow(clippy::too_many_lines)]
    pub async fn handle_rename(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let (old_path, old_len) = parse_string_with_len(data, 5)?;
        let new_path = parse_string(data, 5 + 4 + old_len)?;

        if !self.check_permission(|p| p.can_rename) {
            tracing::warn!(
                "SFTP RENAME denied: no permission for user {:?}",
                self.username
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        let old_full = match self.resolve_path_checked(id, &old_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let new_full = match self.resolve_path_checked(id, &new_path) {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };

        tracing::debug!(
            "SFTP RENAME: raw_old='{}', resolved_old='{}', raw_new='{}', resolved_new='{}'",
            old_path,
            old_full.display(),
            new_path,
            new_full.display()
        );

        if !old_full.exists() {
            tracing::warn!(
                "SFTP RENAME failed: source does not exist - {}",
                old_full.display()
            );
            return Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, "No such file", ""));
        }

        if old_full == new_full {
            return Ok(build_status_packet(id, SSH_FX_OK, "OK", ""));
        }

        let home = PathBuf::from(&self.home_dir);
        if !path_starts_with_ignore_case(&old_full, &home)
            || !path_starts_with_ignore_case(&new_full, &home)
        {
            tracing::warn!(
                "SFTP RENAME denied: path outside home - old={}, new={}",
                old_full.display(),
                new_full.display()
            );
            return Ok(build_status_packet(
                id,
                SSH_FX_PERMISSION_DENIED,
                "Permission denied",
                "",
            ));
        }

        if let Err(resp) = self.check_symlink_in_home(id, &old_full).await {
            return Ok(resp);
        }

        if new_full.exists()
            && let Err(resp) = self.check_symlink_in_home(id, &new_full).await
        {
            return Ok(resp);
        }

        if new_full.exists() {
            return Ok(build_status_packet(id, SSH_FX_FAILURE, "File already exists", ""));
        }

        match tokio::fs::rename(&old_full, &new_full).await {
            Ok(()) => {
                let old_parent = old_full
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let new_parent = new_full
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let operation = if old_parent == new_parent {
                    "RENAME"
                } else {
                    "MOVE"
                };
                self.audit_file_op_pair(
                    operation,
                    &old_full.to_string_lossy(),
                    &new_full.to_string_lossy(),
                    0,
                    "",
                );
                Ok(build_status_packet(id, SSH_FX_OK, "OK", ""))
            }
            Err(e) => {
                tracing::error!(
                    "SFTP Rename failed: {} -> {}: {} (os error {:?})",
                    old_full.display(),
                    new_full.display(),
                    e,
                    e.raw_os_error()
                );
                Ok(build_status_packet(id, SSH_FX_FAILURE, "Failed to rename", ""))
            }
        }
    }

    /// `SSH_FXP_REALPATH`：路径规范化（映射回 `/` 起的虚路径）
    ///
    /// # Errors
    /// 报文解析失败时返回错误
    pub fn handle_realpath(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let id = parse_u32(data, 1)?;
        let path = parse_string(data, 5)?;

        let full_path = if path.is_empty() || path == "." {
            Ok(PathBuf::from(&self.cwd))
        } else {
            self.resolve_path(&path)
        };

        let full_path = match full_path {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("REALPATH failed for '{path}': {e}");
                return Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, &e.to_string(), ""));
            }
        };

        let (resolved, is_dir) = if full_path.exists() {
            match full_path.canonicalize() {
                Ok(canon) => {
                    if !path_starts_with_ignore_case(&canon, Path::new(&self.home_dir)) {
                        tracing::warn!(
                            "REALPATH security: canonicalized path escapes home - input: {}, \
                             canonicalized: {}",
                            path,
                            canon.display()
                        );
                        return Ok(build_status_packet(
                            id,
                            SSH_FX_PERMISSION_DENIED,
                            "Permission denied",
                            "",
                        ));
                    }
                    let is_dir = canon.is_dir();
                    (canon, is_dir)
                }
                Err(_) => (full_path.clone(), full_path.is_dir()),
            }
        } else {
            (full_path, false)
        };

        let path_str = match to_ftp_path(&resolved, Path::new(&self.home_dir)) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("REALPATH failed: {e}");
                return Ok(build_status_packet(id, SSH_FX_NO_SUCH_FILE, &e.to_string(), ""));
            }
        };

        let mut payload = vec![SSH_FXP_NAME];
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());

        payload.extend_from_slice(&(path_str.len() as u32).to_be_bytes());
        payload.extend_from_slice(path_str.as_bytes());

        let longname = format!(
            "{}  1 user user  0 Jan 01 00:00 {}",
            if is_dir {
                "drwxr-xr-x"
            } else {
                "-rw-r--r--"
            },
            path_str
        );
        payload.extend_from_slice(&(longname.len() as u32).to_be_bytes());
        payload.extend_from_slice(longname.as_bytes());

        payload.extend_from_slice(&build_attrs(is_dir, 0));

        tracing::debug!(
            client_ip = %self.client_ip,
            username = ?self.username.as_deref(),
            action = "REALPATH",
            protocol = "SFTP",
            "Resolved '{}' -> '{}'",
            path,
            path_str
        );

        Ok(build_packet(&payload))
    }
}

/// 递归统计目录字节数（删除目录时回收配额用）
fn calculate_dir_size(
    path: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = u64> + Send + '_>> {
    Box::pin(async move {
        let mut total_size: u64 = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    if metadata.is_file() {
                        total_size += metadata.len();
                    } else if metadata.is_dir() {
                        total_size += calculate_dir_size(&entry.path()).await;
                    }
                }
            }
        }
        total_size
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{self, setup, setup_with_perms};

    fn path_req(cmd: u8, id: u32, path: &str) -> Vec<u8> {
        let mut v = vec![cmd];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&test_util::str_field(path));
        v
    }

    fn name_contains(resp: &[u8], needle: &str) -> bool {
        let payload = test_util::payload(resp);
        payload[0] == SSH_FXP_NAME
            && payload
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
    }

    #[tokio::test]
    async fn test_mkdir_opendir_readdir_rmdir() {
        let mut env = setup();

        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_MKDIR, 1, "/docs"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert!(env.dir.path().join("docs").is_dir());

        // 空目录 READDIR 直接 EOF
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_OPENDIR, 2, "/docs"))
            .await
            .unwrap();
        assert_eq!(test_util::payload(&resp)[0], SSH_FXP_HANDLE);
        let handle = parse_string(test_util::payload(&resp), 5).unwrap();

        let mut req = vec![SSH_FXP_READDIR];
        req.extend_from_slice(&3u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field(&handle));
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_EOF);

        // 放入文件后 READDIR 能列出
        std::fs::write(env.dir.path().join("docs").join("a.txt"), b"x").unwrap();
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_OPENDIR, 4, "/docs"))
            .await
            .unwrap();
        let handle = parse_string(test_util::payload(&resp), 5).unwrap();
        let mut req = vec![SSH_FXP_READDIR];
        req.extend_from_slice(&5u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field(&handle));
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        assert!(name_contains(&resp, "a.txt"));

        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_RMDIR, 6, "/docs"))
            .await
            .unwrap();
        // 非空目录 rmdir 拒绝
        assert_ne!(test_util::status_of(&resp), SSH_FX_OK);

        std::fs::remove_file(env.dir.path().join("docs").join("a.txt")).unwrap();
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_RMDIR, 7, "/docs"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert!(!env.dir.path().join("docs").exists());
    }

    #[tokio::test]
    async fn test_remove_file() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("d.txt"), b"bye").unwrap();
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_REMOVE, 1, "/d.txt"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert!(!env.dir.path().join("d.txt").exists());
    }

    #[tokio::test]
    async fn test_remove_denied_without_delete_permission() {
        let mut env = setup_with_perms(|p| p.can_delete = false);
        std::fs::write(env.dir.path().join("d.txt"), b"x").unwrap();
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_REMOVE, 1, "/d.txt"))
            .await
            .unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_PERMISSION_DENIED);
        assert!(env.dir.path().join("d.txt").exists());
    }

    #[tokio::test]
    async fn test_rename_moves_file() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("old.txt"), b"data").unwrap();

        let mut req = vec![SSH_FXP_RENAME];
        req.extend_from_slice(&1u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field("/old.txt"));
        req.extend_from_slice(&test_util::str_field("/new.txt"));
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        assert_eq!(test_util::status_of(&resp), SSH_FX_OK);
        assert!(!env.dir.path().join("old.txt").exists());
        assert_eq!(
            std::fs::read(env.dir.path().join("new.txt")).unwrap(),
            b"data"
        );
    }

    #[tokio::test]
    async fn test_rename_target_exists_rejected() {
        let mut env = setup();
        std::fs::write(env.dir.path().join("a.txt"), b"1").unwrap();
        std::fs::write(env.dir.path().join("b.txt"), b"2").unwrap();

        let mut req = vec![SSH_FXP_RENAME];
        req.extend_from_slice(&1u32.to_be_bytes());
        req.extend_from_slice(&test_util::str_field("/a.txt"));
        req.extend_from_slice(&test_util::str_field("/b.txt"));
        let resp = env.state.dispatch_packet(&req).await.unwrap();
        assert_ne!(test_util::status_of(&resp), SSH_FX_OK);
    }

    #[tokio::test]
    async fn test_realpath_maps_to_virtual_path() {
        let mut env = setup();
        std::fs::create_dir(env.dir.path().join("sub")).unwrap();

        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_REALPATH, 1, "/"))
            .await
            .unwrap();
        assert!(name_contains(&resp, "/"));

        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_REALPATH, 2, "/sub"))
            .await
            .unwrap();
        assert!(name_contains(&resp, "/sub"));
    }

    #[tokio::test]
    async fn test_realpath_rejects_escape() {
        let mut env = setup();
        let resp = env
            .state
            .dispatch_packet(&path_req(SSH_FXP_REALPATH, 1, "/../outside"))
            .await
            .unwrap();
        assert_eq!(test_util::payload(&resp)[0], SSH_FXP_STATUS);
    }
}
