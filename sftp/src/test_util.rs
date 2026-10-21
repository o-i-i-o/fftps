//! 单元测试公共夹具（仅 `cfg(test)` 编译）

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use fftp_common::quota::QuotaManager;
use fftp_common::users::{Permissions, UserManager};

use crate::state::SftpState;

/// 测试环境：临时 home 目录 + 已注册用户 `tester` 的会话状态
pub struct TestEnv {
    pub dir: tempfile::TempDir,
    pub state: SftpState,
}

/// 构造测试环境（`tester` 拥有 [`Permissions::full`]）
pub fn setup() -> TestEnv {
    setup_with_perms(|_| {})
}

/// 构造测试环境并允许调整 `tester` 的权限（用于权限拒绝类用例）
pub fn setup_with_perms(f: impl FnOnce(&mut Permissions)) -> TestEnv {
    let dir = tempfile::tempdir().unwrap();
    let mut perms = Permissions::full();
    f(&mut perms);
    let mut users = UserManager::new();
    users
        .add_user(
            "tester".to_string(),
            "pw",
            dir.path().to_string_lossy().to_string(),
            perms,
            false,
        )
        .unwrap();
    let state = SftpState::new(
        dir.path().to_string_lossy().to_string(),
        Some("tester".to_string()),
        Arc::new(StdMutex::new(users)),
        Arc::new(QuotaManager::new(&std::env::temp_dir())),
        None,
        "127.0.0.1".to_string(),
        false,
    );
    TestEnv { dir, state }
}

/// 构造长度前缀字符串字段（wire 格式，回环测试用）
pub fn str_field(s: &str) -> Vec<u8> {
    let mut v = (s.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}

/// 组装完整 SFTP 报文：u32 长度前缀 + 类型 + 负载
pub fn packet(r#type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    v.push(r#type);
    v.extend_from_slice(body);
    v
}

/// u32 字段（wire 格式）
pub fn u32_field(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// u64 字段（wire 格式）
pub fn u64_field(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// 从应答流中读取一个完整报文（长度前缀 + 负载），返回去掉长度前缀的负载
pub async fn read_packet<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}
