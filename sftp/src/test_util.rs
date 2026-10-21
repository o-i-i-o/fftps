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

/// 构造长度前缀字符串字段
pub fn str_field(s: &str) -> Vec<u8> {
    let mut v = (s.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}

/// 去掉应答报文的长度前缀
pub fn payload(resp: &[u8]) -> &[u8] {
    &resp[4..]
}

/// 从 `SSH_FXP_STATUS` 应答中提取状态码
pub fn status_of(resp: &[u8]) -> u32 {
    crate::protocol::parse_u32(payload(resp), 5).unwrap()
}
