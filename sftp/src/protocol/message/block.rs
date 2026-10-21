use super::{impl_packet_for, impl_request_id, Packet, RequestId};

/// Implementation for `SSH_FXP_BLOCK`（LOCK，draft-ietf-secsh-filexfer §6.6）
///
/// `flags` 低 3 位为锁类型（0 读 / 1 写 / 2 解锁），0x8 为阻塞标志。
#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    pub id: u32,
    pub handle: String,
    pub offset: u64,
    pub length: u64,
    pub flags: u32,
}

impl_request_id!(Block);
impl_packet_for!(Block);

/// Implementation for `SSH_FXP_UNBLOCK`（UNLOCK）
#[derive(Debug, Serialize, Deserialize)]
pub struct Unblock {
    pub id: u32,
    pub handle: String,
    pub offset: u64,
    pub length: u64,
}

impl_request_id!(Unblock);
impl_packet_for!(Unblock);
