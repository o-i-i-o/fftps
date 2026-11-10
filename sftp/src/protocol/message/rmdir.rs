use super::{Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_RMDIR`
#[derive(Debug, Serialize, Deserialize)]
pub struct RmDir {
    pub id: u32,
    pub path: String,
}

impl_request_id!(RmDir);
impl_packet_for!(RmDir);
