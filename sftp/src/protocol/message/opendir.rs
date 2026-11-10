use super::{Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_OPENDIR`
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenDir {
    pub id: u32,
    pub path: String,
}

impl_request_id!(OpenDir);
impl_packet_for!(OpenDir);
