use super::{Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_REALPATH`
#[derive(Debug, Serialize, Deserialize)]
pub struct RealPath {
    pub id: u32,
    pub path: String,
}

impl_request_id!(RealPath);
impl_packet_for!(RealPath);
