use super::{Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_LSTAT`
#[derive(Debug, Serialize, Deserialize)]
pub struct Lstat {
    pub id: u32,
    pub path: String,
}

impl_request_id!(Lstat);
impl_packet_for!(Lstat);
