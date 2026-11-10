use super::{Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_REMOVE`
#[derive(Debug, Serialize, Deserialize)]
pub struct Remove {
    pub id: u32,
    pub filename: String,
}

impl_request_id!(Remove);
impl_packet_for!(Remove);
