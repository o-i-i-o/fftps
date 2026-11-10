use super::{FileAttributes, Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_SETSTAT` and `MKDIR`
#[derive(Debug, Serialize, Deserialize)]
pub struct SetStat {
    pub id: u32,
    pub path: String,
    pub attrs: FileAttributes,
}

impl_request_id!(SetStat);
impl_packet_for!(SetStat);
