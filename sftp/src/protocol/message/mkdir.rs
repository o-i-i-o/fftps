use super::{FileAttributes, Packet, RequestId, impl_packet_for, impl_request_id};

/// Implementation for `SSH_FXP_MKDIR`
#[derive(Debug, Serialize, Deserialize)]
pub struct MkDir {
    pub id: u32,
    pub path: String,
    pub attrs: FileAttributes,
}

impl_request_id!(MkDir);
impl_packet_for!(MkDir);
