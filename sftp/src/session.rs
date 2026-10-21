//! SFTP 子系统会话：实现协议层 [`protocol::Handler`]，路由到各业务模块
//!
//! 报文解码、循环与错误应答封装由 [`crate::protocol::run_with_config`] 完成，
//! 本结构只做参数转发；SYMLINK 的 wire 参数序在 [`Session::symlink`] 中映射。

use std::collections::HashMap;

use crate::protocol::{
    Attrs, Data, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusReply, StatusCode,
    Version,
};
use crate::protocol::Handler as ProtocolHandler;
use crate::state::SftpState;

/// SFTP 会话（每条 SFTP 子系统通道一个实例）
pub struct Session {
    state: SftpState,
}

impl Session {
    /// 由会话状态构建（`handler.rs` 在 subsystem 请求时调用）
    #[must_use]
    pub fn new(state: SftpState) -> Self {
        Self { state }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // 会话结束：关闭句柄并释放锁
        self.state.cleanup();
    }
}

// trait 方法签名统一为 async，无 await 点的实现遵循签名而非裁剪 async
#[allow(clippy::unused_async_trait_impl)]
impl ProtocolHandler for Session {
    type Error = StatusReply;

    /// 全部 v3 命令均已实现，该入口仅为 trait 兜底
    fn unimplemented(&self) -> Self::Error {
        StatusReply::new(StatusCode::OpUnsupported)
    }

    /// INIT：服务端固定应答 v3（客户端按应答自动降级，无需显式拒绝高版本）
    async fn init(
        &mut self,
        version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        tracing::info!(
            client_ip = %self.state.client_ip,
            username = ?self.state.username,
            action = "SFTP_INIT",
            client_version = version,
            server_version = crate::protocol::VERSION,
            "SFTP subsystem initialized"
        );
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.state.open(id, filename, pflags, attrs).await
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.state.close(id, handle).await
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        self.state.read(id, handle, offset, len).await
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        self.state.write(id, handle, offset, data).await
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.state.lstat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        self.state.fstat(id, handle).await
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.state.setstat(id, path, attrs).await
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.state.fsetstat(id, handle, attrs).await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.state.opendir(id, &path)
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        self.state.readdir(id, handle).await
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.state.remove(id, filename).await
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.state.mkdir(id, path, attrs).await
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.state.rmdir(id, path).await
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        self.state.realpath(id, &path)
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.state.stat(id, path).await
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        self.state.rename(id, oldpath, newpath).await
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        self.state.readlink(id, path).await
    }

    /// SYMLINK：OpenSSH 客户端 wire 上按 `(target, linkpath)` 发送（与 draft 相反），
    /// 协议层按 draft 字段名把首串解析进 `linkpath` 参数，此处透传为业务参数序
    /// `(target, link_path)`
    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        self.state.symlink(id, &linkpath, &targetpath)
    }

    async fn block(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        length: u64,
        flags: u32,
    ) -> Result<Status, Self::Error> {
        self.state.block(id, &handle, offset, length, flags)
    }

    async fn unblock(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        length: u64,
    ) -> Result<Status, Self::Error> {
        self.state.unblock(id, &handle, offset, length)
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        self.state.extended(id, request, data).await
    }

    /// 报文循环周期回调：回收超时未访问的句柄（刷新数据并释放锁）
    async fn tick(&mut self) {
        self.state.cleanup_expired_handles().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Config, run_with_config};
    use crate::test_util::{packet, read_packet, str_field, u32_field};
    use tokio::io::{AsyncWriteExt, duplex};

    fn u32_at(buf: &[u8], off: usize) -> u32 {
        u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
    }

    /// 双工流回环：INIT / REALPATH / STAT / OPENDIR / READDIR / CLOSE 全链路
    #[tokio::test]
    async fn sftp_round_trip() {
        let env = crate::test_util::setup();
        std::fs::write(env.dir.path().join("f.txt"), b"data").unwrap();

        let (mut client, server) = duplex(64 * 1024);
        run_with_config(server, Session::new(env.state), Config::default()).await;

        // INIT：服务端应答 VERSION v3
        client.write_all(&packet(1, &u32_field(3))).await.unwrap();
        let version = read_packet(&mut client).await.unwrap();
        assert_eq!(version[0], 2); // SSH_FXP_VERSION
        assert_eq!(u32_at(&version, 1), 3);

        // REALPATH "/"：应答 NAME 单条目，虚路径根
        let mut body = u32_field(1);
        body.extend(str_field("/"));
        client.write_all(&packet(16, &body)).await.unwrap();
        let name = read_packet(&mut client).await.unwrap();
        assert_eq!(name[0], 104); // SSH_FXP_NAME
        assert_eq!(u32_at(&name, 1), 1); // id
        assert_eq!(u32_at(&name, 5), 1); // count
        let fn_len = u32_at(&name, 9) as usize;
        assert_eq!(&name[13..13 + fn_len], b"/");

        // STAT 不存在的文件：应答 STATUS NO_SUCH_FILE
        let mut body = u32_field(2);
        body.extend(str_field("/missing.txt"));
        client.write_all(&packet(17, &body)).await.unwrap();
        let status = read_packet(&mut client).await.unwrap();
        assert_eq!(status[0], 101); // SSH_FXP_STATUS
        assert_eq!(u32_at(&status, 5), 2); // SSH_FX_NO_SUCH_FILE

        // OPENDIR "/" → HANDLE
        let mut body = u32_field(3);
        body.extend(str_field("/"));
        client.write_all(&packet(11, &body)).await.unwrap();
        let handle = read_packet(&mut client).await.unwrap();
        assert_eq!(handle[0], 102); // SSH_FXP_HANDLE
        let handle_len = u32_at(&handle, 5) as usize;
        let handle_str = String::from_utf8(handle[9..9 + handle_len].to_vec()).unwrap();

        // READDIR：枚举出 f.txt
        let mut body = u32_field(4);
        body.extend(str_field(&handle_str));
        client.write_all(&packet(12, &body)).await.unwrap();
        let name = read_packet(&mut client).await.unwrap();
        assert_eq!(name[0], 104); // SSH_FXP_NAME
        assert_eq!(u32_at(&name, 5), 1); // count
        let fn_len = u32_at(&name, 9) as usize;
        assert_eq!(&name[13..13 + fn_len], b"f.txt");

        // CLOSE 目录句柄 → STATUS OK
        let mut body = u32_field(5);
        body.extend(str_field(&handle_str));
        client.write_all(&packet(4, &body)).await.unwrap();
        let status = read_packet(&mut client).await.unwrap();
        assert_eq!(status[0], 101);
        assert_eq!(u32_at(&status, 5), 0); // SSH_FX_OK

        // 关闭客户端流，报文循环退出
        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    /// 无效报文类型回 `STATUS` `BAD_MESSAGE`（协议层兜底路径）
    #[tokio::test]
    async fn unknown_packet_type_rejected() {
        let env = crate::test_util::setup();
        let (mut client, server) = duplex(64 * 1024);
        run_with_config(server, Session::new(env.state), Config::default()).await;

        // 类型 99 未定义 → 应答 STATUS BAD_MESSAGE
        client.write_all(&packet(99, &u32_field(1))).await.unwrap();
        let status = read_packet(&mut client).await.unwrap();
        assert_eq!(status[0], 101); // SSH_FXP_STATUS
        assert_eq!(u32_at(&status, 5), 5); // SSH_FX_BAD_MESSAGE

        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
