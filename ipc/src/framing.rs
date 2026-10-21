//! 帧编解码：`u32 BE 长度` + UTF-8 JSON 载荷
//!
//! 与传输无关，任何 `AsyncRead`/`AsyncWrite` 双工流均可承载。

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{Message, MAX_FRAME_SIZE};

/// 读一帧；流正常结束返回 `None`
///
/// # Errors
/// 流中断、长度非法（超过 [`MAX_FRAME_SIZE`]）或 JSON 不合法时返回错误
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Message>> {
    let mut len_buf = [0_u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("读取帧长度失败"),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_SIZE {
        bail!("非法帧长度: {len}（上限 {MAX_FRAME_SIZE}）");
    }

    let mut payload = vec![0_u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .context("读取帧载荷失败（连接中断）")?;

    let msg: Message = serde_json::from_slice(&payload).context("帧载荷不是合法的协议 JSON")?;
    Ok(Some(msg))
}

/// 写一帧并冲刷
///
/// # Errors
/// 序列化失败或写入失败时返回错误
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, msg: &Message) -> Result<()> {
    let payload = serde_json::to_vec(msg).context("协议消息序列化失败")?;
    if payload.len() > MAX_FRAME_SIZE {
        bail!("帧载荷超过上限: {} 字节", payload.len());
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .context("写入帧长度失败")?;
    writer
        .write_all(&payload)
        .await
        .context("写入帧载荷失败")?;
    writer.flush().await.context("冲刷连接失败")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Command, Request};

    #[tokio::test]
    async fn frame_roundtrip_over_memory_stream() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let msg = Message::Request(Request {
            id: 42,
            cmd: Command::GetStatus,
        });
        write_frame(&mut client, &msg).await.unwrap();
        let decoded = read_frame(&mut server).await.unwrap().unwrap();
        match decoded {
            Message::Request(req) => {
                assert_eq!(req.id, 42);
                assert!(matches!(req.cmd, Command::GetStatus));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn eof_returns_none() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_frame(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_length_rejected() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let huge = (MAX_FRAME_SIZE as u32 + 1).to_be_bytes();
        client.write_all(&huge).await.unwrap();
        assert!(read_frame(&mut server).await.is_err());
    }
}
