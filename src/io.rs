use std::{
    marker::Unpin,
    net::{SocketAddr, IpAddr}
};
use tokio::io::{
    AsyncRead,
    AsyncWrite,
    AsyncReadExt,
    AsyncWriteExt,
};
use crate::consts;
use crate::error::{Error, Result};

pub async fn read_at_least<R>(r: &mut R, buffer: &mut [u8], count: usize) -> Option<usize>
where
    R: AsyncRead + Unpin + Send + Sync,
{
    if let Ok(n) = r.read(buffer).await {
        if n < count {
            return None;
        }
        return Some(n);
    }
    None
}

/// Send a Socks5 reply to client. This function calls `.flush()` on writer.
pub async fn send_reply<W>(w: &mut W, reply: Option<Error>, addr: SocketAddr) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + Sync
{
    const HEADER_SIZE: usize = 4;
    let reply_byte: u8 = match reply {
        Some(r) => r.into(),
        None => 0x00,
    };

    let mut header: [u8; HEADER_SIZE] = [consts::SOCKS5, reply_byte, consts::RESERVED, 0x00];

    let ip: &[u8] = match addr.ip() {
        IpAddr::V4(v4) => {
            header[3] = consts::AddrType::V4 as u8;
            &v4.octets()
        },
        IpAddr::V6(v6) => {
            header[3] = consts::AddrType::V6 as u8;
            &v6.octets()
        },
    };

    let addr_size = ip.len();
    let buffer_cap: usize = addr_size + HEADER_SIZE + 2;

    let mut buffer: Vec<u8> = Vec::with_capacity(buffer_cap);
    buffer.extend_from_slice(&header);
    buffer.extend_from_slice(ip);
    buffer.extend_from_slice(&addr.port().to_be_bytes());

    w.write_all(&mut buffer).await?;
    w.flush().await?;
    Ok(())
}
