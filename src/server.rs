use {
    crate::{*, error::*},
    common::{*, command::*, addrtype::*, DestAddr, Request},
};

#[cfg(feature = "io-util")]
use tokio::io::AsyncWrite;

/// Parse client first request version number and provided authentication methods
pub fn parse_client_methods(buffer: &[u8]) -> Result<(u8, Vec<u8>)> {
    check_buffer_length(buffer, 3)?;
    let mut ptr: usize = 0;

    let v = buffer[ptr];
    ptr += 1;

    let methods_count = buffer[ptr] as usize;
    if methods_count == 0 {
        return Err(Error::from(ParserErrorKind::ZeroAuthMethods));
    }
    ptr += 1;

    Ok((v, buffer[ptr..ptr+methods_count].to_vec()))
}

/// Parse main client request after authentication. Containing destination address and port.
pub fn parse_client_request(buffer: &[u8]) -> Result<(u8, Command)> {
    check_buffer_length(buffer, 5)?;

    let mut ptr = 0;
    let v = buffer[ptr];
    ptr += 1;

    let cmd = CommandKind::try_from(buffer[ptr])?;
    // skip reserved byte
    ptr += 2;

    let addr_type: AddrType = buffer[ptr].try_into()?;
    ptr += 1;

    let addr_length: usize;
    const PORT_LENGTH: usize = 2;
    let dest_addr = match addr_type {
        AddrType::V4 => {
            addr_length = 4;
            check_buffer_length(&buffer[ptr..], addr_length + PORT_LENGTH)?;
            let addr: [u8; 4] = buffer[ptr..ptr+addr_length].try_into()?;
            DestAddr::IP(IpAddr::from(addr))
        },
        AddrType::FQDN => {
            addr_length = buffer[ptr] as usize;
            check_buffer_length(&buffer[ptr..], addr_length + PORT_LENGTH)?;
            ptr += 1;
            DestAddr::FQDN(buffer[ptr..ptr+addr_length].to_vec())
        },
        AddrType::V6 => {
            addr_length = 16;
            check_buffer_length(&buffer[ptr..], addr_length + PORT_LENGTH)?;
            let addr: [u8; 16] = buffer[ptr..ptr+addr_length].try_into()?;
            DestAddr::IP(IpAddr::from(addr))
        },
    };
    ptr += addr_length;

    let dest_port = u16::from_be_bytes(buffer[ptr..ptr+PORT_LENGTH].try_into().unwrap());
    let r = Request::new(dest_addr, dest_port);

    let command = match cmd {
        CommandKind::Connect   => Command::Connect(r),
        CommandKind::Bind      => Command::Bind(r),
        CommandKind::Associate => Command::Associate(r),
    };

    Ok((v, command))
}

pub struct Reply;

impl Reply {
    pub fn new(reply: Option<Error>, addr: SocketAddr) -> Vec<u8> {
        const HEADER_SIZE: usize = 4;
        let reply_byte: u8 = match reply {
            Some(r) => r.into(),
            None => 0x00,
        };

        let mut header: [u8; HEADER_SIZE] = [common::SOCKS5, reply_byte, common::RESERVED, 0x00];

        let ip: &[u8] = match addr.ip() {
            IpAddr::V4(v4) => {
                header[3] = common::addrtype::V4;
                &v4.octets()
            },
            IpAddr::V6(v6) => {
                header[3] = common::addrtype::V6;
                &v6.octets()
            },
        };

        let addr_size = ip.len();
        let buffer_cap: usize = addr_size + HEADER_SIZE + 2;

        let mut buffer: Vec<u8> = Vec::with_capacity(buffer_cap);
        buffer.extend_from_slice(&header);
        buffer.extend_from_slice(ip);
        buffer.extend_from_slice(&addr.port().to_be_bytes());

        buffer
    }
}

#[cfg(feature = "io-util")]
async fn send_reply<W>(w: &mut W, reply: Option<Error>, addr: SocketAddr) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + Sync
{
    let reply = socks5rs::Reply::new(reply, addr);
    w.write_all(&reply).await?;
    w.flush().await?;
    Ok(())
}
