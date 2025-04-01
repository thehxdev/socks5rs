// TODO: Write tests!

use std::net::IpAddr;

pub mod consts;
pub mod io;
pub mod error;

use error::{Error, Result, ParserErrorKind};

/// Destination address in a socks5 request
#[derive(Debug)]
pub enum DestAddr {
    /// IP address
    IP(IpAddr),
    /// Fully Qualified Domain Name (requires DNS resolution)
    FQDN(Vec<u8>),
}

#[derive(Debug)]
pub struct Request {
    pub dest_addr: DestAddr,
    pub dest_port: u16,
}

#[derive(Debug)]
pub enum Command {
    Connect(Request),
    Bind(Request),
    Associate(Request),
}

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

    // return only owned types to avoid any lifetime problems
    // in user side.
    Ok((v, buffer[ptr..ptr+methods_count].to_vec()))
}

pub fn parse_client_request(buffer: &[u8]) -> Result<(u8, Command)> {
    check_buffer_length(buffer, 5)?;

    let mut ptr = 0;
    let v = buffer[ptr];
    ptr += 1;

    let cmd = consts::Command::try_from(buffer[ptr])?;
    // skip reserved byte
    ptr += 2;

    let addr_type: consts::AddrType = buffer[ptr].try_into()?;
    ptr += 1;

    let addr_length: usize;
    const PORT_LENGTH: usize = 2;
    let dest_addr = match addr_type {
        consts::AddrType::V4 => {
            addr_length = 4;
            check_buffer_length(&buffer[ptr..], addr_length + PORT_LENGTH)?;
            let addr: [u8; 4] = buffer[ptr..ptr+addr_length].try_into().unwrap();
            DestAddr::IP(IpAddr::from(addr))
        },
        consts::AddrType::FQDN => {
            addr_length = buffer[ptr] as usize;
            check_buffer_length(&buffer[ptr..], addr_length + PORT_LENGTH)?;
            ptr += 1;
            DestAddr::FQDN(buffer[ptr..ptr+addr_length].to_vec())
        },
        consts::AddrType::V6 => {
            addr_length = 16;
            check_buffer_length(&buffer[ptr..], addr_length + PORT_LENGTH)?;
            let addr: [u8; 16] = buffer[ptr..ptr+addr_length].try_into().unwrap();
            DestAddr::IP(IpAddr::from(addr))
        },
    };
    ptr += addr_length;

    let dest_port = u16::from_be_bytes(buffer[ptr..ptr+PORT_LENGTH].try_into().unwrap());
    let r = Request{
        dest_addr,
        dest_port,
    };

    let command = match cmd {
        consts::Command::Connect   => Command::Connect(r),
        consts::Command::Bind      => Command::Bind(r),
        consts::Command::Associate => Command::Associate(r),
    };

    Ok((v, command))
}

pub const fn check_buffer_length(buffer: &[u8], min_length: usize) -> Result<()> {
    if buffer.len() < min_length {
        return Err(Error::SHORT_BUFFER_ERROR);
    }
    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_server() {
//         let mut server = Server::new();
//         server.listen_and_serve("[::1]:1080");
//     }
// }
