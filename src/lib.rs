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

#[cfg(test)]
mod tests {
    use super::*;
    use consts::*;
    use error::Result;
    use super::{Command, DestAddr};
    use std::net::IpAddr;

    #[test]
    fn test_parse_client_methods() -> Result<()> {
        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00];
        parse_client_methods(buffer)?;

        let buffer: &[u8] = &[SOCKS5, 0x02, 0x00, 0x01];
        parse_client_methods(buffer)?;

        let buffer: &[u8] = &[SOCKS5, 0x00, 0x01];
        assert!(parse_client_methods(buffer).is_err());

        let buffer: &[u8] = &[SOCKS5, 0x01];
        assert!(parse_client_methods(buffer).is_err());

        Ok(())
    }

    #[test]
    fn test_parse_client_request() -> Result<()> {
        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00, addr_type::V4, 127, 0, 0, 1, 0x01, 0xbb];
        let (v, cmd) = parse_client_request(buffer)?;
        assert_eq!(SOCKS5, v);
        let r = match cmd {
            Command::Connect(r) => r,
            Command::Bind(r) => r,
            Command::Associate(r) => r,
        };
        match r.dest_addr {
            DestAddr::IP(addr) => assert_eq!(addr, IpAddr::from([127, 0, 0, 1])),
            _ => (),
        };

        assert_eq!(r.dest_port, 443_u16);


        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00, addr_type::FQDN, 0x05, b'x', b'.', b'c', b'o', b'm', 0x01, 0xbb];
        let (_, cmd) = parse_client_request(buffer)?;
        let r = match cmd {
            Command::Connect(r) => r,
            Command::Bind(r) => r,
            Command::Associate(r) => r,
        };

        unsafe {
            match r.dest_addr {
                DestAddr::FQDN(domain) => assert_eq!(String::from_utf8_unchecked(domain), "x.com"),
                _ => (),
            }
        }

        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00, addr_type::FQDN, 0x08, b'x', b'.', b'c', b'o', b'm', 0x01, 0xbb];
        assert!(parse_client_request(buffer).is_err());

        let buffer: &[u8] = &[SOCKS5, 0x05, 0x00, addr_type::FQDN, 0x05, b'x', b'.', b'c', b'o', b'm', 0x01, 0xbb];
        assert!(parse_client_request(buffer).is_err());

        Ok(())
    }
}
