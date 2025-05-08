//! socks5rs is a minimal, low-level and simple socks5 protocol implementation.
//! It operates on raw bytes instead of abstracting I/O to achive better reusability and testablity.

use std::net::{IpAddr, SocketAddr};

pub mod common;
pub mod error;
pub mod server;

#[cfg(test)]
mod tests {
    use super::*;
    use super::{common::*, common::command::*, server::*};
    use error::Result;
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
        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00, addrtype::V4, 127, 0, 0, 1, 0x01, 0xbb];
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


        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00, addrtype::FQDN, 0x05, b'x', b'.', b'c', b'o', b'm', 0x01, 0xbb];
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

        let buffer: &[u8] = &[SOCKS5, 0x01, 0x00, addrtype::FQDN, 0x08, b'x', b'.', b'c', b'o', b'm', 0x01, 0xbb];
        assert!(parse_client_request(buffer).is_err());

        let buffer: &[u8] = &[SOCKS5, 0x05, 0x00, addrtype::FQDN, 0x05, b'x', b'.', b'c', b'o', b'm', 0x01, 0xbb];
        assert!(parse_client_request(buffer).is_err());

        Ok(())
    }
}
