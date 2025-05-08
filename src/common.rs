use {
    std::net::IpAddr,
    crate::error::{Error, Socks5ErrorKind}
};

/// Byte representation of version field in socks5 request and responses
pub const SOCKS5: u8 = 0x05;

/// Reserved byte
pub const RESERVED: u8 = 0x00;


#[derive(Debug)]
/// Destination address in a socks5 request
pub enum DestAddr {
    /// IP address
    IP(IpAddr),
    /// Fully Qualified Domain Name (requires DNS resolution)
    FQDN(Vec<u8>),
}

#[derive(Debug)]
/// Socks5 request
pub struct Request {
    /// Destination address
    pub dest_addr: DestAddr,
    /// Destination port
    pub dest_port: u16,
}

impl Request {
    pub fn new(dest_addr: DestAddr, dest_port: u16) -> Self {
        Self{ dest_addr, dest_port }
    }
}


/// Socks5 address type byte representation
pub mod addrtype {
    use super::*;

    pub const V4: u8 = 0x01;
    pub const FQDN: u8 = 0x03;
    pub const V6: u8 = 0x04;

    #[repr(u8)]
    #[derive(Debug)]
    pub enum AddrType {
        /// IPv4
        V4 = V4,
        /// Fully Qualified Domain Name
        FQDN = FQDN,
        /// IPv6
        V6 = V6,
    }

    impl TryFrom<u8> for AddrType {
        type Error = Error;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                V4 => Ok(AddrType::V4),
                FQDN => Ok(AddrType::FQDN),
                V6 => Ok(AddrType::V6),
                _ => Err(Error::from(Socks5ErrorKind::AddressTypeNotSupported)),
            }
        }
    }
}

/// Socks5 commands byte representation
pub mod command {
    use super::*;

    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const ASSOCIATE: u8 = 0x03;

    #[repr(u8)]
    #[derive(Debug)]
    /// Socks5 client command kind
    pub enum CommandKind {
        Connect = CONNECT,
        Bind = BIND,
        Associate = ASSOCIATE,
    }

    impl TryFrom<u8> for CommandKind {
        type Error = Error;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                CONNECT => Ok(CommandKind::Connect),
                BIND => Ok(CommandKind::Bind),
                ASSOCIATE => Ok(CommandKind::Associate),
                _ => Err(Error::from(Socks5ErrorKind::CommandNotSupported)),
            }
        }
    }

    #[derive(Debug)]
    pub enum Command {
        Connect(Request),
        Bind(Request),
        Associate(Request),
    }
}

/// Socks5 authentication methods byte representation
pub mod method {
    pub const NO_AUTH: u8 = 0x00;
    pub const GSSAPI: u8 = 0x01;
    pub const USER_PASS: u8 = 0x02;
    pub const NO_ACCEPTABLE_METHODS: u8 = 0xff;

    #[repr(u8)]
    #[derive(Debug)]
    pub enum Method {
        NoAuth = NO_AUTH,
        GSSAPI = GSSAPI,
        UserPass = USER_PASS,
        NoAcceptableMethods = NO_ACCEPTABLE_METHODS,
    }
}

