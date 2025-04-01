#![allow(dead_code)]

use crate::error::{Error, Socks5ErrorKind};

pub const SOCKS5: u8 = 0x05;
pub const RESERVED: u8 = 0x00;
pub const MTU: usize = 1280;

pub mod addr_type {
    pub const V4: u8 = 0x01;
    pub const FQDN: u8 = 0x03;
    pub const V6: u8 = 0x04;
}

pub mod command {
    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const ASSOCIATE: u8 = 0x03;
}

#[repr(u8)]
#[derive(Debug)]
/// Byte representation of socks5 authentication methods
pub enum Method {
    NoAuth = 0x00,
    UserPass = 0x02,
    NoAcceptableMethods = 0xff,
}

#[repr(u8)]
#[derive(Debug)]
/// Byte representation of socks5 commands
pub enum Command {
    Connect = command::CONNECT,
    Bind,
    Associate,
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use command::*;
        match value {
            CONNECT => Ok(Command::Connect),
            BIND => Ok(Command::Bind),
            ASSOCIATE => Ok(Command::Associate),
            _ => Err(Error::from(Socks5ErrorKind::CommandNotSupported)),
        }
    }
}

#[repr(u8)]
#[derive(Debug)]
/// Byte representation of socks5 address types
pub enum AddrType {
    /// IPv4
    V4 = addr_type::V4,
    /// Fully Qualified Domain Name
    FQDN = addr_type::FQDN,
    /// IPv6
    V6 = addr_type::V6,
}

impl TryFrom<u8> for AddrType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use addr_type::*;
        match value {
            V4 => Ok(AddrType::V4),
            FQDN => Ok(AddrType::FQDN),
            V6 => Ok(AddrType::V6),
            _ => Err(Error::from(Socks5ErrorKind::AddressTypeNotSupported)),
        }
    }
}
