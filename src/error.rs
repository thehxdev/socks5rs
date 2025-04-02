#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
/// Socks5 related errors that can be sent to client as Reply
pub enum Socks5ErrorKind {
    GeneralServerFailure = 0x01,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Into<u8> for Socks5ErrorKind {
    fn into(self) -> u8 {
        self as u8
    }
}

impl ToString for Socks5ErrorKind {
    fn to_string(&self) -> String {
        let s: &'static str = match self {
            Socks5ErrorKind::GeneralServerFailure    => "general server failure",
            Socks5ErrorKind::ConnectionNotAllowed    => "connection not allowed",
            Socks5ErrorKind::NetworkUnreachable      => "network unreachable",
            Socks5ErrorKind::HostUnreachable         => "host unreachable",
            Socks5ErrorKind::ConnectionRefused       => "host unreachable",
            Socks5ErrorKind::TTLExpired              => "TTL expired",
            Socks5ErrorKind::CommandNotSupported     => "command not supported",
            Socks5ErrorKind::AddressTypeNotSupported => "address type not supported"
        };
        String::from(s)
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
/// Errors that are related to parsing Socks5 requests
pub enum ParserErrorKind {
    /// Buffer is shorter than expected
    ShortBuffer,
    /// No authentication methods provided in first client request
    ZeroAuthMethods,
}

#[derive(Debug)]
/// Error representation. This enum captures IO, Socks5 and Parser related errors.
pub enum Repr {
    IO(tokio::io::Error),
    Socks5(Socks5ErrorKind),
    Parser(ParserErrorKind),
}

#[derive(Debug)]
pub struct Error {
    repr: Repr,
}

impl Error {
    pub const SHORT_BUFFER_ERROR: Error = Error {repr: Repr::Parser(ParserErrorKind::ShortBuffer)};

    /// Convert Error type to Socks5 reply byte
    pub fn to_socks5_reply(&self) -> u8 {
        use tokio::io::ErrorKind;
        match self.repr {
            Repr::IO(ref e) => {
                let code = match e.kind() {
                    ErrorKind::NetworkUnreachable => Socks5ErrorKind::NetworkUnreachable,
                    _ => Socks5ErrorKind::GeneralServerFailure,
                };
                code as u8
            },
            Repr::Socks5(e) => e.into(),
            Repr::Parser(_) => Socks5ErrorKind::GeneralServerFailure as u8,
        }
    }
}

impl From<tokio::io::Error> for Error {
    fn from(value: tokio::io::Error) -> Self {
        Self { repr: Repr::IO(value) }
    }
}

impl From<Socks5ErrorKind> for Error {
    fn from(value: Socks5ErrorKind) -> Self {
        Self { repr: Repr::Socks5(value) }
    }
}

impl From<ParserErrorKind> for Error {
    fn from(value: ParserErrorKind) -> Self {
        Self { repr: Repr::Parser(value) }
    }
}

impl Into<u8> for Error {
    fn into(self) -> u8 {
        self.to_socks5_reply()
    }
}


impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.repr {
            Repr::IO(e) => write!(f, "{}", e.kind()),
            Repr::Socks5(e) => write!(f, "{}", e.to_string()),
            Repr::Parser(e) => write!(f, "{e:?}"),
        }
    }
}

/// Socks5 result type to capture all kinds of errors that might be happen while
/// working with the protocol.
pub type Result<T> = std::result::Result<T, Error>;
