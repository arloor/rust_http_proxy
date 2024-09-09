use std::{
    fmt::{self, Formatter},
    net::SocketAddr,
};

/// SOCKS5 address type
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

impl Address {
    pub fn host(&self) -> String {
        match self {
            Address::SocketAddress(ref addr) => addr.ip().to_string(),
            Address::DomainNameAddress(host, _) => host.to_owned(),
        }
    }
}

// to_string() -> host:port
impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{addr}"),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{addr}:{port}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}
