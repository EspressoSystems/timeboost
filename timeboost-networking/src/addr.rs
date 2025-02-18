use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A network address.
///
/// Either an IP address and port number or else a hostname and port number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    Inet(IpAddr, u16),
    Name(String, u16),
}

impl Address {
    /// Get the port number of an address.
    pub fn port(&self) -> u16 {
        match self {
            Self::Inet(_, p) => *p,
            Self::Name(_, p) => *p,
        }
    }

    /// We need to be able to set the port to something else.
    pub fn set_port(&mut self, p: u16) {
        match self {
            Self::Inet(ip, _) => *self = Self::Inet(*ip, p),
            Self::Name(hn, _) => *self = Self::Name(hn.clone(), p),
        }
    }

    /// Convert an address to a URL string (basically just adds the scheme).
    /// TODO: Support TLS (if it comes up).
    pub fn url_string(&self) -> String {
        match self {
            Address::Inet(ip, port) => format!("http://{ip}:{port}"),
            Address::Name(hn, port) => format!("http://{hn}:{port}"),
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Inet(..))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(a, p) => write!(f, "{a}:{p}"),
            Self::Name(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

impl From<(&str, u16)> for Address {
    fn from((h, p): (&str, u16)) -> Self {
        Self::Name(h.to_string(), p)
    }
}

impl From<(String, u16)> for Address {
    fn from((h, p): (String, u16)) -> Self {
        Self::Name(h, p)
    }
}

impl From<(IpAddr, u16)> for Address {
    fn from((ip, p): (IpAddr, u16)) -> Self {
        Self::Inet(ip, p)
    }
}

impl From<(Ipv4Addr, u16)> for Address {
    fn from((ip, p): (Ipv4Addr, u16)) -> Self {
        Self::Inet(IpAddr::V4(ip), p)
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    fn from((ip, p): (Ipv6Addr, u16)) -> Self {
        Self::Inet(IpAddr::V6(ip), p)
    }
}

impl From<SocketAddr> for Address {
    fn from(a: SocketAddr) -> Self {
        Self::Inet(a.ip(), a.port())
    }
}

impl std::str::FromStr for Address {
    type Err = InvalidAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = |a: &str, p: Option<&str>| {
            let p: u16 = if let Some(p) = p {
                p.parse().map_err(|_| InvalidAddress(()))?
            } else {
                0
            };
            IpAddr::from_str(a)
                .map(|a| Self::Inet(a, p))
                .or_else(|_| Ok(Self::Name(a.to_string(), p)))
        };
        match s.rsplit_once(':') {
            None => parse(s, None),
            Some((a, p)) => parse(a, Some(p)),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid address")]
pub struct InvalidAddress(());

#[cfg(test)]
mod tests {
    use super::Address;
    use std::net::IpAddr;

    #[test]
    fn test_parse() {
        let a: Address = "127.0.0.1:1234".parse().unwrap();
        let Address::Inet(a, p) = a else {
            unreachable!()
        };
        assert_eq!(IpAddr::from([127, 0, 0, 1]), a);
        assert_eq!(1234, p);

        let a: Address = "::1:1234".parse().unwrap();
        let Address::Inet(a, p) = a else {
            unreachable!()
        };
        assert_eq!("::1".parse::<IpAddr>().unwrap(), a);
        assert_eq!(1234, p);

        let a: Address = "localhost:1234".parse().unwrap();
        let Address::Name(h, p) = a else {
            unreachable!()
        };
        assert_eq!("localhost", &h);
        assert_eq!(1234, p);

        let a: Address = "sub.domain.com:1234".parse().unwrap();
        let Address::Name(h, p) = a else {
            unreachable!()
        };
        assert_eq!("sub.domain.com", &h);
        assert_eq!(1234, p);
    }
}
