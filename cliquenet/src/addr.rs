use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use multisig::{Committee, PublicKey, x25519};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

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

    /// Set the address port.
    pub fn set_port(&mut self, p: u16) {
        match self {
            Self::Inet(_, o) => *o = p,
            Self::Name(_, o) => *o = p,
        }
    }

    pub fn with_port(mut self, p: u16) -> Self {
        match self {
            Self::Inet(ip, _) => self = Self::Inet(ip, p),
            Self::Name(hn, _) => self = Self::Name(hn, p),
        }
        self
    }

    pub fn with_offset(mut self, o: u16) -> Self {
        match self {
            Self::Inet(ip, p) => self = Self::Inet(ip, p + o),
            Self::Name(hn, p) => self = Self::Name(hn, p + o),
        }
        self
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

impl TryFrom<&str> for Address {
    type Error = InvalidAddress;

    fn try_from(val: &str) -> Result<Self, Self::Error> {
        val.parse()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid address")]
pub struct InvalidAddress(());

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let a = s.parse().map_err(de::Error::custom)?;
        Ok(a)
    }
}

/// A `Committee` plus address information.
#[derive(Debug, Clone)]
pub struct AddressableCommittee {
    committee: Committee,
    addresses: HashMap<PublicKey, (x25519::PublicKey, Address)>,
}

impl AddressableCommittee {
    pub fn new<I, A>(c: Committee, addrs: I) -> Self
    where
        I: IntoIterator<Item = (PublicKey, x25519::PublicKey, A)>,
        A: Into<Address>,
    {
        let this = Self {
            committee: c,
            addresses: addrs
                .into_iter()
                .map(|(k, x, a)| (k, (x, a.into())))
                .collect(),
        };
        this.assert_shared_domain();
        this
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    pub fn address(&self, p: &PublicKey) -> Option<&(x25519::PublicKey, Address)> {
        self.addresses.get(p)
    }

    pub fn parties(&self) -> impl Iterator<Item = &PublicKey> {
        self.addresses.keys()
    }

    pub fn entries(&self) -> impl Iterator<Item = (PublicKey, x25519::PublicKey, Address)> {
        self.addresses.iter().map(|(k, (x, a))| (*k, *x, a.clone()))
    }

    pub fn diff(
        &self,
        other: &Self,
    ) -> impl Iterator<Item = (PublicKey, x25519::PublicKey, Address)> {
        self.addresses
            .iter()
            .filter(|(k, _)| !other.addresses.contains_key(k))
            .map(|(k, (x, a))| (*k, *x, a.clone()))
    }

    /// Assert that addresses and committee have the same keys.
    fn assert_shared_domain(&self) {
        for p in self.committee.parties() {
            assert!(self.addresses.contains_key(p), "{p} has no address")
        }
        for k in self.addresses.keys() {
            assert!(self.committee.contains_key(k), "{k} not in committee")
        }
    }
}

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
