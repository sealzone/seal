//! IP networks in CIDR form, for the addresses an app may start sessions from
//! (`TenantState::app_networks`).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// An IP network in canonical CIDR form: `203.0.113.0/24`, `2001:db8::/32`, or one address as
/// `/32` (IPv4) or `/128` (IPv6). States are signed as JSON, so every network has exactly one
/// spelling: the prefix is always written, no bits are set past it, and the address is written
/// as `std::net` writes it (IPv6 compressed and in lower case). Anything else is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// `addr/prefix`, refused when the prefix is too long or `addr` has bits past it.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, ProtoError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(ProtoError::invalid("network", format!("/{prefix} is longer than /{max}")));
        }
        if masked(addr, prefix) != addr {
            return Err(ProtoError::invalid(
                "network",
                format!(
                    "{addr}/{prefix} has address bits past the prefix (did you mean {}/{prefix}?)",
                    masked(addr, prefix)
                ),
            ));
        }
        Ok(Self { addr, prefix })
    }

    /// Whether `ip` is in this network. An IPv4-mapped IPv6 address (`::ffff:203.0.113.7`, how
    /// a dual-stack listener reports an IPv4 peer) counts as the IPv4 address it maps.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        ip.is_ipv4() == self.addr.is_ipv4() && masked(ip, self.prefix) == self.addr
    }
}

fn masked(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix.min(32))).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix.min(128))).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Cidr {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, ProtoError> {
        let (addr, prefix) = s.split_once('/').ok_or_else(|| {
            ProtoError::invalid("network", format!("{s:?} has no /prefix (one address is /32 or /128)"))
        })?;
        let addr: IpAddr =
            addr.parse().map_err(|_| ProtoError::invalid("network", format!("{s:?}: not an IP address")))?;
        if prefix.is_empty()
            || prefix.len() > 3
            || !prefix.bytes().all(|b| b.is_ascii_digit())
            || prefix.starts_with('0') && prefix != "0"
        {
            return Err(ProtoError::invalid("network", format!("{s:?}: the prefix is not a number")));
        }
        let cidr =
            Cidr::new(addr, prefix.parse().map_err(|_| ProtoError::invalid("network", format!("{s:?}: bad prefix")))?)?;
        if cidr.to_string() != s {
            return Err(ProtoError::invalid("network", format!("{s:?} is not canonical: write {cidr}")));
        }
        Ok(cidr)
    }
}

impl Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn canonical_spellings_only() {
        for ok in [
            "203.0.113.0/24",
            "203.0.113.7/32",
            "0.0.0.0/0",
            "2001:db8::/32",
            "::/0",
            "2001:db8::1/128",
            "::ffff:1.2.3.0/120",
        ] {
            assert_eq!(ok.parse::<Cidr>().unwrap().to_string(), ok);
        }
        for bad in [
            "203.0.113.7/24", // host bits
            "203.0.113.0",    // no prefix
            "203.0.113.0/33",
            "203.0.113.0/024",
            "203.0.113.0/+8",
            "2001:DB8::/32",  // upper case
            "2001:0db8::/32", // not compressed
            "203.0.113.0/24 ",
            "example.com/24",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn contains_by_prefix() {
        let net: Cidr = "203.0.113.0/24".parse().unwrap();
        assert!(net.contains(ip("203.0.113.0")) && net.contains(ip("203.0.113.255")));
        assert!(!net.contains(ip("203.0.114.1")));
        assert!(net.contains(ip("::ffff:203.0.113.9")), "an IPv4-mapped peer counts as IPv4");
        assert!(!net.contains(ip("2001:db8::1")));
        let any4: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(any4.contains(ip("198.51.100.1")) && !any4.contains(ip("::1")));
        let v6: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")) && !v6.contains(ip("2001:db9::1")));
        let one: Cidr = "198.51.100.7/32".parse().unwrap();
        assert!(one.contains(ip("198.51.100.7")) && !one.contains(ip("198.51.100.8")));
    }

    #[test]
    fn json_is_the_string() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert_eq!(serde_json::to_string(&net).unwrap(), "\"10.0.0.0/8\"");
        assert!(serde_json::from_str::<Cidr>("\"10.0.0.1/8\"").is_err());
    }
}
