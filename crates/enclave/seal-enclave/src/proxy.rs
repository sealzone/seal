//! PROXY protocol v2 (HAProxy's "The PROXY protocol", section 2.2, the binary header): what
//! Seal's front door puts before each connection it passes to a hosted replica, naming the
//! client's address, which the replica would otherwise never see (the front connects to it).
//!
//! The header is only bytes the connecting side writes, so the address in it is trusted only
//! where nobody but the front door can connect: a Seal-hosted replica, which is reachable only
//! from the front (`SealService::behind_front_door`). Anywhere else the header is read past and
//! its address ignored. A connection that starts with no header is untouched: a TLS record
//! starts with 0x16, the signature with 0x0D, so the first byte tells them apart.
//!
//! Layout: the 12-byte signature; version and command (0x21 PROXY, 0x20 LOCAL); address family
//! and transport (0x11 TCP over IPv4, 0x21 TCP over IPv6); the length of the rest (big-endian);
//! then source and destination addresses and ports, and optional TLVs, which are skipped.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub(crate) const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// The longest address block and TLVs read: the front sends 12 or 36 bytes.
const MAX_LEN: usize = 512;

/// The source a PROXY v2 header at the start of `tcp` names, reading exactly the header: `None`
/// when the connection starts without one, or when it names no TCP source (`LOCAL`, the proxy's
/// own connection, or another family). Leaves `tcp` at the TLS ClientHello. An error for a
/// header that is not version 2 or is malformed.
pub(crate) async fn read(tcp: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let mut first = [0u8; 1];
    if tcp.peek(&mut first).await? == 0 || first[0] != SIGNATURE[0] {
        return Ok(None);
    }
    let mut fixed = [0u8; 16];
    tcp.read_exact(&mut fixed).await?;
    let mut rest = vec![0; rest_len(&fixed)?];
    tcp.read_exact(&mut rest).await?;
    source(&fixed, &rest)
}

/// The length of what follows the 16 fixed bytes, once they are a version 2 header.
fn rest_len(fixed: &[u8; 16]) -> io::Result<usize> {
    if fixed[..12] != SIGNATURE {
        return Err(malformed("not a PROXY v2 signature"));
    }
    if fixed[12] >> 4 != 2 {
        return Err(malformed("not PROXY protocol version 2"));
    }
    let len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if len > MAX_LEN {
        return Err(malformed("PROXY header too long"));
    }
    Ok(len)
}

/// The source address of a header (`fixed`, then `rest` of `rest_len` bytes).
fn source(fixed: &[u8; 16], rest: &[u8]) -> io::Result<Option<SocketAddr>> {
    match fixed[12] & 0x0f {
        0x0 => return Ok(None), // LOCAL: the proxy's own connection
        0x1 => {}               // PROXY
        _ => return Err(malformed("unknown PROXY command")),
    }
    let port = |at: usize| u16::from_be_bytes([rest[at], rest[at + 1]]);
    match fixed[13] {
        0x11 if rest.len() >= 12 => {
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&rest[..4]).expect("4 bytes"));
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port(8))))
        }
        0x21 if rest.len() >= 36 => {
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&rest[..16]).expect("16 bytes"));
            Ok(Some(SocketAddr::new(IpAddr::V6(ip), port(32))))
        }
        0x11 | 0x21 => Err(malformed("PROXY addresses truncated")),
        // UNSPEC, UDP or UNIX: no TCP source; the connection's own address stands.
        _ => Ok(None),
    }
}

fn malformed(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::AsyncWriteExt;

    /// The front door's encoding (seal-console `front/src/proxy.rs`, `proxy_v2`).
    fn front(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let mut h = SIGNATURE.to_vec();
        h.push(0x21);
        match (src, dst) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => {
                h.push(0x11);
                h.extend_from_slice(&12u16.to_be_bytes());
                h.extend_from_slice(&s.ip().octets());
                h.extend_from_slice(&d.ip().octets());
                h.extend_from_slice(&s.port().to_be_bytes());
                h.extend_from_slice(&d.port().to_be_bytes());
            }
            (s, d) => {
                let v6 = |a: SocketAddr| match a {
                    SocketAddr::V4(v) => v.ip().to_ipv6_mapped(),
                    SocketAddr::V6(v) => *v.ip(),
                };
                h.push(0x21);
                h.extend_from_slice(&36u16.to_be_bytes());
                h.extend_from_slice(&v6(s).octets());
                h.extend_from_slice(&v6(d).octets());
                h.extend_from_slice(&s.port().to_be_bytes());
                h.extend_from_slice(&d.port().to_be_bytes());
            }
        }
        h
    }

    fn parse(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
        let fixed: [u8; 16] = bytes[..16].try_into().unwrap();
        let len = rest_len(&fixed)?;
        source(&fixed, &bytes[16..16 + len])
    }

    #[test]
    fn the_spec_examples() {
        // TCP over IPv4, 192.0.2.1:56324 to 192.0.2.2:443.
        let v4: Vec<u8> =
            [&SIGNATURE[..], &[0x21, 0x11, 0, 12, 192, 0, 2, 1, 192, 0, 2, 2, 0xdc, 0x04, 0x01, 0xbb]].concat();
        assert_eq!(parse(&v4).unwrap(), Some("192.0.2.1:56324".parse().unwrap()));
        // LOCAL: the proxy's own connection, whatever follows.
        let local: Vec<u8> = [&SIGNATURE[..], &[0x20, 0x00, 0, 0]].concat();
        assert_eq!(parse(&local).unwrap(), None);
        // UNSPEC family: no source.
        let unspec: Vec<u8> = [&SIGNATURE[..], &[0x21, 0x00, 0, 0]].concat();
        assert_eq!(parse(&unspec).unwrap(), None);
        // TLVs after the addresses are skipped.
        let mut tlv = v4.clone();
        tlv[15] = 12 + 4;
        tlv.extend_from_slice(&[0x04, 0, 1, 0]);
        assert_eq!(parse(&tlv).unwrap(), Some("192.0.2.1:56324".parse().unwrap()));
    }

    #[test]
    fn refuses_what_is_not_a_v2_header() {
        let ok = front("192.0.2.1:1".parse().unwrap(), "192.0.2.2:2".parse().unwrap());
        let mut v1 = ok.clone();
        v1[12] = 0x11;
        assert!(parse(&v1).is_err(), "version 1 in a v2 frame");
        let mut sig = ok.clone();
        sig[3] = b'X';
        assert!(parse(&sig).is_err());
        let mut cmd = ok.clone();
        cmd[12] = 0x22;
        assert!(parse(&cmd).is_err(), "an unknown command");
        let mut short = ok.clone();
        short[15] = 8;
        assert!(parse(&short).is_err(), "addresses cut short");
        let mut long = ok;
        long[14..16].copy_from_slice(&((MAX_LEN + 1) as u16).to_be_bytes());
        assert!(rest_len(&long[..16].try_into().unwrap()).is_err());
    }

    proptest! {
        #[test]
        fn reads_the_front_doors_header(src: SocketAddr, dst: SocketAddr) {
            let named = parse(&front(src, dst)).unwrap().unwrap();
            prop_assert_eq!(named.port(), src.port());
            // A mixed pair goes as IPv6, an IPv4 source as its mapped address: the same address.
            prop_assert_eq!(named.ip().to_canonical(), src.ip().to_canonical());
        }

        #[test]
        fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 16..600)) {
            let fixed: [u8; 16] = bytes[..16].try_into().unwrap();
            if let Ok(len) = rest_len(&fixed) {
                if bytes.len() >= 16 + len {
                    let _ = source(&fixed, &bytes[16..16 + len]);
                }
            }
        }
    }

    #[tokio::test]
    async fn reads_exactly_the_header_and_leaves_the_rest() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            let mut bytes = front("203.0.113.7:51234".parse().unwrap(), addr);
            bytes.extend_from_slice(&[0x16, 0x03, 0x01]); // the start of a TLS record
            c.write_all(&bytes).await.unwrap();
            let mut plain = TcpStream::connect(addr).await.unwrap();
            plain.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
            (c, plain)
        });
        let (mut proxied, _) = listener.accept().await.unwrap();
        assert_eq!(read(&mut proxied).await.unwrap(), Some("203.0.113.7:51234".parse().unwrap()));
        let mut next = [0u8; 3];
        proxied.read_exact(&mut next).await.unwrap();
        assert_eq!(next, [0x16, 0x03, 0x01], "the TLS bytes are untouched");
        let (mut plain, _) = listener.accept().await.unwrap();
        assert_eq!(read(&mut plain).await.unwrap(), None, "no header: nothing read");
        plain.read_exact(&mut next).await.unwrap();
        assert_eq!(next, [0x16, 0x03, 0x01]);
        drop(client.await.unwrap());
    }
}
