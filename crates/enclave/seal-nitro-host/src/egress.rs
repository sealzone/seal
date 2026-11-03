//! Egress: the enclave's outbound streams. On `EGRESS_PORT` the enclave sends
//! `CONNECT host:port HTTP/1.1` (and headers, ignored) within `HEAD_TIMEOUT`; the parent
//! resolves `host`, connects to the first allowed address within `CONNECT_TIMEOUT`, answers
//! `HTTP/1.1 200 Connection established` and relays bytes both ways until either side closes.
//! Otherwise it answers `400` (not a `CONNECT` it can read), `403` (no allowed address), `502`
//! (no name, no connection) or `503` (`max_tunnels` open) and closes.
//!
//! What the enclave reaches is what a NAT gateway gives replicas on Azure and GCP: any public or
//! private address, on any port. Refused: addresses that are the instance's own rather than a
//! network's, which the enclave never needs. `forbidden` lists them: unspecified, loopback,
//! link-local (IMDS, the Time Sync Service and the Amazon DNS resolver, `169.254.0.0/16`,
//! `fe80::/10`), EC2's IPv6 service addresses (`fd00:ec2::/32`), multicast and broadcast, and
//! any of those behind the NAT64 prefix `64:ff9b::/96`. `is_own` adds the instance's interface
//! addresses (its VPC addresses), and their NAT64 forms: an address the kernel would answer
//! from itself. So the instance role's credentials and the parent's own services stay out of
//! reach of whatever runs in the enclave.
//!
//! This filtering protects the parent, as defence in depth; it is not a security boundary of
//! Seal's. The enclave trusts nothing it reaches through the parent (every stream is TLS it
//! verifies), and whoever has root on the parent can change or bypass this process.
//!
//! The streams are the enclave's TLS (it verifies every peer at trusted time); the parent sees
//! only names, addresses and sizes, as any network does.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use seal_proto::nitro::MAX_CONNECT_HEAD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// From an accepted connection to its whole `CONNECT` head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Resolving the name and connecting.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Which destinations are refused, beyond `forbidden`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    /// Tests only: let loopback through, where their upstreams listen.
    pub allow_loopback: bool,
}

impl Policy {
    /// Why `ip` is refused under this policy, if it is.
    pub fn refusal_for(&self, ip: IpAddr) -> Option<&'static str> {
        self.refuses(ip)
    }

    fn refuses(&self, ip: IpAddr) -> Option<&'static str> {
        let ip = ip.to_canonical();
        if self.allow_loopback && ip.is_loopback() {
            return None;
        }
        forbidden(ip).or_else(|| {
            let own = is_own(ip) || nat64_embedded(ip).is_some_and(|v4| is_own(IpAddr::V4(v4)));
            own.then_some("the instance's own address")
        })
    }
}

/// The IPv4 address behind the NAT64 well-known prefix `64:ff9b::/96`, if `ip` is under it.
fn nat64_embedded(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(v6) = ip else { return None };
    let o = v6.octets();
    (o[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]).then(|| Ipv4Addr::new(o[12], o[13], o[14], o[15]))
}

/// Whether `ip` is one of this instance's own addresses: the kernel would send to it from
/// that very address. Asked of a UDP socket's route (`connect` sends nothing), so no interface
/// list is needed; an address with no route is not ours.
pub fn is_own(ip: IpAddr) -> bool {
    let any: SocketAddr = match ip {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let Ok(socket) = std::net::UdpSocket::bind(any) else { return false };
    socket.connect((ip, 9)).is_ok() && socket.local_addr().is_ok_and(|local| local.ip() == ip)
}

/// Why `ip` is refused, if it is (module docs; the instance's own VPC addresses are `is_own`).
pub fn forbidden(ip: IpAddr) -> Option<&'static str> {
    if let Some(v4) = nat64_embedded(ip) {
        return forbidden(IpAddr::V4(v4));
    }
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.octets()[0] == 0 {
                Some("unspecified")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_link_local() {
                Some("link-local (the instance's own services)")
            } else if v4.is_multicast() || v4 == Ipv4Addr::BROADCAST {
                Some("multicast or broadcast")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if v6.is_unspecified() {
                Some("unspecified")
            } else if v6.is_loopback() {
                Some("loopback")
            } else if s[0] & 0xffc0 == 0xfe80 {
                Some("link-local (the instance's own services)")
            } else if s[0] == 0xfd00 && s[1] == 0x0ec2 {
                Some("EC2's own services")
            } else if v6.is_multicast() {
                Some("multicast or broadcast")
            } else {
                None
            }
        }
    }
}

/// A `CONNECT` request that cannot be served: the status and why.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub reason: String,
}

fn refusal(status: u16, reason: impl Into<String>) -> Refusal {
    Refusal { status, reason: reason.into() }
}

/// `host` and `port` of a `CONNECT host:port HTTP/1.x` head (up to its blank line).
pub fn parse_request(head: &[u8]) -> Result<(String, u16), Refusal> {
    let head = std::str::from_utf8(head).map_err(|_| refusal(400, "the request is not text"))?;
    let line = head.split("\r\n").next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some(method), Some(authority), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(refusal(400, "not a request line"));
    };
    if method != "CONNECT" {
        return Err(refusal(405, "only CONNECT"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(refusal(400, "not HTTP/1"));
    }
    authority_of(authority).ok_or_else(|| refusal(400, "not host:port"))
}

/// `host:port` or `[v6]:port`, with `host` a name (letters, digits, `-`, `.`, `_`) or an
/// address.
fn authority_of(authority: &str) -> Option<(String, u16)> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (v6, port) = rest.split_once("]:")?;
            (v6.parse::<Ipv6Addr>().ok()?.to_string(), port)
        }
        None => {
            let (host, port) = authority.rsplit_once(':')?;
            let name_char = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_');
            if host.is_empty() || host.len() > 253 || !host.bytes().all(name_char) {
                return None;
            }
            (host.to_owned(), port)
        }
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    Some((host, port))
}

/// The head of a request: everything up to and including its blank line, read one byte at a time
/// so nothing past it is taken from the stream.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, Refusal> {
    let mut head = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_CONNECT_HEAD {
            return Err(refusal(400, "the request head is too long"));
        }
        match stream.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return Err(refusal(400, "the request ended early")),
        }
    }
    Ok(head)
}

/// A connection to the first address of `host:port` the policy allows.
async fn open(host: &str, port: u16, policy: &Policy) -> Result<TcpStream, Refusal> {
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => {
            tokio::net::lookup_host((host, port)).await.map_err(|e| refusal(502, format!("{host}: {e}")))?.collect()
        }
    };
    let mut refused = None;
    let mut failed = None;
    for addr in addrs {
        if let Some(why) = policy.refuses(addr.ip()) {
            refused = Some(format!("{addr} is {why}"));
            continue;
        }
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => failed = Some(format!("{addr}: {e}")),
        }
    }
    Err(match (failed, refused) {
        (Some(failed), _) => refusal(502, failed),
        (None, Some(refused)) => refusal(403, refused),
        (None, None) => refusal(502, format!("{host} has no address")),
    })
}

fn status_text(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, refused: &Refusal) {
    let answer = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        refused.status,
        status_text(refused.status)
    );
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Serves one `CONNECT` on `stream` (module docs): `Ok` once the relay ends, the refusal if
/// there was one.
pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, policy: &Policy) -> Result<(), Refusal> {
    let target = async {
        let head = read_head(&mut stream).await?;
        let (host, port) = parse_request(&head)?;
        let upstream = open(&host, port, policy).await?;
        Ok::<_, Refusal>((host, port, upstream))
    };
    let (host, port, mut upstream) = match tokio::time::timeout(HEAD_TIMEOUT + CONNECT_TIMEOUT, target).await {
        Ok(Ok(opened)) => opened,
        Ok(Err(refused)) => {
            refuse(&mut stream, &refused).await;
            return Err(refused);
        }
        Err(_) => {
            let refused = refusal(502, "timed out");
            refuse(&mut stream, &refused).await;
            return Err(refused);
        }
    };
    if stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return Ok(());
    }
    match tokio::io::copy_bidirectional(&mut stream, &mut upstream).await {
        Ok((out, back)) => tracing::debug!(%host, port, out, back, "tunnel closed"),
        Err(e) => tracing::debug!(%host, port, error = %e, "tunnel ended"),
    }
    Ok(())
}

/// Accepts the enclave's egress connections on `listener`, at most `max_tunnels` at once; a
/// connection from another CID than `enclave_cid` is closed.
pub async fn serve(listener: seal_net::vsock::VsockListener, enclave_cid: u32, max_tunnels: usize, policy: Policy) {
    let tunnels = Arc::new(Semaphore::new(max_tunnels));
    loop {
        let (mut stream, cid) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "egress accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if cid != enclave_cid {
            tracing::warn!(cid, "egress connection refused: not from the enclave");
            continue;
        }
        let Ok(permit) = tunnels.clone().try_acquire_owned() else {
            tokio::spawn(async move { refuse(&mut stream, &refusal(503, "too many tunnels")).await });
            continue;
        };
        tokio::spawn(async move {
            if let Err(refused) = handle(stream, &policy).await {
                tracing::info!(status = refused.status, reason = %refused.reason, "egress refused");
            }
            drop(permit);
        });
    }
}
