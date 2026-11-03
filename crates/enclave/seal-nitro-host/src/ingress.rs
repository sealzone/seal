//! Ingress: the enclave's one port, served on the instance. Each TCP connection to `listen`
//! is relayed to the enclave's vsock port (its CID, the same port number as the release's
//! `listen`), after a PROXY protocol v2 header naming the client, which the enclave takes as
//! the connection's source (its network rules and per-source limits). The enclave terminates
//! TLS itself, so the parent relays bytes it cannot read.
//!
//! The port holds what the enclave's does (`Limits`): at most `connections` at once, and
//! `per_source` from one source, an IPv4 address or an IPv6 /64, keyed as the enclave keys
//! them; past either a connection is closed at once. A relay ends as soon as the enclave's side
//! ends (a client that ignores the close holds nothing), and when no byte has moved either way
//! for `idle`, as a NAT gateway forgets an idle flow (TCP keepalive probes carry no bytes, so
//! they do not count here). A client's own close is passed on and the relay waits for the
//! enclave to finish.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// Connecting to the enclave's vsock port, and writing the PROXY header.
const ENCLAVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What the inbound port holds (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub connections: usize,
    pub per_source: usize,
    pub idle: Duration,
}

impl Default for Limits {
    /// The enclave's own: `MAX_CONNECTIONS` (1024) and `MAX_CONNECTIONS_PER_SOURCE` (512); idle
    /// after 350 s, an AWS NAT gateway's idle timeout.
    fn default() -> Self {
        Self { connections: 1024, per_source: 512, idle: Duration::from_secs(350) }
    }
}

/// The 12-byte PROXY v2 signature.
const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// A PROXY v2 header (`PROXY`, TCP) naming `client` and `local`: over IPv4 when both are, else
/// over IPv6 with IPv4 addresses mapped.
pub fn proxy_v2(client: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let mut h = SIGNATURE.to_vec();
    h.push(0x21);
    match (client, local) {
        (SocketAddr::V4(c), SocketAddr::V4(l)) => {
            h.push(0x11);
            h.extend_from_slice(&12u16.to_be_bytes());
            h.extend_from_slice(&c.ip().octets());
            h.extend_from_slice(&l.ip().octets());
            h.extend_from_slice(&c.port().to_be_bytes());
            h.extend_from_slice(&l.port().to_be_bytes());
        }
        (c, l) => {
            let v6 = |a: SocketAddr| match a {
                SocketAddr::V4(v) => v.ip().to_ipv6_mapped(),
                SocketAddr::V6(v) => *v.ip(),
            };
            h.push(0x21);
            h.extend_from_slice(&36u16.to_be_bytes());
            h.extend_from_slice(&v6(c).octets());
            h.extend_from_slice(&v6(l).octets());
            h.extend_from_slice(&c.port().to_be_bytes());
            h.extend_from_slice(&l.port().to_be_bytes());
        }
    }
    h
}

/// The key a source's connections are counted under: an IPv4 address, or an IPv6 /64.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut s = v6.segments();
            s[4..].fill(0);
            IpAddr::V6(s.into())
        }
    }
}

/// Connections held per source.
struct Sources {
    held: Mutex<HashMap<IpAddr, usize>>,
    max: usize,
}

/// One source's connection, counted until dropped.
struct SourceSlot {
    sources: Arc<Sources>,
    key: IpAddr,
}

impl Sources {
    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<SourceSlot> {
        let key = source_key(ip);
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let count = held.entry(key).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(SourceSlot { sources: self.clone(), key })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut held = self.sources.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

/// When a byte last moved, either way.
struct Activity(Mutex<Instant>);

impl Activity {
    fn touch(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
    fn idle_for(&self) -> Duration {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
    }
}

/// How one direction ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    Eof,
    Idle,
    Failed,
}

/// Copies `from` to `to` until `from` ends, a side fails, or nothing has moved either way for
/// `idle`.
async fn pump<R, W>(from: &mut R, to: &mut W, activity: &Activity, idle: Duration) -> End
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let wait = idle.saturating_sub(activity.idle_for());
        if wait.is_zero() {
            return End::Idle;
        }
        let n = match tokio::time::timeout(wait, from.read(&mut buf)).await {
            Ok(Ok(0)) => return End::Eof,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return End::Failed,
            Err(_) => continue,
        };
        activity.touch();
        match tokio::time::timeout(idle, to.write_all(&buf[..n])).await {
            Ok(Ok(())) => activity.touch(),
            _ => return End::Failed,
        }
    }
}

/// Relays `client` and `enclave` (module docs): over once the enclave's side ends or the flow
/// goes `idle`; a client's close is passed on to the enclave, which then finishes.
pub async fn relay<C, E>(client: C, enclave: E, idle: Duration)
where
    C: AsyncRead + AsyncWrite + Unpin,
    E: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut enclave_read, mut enclave_write) = tokio::io::split(enclave);
    let activity = Activity(Mutex::new(Instant::now()));
    let down = pump(&mut enclave_read, &mut client_write, &activity, idle);
    let up = async {
        if pump(&mut client_read, &mut enclave_write, &activity, idle).await == End::Eof {
            let _ = enclave_write.shutdown().await;
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = down => {}
        _ = up => {}
    }
}

/// Relays one client to the enclave.
pub async fn forward(client: TcpStream, peer: SocketAddr, enclave_cid: u32, enclave_port: u32, idle: Duration) {
    let local = match client.local_addr() {
        Ok(local) => local,
        Err(e) => return tracing::debug!(%peer, error = %e, "inbound connection without a local address"),
    };
    let _ = client.set_nodelay(true);
    let opened = async {
        let mut enclave = seal_net::vsock::connect(enclave_cid, enclave_port, ENCLAVE_CONNECT_TIMEOUT).await?;
        enclave.write_all(&proxy_v2(peer, local)).await?;
        std::io::Result::Ok(enclave)
    };
    let enclave = match tokio::time::timeout(ENCLAVE_CONNECT_TIMEOUT, opened).await {
        Ok(Ok(enclave)) => enclave,
        Ok(Err(e)) => return tracing::info!(%peer, error = %e, "the enclave's port does not answer"),
        Err(_) => return tracing::info!(%peer, "the enclave's port does not answer"),
    };
    relay(client, enclave, idle).await;
    tracing::debug!(%peer, "inbound connection closed");
}

/// Accepts clients on `listener` within `limits` and relays each to `enclave_cid:enclave_port`.
pub async fn serve(listener: TcpListener, enclave_cid: u32, enclave_port: u32, limits: Limits) {
    let slots = Arc::new(Semaphore::new(limits.connections));
    let sources = Arc::new(Sources { held: Mutex::new(HashMap::new()), max: limits.per_source });
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "inbound accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "inbound connection refused: the port is full");
            continue;
        };
        let Some(source) = sources.take(peer.ip()) else {
            tracing::debug!(%peer, "inbound connection refused: its source holds its share of the port");
            continue;
        };
        tokio::spawn(async move {
            forward(client, peer, enclave_cid, enclave_port, limits.idle).await;
            drop((slot, source));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_keyed_as_the_enclave_keys_them() {
        let key = |s: &str| source_key(s.parse().unwrap());
        assert_eq!(key("203.0.113.7"), key("::ffff:203.0.113.7"));
        assert_ne!(key("203.0.113.7"), key("203.0.113.8"));
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb::2"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
    }

    #[test]
    fn the_spec_example() {
        // TCP over IPv4, 192.0.2.1:56324 to 192.0.2.2:443 (as the enclave's parser's test).
        let v4: Vec<u8> =
            [&SIGNATURE[..], &[0x21, 0x11, 0, 12, 192, 0, 2, 1, 192, 0, 2, 2, 0xdc, 0x04, 0x01, 0xbb]].concat();
        assert_eq!(proxy_v2("192.0.2.1:56324".parse().unwrap(), "192.0.2.2:443".parse().unwrap()), v4);
        let mixed = proxy_v2("[2001:db8::1]:1".parse().unwrap(), "192.0.2.2:443".parse().unwrap());
        assert_eq!(mixed.len(), 16 + 36);
        assert_eq!(&mixed[12..16], &[0x21, 0x21, 0, 36]);
        assert_eq!(&mixed[32..48], &"::ffff:192.0.2.2".parse::<std::net::Ipv6Addr>().unwrap().octets());
    }
}
