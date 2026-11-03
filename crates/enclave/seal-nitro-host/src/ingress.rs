//! Ingress: the enclave's one port, served on the instance. Each TCP connection to `listen`
//! is relayed to the enclave's vsock port (its CID, the same port number as the release's
//! `listen`), after a PROXY protocol v2 header naming the client, which the enclave takes as
//! the connection's source (its network rules and per-source limits). At most
//! `max_connections` at once; past that a connection is closed. The enclave terminates TLS
//! itself, so the parent relays bytes it cannot read.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Connecting to the enclave's vsock port.
const ENCLAVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Relays one client to the enclave.
pub async fn forward(mut client: TcpStream, peer: SocketAddr, enclave_cid: u32, enclave_port: u32) {
    let local = match client.local_addr() {
        Ok(local) => local,
        Err(e) => return tracing::debug!(%peer, error = %e, "inbound connection without a local address"),
    };
    let _ = client.set_nodelay(true);
    let mut enclave = match seal_net::vsock::connect(enclave_cid, enclave_port, ENCLAVE_CONNECT_TIMEOUT).await {
        Ok(enclave) => enclave,
        Err(e) => return tracing::info!(%peer, error = %e, "the enclave's port does not answer"),
    };
    if let Err(e) = enclave.write_all(&proxy_v2(peer, local)).await {
        return tracing::debug!(%peer, error = %e, "the enclave closed the connection");
    }
    match tokio::io::copy_bidirectional(&mut client, &mut enclave).await {
        Ok((up, down)) => tracing::debug!(%peer, up, down, "inbound connection closed"),
        Err(e) => tracing::debug!(%peer, error = %e, "inbound connection ended"),
    }
}

/// Accepts clients on `listener` and relays each to `enclave_cid:enclave_port`.
pub async fn serve(listener: TcpListener, enclave_cid: u32, enclave_port: u32, max_connections: usize) {
    let slots = Arc::new(Semaphore::new(max_connections));
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
        tokio::spawn(async move {
            forward(client, peer, enclave_cid, enclave_port).await;
            drop(slot);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
