//! vsock (`AF_VSOCK`) stream sockets, Linux only (elsewhere every call fails with
//! `ErrorKind::Unsupported`): how a Nitro enclave, which has no network
//! interface, and its parent instance reach each other (`seal_proto::nitro`). Whatever crosses
//! one is as untrusted as any network: the enclave's API is TLS it terminates itself, and its
//! outbound streams are TLS verified above the dialer.
//!
//! Sockets are made with `socket2` (already under tokio), so there is no `unsafe` here. A
//! connected vsock socket is handed to tokio as a `TcpStream`: tokio and mio only read, write,
//! peek and shut down a stream socket and wait for its readiness, which `AF_VSOCK` supports
//! alike, so everything works but `peer_addr`, `local_addr` and the TCP options (`set_nodelay`
//! fails; ignore it). Accepting is not left to tokio's `TcpListener`, which cannot name a vsock
//! peer and drops the connection: `VsockListener` registers its listening socket the same way,
//! waits for it to turn readable (a connection is waiting) and accepts with `socket2`.

use std::io;
use std::time::Duration;

use socket2::{Domain, SockAddr, SockRef, Socket, Type};
use tokio::io::Interest;
use tokio::net::TcpStream;

/// Any CID: what a listener binds to.
pub const CID_ANY: u32 = u32::MAX;
/// This machine's own CID, for loopback (the `vsock_loopback` module).
pub const CID_LOCAL: u32 = 1;
/// A port the kernel picks: what a listener binds to in tests.
pub const PORT_ANY: u32 = u32::MAX;

/// Connections waiting to be accepted.
const BACKLOG: i32 = 1024;

/// A stream to `cid:port`, connected within `timeout`.
pub async fn connect(cid: u32, port: u32, timeout: Duration) -> io::Result<TcpStream> {
    let socket = tokio::task::spawn_blocking(move || {
        let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
        socket.connect_timeout(&SockAddr::vsock(cid, port), timeout)?;
        socket.set_nonblocking(true)?;
        Ok::<_, io::Error>(socket)
    })
    .await
    .map_err(io::Error::other)??;
    TcpStream::from_std(socket.into())
}

/// A listening vsock socket.
pub struct VsockListener {
    /// Listening, not connected: registered with tokio only to wait for readiness (module docs).
    socket: TcpStream,
    port: u32,
}

impl VsockListener {
    /// Listens on `cid:port` (`CID_ANY`, and `PORT_ANY` for a port the kernel picks).
    pub fn bind(cid: u32, port: u32) -> io::Result<Self> {
        let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
        socket.bind(&SockAddr::vsock(cid, port))?;
        socket.listen(BACKLOG)?;
        socket.set_nonblocking(true)?;
        let port = socket
            .local_addr()?
            .as_vsock_address()
            .map(|(_, port)| port)
            .ok_or_else(|| io::Error::other("a vsock listener without a vsock address"))?;
        Ok(Self { socket: TcpStream::from_std(socket.into())?, port })
    }

    /// The port listened on.
    pub fn port(&self) -> u32 {
        self.port
    }

    /// The next connection, and its peer's CID.
    pub async fn accept(&self) -> io::Result<(TcpStream, u32)> {
        loop {
            self.socket.readable().await?;
            match self.socket.try_io(Interest::READABLE, || SockRef::from(&self.socket).accept()) {
                Ok((socket, peer)) => {
                    socket.set_nonblocking(true)?;
                    let cid = peer.as_vsock_address().map(|(cid, _)| cid).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "a vsock connection from a non-vsock peer")
                    })?;
                    return Ok((TcpStream::from_std(socket.into())?, cid));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Whether `e` says this machine has no vsock (no module, no device, no loopback transport):
/// for tests that then skip.
pub fn unsupported(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EAFNOSUPPORT | libc::ENODEV | libc::EADDRNOTAVAIL))
        || e.kind() == io::ErrorKind::Unsupported
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Over the loopback transport, when this machine has one.
    #[tokio::test]
    async fn streams_over_loopback() {
        let listener = match VsockListener::bind(CID_ANY, PORT_ANY) {
            Ok(listener) => listener,
            Err(e) if unsupported(&e) => return eprintln!("no vsock here ({e}); skipped"),
            Err(e) => panic!("{e}"),
        };
        let port = listener.port();
        assert_ne!(port, PORT_ANY);
        let server = tokio::spawn(async move {
            let (mut stream, cid) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            // Peeking leaves the bytes for the read.
            let mut peeked = [0u8; 1];
            stream.peek(&mut peeked).await.unwrap();
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
            stream.shutdown().await.unwrap();
            (cid, peeked[0])
        });
        let mut client = match connect(CID_LOCAL, port, Duration::from_secs(5)).await {
            Ok(client) => client,
            Err(e) if unsupported(&e) => return eprintln!("no vsock loopback here ({e}); skipped"),
            Err(e) => panic!("{e}"),
        };
        assert!(client.set_nodelay(true).is_err(), "not TCP");
        client.write_all(b"hello").await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello");
        let (cid, peeked) = server.await.unwrap();
        assert_eq!(cid, CID_LOCAL);
        assert_eq!(peeked, b'h');
    }

    #[tokio::test]
    async fn accepts_one_connection_after_another() {
        let listener = match VsockListener::bind(CID_ANY, PORT_ANY) {
            Ok(listener) => listener,
            Err(e) if unsupported(&e) => return eprintln!("no vsock here ({e}); skipped"),
            Err(e) => panic!("{e}"),
        };
        let port = listener.port();
        let server = tokio::spawn(async move {
            for i in 0..5u8 {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(&[i]).await.unwrap();
            }
        });
        for i in 0..5u8 {
            let Ok(mut client) = connect(CID_LOCAL, port, Duration::from_secs(5)).await else {
                return eprintln!("no vsock loopback here; skipped");
            };
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte[0], i);
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connecting_to_nobody_fails() {
        // A port nobody listens on (on loopback, a reset; without vsock, unsupported).
        let probe = match VsockListener::bind(CID_ANY, PORT_ANY) {
            Ok(listener) => listener.port(),
            Err(_) => 1,
        };
        assert!(connect(CID_LOCAL, probe, Duration::from_secs(5)).await.is_err());
    }
}
