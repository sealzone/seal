//! Outbound network. Three rules, enforced by types:
//!
//! 1. An `UpstreamStream` is only ever a TLS stream verified against the trust
//!    anchors compiled into the image for the destination's host. Nothing
//!    outside this crate can construct one (except `testing`).
//! 2. Protocol-specific TLS startup (Postgres `SSLRequest`) happens here, so
//!    adapters never touch a plaintext upstream socket.
//! 3. When the sealed policy pins upstream keys (`SecretPolicy::pins`), the verified chain
//!    must also contain a pinned key. Pins narrow the baked roots, never replace them.
//!
//! Every outbound byte stream starts at a `Dialer`. `TcpDialer` is the usual one; a cloud
//! without a network interface supplies its own (`seal-cloud`). Whatever carries the bytes is
//! untrusted, like any host: everything above it is TLS verified here, or HPKE-sealed.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use seal_proto::policy::{Destination, SpkiPin};
use tokio::io::{AsyncRead, AsyncWrite};

mod https;
#[cfg(test)]
mod test_pki;
#[cfg(test)]
mod tls_tests;
mod verify;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Any duplex byte stream (inbound connections, test pipes).
pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("connect to {host}:{port}: {reason}")]
    Connect { host: String, port: u16, reason: String },
    #[error("TLS with {host}: {reason}")]
    Tls { host: String, reason: String },
    /// Postgres answered `N` to SSLRequest: refused, never downgraded.
    #[error("{host} does not offer TLS")]
    NoTls { host: String },
    /// The chain verified, but no certificate in it carries a pinned key.
    #[error("{host} presented no pinned key")]
    PinMismatch { host: String },
    #[error("http: {0}")]
    Http(String),
}

impl NetError {
    /// The public code (`Tls`, `NoTls`, `PinMismatch` → `PolicyDenied`, the rest → `Unavailable`).
    pub fn code(&self) -> seal_proto::ErrorCode {
        use seal_proto::ErrorCode;
        match self {
            NetError::Tls { .. } | NetError::NoTls { .. } | NetError::PinMismatch { .. } => ErrorCode::PolicyDenied,
            NetError::Connect { .. } | NetError::Http(_) => ErrorCode::Unavailable,
        }
    }
}

/// A verified TLS stream to a destination. Opaque on purpose.
pub struct UpstreamStream {
    inner: BoxStream,
    /// ALPN protocol the server selected, if any.
    pub alpn: Option<Vec<u8>>,
    /// RFC 5929 `tls-server-end-point` channel-binding data: the hash of the verified leaf
    /// certificate under its signature's hash (SHA-256 for MD5, SHA-1 and SHA-256; SHA-384 and
    /// SHA-512 as signed). `None` when the signature algorithm names no hash (Ed25519,
    /// RSASSA-PSS) or the stream is not TLS.
    pub tls_server_end_point: Option<Vec<u8>>,
}

impl UpstreamStream {
    pub fn into_inner(self) -> BoxStream {
        self.inner
    }
    /// Adapter unit tests only: wrap any stream as if it were verified TLS.
    #[cfg(feature = "testing")]
    pub fn from_test_stream(inner: BoxStream) -> Self {
        Self { inner, alpn: None, tls_server_end_point: None }
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
pub trait UpstreamConnector: Send + Sync {
    /// TLS to `dest`, verified for `dest.host()` (SNI and certificate name) against the baked
    /// roots and, when `pins` is non-empty, holding a pinned key (`PinMismatch` otherwise).
    /// Names match exactly; the one exception is a DNS SAN written with a single trailing dot
    /// (`….sql.goog.`, as Cloud SQL writes them), which matches the same name without it after
    /// the chain itself has verified; nothing else widens webpki's rules. Per destination:
    /// - `Https`: ALPN `http/1.1`.
    /// - `Postgres`: `SSLRequest` → expect `S` → TLS (`N` = `NetError::NoTls`).
    /// - `ClickHouse`, `Redis`: direct TLS.
    async fn connect(&self, dest: &Destination, pins: &BTreeSet<SpkiPin>) -> Result<UpstreamStream, NetError>;
}

/// Managed-database CAs not in the Mozilla set, as PEM. Sources and hashes: `certs/README.md`.
const BAKED_PEM: &[&[u8]] = &[include_bytes!("../certs/aws-rds-global-bundle.pem")];

/// The trust anchors baked into the image: Mozilla roots (webpki-roots) plus
/// managed-database CAs from `certs/` (AWS RDS global bundle). Azure Database and
/// Azure Cache roots are already in the Mozilla set. Changing them changes the measurement.
pub fn baked_roots() -> rustls::RootCertStore {
    use rustls::pki_types::{pem::PemObject, CertificateDer};

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for pem in BAKED_PEM {
        for cert in CertificateDer::pem_slice_iter(pem) {
            // Compile-time data, checked by `tests::baked_roots_load`.
            roots.add(cert.expect("baked PEM parses")).expect("baked cert is a valid trust anchor");
        }
    }
    roots
}

/// Opens a raw byte stream to `host:port`. Name resolution happens behind it, so it is
/// untrusted: callers verify TLS on top.
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, NetError>;
}

/// Time to resolve and open a TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time from an open stream to a finished TLS handshake (including Postgres `SSLRequest`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// `[::1]` → `::1`; anything else unchanged.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

/// OS DNS + TCP, with a 10 s connect timeout.
pub struct TcpDialer;

#[async_trait]
impl Dialer for TcpDialer {
    async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, NetError> {
        let err = |reason: String| NetError::Connect { host: host.to_string(), port, reason };
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((unbracket(host), port)))
            .await
            .map_err(|_| err(format!("timed out after {} s", CONNECT_TIMEOUT.as_secs())))?
            .map_err(|e| err(e.to_string()))?;
        stream.set_nodelay(true).map_err(|e| err(e.to_string()))?;
        Ok(Box::new(stream))
    }
}

/// Sends one datagram to `host:port` and returns the one reply (Roughtime). Untrusted like a
/// `Dialer`: callers authenticate the reply themselves.
#[async_trait]
pub trait Datagrams: Send + Sync {
    async fn exchange(
        &self,
        host: &str,
        port: u16,
        request: &[u8],
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, NetError>;
}

/// OS DNS + UDP: a fresh ephemeral socket per exchange, connected to the first resolved
/// address, so only datagrams from it are read. `timeout` covers resolution and the reply.
pub struct UdpDatagrams;

#[async_trait]
impl Datagrams for UdpDatagrams {
    async fn exchange(
        &self,
        host: &str,
        port: u16,
        request: &[u8],
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, NetError> {
        let err = |reason: String| NetError::Connect { host: host.to_string(), port, reason };
        let exchange = async {
            let addr = tokio::net::lookup_host((unbracket(host), port))
                .await
                .map_err(|e| err(e.to_string()))?
                .next()
                .ok_or_else(|| err("no address".into()))?;
            let local: std::net::SocketAddr = if addr.is_ipv4() {
                (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let socket = tokio::net::UdpSocket::bind(local).await.map_err(|e| err(e.to_string()))?;
            socket.connect(addr).await.map_err(|e| err(e.to_string()))?;
            socket.send(request).await.map_err(|e| err(e.to_string()))?;
            let mut buf = vec![0u8; 65_535];
            let n = socket.recv(&mut buf).await.map_err(|e| err(e.to_string()))?;
            buf.truncate(n);
            Ok(buf)
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| err(format!("no reply within {} ms", timeout.as_millis())))?
    }
}

/// Production connector: `dialer`, then TLS (1.2 or 1.3, `ring`, no session resumption)
/// against `baked_roots()`. A pinned key counts only on a path that verifies: the leaf's own
/// key, or an intermediate or root the leaf chains to; a pinned certificate merely sent along
/// does not. A Postgres reply other than `S` or `N` to `SSLRequest` is `NetError::Tls`. The
/// dial and the handshake each time out after 10 s (`NetError::Connect`).
pub struct BakedRootsConnector {
    dialer: Arc<dyn Dialer>,
    roots: Arc<rustls::RootCertStore>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
    /// ALPN `http/1.1`, for `Https`.
    http: Arc<rustls::ClientConfig>,
    /// No ALPN, for the database protocols.
    plain: Arc<rustls::ClientConfig>,
}

impl BakedRootsConnector {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self::from_roots(dialer, baked_roots()).expect("baked roots build a verifier")
    }

    /// Sim builds only: also trust these PEM roots.
    #[cfg(feature = "sim")]
    pub fn with_extra_roots(dialer: Arc<dyn Dialer>, extra_pem: &[u8]) -> Result<Self, NetError> {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let bad = |reason: String| NetError::Tls { host: "extra roots".into(), reason };
        let mut roots = baked_roots();
        let mut added = 0;
        for cert in CertificateDer::pem_slice_iter(extra_pem) {
            roots.add(cert.map_err(|e| bad(e.to_string()))?).map_err(|e| bad(e.to_string()))?;
            added += 1;
        }
        if added == 0 {
            return Err(bad("no certificate in PEM".into()));
        }
        Self::from_roots(dialer, roots)
    }

    /// A connector trusting exactly `roots`.
    fn from_roots(dialer: Arc<dyn Dialer>, roots: rustls::RootCertStore) -> Result<Self, NetError> {
        let bad = |reason: String| NetError::Tls { host: "trust anchors".into(), reason };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let algs = provider.signature_verification_algorithms;
        let roots = Arc::new(roots);
        let verifier = verify::SealVerifier::new(roots.clone(), provider.clone()).map_err(bad)?;
        let mut plain = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| bad(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        // Every connection verifies the presented chain now, never a resumed session's.
        plain.resumption = rustls::client::Resumption::disabled();
        let mut http = plain.clone();
        http.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self { dialer, roots, algs, http: Arc::new(http), plain: Arc::new(plain) })
    }

    async fn handshake(
        &self,
        dest: &Destination,
        name: rustls::pki_types::ServerName<'static>,
        mut stream: BoxStream,
    ) -> Result<tokio_rustls::client::TlsStream<BoxStream>, NetError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let host = dest.host();
        let io =
            |e: std::io::Error| NetError::Connect { host: host.to_string(), port: dest.port(), reason: e.to_string() };
        let config = match dest {
            Destination::Https { .. } => self.http.clone(),
            Destination::Postgres { .. } | Destination::ClickHouse { .. } | Destination::Redis { .. } => {
                self.plain.clone()
            }
        };
        if let Destination::Postgres { .. } = dest {
            // SSLRequest: Int32 length 8, Int32 code 80877103. Read exactly one byte back, so
            // nothing the server sends before the handshake is ever taken as TLS-protected.
            stream.write_all(&[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]).await.map_err(io)?;
            stream.flush().await.map_err(io)?;
            let mut reply = [0u8; 1];
            stream.read_exact(&mut reply).await.map_err(io)?;
            match reply[0] {
                b'S' => {}
                b'N' => return Err(NetError::NoTls { host: host.to_string() }),
                other => {
                    return Err(NetError::Tls {
                        host: host.to_string(),
                        reason: format!("unexpected reply 0x{other:02x} to SSLRequest"),
                    })
                }
            }
        }
        tokio_rustls::TlsConnector::from(config).connect(name, stream).await.map_err(|e| {
            match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
                Some(tls) => NetError::Tls { host: host.to_string(), reason: tls.to_string() },
                None => io(e),
            }
        })
    }
}

#[async_trait]
impl UpstreamConnector for BakedRootsConnector {
    async fn connect(&self, dest: &Destination, pins: &BTreeSet<SpkiPin>) -> Result<UpstreamStream, NetError> {
        let host = dest.host();
        let bare = unbracket(host);
        let name = rustls::pki_types::ServerName::try_from(bare.to_string()).map_err(|_| NetError::Tls {
            host: host.to_string(),
            reason: "not a valid DNS name or IP address".into(),
        })?;
        let stream = self.dialer.dial(bare, dest.port()).await?;
        let tls =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake(dest, name, stream)).await.map_err(|_| {
                NetError::Connect {
                    host: host.to_string(),
                    port: dest.port(),
                    reason: format!("TLS handshake timed out after {} s", HANDSHAKE_TIMEOUT.as_secs()),
                }
            })??;
        let (_, conn) = tls.get_ref();
        if !pins.is_empty() {
            let presented = conn.peer_certificates().unwrap_or_default();
            let now = rustls::pki_types::UnixTime::now();
            if !verify::chain_has_pin(presented, &self.roots, pins, &self.algs, now) {
                tracing::warn!(host, "upstream chain carries no pinned key");
                return Err(NetError::PinMismatch { host: host.to_string() });
            }
        }
        let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
        let tls_server_end_point = conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|leaf| verify::tls_server_end_point(leaf));
        Ok(UpstreamStream { inner: Box::new(tls), alpn, tls_server_end_point })
    }
}

/// Minimal HTTPS client for JSON APIs (JWKS, STS, the control service).
/// URL must be `https://`; verified like any upstream (no pins); bodies capped at 1 MiB; 10 s
/// timeout for the whole exchange. One connection per request; redirects are returned, never
/// followed. `post` and `put` send `content-type: application/json` unless `headers` set one.
pub struct HttpsClient {
    connector: Arc<dyn UpstreamConnector>,
    timeout: Duration,
}

impl HttpsClient {
    pub fn new(connector: Arc<dyn UpstreamConnector>) -> Self {
        Self { connector, timeout: https::TIMEOUT }
    }
    pub async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), NetError> {
        self.request(hyper::Method::GET, url, headers, None).await
    }
    pub async fn post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<(u16, Vec<u8>), NetError> {
        self.request(hyper::Method::POST, url, headers, Some(body)).await
    }
    pub async fn put(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<(u16, Vec<u8>), NetError> {
        self.request(hyper::Method::PUT, url, headers, Some(body)).await
    }
    pub async fn delete(&self, url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), NetError> {
        self.request(hyper::Method::DELETE, url, headers, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_roots_load() {
        let roots = baked_roots();
        // 114 Amazon RDS regional roots in the bundle; see certs/README.md.
        assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len() + 114);
    }
}
