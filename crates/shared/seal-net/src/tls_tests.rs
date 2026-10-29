//! Connector and client tests against local TLS servers and a test PKI.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use seal_proto::policy::{Destination, SpkiPin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::test_pki::{dns, intermediate, intermediate_living, ip, leaf, root, root_living, Issued, Life};
use crate::*;

const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

/// Dials one fixed address whatever the host, so any name can be served locally.
struct FixedDialer(SocketAddr);

#[async_trait]
impl Dialer for FixedDialer {
    async fn dial(&self, _host: &str, _port: u16) -> Result<BoxStream, NetError> {
        TcpDialer.dial(&self.0.ip().to_string(), self.0.port()).await
    }
}

/// What the server does before TLS.
#[derive(Clone, Copy)]
enum Startup {
    Direct,
    /// Expect an SSLRequest, answer with this byte, then TLS if it was `S`.
    Postgres(u8),
}

/// What the server does after TLS.
#[derive(Clone)]
enum Handler {
    /// Write `hello`.
    Hello,
    /// Read one HTTP request (headers and `content-length` body), report it, write `response`.
    Http(Vec<u8>, mpsc::UnboundedSender<Vec<u8>>),
    /// Never answer.
    Silent,
}

struct Server {
    chain: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    alpn: Vec<Vec<u8>>,
    startup: Startup,
    handler: Handler,
}

impl Server {
    fn new(leaf: &Issued, extra: &[&Issued]) -> Self {
        let mut chain = vec![leaf.der.clone()];
        chain.extend(extra.iter().map(|c| c.der.clone()));
        Self { chain, key: leaf.key_der(), alpn: vec![], startup: Startup::Direct, handler: Handler::Hello }
    }

    fn alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    fn startup(mut self, startup: Startup) -> Self {
        self.startup = startup;
        self
    }

    fn handler(mut self, handler: Handler) -> Self {
        self.handler = handler;
        self
    }

    /// Serves every connection on a fresh loopback port.
    async fn spawn(self) -> SocketAddr {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.chain, self.key)
            .unwrap();
        config.alpn_protocols = self.alpn;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (startup, handler) = (self.startup, self.handler);
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Startup::Postgres(reply) = startup {
                        let mut req = [0u8; 8];
                        if tcp.read_exact(&mut req).await.is_err() || req != SSL_REQUEST {
                            return;
                        }
                        tcp.write_all(&[reply]).await.unwrap();
                        if reply != b'S' {
                            return;
                        }
                    }
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    match handler {
                        Handler::Hello => {
                            let _ = tls.write_all(b"hello").await;
                            let _ = tls.shutdown().await;
                        }
                        Handler::Http(response, seen) => {
                            let request = read_http_request(&mut tls).await;
                            let _ = seen.send(request);
                            let _ = tls.write_all(&response).await;
                            let _ = tls.shutdown().await;
                        }
                        Handler::Silent => {
                            let mut sink = [0u8; 1024];
                            while let Ok(n) = tls.read(&mut sink).await {
                                if n == 0 {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }
}

async fn read_http_request(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() {
            return buf;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    let len =
        head.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse::<usize>().unwrap());
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
    buf.extend_from_slice(&body);
    buf
}

/// Baked roots plus `extra`, as a sim build's `with_extra_roots` would trust.
fn connector(addr: SocketAddr, extra: &[&Issued]) -> BakedRootsConnector {
    let mut roots = baked_roots();
    for r in extra {
        roots.add(r.der.clone()).unwrap();
    }
    BakedRootsConnector::from_roots(Arc::new(FixedDialer(addr)), roots).unwrap()
}

fn https(host: &str) -> Destination {
    Destination::Https { host: host.into(), port: 443, path_prefix: "/".into() }
}

fn postgres(host: &str) -> Destination {
    Destination::Postgres { host: host.into(), port: 5432, user: "app".into(), database: "app".into() }
}

fn redis(host: &str) -> Destination {
    Destination::Redis { host: host.into(), port: 6379, user: None, db: 0 }
}

fn clickhouse(host: &str) -> Destination {
    Destination::ClickHouse { host: host.into(), port: 9440, user: "app".into(), database: None }
}

fn no_pins() -> BTreeSet<SpkiPin> {
    BTreeSet::new()
}

fn pins(p: &[SpkiPin]) -> BTreeSet<SpkiPin> {
    p.iter().copied().collect()
}

async fn read_all(stream: UpstreamStream) -> Vec<u8> {
    let mut inner = stream.into_inner();
    let mut out = Vec::new();
    inner.read_to_end(&mut out).await.unwrap();
    out
}

/// root → inter → leaf for `host`.
struct Pki {
    root: Issued,
    inter: Issued,
    leaf: Issued,
}

fn pki(label: &str, sans: Vec<x509_cert::ext::pkix::name::GeneralName>, life: Life) -> Pki {
    let root = root(&format!("{label} root"));
    let inter = intermediate(&root, &format!("{label} inter"));
    let leaf = leaf(&inter, &format!("{label} leaf"), sans, life);
    Pki { root, inter, leaf }
}

#[track_caller]
fn assert_tls(r: Result<UpstreamStream, NetError>) {
    match r {
        Err(NetError::Tls { .. }) => {}
        Err(e) => panic!("expected a TLS error, got {e:?}"),
        Ok(_) => panic!("expected a TLS error, got a stream"),
    }
}

#[tokio::test]
async fn https_verifies_and_sets_alpn() {
    let p = pki("https", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).alpn(&[b"h2", b"http/1.1"]).spawn().await;
    let stream = connector(addr, &[&p.root]).connect(&https("api.example.test"), &no_pins()).await.unwrap();
    assert_eq!(stream.alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert_eq!(read_all(stream).await, b"hello");
}

#[tokio::test]
async fn databases_use_direct_tls_without_alpn() {
    let p = pki("db", vec![dns("db.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).alpn(&[b"http/1.1"]).spawn().await;
    let c = connector(addr, &[&p.root]);
    for dest in [redis("db.example.test"), clickhouse("db.example.test")] {
        let stream = c.connect(&dest, &no_pins()).await.unwrap();
        assert_eq!(stream.alpn, None);
        assert_eq!(read_all(stream).await, b"hello");
    }
}

#[tokio::test]
async fn wrong_name_is_refused() {
    let p = pki("name", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    let c = connector(addr, &[&p.root]);
    assert_tls(c.connect(&https("evil.example.test"), &no_pins()).await);
    assert_tls(c.connect(&https("example.test"), &no_pins()).await);
}

#[tokio::test]
async fn expired_is_refused() {
    let p = pki("expired", vec![dns("api.example.test")], Life::Expired);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    assert_tls(connector(addr, &[&p.root]).connect(&https("api.example.test"), &no_pins()).await);
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[test]
fn trusted_time_is_none_until_recorded() {
    use rustls::time_provider::TimeProvider;
    let time = TrustedTlsTime::new();
    assert!(time.current_time().is_none());
    time.record(1_000);
    let now = time.current_time().unwrap().as_secs();
    assert!((1_000..=1_002).contains(&now), "{now}");
}

#[tokio::test]
async fn trusted_time_decides_validity() {
    const DAY: u64 = 86_400;
    // A whole chain valid from 3 days ago until yesterday.
    let root = root_living("trusted root", Life::Expired);
    let inter = intermediate_living(&root, "trusted inter", Life::Expired);
    let p = Pki { leaf: leaf(&inter, "trusted leaf", vec![dns("api.example.test")], Life::Expired), inter, root };
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    let time = Arc::new(TrustedTlsTime::new());
    let c = connector(addr, &[&p.root]).with_time(time.clone());
    // No reading yet: refused, never the system clock.
    match c.connect(&https("api.example.test"), &no_pins()).await {
        Err(NetError::Tls { reason, .. }) => assert!(reason.contains("current time"), "{reason}"),
        other => panic!("expected a TLS error, got {:?}", other.err()),
    }
    // While the leaf was valid: accepted, pins included, although it has expired by the system clock.
    time.record(unix_now() - 2 * DAY);
    let stream = c.connect(&https("api.example.test"), &pins(&[p.inter.pin()])).await.unwrap();
    assert_eq!(read_all(stream).await, b"hello");
    // After it expired, and before it was valid.
    time.record(unix_now());
    assert_tls(c.connect(&https("api.example.test"), &no_pins()).await);
    time.record(unix_now() - 4 * DAY);
    assert_tls(c.connect(&https("api.example.test"), &no_pins()).await);
}

#[tokio::test]
async fn untrusted_root_is_refused() {
    let p = pki("untrusted", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter, &p.root]).spawn().await;
    // Only the baked roots: the presented root is not one of them.
    assert_tls(connector(addr, &[]).connect(&https("api.example.test"), &no_pins()).await);
}

#[tokio::test]
async fn pins_match_leaf_intermediate_or_root() {
    let p = pki("pins", vec![dns("api.example.test")], Life::Valid);
    // The root is not presented: it is matched from the trust store.
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    let c = connector(addr, &[&p.root]);
    let other = root("unrelated").pin();
    for pin in [p.leaf.pin(), p.inter.pin(), p.root.pin()] {
        let stream = c.connect(&https("api.example.test"), &pins(&[other, pin])).await.unwrap();
        assert_eq!(read_all(stream).await, b"hello");
    }
}

#[tokio::test]
async fn pin_on_presented_root_matches() {
    let p = pki("presented", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter, &p.root]).spawn().await;
    let stream = connector(addr, &[&p.root]).connect(&https("api.example.test"), &pins(&[p.root.pin()])).await.unwrap();
    assert_eq!(read_all(stream).await, b"hello");
}

#[tokio::test]
async fn pin_mismatch() {
    let p = pki("mismatch", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    let c = connector(addr, &[&p.root]);
    // A random key, and a baked Mozilla root the chain does not lead to.
    let mozilla_pin = crate::verify::anchor_pin(&webpki_roots::TLS_SERVER_ROOTS[0]);
    for set in [pins(&[SpkiPin([7; 32])]), pins(&[mozilla_pin])] {
        match c.connect(&https("api.example.test"), &set).await {
            Err(NetError::PinMismatch { host }) => assert_eq!(host, "api.example.test"),
            other => panic!("expected PinMismatch, got {:?}", other.err()),
        }
    }
    // Pins never replace the roots: a pinned leaf under an untrusted root is still refused.
    let untrusted = connector(addr, &[]);
    assert_tls(untrusted.connect(&https("api.example.test"), &pins(&[p.leaf.pin()])).await);
}

#[tokio::test]
async fn pinned_certificate_off_the_path_does_not_count() {
    let p = pki("offpath", vec![dns("api.example.test")], Life::Valid);
    let sibling = intermediate(&p.root, "offpath sibling");
    let addr = Server::new(&p.leaf, &[&p.inter, &sibling]).spawn().await;
    let c = connector(addr, &[&p.root]);
    match c.connect(&https("api.example.test"), &pins(&[sibling.pin()])).await {
        Err(NetError::PinMismatch { .. }) => {}
        other => panic!("expected PinMismatch, got {:?}", other.err()),
    }
    // The real intermediate still matches with the sibling sent along.
    c.connect(&https("api.example.test"), &pins(&[p.inter.pin()])).await.unwrap();
}

#[test]
fn anchor_pin_equals_spki_der_hash() {
    let p = pki("hash", vec![dns("api.example.test")], Life::Valid);
    for cert in [&p.root, &p.inter, &p.leaf] {
        assert_eq!(crate::verify::cert_pin(&cert.der), Some(cert.pin()));
    }
    // And for a real RSA root from the baked set (long-form DER lengths).
    let rds = include_bytes!("../certs/aws-rds-global-bundle.pem");
    use rustls::pki_types::pem::PemObject;
    let first = CertificateDer::pem_slice_iter(rds).next().unwrap().unwrap();
    use x509_cert::der::{Decode, Encode};
    let parsed = x509_cert::Certificate::from_der(first.as_ref()).unwrap();
    let spki = parsed.tbs_certificate().subject_public_key_info().to_der().unwrap();
    use sha2::Digest;
    assert_eq!(crate::verify::cert_pin(&first), Some(SpkiPin(sha2::Sha256::digest(&spki).into())));
}

#[tokio::test]
async fn trailing_dot_san_matches_only_the_exact_name() {
    let p = pki("dot", vec![dns("db.proj.sql.goog.")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).startup(Startup::Postgres(b'S')).spawn().await;
    let c = connector(addr, &[&p.root]);
    let stream = c.connect(&postgres("db.proj.sql.goog"), &no_pins()).await.unwrap();
    assert_eq!(read_all(stream).await, b"hello");
    // Pins still apply on the exception path.
    c.connect(&postgres("db.proj.sql.goog"), &pins(&[p.inter.pin()])).await.unwrap();
    assert!(matches!(
        c.connect(&postgres("db.proj.sql.goog"), &pins(&[SpkiPin([1; 32])])).await,
        Err(NetError::PinMismatch { .. })
    ));
    for host in ["other.proj.sql.goog", "proj.sql.goog", "x.db.proj.sql.goog", "db.proj.sql"] {
        assert_tls(c.connect(&postgres(host), &no_pins()).await);
    }
    // An IP reference never takes the exception.
    assert_tls(c.connect(&postgres("127.0.0.1"), &no_pins()).await);
}

#[test]
fn webpki_alone_rejects_the_trailing_dot_san() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    let p = pki("dot webpki", vec![dns("db.proj.sql.goog.")], Life::Valid);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(p.root.der.clone()).unwrap();
    let roots = Arc::new(roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let name = ServerName::try_from("db.proj.sql.goog").unwrap();
    let chain = [p.inter.der.clone()];
    let plain =
        rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone()).build().unwrap();
    assert!(matches!(
        plain.verify_server_cert(&p.leaf.der, &chain, &name, &[], UnixTime::now()),
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. }
        ))
    ));
    let seal = crate::verify::SealVerifier::new(roots, provider).unwrap();
    seal.verify_server_cert(&p.leaf.der, &chain, &name, &[], UnixTime::now()).unwrap();
    // The exception reports a plain name error when it does not apply.
    let other = ServerName::try_from("other.proj.sql.goog").unwrap();
    assert!(matches!(
        seal.verify_server_cert(&p.leaf.der, &chain, &other, &[], UnixTime::now()),
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName))
    ));
}

#[tokio::test]
async fn trailing_dot_nothing_else_widens() {
    for san in ["db.proj.sql.goog..", "*.proj.sql.goog.", "proj.sql.goog."] {
        let p = pki(&format!("widen {san}"), vec![dns(san)], Life::Valid);
        let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
        assert_tls(connector(addr, &[&p.root]).connect(&https("db.proj.sql.goog"), &no_pins()).await);
    }
}

#[tokio::test]
async fn trailing_dot_needs_a_valid_chain() {
    // Untrusted root.
    let p = pki("dot untrusted", vec![dns("db.proj.sql.goog.")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter, &p.root]).spawn().await;
    assert_tls(connector(addr, &[]).connect(&https("db.proj.sql.goog"), &no_pins()).await);
    // Expired leaf.
    let p = pki("dot expired", vec![dns("db.proj.sql.goog.")], Life::Expired);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    assert_tls(connector(addr, &[&p.root]).connect(&https("db.proj.sql.goog"), &no_pins()).await);
    // Missing intermediate.
    let p = pki("dot nointer", vec![dns("db.proj.sql.goog.")], Life::Valid);
    let addr = Server::new(&p.leaf, &[]).spawn().await;
    assert_tls(connector(addr, &[&p.root]).connect(&https("db.proj.sql.goog"), &no_pins()).await);
}

#[tokio::test]
async fn postgres_ssl_request() {
    let p = pki("pg", vec![dns("pg.example.test")], Life::Valid);
    let ok = Server::new(&p.leaf, &[&p.inter]).startup(Startup::Postgres(b'S')).spawn().await;
    let stream = connector(ok, &[&p.root]).connect(&postgres("pg.example.test"), &no_pins()).await.unwrap();
    assert_eq!(stream.alpn, None);
    assert_eq!(read_all(stream).await, b"hello");

    let no = Server::new(&p.leaf, &[&p.inter]).startup(Startup::Postgres(b'N')).spawn().await;
    match connector(no, &[&p.root]).connect(&postgres("pg.example.test"), &no_pins()).await {
        Err(e @ NetError::NoTls { .. }) => assert_eq!(e.code(), seal_proto::ErrorCode::PolicyDenied),
        other => panic!("expected NoTls, got {:?}", other.err()),
    }

    let garbage = Server::new(&p.leaf, &[&p.inter]).startup(Startup::Postgres(b'E')).spawn().await;
    assert_tls(connector(garbage, &[&p.root]).connect(&postgres("pg.example.test"), &no_pins()).await);
}

#[tokio::test]
async fn postgres_server_bytes_before_tls_are_not_accepted() {
    // The server answers `S` and then plaintext: it must not pass as the handshake.
    let p = pki("pginject", vec![dns("pg.example.test")], Life::Valid);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut req = [0u8; 8];
        tcp.read_exact(&mut req).await.unwrap();
        tcp.write_all(b"SZ\x00\x00\x00\x05I").await.unwrap();
        let mut sink = Vec::new();
        let _ = tcp.read_to_end(&mut sink).await;
    });
    assert!(connector(addr, &[&p.root]).connect(&postgres("pg.example.test"), &no_pins()).await.is_err());
}

#[tokio::test]
async fn ip_literal_hosts_verify_ip_sans() {
    let p = pki("ip", vec![ip("127.0.0.1"), ip("::1"), dns("127.0.0.2")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    // The real dialer, by IP.
    let mut roots = baked_roots();
    roots.add(p.root.der.clone()).unwrap();
    let real = BakedRootsConnector::from_roots(Arc::new(TcpDialer), roots).unwrap();
    let dest = Destination::Https { host: "127.0.0.1".into(), port: addr.port(), path_prefix: "/".into() };
    assert_eq!(read_all(real.connect(&dest, &no_pins()).await.unwrap()).await, b"hello");

    let c = connector(addr, &[&p.root]);
    assert_eq!(read_all(c.connect(&https("[::1]"), &no_pins()).await.unwrap()).await, b"hello");
    // A DNS SAN spelling an address is not an IP SAN.
    assert_tls(c.connect(&https("127.0.0.2"), &no_pins()).await);
}

#[tokio::test]
async fn dial_errors_are_connect_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    match TcpDialer.dial("127.0.0.1", port).await {
        Err(e @ NetError::Connect { .. }) => assert_eq!(e.code(), seal_proto::ErrorCode::Unavailable),
        Err(e) => panic!("expected Connect, got {e:?}"),
        Ok(_) => panic!("expected Connect, got a stream"),
    }
}

#[cfg(feature = "sim")]
#[tokio::test]
async fn with_extra_roots_trusts_the_given_pem() {
    let p = pki("sim", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    let c = BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(addr)), p.root.pem().as_bytes()).unwrap();
    assert_eq!(read_all(c.connect(&https("api.example.test"), &no_pins()).await.unwrap()).await, b"hello");
    assert!(BakedRootsConnector::with_extra_roots(Arc::new(TcpDialer), b"not pem").is_err());
}

#[tokio::test]
async fn new_uses_baked_roots_only() {
    let p = pki("new", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter, &p.root]).spawn().await;
    let c = BakedRootsConnector::new(Arc::new(FixedDialer(addr)));
    assert_tls(c.connect(&https("api.example.test"), &no_pins()).await);
}

// HttpsClient

fn http_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n{headers}\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

async fn http_server(response: Vec<u8>) -> (HttpsClient, mpsc::UnboundedReceiver<Vec<u8>>) {
    let p = pki("http", vec![dns("api.example.test")], Life::Valid);
    let (tx, rx) = mpsc::unbounded_channel();
    let addr = Server::new(&p.leaf, &[&p.inter]).handler(Handler::Http(response, tx)).spawn().await;
    (HttpsClient::new(Arc::new(connector(addr, &[&p.root]))), rx)
}

#[tokio::test]
async fn https_client_get_and_post() {
    let (client, mut seen) = http_server(http_response("200 OK", "", b"{\"ok\":true}")).await;
    let (status, body) =
        client.get("https://api.example.test/keys?x=1", &[("authorization", "Bearer t")]).await.unwrap();
    assert_eq!((status, body.as_slice()), (200, &b"{\"ok\":true}"[..]));
    let req = String::from_utf8(seen.recv().await.unwrap()).unwrap();
    assert!(req.starts_with("GET /keys?x=1 HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("host: api.example.test\r\n"), "{req}");
    assert!(req.contains("authorization: Bearer t\r\n"), "{req}");

    let (status, _) = client.post("https://api.example.test/token", &[], b"{\"a\":1}").await.unwrap();
    assert_eq!(status, 200);
    let req = String::from_utf8(seen.recv().await.unwrap()).unwrap();
    assert!(req.starts_with("POST /token HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("content-type: application/json\r\n"), "{req}");
    assert!(req.ends_with("\r\n\r\n{\"a\":1}"), "{req}");

    client
        .post("https://api.example.test/form", &[("content-type", "application/x-www-form-urlencoded")], b"a=1")
        .await
        .unwrap();
    let req = String::from_utf8(seen.recv().await.unwrap()).unwrap();
    assert!(req.contains("content-type: application/x-www-form-urlencoded\r\n"), "{req}");
    assert!(!req.contains("application/json"), "{req}");
}

#[tokio::test]
async fn https_client_returns_redirects() {
    let (client, _seen) = http_server(http_response("302 Found", "location: https://elsewhere.test/\r\n", b"")).await;
    let (status, body) = client.get("https://api.example.test/", &[]).await.unwrap();
    assert_eq!((status, body.len()), (302, 0));
}

#[tokio::test]
async fn https_client_caps_the_body() {
    let (client, _seen) = http_server(http_response("200 OK", "", &vec![b'a'; https::MAX_BODY])).await;
    assert_eq!(client.get("https://api.example.test/", &[]).await.unwrap().1.len(), https::MAX_BODY);

    let (client, _seen) = http_server(http_response("200 OK", "", &vec![b'a'; https::MAX_BODY + 1])).await;
    match client.get("https://api.example.test/", &[]).await {
        Err(NetError::Http(m)) => assert!(m.contains("1 MiB"), "{m}"),
        other => panic!("expected the cap, got {other:?}"),
    }

    // Chunked, no length up front.
    let mut chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..17 {
        chunked.extend_from_slice(format!("{:x}\r\n", 64 * 1024).as_bytes());
        chunked.extend_from_slice(&vec![b'b'; 64 * 1024]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let (client, _seen) = http_server(chunked).await;
    assert!(matches!(client.get("https://api.example.test/", &[]).await, Err(NetError::Http(_))));
}

#[tokio::test]
async fn https_client_times_out() {
    let p = pki("slow", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).handler(Handler::Silent).spawn().await;
    let mut client = HttpsClient::new(Arc::new(connector(addr, &[&p.root])));
    assert_eq!(client.timeout, Duration::from_secs(10));
    client.timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    match client.get("https://api.example.test/", &[]).await {
        Err(NetError::Http(m)) => assert!(m.contains("timed out"), "{m}"),
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

struct NeverConnect;

#[async_trait]
impl UpstreamConnector for NeverConnect {
    async fn connect(&self, _dest: &Destination, _pins: &BTreeSet<SpkiPin>) -> Result<UpstreamStream, NetError> {
        panic!("must not connect")
    }
}

#[tokio::test]
async fn https_client_refuses_other_urls() {
    let client = HttpsClient::new(Arc::new(NeverConnect));
    for url in [
        "http://api.example.test/",
        "ftp://api.example.test/",
        "api.example.test/x",
        "https://user:pw@api.example.test/",
        "https:///x",
        "",
    ] {
        assert!(matches!(client.get(url, &[]).await, Err(NetError::Http(_))), "{url}");
        assert!(matches!(client.post(url, &[], b"{}").await, Err(NetError::Http(_))), "{url}");
    }
}

#[tokio::test]
async fn https_client_propagates_tls_errors() {
    let p = pki("httpname", vec![dns("api.example.test")], Life::Valid);
    let addr = Server::new(&p.leaf, &[&p.inter]).spawn().await;
    let client = HttpsClient::new(Arc::new(connector(addr, &[&p.root])));
    assert!(matches!(client.get("https://evil.example.test/", &[]).await, Err(NetError::Tls { .. })));
}

// UdpDatagrams

#[tokio::test]
async fn udp_exchange_with_local_echo() {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, from)) = echo.recv_from(&mut buf).await else { return };
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = echo.send_to(&reply, from).await;
        }
    });
    for request in [&b"ping"[..], &[0u8; 1024][..]] {
        let reply = UdpDatagrams.exchange("127.0.0.1", port, request, Duration::from_secs(2)).await.unwrap();
        assert_eq!(&reply[..5], b"echo:");
        assert_eq!(&reply[5..], request);
    }
}

#[tokio::test]
async fn udp_exchange_times_out() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let started = std::time::Instant::now();
    match UdpDatagrams.exchange("127.0.0.1", port, b"ping", Duration::from_millis(200)).await {
        Err(NetError::Connect { .. }) => {}
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(silent);
}
