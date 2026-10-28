//! The local servers around Seal's own: the untrusted TLS-terminating proxy in front of the
//! guardian, the HTTPS test upstream, and a small HTTP/1.1 client for the app. Only
//! `server_config` (the test CA's certificate) needs the `sim` feature.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
#[cfg(feature = "sim")]
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream};

#[cfg(feature = "sim")]
use crate::setup::Sim;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The server side of the test CA's `localhost` certificate (`tls-chain.pem`, `tls-key.pem`).
#[cfg(feature = "sim")]
pub fn server_config(sim: &Sim, alpn: &[&[u8]]) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let chain = CertificateDer::pem_file_iter(sim.path("tls-chain.pem"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(sim.path("tls-key.pem"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// A client trusting only the roots in `pem`.
pub fn client_config(pem: &[u8]) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        roots.add(cert?)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Waits until something accepts TCP connections on `port`.
pub async fn wait_for_port(port: u16, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(anyhow!("nothing listens on port {port} after {timeout:?}"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// An ordinary, untrusted TLS-terminating proxy: accepts TLS on `listener` with `tls` and
/// forwards the plain bytes to `backend`, as the proxy in front of a real guardian does.
pub async fn proxy(listener: TcpListener, backend: SocketAddr, tls: Arc<rustls::ServerConfig>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut inbound) = acceptor.accept(stream).await else { return };
            let Ok(mut outbound) = TcpStream::connect(backend).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
        });
    }
}

/// One request the test upstream saw.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// The `Authorization` header, as it arrived.
    pub authorization: Option<String>,
}

/// What the test upstream saw, in order; also appended to a file as JSON lines when made with
/// `recording_to`, for tests in other processes.
#[derive(Default)]
pub struct Upstream {
    pub seen: Mutex<Vec<Seen>>,
    file: Option<Mutex<std::fs::File>>,
}

impl Upstream {
    pub fn recording_to(path: &std::path::Path) -> anyhow::Result<Self> {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { seen: Mutex::default(), file: Some(Mutex::new(file)) })
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn record(&self, seen: Seen) {
        if let Some(file) = &self.file {
            use std::io::Write as _;
            let line = serde_json::to_string(&seen).expect("a request serializes") + "\n";
            let _ = file.lock().unwrap_or_else(|e| e.into_inner()).write_all(line.as_bytes());
        }
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).push(seen);
    }
}

/// The test upstream: HTTPS with the test CA's certificate. Records every request and answers
/// `{"path": ..., "authorization": <the header it got>}`, echoing the credential back so the
/// enclave's response scrubbing has something to do; `GET …/bytes/N` answers N bytes instead,
/// for timing large responses. `print` logs each request to stdout.
pub async fn upstream(listener: TcpListener, tls: Arc<rustls::ServerConfig>, record: Arc<Upstream>, print: bool) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        let (acceptor, record) = (acceptor.clone(), record.clone());
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else { return };
            let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                let record = record.clone();
                async move {
                    let authorization =
                        req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                    let seen = Seen {
                        method: req.method().to_string(),
                        path: req.uri().path().to_string(),
                        authorization: authorization.clone(),
                    };
                    if print {
                        println!(
                            "upstream: {} {} with Authorization: {}",
                            seen.method,
                            seen.path,
                            authorization.as_deref().unwrap_or("(none)")
                        );
                    }
                    record.record(seen);
                    let large = req.uri().path().rsplit_once("/bytes/").and_then(|(_, n)| n.parse::<usize>().ok());
                    if let Some(n) = large.filter(|n| *n <= 1 << 30) {
                        let response = hyper::Response::new(Full::new(Bytes::from(vec![b'x'; n])));
                        return Ok::<_, std::convert::Infallible>(response);
                    }
                    let body = serde_json::json!({"path": req.uri().path(), "authorization": authorization});
                    let response = hyper::Response::builder()
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body.to_string())))
                        .expect("a valid response");
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await;
        });
    }
}

/// One HTTP/1.1 GET on a fresh connection: plain `http://` (the local tunnel) or `https://`
/// trusting only `roots` (PEM). Returns the status and body.
pub async fn get(url: &str, headers: &[(&str, &str)], roots: Option<&[u8]>) -> anyhow::Result<(u16, String)> {
    get_at(None, url, headers, roots).await
}

/// As `get`, but connecting to `addr` when given (another replica serving the URL's host).
pub async fn get_at(
    addr: Option<SocketAddr>,
    url: &str,
    headers: &[(&str, &str)],
    roots: Option<&[u8]>,
) -> anyhow::Result<(u16, String)> {
    let parsed = url::Url::parse(url).with_context(|| url.to_string())?;
    let host = parsed.host_str().ok_or_else(|| anyhow!("{url}: no host"))?.to_string();
    let port = parsed.port_or_known_default().ok_or_else(|| anyhow!("{url}: no port"))?;
    let tcp = match addr {
        Some(addr) => TcpStream::connect(addr).await,
        None => TcpStream::connect((host.as_str(), port)).await,
    };
    let tcp = tcp.with_context(|| format!("connect {host}:{port}"))?;
    let path = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };
    let mut request = hyper::Request::get(path).header("host", format!("{host}:{port}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request.body(Full::new(Bytes::new()))?;
    let (status, body) = match parsed.scheme() {
        "http" => send(TokioIo::new(tcp), request).await?,
        "https" => {
            let roots = roots.ok_or_else(|| anyhow!("{url}: https needs roots"))?;
            let connector = tokio_rustls::TlsConnector::from(client_config(roots)?);
            let tls = connector.connect(ServerName::try_from(host.clone())?, tcp).await.context("TLS")?;
            send(TokioIo::new(tls), request).await?
        }
        other => return Err(anyhow!("{url}: unsupported scheme {other}")),
    };
    Ok((status, body))
}

/// One kept-alive HTTP/1.1 connection, for requests that must share it.
pub struct Conn {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    authority: String,
    base_path: String,
}

impl Conn {
    /// Connects to `base` (`http://` or `https://` trusting only `roots`).
    pub async fn open(base: &str, roots: Option<&[u8]>) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(base).with_context(|| base.to_string())?;
        let host = parsed.host_str().ok_or_else(|| anyhow!("{base}: no host"))?.to_string();
        let port = parsed.port_or_known_default().ok_or_else(|| anyhow!("{base}: no port"))?;
        let tcp = TcpStream::connect((host.as_str(), port)).await.with_context(|| format!("connect {host}:{port}"))?;
        let sender = match (parsed.scheme(), roots) {
            ("http", _) => {
                let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
                tokio::spawn(conn);
                sender
            }
            ("https", Some(roots)) => {
                let connector = tokio_rustls::TlsConnector::from(client_config(roots)?);
                let tls = connector.connect(ServerName::try_from(host.clone())?, tcp).await.context("TLS")?;
                let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
                tokio::spawn(conn);
                sender
            }
            _ => return Err(anyhow!("{base}: http, or https with roots")),
        };
        let base_path = parsed.path().trim_end_matches('/').to_string();
        Ok(Self { sender, authority: format!("{host}:{port}"), base_path })
    }

    /// `GET <base><path>` on this connection.
    pub async fn get(&mut self, path: &str, headers: &[(&str, &str)]) -> anyhow::Result<(u16, String)> {
        let mut request = hyper::Request::get(format!("{}{path}", self.base_path)).header("host", &self.authority);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        self.sender.ready().await.context("the connection closed")?;
        let response = self.sender.send_request(request.body(Full::new(Bytes::new()))?).await?;
        let status = response.status().as_u16();
        let body = response.into_body().collect().await?.to_bytes();
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

async fn send<T>(io: TokioIo<T>, request: hyper::Request<Full<Bytes>>) -> anyhow::Result<(u16, String)>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);
    let response = sender.send_request(request).await?;
    let status = response.status().as_u16();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}
