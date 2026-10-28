//! Byte transport: TLS to the enclave under a `verify` config, one HTTP/1.1 exchange per
//! connection, and plain HTTP for the link-local metadata endpoints identity providers call.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::ClientError;

/// Time to open a TCP connection and finish the TLS handshake.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One whole HTTP exchange: connect, request, response body.
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);
/// Largest response body accepted (an attestation carries evidence and log proofs).
const MAX_BODY: usize = 4 << 20;

/// Why a TLS connection to an enclave failed.
#[derive(Debug)]
pub(crate) enum ConnectError {
    /// Nothing was sent: try another replica.
    Unreachable(String),
    /// The replica presented a key other than the pinned one.
    Pin,
}

impl From<ConnectError> for ClientError {
    fn from(e: ConnectError) -> Self {
        match e {
            ConnectError::Unreachable(m) => ClientError::Network(m),
            ConnectError::Pin => {
                ClientError::Verification("the enclave presented a key other than the attested one".into())
            }
        }
    }
}

/// `[::1]` → `::1`; anything else unchanged.
pub(crate) fn unbracket(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

/// TCP to `host:port`, then TLS under `config` (whose verifier decides which key is accepted).
pub(crate) async fn tls_connect(
    config: Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
) -> Result<TlsStream<TcpStream>, ConnectError> {
    let bare = unbracket(host);
    let name = rustls::pki_types::ServerName::try_from(bare.to_string())
        .map_err(|_| ConnectError::Unreachable(format!("{host} is not a valid host name")))?;
    let connect = async {
        let tcp = TcpStream::connect((bare, port))
            .await
            .map_err(|e| ConnectError::Unreachable(format!("connect to {host}:{port}: {e}")))?;
        let _ = tcp.set_nodelay(true);
        tokio_rustls::TlsConnector::from(config).connect(name, tcp).await.map_err(|e| {
            match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
                Some(rustls::Error::InvalidCertificate(_)) => ConnectError::Pin,
                Some(tls) => ConnectError::Unreachable(format!("TLS with {host}:{port}: {tls}")),
                None => ConnectError::Unreachable(format!("TLS with {host}:{port}: {e}")),
            }
        })
    };
    tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| ConnectError::Unreachable(format!("connect to {host}:{port}: timed out")))?
}

/// Aborts the connection task when the exchange ends, however it ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One HTTP/1.1 request on `stream`. Header values are never echoed into errors: they carry
/// bearer credentials.
pub(crate) async fn exchange<S>(
    stream: S,
    method: hyper::Method,
    authority: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<(u16, Vec<u8>), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut req = hyper::Request::builder().method(method).uri(path).header(hyper::header::HOST, authority);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    if body.is_some() && !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-type")) {
        req = req.header(hyper::header::CONTENT_TYPE, "application/json");
    }
    let req =
        req.body(Full::new(Bytes::from(body.unwrap_or_default()))).map_err(|_| "invalid request header".to_string())?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
    let _conn = AbortOnDrop(tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "connection ended");
        }
    }));
    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| {
        if e.is::<http_body_util::LengthLimitError>() {
            "response body too large".to_string()
        } else {
            e.to_string()
        }
    })?;
    Ok((status, body.to_bytes().to_vec()))
}

/// A GET over plain HTTP, for metadata endpoints that only speak it (Azure IMDS, the GCP
/// metadata server). The URL must be `http://`; `timeout` covers the whole exchange.
pub(crate) async fn plain_get(
    url: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, Vec<u8>), ClientError> {
    let parsed = url::Url::parse(url).map_err(|_| ClientError::Invalid(format!("invalid URL {url}")))?;
    if parsed.scheme() != "http" {
        return Err(ClientError::Invalid("plain HTTP takes http:// URLs only".into()));
    }
    let host = parsed.host_str().ok_or_else(|| ClientError::Invalid(format!("{url} has no host")))?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let authority = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let path = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };
    let net = |e: String| ClientError::Network(format!("{host}: {e}"));
    let run = async {
        let tcp = TcpStream::connect((unbracket(&host), port)).await.map_err(|e| net(e.to_string()))?;
        exchange(tcp, hyper::Method::GET, &authority, &path, headers, None).await.map_err(net)
    };
    tokio::time::timeout(timeout, run).await.map_err(|_| net("timed out".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn plain_get_sends_headers_and_reads_the_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = Vec::new();
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello").await.unwrap();
            String::from_utf8(got).unwrap()
        });
        let url = format!("http://127.0.0.1:{port}/metadata/x?a=b");
        let (status, body) = plain_get(&url, &[("metadata", "true")], Duration::from_secs(5)).await.unwrap();
        assert_eq!((status, body.as_slice()), (200, &b"hello"[..]));
        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /metadata/x?a=b http/1.1\r\n"), "{request}");
        assert!(request.contains("metadata: true\r\n"));
        assert!(request.contains(&format!("host: 127.0.0.1:{port}\r\n")));
    }

    #[tokio::test]
    async fn plain_get_refuses_other_schemes() {
        let err = plain_get("https://example.com/", &[], Duration::from_secs(1)).await.unwrap_err();
        assert!(matches!(err, ClientError::Invalid(_)));
    }
}
