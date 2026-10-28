//! The log and the control plane over HTTPS (`seal_net::HttpsClient`, baked roots). Sim builds
//! may also reach them over plain HTTP on loopback, where staging runs them next to the
//! registrar.

use std::sync::Arc;

use async_trait::async_trait;
use seal_proto::release::{LogEntry, TlogProof};
use seal_proto::state::LoggedRoot;
use seal_proto::TenantId;
use serde::Deserialize;

use crate::{UpstreamError, Upstreams};

pub struct HttpUpstreams {
    https: Arc<seal_net::HttpsClient>,
    log: String,
    control: String,
    control_write_token: String,
}

/// `https://`, or plain `http://` on loopback in sim builds.
pub fn check_url(what: &str, url: &url::Url) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if cfg!(feature = "sim") && is_loopback(url) => Ok(()),
        "http" if cfg!(feature = "sim") => Err(format!("{what}: plain http:// is allowed on loopback only")),
        _ => Err(format!("{what}: needs an https:// URL")),
    }
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

impl HttpUpstreams {
    pub fn new(
        https: Arc<seal_net::HttpsClient>,
        log: &url::Url,
        control: &url::Url,
        control_write_token: String,
    ) -> Self {
        let base = |u: &url::Url| u.as_str().trim_end_matches('/').to_string();
        Self { https, log: base(log), control: base(control), control_write_token }
    }

    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), UpstreamError> {
        #[cfg(feature = "sim")]
        if url.starts_with("http://") {
            return plain::send(method, url, headers, body).await;
        }
        let r = match (method, body) {
            ("GET", _) => self.https.get(url, headers).await,
            ("POST", Some(b)) => self.https.post(url, headers, b).await,
            ("PUT", Some(b)) => self.https.put(url, headers, b).await,
            _ => return Err(UpstreamError(format!("unsupported request {method} {url}"))),
        };
        r.map_err(|e| UpstreamError(format!("{url}: {e}")))
    }

    fn ok(url: &str, status: u16, body: &[u8]) -> Result<(), UpstreamError> {
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(UpstreamError(format!(
                "{url} answered {status}: {}",
                String::from_utf8_lossy(&body[..body.len().min(200)])
            )))
        }
    }
}

#[async_trait]
impl Upstreams for HttpUpstreams {
    async fn log_append(&self, entry: &LogEntry) -> Result<u64, UpstreamError> {
        #[derive(Deserialize)]
        struct Index {
            index: u64,
        }
        let url = format!("{}/v1/entries", self.log);
        let body = serde_json::to_vec(entry).map_err(|e| UpstreamError(e.to_string()))?;
        let (status, resp) = self.send("POST", &url, &[("content-type", "application/json")], Some(&body)).await?;
        Self::ok(&url, status, &resp)?;
        serde_json::from_slice::<Index>(&resp).map(|i| i.index).map_err(|e| UpstreamError(format!("{url}: {e}")))
    }

    async fn log_proof(&self, index: u64) -> Result<TlogProof, UpstreamError> {
        let url = format!("{}/v1/proof/{index}", self.log);
        let (status, resp) = self.send("GET", &url, &[("accept", "application/json")], None).await?;
        Self::ok(&url, status, &resp)?;
        serde_json::from_slice(&resp).map_err(|e| UpstreamError(format!("{url}: {e}")))
    }

    async fn put_root(&self, tenant: &TenantId, root: &LoggedRoot) -> Result<(), UpstreamError> {
        let url = format!("{}/v1/tenants/{tenant}/root", self.control);
        let body = serde_json::to_vec(root).map_err(|e| UpstreamError(e.to_string()))?;
        let auth = format!("Bearer {}", self.control_write_token);
        let headers = [("content-type", "application/json"), ("authorization", auth.as_str())];
        let (status, resp) = self.send("PUT", &url, &headers, Some(&body)).await?;
        Self::ok(&url, status, &resp)
    }
}

/// Sim builds: one plain HTTP/1.1 exchange with a loopback address.
#[cfg(feature = "sim")]
mod plain {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    use super::UpstreamError;

    const MAX_BODY: usize = 1 << 20;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    pub async fn send(
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), UpstreamError> {
        let err = |e: &dyn std::fmt::Display| UpstreamError(format!("{url}: {e}"));
        let parsed = url::Url::parse(url).map_err(|e| err(&e))?;
        if !super::is_loopback(&parsed) {
            return Err(err(&"plain HTTP only on loopback"));
        }
        let host = parsed.host_str().ok_or_else(|| err(&"no host"))?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let exchange = async {
            let addr = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let stream = tokio::net::TcpStream::connect((addr.as_str(), port)).await.map_err(|e| err(&e))?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| err(&e))?;
            let conn = tokio::spawn(conn);
            let mut req = hyper::Request::builder()
                .method(method)
                .uri(parsed.path())
                .header(hyper::header::HOST, format!("{host}:{port}"));
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let req = req.body(Full::new(Bytes::from(body.unwrap_or_default().to_vec()))).map_err(|e| err(&e))?;
            let resp = sender.send_request(req).await.map_err(|e| err(&e))?;
            let status = resp.status().as_u16();
            let body =
                Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| err(&e))?.to_bytes().to_vec();
            conn.abort();
            Ok((status, body))
        };
        tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| err(&"timed out"))?
    }
}
