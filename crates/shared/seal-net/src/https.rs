//! `HttpsClient`: one HTTP/1.1 request per verified connection.

use std::collections::BTreeSet;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use seal_proto::policy::Destination;

use crate::{HttpsClient, NetError};

/// Largest response body accepted.
pub(crate) const MAX_BODY: usize = 1 << 20;
/// Whole request: connect, TLS, request, response body.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);

/// Aborts the connection task when the request ends, however it ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn http(reason: &str) -> NetError {
    NetError::Http(reason.to_string())
}

impl HttpsClient {
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), NetError> {
        let uri: Uri = url.parse().map_err(|_| http("invalid URL"))?;
        if uri.scheme_str() != Some("https") {
            return Err(http("only https:// URLs are allowed"));
        }
        let authority = uri.authority().ok_or_else(|| http("URL has no host"))?;
        if authority.as_str().contains('@') {
            return Err(http("URLs with credentials are refused"));
        }
        let host = authority.host().to_ascii_lowercase();
        if host.is_empty() {
            return Err(http("URL has no host"));
        }
        let dest = Destination::Https { host, port: authority.port_u16().unwrap_or(443), path_prefix: "/".into() };
        let path = uri.path_and_query().map_or("/", |p| p.as_str());

        let mut req = Request::builder().method(method).uri(path).header(hyper::header::HOST, authority.as_str());
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        if body.is_some() && !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-type")) {
            req = req.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        // Never echo header values: they carry bearer tokens.
        let req = req
            .body(Full::new(Bytes::copy_from_slice(body.unwrap_or_default())))
            .map_err(|_| http("invalid request header"))?;

        let exchange = async {
            let stream = self.connector.connect(&dest, &BTreeSet::new()).await?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| NetError::Http(e.to_string()))?;
            let _conn = AbortOnDrop(tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!(error = %e, "https connection ended");
                }
            }));
            let resp = sender.send_request(req).await.map_err(|e| NetError::Http(e.to_string()))?;
            let status = resp.status().as_u16();
            let body = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    http("response body exceeds 1 MiB")
                } else {
                    NetError::Http(e.to_string())
                }
            })?;
            Ok((status, body.to_bytes().to_vec()))
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| NetError::Http(format!("timed out after {} s", self.timeout.as_secs_f32())))?
    }
}
