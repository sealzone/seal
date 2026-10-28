//! What the control plane fetches: freshness statements, checkpoints, entries and proofs from
//! the log, wrap keys from each platform's guardian; and what it appends to the log: the roots
//! and states of submitted proposals. Everything fetched is checked by the caller against the
//! configured keys before it is stored or served.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;

use seal_proto::release::{LogEntry, SignedCheckpoint, SignedTenantWrapKey, TlogProof};
use seal_proto::state::{SignedStateFreshness, SignedTenantAnchor, SignedTenantState, TenantBundle};
use seal_proto::{PlatformId, TenantId, TenantKeyVersion, TenantRootId};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UpstreamError(pub String);

/// The log's answer to an append.
#[derive(Debug, PartialEq, Eq)]
pub enum Appended {
    /// The entry's index.
    At(u64),
    /// Refused (4xx), with the log's reason: a state already logged, a version not above the
    /// logged ones, signatures the log does not accept.
    Refused(String),
}

#[async_trait::async_trait]
pub trait Upstreams: Send + Sync {
    /// The log's `StateFreshness` for the tenant's latest logged state; `None` when the log
    /// has no state for it.
    async fn log_freshness(&self, tenant: &TenantId) -> Result<Option<SignedStateFreshness>, UpstreamError>;
    /// The log's latest checkpoint.
    async fn log_checkpoint(&self) -> Result<SignedCheckpoint, UpstreamError>;
    /// Appends a root (`POST /v1/entries`).
    async fn log_append_root(&self, entry: &LogEntry) -> Result<Appended, UpstreamError>;
    /// Appends a state (`POST /v1/tenants/{tenant}/states`); the log checks its signatures
    /// and version.
    async fn log_append_state(&self, tenant: &TenantId, state: &SignedTenantState) -> Result<Appended, UpstreamError>;
    /// The inclusion proof of entry `index` against the log's latest checkpoint.
    async fn log_proof(&self, index: u64) -> Result<TlogProof, UpstreamError>;
    /// The entry at `index`; `None` past the end.
    async fn log_entry(&self, index: u64) -> Result<Option<LogEntry>, UpstreamError>;
    /// `platform`'s guardian's certified wrap key; `None` when no guardian is configured for
    /// it or it has none.
    async fn wrap_key(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        root_id: &TenantRootId,
        version: TenantKeyVersion,
    ) -> Result<Option<SignedTenantWrapKey>, UpstreamError>;
    /// `platform`'s guardian's anchor for `bundle` (`POST /v1/anchors/{tenant}/{root_id}`);
    /// `None` when no guardian is configured for it or it refused.
    async fn anchor(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        root_id: &TenantRootId,
        bundle: &TenantBundle,
    ) -> Result<Option<SignedTenantAnchor>, UpstreamError>;
}

/// The log and guardians over HTTPS (`seal_net::HttpsClient`, baked roots). Sim builds may
/// add roots and reach loopback `http://` URLs (see `config`).
pub struct HttpUpstreams {
    https: Arc<seal_net::HttpsClient>,
    log: String,
    guardians: BTreeMap<PlatformId, String>,
}

fn base(url: &url::Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

impl HttpUpstreams {
    pub fn new(https: Arc<seal_net::HttpsClient>, log: &url::Url, guardians: BTreeMap<PlatformId, url::Url>) -> Self {
        Self { https, log: base(log), guardians: guardians.iter().map(|(p, u)| (*p, base(u))).collect() }
    }

    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), UpstreamError> {
        #[cfg(feature = "sim")]
        if url.starts_with("http://") {
            return plain::request(url, None).await;
        }
        self.https.get(url, &[("accept", "application/json")]).await.map_err(|e| UpstreamError(e.to_string()))
    }

    async fn post(&self, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>), UpstreamError> {
        #[cfg(feature = "sim")]
        if url.starts_with("http://") {
            return plain::request(url, Some(body)).await;
        }
        self.https.post(url, &[("accept", "application/json")], body).await.map_err(|e| UpstreamError(e.to_string()))
    }

    async fn append<T: serde::Serialize>(&self, url: &str, body: &T) -> Result<Appended, UpstreamError> {
        #[derive(serde::Deserialize)]
        struct Index {
            index: u64,
        }
        let body = serde_json::to_vec(body).map_err(|e| UpstreamError(e.to_string()))?;
        let (status, response) = self.post(url, &body).await?;
        match status {
            200..=299 => serde_json::from_slice::<Index>(&response)
                .map(|i| Appended::At(i.index))
                .map_err(|e| UpstreamError(format!("{url}: {e}"))),
            400..=499 => Ok(Appended::Refused(
                String::from_utf8_lossy(&response).chars().filter(|c| !c.is_control()).take(200).collect(),
            )),
            status => Err(UpstreamError(format!("{url} answered {status}"))),
        }
    }

    /// The decoded body; `None` on 404.
    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<Option<T>, UpstreamError> {
        let (status, body) = self.get(url).await?;
        match status {
            200..=299 => serde_json::from_slice(&body).map(Some).map_err(|e| UpstreamError(format!("{url}: {e}"))),
            404 => Ok(None),
            status => Err(UpstreamError(format!("{url} answered {status}"))),
        }
    }
}

#[async_trait::async_trait]
impl Upstreams for HttpUpstreams {
    async fn log_freshness(&self, tenant: &TenantId) -> Result<Option<SignedStateFreshness>, UpstreamError> {
        self.get_json(&format!("{}/v1/tenants/{tenant}/freshness", self.log)).await
    }

    async fn log_checkpoint(&self) -> Result<SignedCheckpoint, UpstreamError> {
        let url = format!("{}/v1/checkpoint", self.log);
        self.get_json(&url).await?.ok_or_else(|| UpstreamError(format!("{url} answered 404")))
    }

    async fn log_append_root(&self, entry: &LogEntry) -> Result<Appended, UpstreamError> {
        self.append(&format!("{}/v1/entries", self.log), entry).await
    }

    async fn log_append_state(&self, tenant: &TenantId, state: &SignedTenantState) -> Result<Appended, UpstreamError> {
        self.append(&format!("{}/v1/tenants/{tenant}/states", self.log), state).await
    }

    async fn log_proof(&self, index: u64) -> Result<TlogProof, UpstreamError> {
        let url = format!("{}/v1/proof/{index}", self.log);
        self.get_json(&url).await?.ok_or_else(|| UpstreamError(format!("{url} answered 404")))
    }

    async fn log_entry(&self, index: u64) -> Result<Option<LogEntry>, UpstreamError> {
        self.get_json(&format!("{}/v1/entries/{index}", self.log)).await
    }

    async fn wrap_key(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        root_id: &TenantRootId,
        version: TenantKeyVersion,
    ) -> Result<Option<SignedTenantWrapKey>, UpstreamError> {
        let Some(guardian) = self.guardians.get(&platform) else {
            return Ok(None);
        };
        self.get_json(&format!("{guardian}/v1/wrap-keys/{tenant}/{root_id}/{version}")).await
    }

    async fn anchor(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        root_id: &TenantRootId,
        bundle: &TenantBundle,
    ) -> Result<Option<SignedTenantAnchor>, UpstreamError> {
        let Some(guardian) = self.guardians.get(&platform) else {
            return Ok(None);
        };
        let url = format!("{guardian}/v1/anchors/{tenant}/{root_id}");
        let body = serde_json::to_vec(bundle).map_err(|e| UpstreamError(e.to_string()))?;
        let (status, response) = self.post(&url, &body).await?;
        match status {
            200..=299 => serde_json::from_slice(&response).map(Some).map_err(|e| UpstreamError(format!("{url}: {e}"))),
            403 => Ok(None),
            status => Err(UpstreamError(format!("{url} answered {status}"))),
        }
    }
}

/// Sim builds: one plain HTTP/1.1 GET, or POST of a JSON body, to a loopback address (the dev
/// log and a local guardian serve plain HTTP). `config` admits `http://` URLs only on loopback.
#[cfg(feature = "sim")]
mod plain {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    use super::UpstreamError;

    const MAX_BODY: usize = 1 << 20;
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    pub async fn request(url: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), UpstreamError> {
        let err = |e: &dyn std::fmt::Display| UpstreamError(format!("{url}: {e}"));
        let parsed = url::Url::parse(url).map_err(|e| err(&e))?;
        if !crate::server::config::is_loopback(&parsed) {
            return Err(err(&"plain HTTP only on loopback"));
        }
        let host = parsed.host_str().ok_or_else(|| err(&"no host"))?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(80);
        let path = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_string(),
        };
        let exchange = async {
            let addr = host.trim_start_matches('[').trim_end_matches(']').to_string();
            let stream = tokio::net::TcpStream::connect((addr.as_str(), port)).await.map_err(|e| err(&e))?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| err(&e))?;
            let conn = tokio::spawn(conn);
            let method = if body.is_some() { hyper::Method::POST } else { hyper::Method::GET };
            let req = hyper::Request::builder()
                .method(method)
                .uri(path)
                .header(hyper::header::HOST, format!("{host}:{port}"))
                .header(hyper::header::ACCEPT, "application/json")
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::copy_from_slice(body.unwrap_or_default())))
                .map_err(|e| err(&e))?;
            let resp = sender.send_request(req).await.map_err(|e| err(&e))?;
            let status = resp.status().as_u16();
            let body = Limited::new(resp.into_body(), MAX_BODY).collect().await.map_err(|e| err(&e))?;
            conn.abort();
            Ok((status, body.to_bytes().to_vec()))
        };
        tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| err(&"timed out"))?
    }
}
