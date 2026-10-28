//! Client for the control plane's API (see the crate docs), one method per endpoint, named
//! after its HTTP verb. Used by the enclave (`TenantStore`, `ReleaseStore`, `Telemetry`) and
//! by admin tools. Everything it returns is unverified: callers verify with `seal-verify`
//! (or against attested telemetry keys) before use, so a malicious control plane can withhold
//! documents but never forge them.
//!
//! Reads of a tenant's bundle, documents, proposals and telemetry, and writes of its roots,
//! states, co-signatures and proposals, carry the client's `Credential`: an admin key
//! (`SigningKeyCredential`) or the enclave's own (in `seal-enclave`). Console control tokens
//! are the browser's, which calls the API directly. Without one, writes carry the write token, when the client has it.

use std::sync::Arc;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use seal_crypto::sign::SigningKey;
use seal_proto::control::{ControlRequest, CONTROL_REQUEST_LABEL, SIGNED_SCHEME};
use seal_proto::integrity::SignedSignal;
use seal_proto::release::{ReleaseCosign, ReleaseEvidence, SignedCheckpoint, SignedServiceKeyCertificate};
use seal_proto::session::SignedSessionEnd;
use seal_proto::signed::Signed;
use seal_proto::state::{LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantState, TenantBundle, TenantRoot};
use seal_proto::telemetry::SignedTelemetryBatch;
use seal_proto::{codec, ErrorCode, Measurement, PlatformId, TenantId, TenantRootId, UnixTime};

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("network: {0}")]
    Net(#[from] seal_net::NetError),
    /// A non-2xx answer.
    #[error("control plane answered {status}")]
    Rejected { status: u16 },
    #[error("malformed response: {0}")]
    Malformed(String),
    /// The credential could not authorize the request (an enclave that cannot attest).
    #[error("credential: {0}")]
    Credential(String),
}

impl ControlError {
    /// The public code (`Rejected` 401/403 → `NotAllowed`, other 4xx → `BadRequest`;
    /// everything else → `Unavailable`).
    pub fn code(&self) -> ErrorCode {
        match self {
            ControlError::Rejected { status: 401 | 403 } => ErrorCode::NotAllowed,
            ControlError::Rejected { status: 400..=499 } => ErrorCode::BadRequest,
            _ => ErrorCode::Unavailable,
        }
    }
}

/// One request a credential authorizes.
pub struct Target<'a> {
    pub tenant: &'a TenantId,
    pub method: &'a str,
    /// Path and query exactly as sent.
    pub path: &'a str,
    pub body: &'a [u8],
}

impl Target<'_> {
    /// The `ControlRequest` naming exactly this request, made at `issued_at`.
    pub fn request(&self, root_id: TenantRootId, issued_at: UnixTime) -> ControlRequest {
        ControlRequest {
            tenant: self.tenant.clone(),
            root_id,
            method: self.method.to_string(),
            path: self.path.to_string(),
            body_sha256: Sha256::digest(self.body).into(),
            issued_at,
        }
    }
}

/// What authorizes a reader or writer of a tenant's documents: returns the `Authorization`
/// header value for one request.
#[async_trait]
pub trait Credential: Send + Sync {
    async fn authorization(&self, target: &Target<'_>) -> Result<String, ControlError>;
}

/// `Authorization` for a signed request: `SealSigned <base64url(JSON)>`.
pub fn signed_authorization(request: &Signed<ControlRequest>) -> String {
    let json = serde_json::to_vec(request).expect("a signed request serializes");
    format!("{SIGNED_SCHEME} {}", codec::b64url(&json))
}

fn unix_now() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Requests signed with an Ed25519 key: an admin key of the tenant's latest root (admin tools).
pub struct SigningKeyCredential {
    key: SigningKey,
    root_id: TenantRootId,
}

impl SigningKeyCredential {
    pub fn new(key: SigningKey, root_id: TenantRootId) -> Self {
        Self { key, root_id }
    }
}

#[async_trait]
impl Credential for SigningKeyCredential {
    async fn authorization(&self, target: &Target<'_>) -> Result<String, ControlError> {
        let request = target.request(self.root_id, unix_now());
        Ok(signed_authorization(&self.key.sign_into(CONTROL_REQUEST_LABEL, request)))
    }
}

/// A document waiting for admin signatures: `{"id", "kind": "state" | "root", "document",
/// "created_at", "updated_at"}`. Its id is the lowercase hex of the digest admins sign,
/// `labeled_digest(TENANT_STATE_LABEL | TENANT_ROOT_LABEL, document.body)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    #[serde(flatten)]
    pub document: Proposed,
    pub created_at: UnixTime,
    pub updated_at: UnixTime,
}

// One per request or stored proposal: the size of the `State` variant costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "document", rename_all = "snake_case")]
pub enum Proposed {
    State(SignedTenantState),
    Root(Signed<TenantRoot>),
}

impl Proposed {
    /// The proposal id of this document.
    pub fn id(&self) -> String {
        use seal_proto::state::{TENANT_ROOT_LABEL, TENANT_STATE_LABEL};
        let digest = match self {
            Proposed::State(s) => codec::labeled_digest(TENANT_STATE_LABEL, &s.body),
            Proposed::Root(r) => codec::labeled_digest(TENANT_ROOT_LABEL, &r.body),
        };
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// What a submitted proposal became: the logged root or state, with its inclusion proof.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Submitted {
    Root(LoggedRoot),
    State(LoggedState),
}

/// `GET /v1/tenants/{tenant}/documents`: the whole root chain, the logged states above
/// `since_version` oldest first, and the log's latest checkpoint (`None` while the log is
/// unreachable), so readers compute when each document became public and what the witnesses'
/// time is now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Documents {
    pub roots: Vec<LoggedRoot>,
    pub states: Vec<LoggedState>,
    pub checkpoint: Option<SignedCheckpoint>,
}

pub struct ControlClient {
    /// The base URL without a trailing slash; paths are appended to it.
    base: String,
    https: Arc<seal_net::HttpsClient>,
    write_token: Option<String>,
    credential: std::sync::RwLock<Option<Arc<dyn Credential>>>,
}

/// The path segment of a platform: its wire name (`azure_snp_aci`, `sim`, ...).
fn platform_segment(platform: PlatformId) -> String {
    match serde_json::to_value(platform) {
        Ok(serde_json::Value::String(name)) => name,
        _ => unreachable!("a PlatformId serializes as a string"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Put,
    Post,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Post => "POST",
            Method::Delete => "DELETE",
        }
    }
}

/// Who a request is sent as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum As<'a> {
    /// No credential: public reads and documents verified by their own signatures.
    Anyone,
    /// The client's credential for `tenant`.
    Reader(&'a TenantId),
    /// The credential for `tenant`, else the write token.
    Writer(&'a TenantId),
    /// The write token.
    Operator,
}

impl ControlClient {
    /// `write_token` is needed only for releases (and for admin writes without a credential).
    /// Enclaves pass `None`.
    pub fn new(base: url::Url, https: std::sync::Arc<seal_net::HttpsClient>, write_token: Option<String>) -> Self {
        let base = base.as_str().trim_end_matches('/').to_string();
        Self { base, https, write_token, credential: std::sync::RwLock::new(None) }
    }

    /// Authorizes the tenant's protected reads and writes with `credential`.
    pub fn with_credential(self, credential: Arc<dyn Credential>) -> Self {
        self.set_credential(credential);
        self
    }

    /// As `with_credential`, from now on (an admin tool that just created the tenant's chain).
    pub fn set_credential(&self, credential: Arc<dyn Credential>) {
        *self.credential.write().unwrap_or_else(|p| p.into_inner()) = Some(credential);
    }

    async fn exchange(&self, method: Method, path: &str, body: &[u8], who: As<'_>) -> Result<Vec<u8>, ControlError> {
        let url = format!("{}{path}", self.base);
        let credential = self.credential.read().unwrap_or_else(|p| p.into_inner()).clone();
        let authorization = match (who, &credential, &self.write_token) {
            (As::Reader(tenant) | As::Writer(tenant), Some(credential), _) => {
                // What the server sees: the path and query as `HttpsClient` sends them.
                let uri: hyper::Uri = url.parse().map_err(|_| ControlError::Malformed(format!("URL {url}")))?;
                let sent = uri.path_and_query().map_or("/", |p| p.as_str());
                let target = Target { tenant, method: method.as_str(), path: sent, body };
                Some(credential.authorization(&target).await?)
            }
            (As::Writer(_) | As::Operator, _, Some(token)) => Some(format!("Bearer {token}")),
            _ => None,
        };
        let mut headers = vec![("accept", "application/json")];
        if method != Method::Get {
            headers.push(("content-type", "application/json"));
        }
        if let Some(authorization) = &authorization {
            headers.push(("authorization", authorization.as_str()));
        }
        let (status, response) = match method {
            Method::Get => self.https.get(&url, &headers).await?,
            Method::Put => self.https.put(&url, &headers, body).await?,
            Method::Post => self.https.post(&url, &headers, body).await?,
            Method::Delete => self.https.delete(&url, &headers).await?,
        };
        if !(200..300).contains(&status) {
            return Err(ControlError::Rejected { status });
        }
        Ok(response)
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str, who: As<'_>) -> Result<T, ControlError> {
        let body = self.exchange(Method::Get, path, &[], who).await?;
        serde_json::from_slice(&body).map_err(|e| ControlError::Malformed(e.to_string()))
    }

    async fn send<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &B,
        who: As<'_>,
    ) -> Result<Vec<u8>, ControlError> {
        let body = serde_json::to_vec(body).map_err(|e| ControlError::Malformed(e.to_string()))?;
        self.exchange(method, path, &body, who).await
    }

    pub async fn get_bundle(&self, tenant: &TenantId) -> Result<TenantBundle, ControlError> {
        self.get_json(&format!("/v1/tenants/{tenant}/bundle"), As::Reader(tenant)).await
    }
    /// The root chain and the logged states above `since_version` (all without it), with their proofs.
    pub async fn get_documents(
        &self,
        tenant: &TenantId,
        since_version: Option<u64>,
    ) -> Result<Documents, ControlError> {
        let path = match since_version {
            Some(v) => format!("/v1/tenants/{tenant}/documents?since_version={v}"),
            None => format!("/v1/tenants/{tenant}/documents"),
        };
        self.get_json(&path, As::Reader(tenant)).await
    }
    pub async fn put_root(&self, tenant: &TenantId, root: &LoggedRoot) -> Result<(), ControlError> {
        self.send(Method::Put, &format!("/v1/tenants/{tenant}/root"), root, As::Writer(tenant)).await.map(drop)
    }
    /// A state its caller already logged, with its inclusion proof.
    pub async fn put_state(&self, tenant: &TenantId, state: &LoggedState) -> Result<(), ControlError> {
        self.send(Method::Put, &format!("/v1/tenants/{tenant}/state"), state, As::Writer(tenant)).await.map(drop)
    }
    /// Open proposals.
    pub async fn get_proposals(&self, tenant: &TenantId) -> Result<Vec<Proposal>, ControlError> {
        self.get_json(&format!("/v1/tenants/{tenant}/proposals"), As::Reader(tenant)).await
    }
    /// Creates the proposal of `document` or adds its signatures to it (`document.id()`).
    pub async fn put_proposal(&self, tenant: &TenantId, document: &Proposed) -> Result<Proposal, ControlError> {
        let path = format!("/v1/tenants/{tenant}/proposals/{}", document.id());
        let body = match document {
            Proposed::State(s) => serde_json::to_vec(s),
            Proposed::Root(r) => serde_json::to_vec(r),
        }
        .map_err(|e| ControlError::Malformed(e.to_string()))?;
        let response = self.exchange(Method::Put, &path, &body, As::Writer(tenant)).await?;
        serde_json::from_slice(&response).map_err(|e| ControlError::Malformed(e.to_string()))
    }
    pub async fn delete_proposal(&self, tenant: &TenantId, id: &str) -> Result<(), ControlError> {
        self.exchange(Method::Delete, &format!("/v1/tenants/{tenant}/proposals/{id}"), &[], As::Writer(tenant))
            .await
            .map(drop)
    }
    /// Submits a proposal holding the threshold of signatures: the control plane logs it and
    /// stores it as the tenant's next root or state.
    pub async fn post_proposal_submit(&self, tenant: &TenantId, id: &str) -> Result<Submitted, ControlError> {
        let response = self
            .exchange(Method::Post, &format!("/v1/tenants/{tenant}/proposals/{id}/submit"), &[], As::Writer(tenant))
            .await?;
        serde_json::from_slice(&response).map_err(|e| ControlError::Malformed(e.to_string()))
    }
    /// Enclaves (signals they sign) and external sources such as EDR relays (signed with the
    /// source's registered key). Needs no credential.
    pub async fn post_signal(&self, tenant: &TenantId, signal: &SignedSignal) -> Result<(), ControlError> {
        self.send(Method::Post, &format!("/v1/tenants/{tenant}/signals"), signal, As::Anyone).await.map(drop)
    }
    /// A tenant-run freshness signer's statement (`seal settings freshness sign`). Needs no credential.
    pub async fn post_freshness(
        &self,
        tenant: &TenantId,
        statement: &SignedStateFreshness,
    ) -> Result<(), ControlError> {
        self.send(Method::Post, &format!("/v1/tenants/{tenant}/freshness"), statement, As::Anyone).await.map(drop)
    }
    /// Enclaves only. Needs no credential.
    pub async fn post_session_end(&self, tenant: &TenantId, end: &SignedSessionEnd) -> Result<(), ControlError> {
        self.send(Method::Post, &format!("/v1/tenants/{tenant}/session-ends"), end, As::Anyone).await.map(drop)
    }
    /// Enclaves, at boot: the guardian's certificate over their service keys. Its telemetry
    /// public keys are what the control plane accepts enclave-signed signals, session ends,
    /// telemetry batches and reads with. Needs no credential.
    pub async fn post_service_key_certificate(
        &self,
        tenant: &TenantId,
        certificate: &SignedServiceKeyCertificate,
    ) -> Result<(), ControlError> {
        let path = format!("/v1/tenants/{tenant}/service-key-certificates");
        self.send(Method::Post, &path, certificate, As::Anyone).await.map(drop)
    }
    /// Every certificate the tenant's enclaves posted (public). Readers (`seal telemetry`)
    /// verify each with `seal_verify::verify_service_certificate` and check its tenant and root id.
    pub async fn get_service_key_certificates(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<SignedServiceKeyCertificate>, ControlError> {
        self.get_json(&format!("/v1/tenants/{tenant}/service-key-certificates"), As::Anyone).await
    }
    /// Batches with entries at or after `since`, every page. Readers verify each batch against
    /// the telemetry public keys of an enclave they verified
    /// (`AttestationBinding::telemetry_public_keys`) and report gaps in each `stream`'s sequence
    /// and streams without a `last` batch.
    pub async fn get_telemetry(
        &self,
        tenant: &TenantId,
        since: UnixTime,
    ) -> Result<Vec<SignedTelemetryBatch>, ControlError> {
        let mut all: Vec<SignedTelemetryBatch> = Vec::new();
        loop {
            let mut path = format!("/v1/tenants/{tenant}/telemetry?since={since}");
            if let Some(last) = all.last() {
                let stream: String = last.body.stream.iter().map(|b| format!("{b:02x}")).collect();
                path.push_str(&format!("&after={stream}-{}", last.body.sequence));
            }
            let page: Vec<SignedTelemetryBatch> = self.get_json(&path, As::Reader(tenant)).await?;
            let advanced = page.first().is_some_and(|b| {
                all.last().is_none_or(|l| (b.body.stream, b.body.sequence) > (l.body.stream, l.body.sequence))
            });
            if !advanced {
                return Ok(all);
            }
            all.extend(page);
        }
    }
    /// Enclaves only. Needs no credential.
    pub async fn post_telemetry(&self, tenant: &TenantId, batch: &SignedTelemetryBatch) -> Result<(), ControlError> {
        self.send(Method::Post, &format!("/v1/tenants/{tenant}/telemetry"), batch, As::Anyone).await.map(drop)
    }
    pub async fn get_release_cosign(
        &self,
        tenant: &TenantId,
        measurement: &Measurement,
    ) -> Result<Signed<ReleaseCosign>, ControlError> {
        self.get_json(&format!("/v1/tenants/{tenant}/release-cosigns/{measurement}"), As::Anyone).await
    }
    pub async fn put_release_cosign(
        &self,
        tenant: &TenantId,
        measurement: &Measurement,
        cosign: &Signed<ReleaseCosign>,
    ) -> Result<(), ControlError> {
        let path = format!("/v1/tenants/{tenant}/release-cosigns/{measurement}");
        self.send(Method::Put, &path, cosign, As::Writer(tenant)).await.map(drop)
    }
    pub async fn get_release(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
    ) -> Result<ReleaseEvidence, ControlError> {
        self.get_json(&format!("/v1/releases/{}/{measurement}", platform_segment(platform)), As::Anyone).await
    }
    pub async fn put_release(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
        evidence: &ReleaseEvidence,
    ) -> Result<(), ControlError> {
        let path = format!("/v1/releases/{}/{measurement}", platform_segment(platform));
        self.send(Method::Put, &path, evidence, As::Operator).await.map(drop)
    }
    /// Every release stored for `platform`, in log order. Readers verify each with
    /// `seal_verify::ReleaseVerifier`.
    pub async fn get_releases(&self, platform: PlatformId) -> Result<Vec<ReleaseEvidence>, ControlError> {
        self.get_json(&format!("/v1/releases/{}", platform_segment(platform)), As::Anyone).await
    }
    /// The release's deployment template (Azure: the ARM template with its `ccePolicy`).
    /// Unverified: `seal deploy` checks its measurement against the verified release.
    pub async fn get_release_template(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
    ) -> Result<serde_json::Value, ControlError> {
        self.get_json(&format!("/v1/releases/{}/{measurement}/template", platform_segment(platform)), As::Anyone).await
    }
    pub async fn put_release_template(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
        template: &serde_json::Value,
    ) -> Result<(), ControlError> {
        let path = format!("/v1/releases/{}/{measurement}/template", platform_segment(platform));
        self.send(Method::Put, &path, template, As::Operator).await.map(drop)
    }
    pub async fn get_checkpoint(&self) -> Result<SignedCheckpoint, ControlError> {
        self.get_json("/v1/checkpoint", As::Anyone).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_follow_the_status() {
        let rejected = |status| ControlError::Rejected { status }.code();
        assert_eq!(rejected(401), ErrorCode::NotAllowed);
        assert_eq!(rejected(403), ErrorCode::NotAllowed);
        assert_eq!(rejected(400), ErrorCode::BadRequest);
        assert_eq!(rejected(409), ErrorCode::BadRequest);
        assert_eq!(rejected(503), ErrorCode::Unavailable);
        assert_eq!(ControlError::Malformed("x".into()).code(), ErrorCode::Unavailable);
    }

    #[test]
    fn platforms_use_their_wire_names() {
        assert_eq!(platform_segment(PlatformId::AzureSnpAci), "azure_snp_aci");
        assert_eq!(platform_segment(PlatformId::Sim), "sim");
    }
}
