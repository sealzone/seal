//! Workload identity detection: Azure IMDS managed identity, AWS (env/IMDS
//! credentials → presigned STS), Kubernetes projected token, GCP metadata,
//! GitHub Actions OIDC, then `SEAL_APP_KEY`. First match wins. Warns once when
//! `SEAL_APP_KEY` and the blob both come from environment variables. GitHub tokens are
//! requested fresh for every proof, and Kubernetes projected tokens must be configured with
//! `expirationSeconds: 600`, because the enclave refuses older ones
//! (`seal_authz::MAX_OIDC_TOKEN_AGE_SECS`).
//!
//! What each provider is detected by and sends (audiences are what `seal-authz` accepts):
//!
//! - `AzureManagedIdentity`: when `SEAL_AZURE_AUDIENCE` is set, the Entra app ID URI the
//!   tenant registered (`AZURE_CLIENT_ID` picks a user-assigned identity). Sends an IMDS token
//!   for that audience, or one from `IDENTITY_ENDPOINT` where App Service sets it.
//! - `AwsIdentity` (feature `aws`): when AWS credentials resolve (environment, web identity,
//!   container or instance role). Sends a presigned STS `GetCallerIdentity` with a signed
//!   `X-Seal-Binding`.
//! - `KubernetesIdentity`: when the projected token file exists (`SEAL_KUBERNETES_TOKEN_FILE`,
//!   default `/var/run/secrets/seal.zone/token`, audience `seal:<tenant>`). Sends the file's
//!   token, re-read for every proof.
//! - `GcpIdentity`: when the metadata server answers (`GCE_METADATA_HOST` overrides its host).
//!   Sends an identity token for audience `seal:<tenant>`, `format=full`.
//! - `GitHubActionsIdentity`: when `ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN` are set
//!   (`permissions: id-token: write`). Sends a fresh token per proof, audience `seal:<tenant>`.
//! - `AppKeyIdentity`: when `SEAL_APP_KEY` is set. Sends an Ed25519 signature over
//!   `labeled_digest(PROOF_CONTEXT_LABEL, ctx)`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use seal_proto::identity::{IdentityProof, OidcProvider, ProofContext, PROOF_CONTEXT_LABEL};
use seal_proto::signed::SigAlg;
use seal_proto::{Bearer, KeyId, PublicKey, TenantId};

use crate::ClientError;

#[cfg(feature = "aws")]
mod aws;
#[cfg(feature = "aws")]
pub use aws::AwsIdentity;

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Short name for logs and errors, e.g. `azure-managed-identity`.
    fn kind(&self) -> &'static str;
    async fn prove(&self, ctx: &ProofContext) -> Result<IdentityProof, ClientError>;
}

/// Metadata and token endpoints are fetched through this, so tests can answer for them.
#[async_trait]
pub(crate) trait Fetch: Send + Sync {
    /// `(status, body)`. `http://` for link-local metadata servers, `https://` otherwise
    /// (verified against the baked roots).
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), ClientError>;
}

/// The network: plain HTTP for `http://`, `seal_net::HttpsClient` for `https://`.
pub(crate) struct NetFetch {
    https: seal_net::HttpsClient,
    timeout: Duration,
}

impl NetFetch {
    pub(crate) fn shared(timeout: Duration) -> Arc<dyn Fetch> {
        let connector = Arc::new(seal_net::BakedRootsConnector::new(Arc::new(seal_net::TcpDialer)));
        Arc::new(Self { https: seal_net::HttpsClient::new(connector), timeout })
    }
}

#[async_trait]
impl Fetch for NetFetch {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), ClientError> {
        if url.starts_with("http://") {
            crate::transport::plain_get(url, headers, self.timeout).await
        } else {
            self.https.get(url, headers).await.map_err(|e| ClientError::Network(e.to_string()))
        }
    }
}

/// Token endpoints answer in seconds; a metadata server that does not is not there.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

fn no_identity(kind: &str, what: impl std::fmt::Display) -> ClientError {
    ClientError::NoIdentity(format!("{kind}: {what}"))
}

/// GET that must answer 200; the body otherwise stays out of the error (it may echo credentials).
async fn get_ok(fetch: &dyn Fetch, kind: &str, url: &str, headers: &[(&str, &str)]) -> Result<Vec<u8>, ClientError> {
    let (status, body) = fetch.get(url, headers).await?;
    if status != 200 {
        return Err(no_identity(kind, format!("token endpoint answered HTTP {status}")));
    }
    Ok(body)
}

fn seal_audience(tenant: &TenantId) -> String {
    format!("seal:{tenant}")
}

/// Providers that mint audience-scoped tokens refuse contexts for another tenant.
fn same_tenant(kind: &str, mine: &TenantId, ctx: &ProofContext) -> Result<(), ClientError> {
    if &ctx.tenant == mine {
        Ok(())
    } else {
        Err(no_identity(kind, format!("configured for tenant {mine}, asked to prove for {}", ctx.tenant)))
    }
}

fn oidc(provider: OidcProvider, jwt: String) -> IdentityProof {
    IdentityProof::Oidc { provider, jwt: Bearer::new(jwt) }
}

/// The environment `detect_identity` reads. Tests substitute their own.
pub(crate) trait Env: Send + Sync {
    fn var(&self, name: &str) -> Option<String>;
    fn file_exists(&self, path: &str) -> bool;
    /// Whether detection may probe the network beyond `detect`'s `probe` (the AWS chain).
    #[cfg_attr(not(feature = "aws"), allow(dead_code))]
    fn probes_network(&self) -> bool;
}

pub(crate) struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.is_empty())
    }
    fn file_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).is_file()
    }
    fn probes_network(&self) -> bool {
        true
    }
}

pub async fn detect_identity(
    tenant: &seal_proto::TenantId,
) -> Result<std::sync::Arc<dyn IdentityProvider>, ClientError> {
    detect(tenant, &ProcessEnv, NetFetch::shared(FETCH_TIMEOUT), NetFetch::shared(PROBE_TIMEOUT)).await
}

/// The detection order of the module docs. `probe` answers the GCP metadata check, with a
/// short timeout so machines without one do not wait.
pub(crate) async fn detect(
    tenant: &TenantId,
    env: &dyn Env,
    fetch: Arc<dyn Fetch>,
    probe: Arc<dyn Fetch>,
) -> Result<Arc<dyn IdentityProvider>, ClientError> {
    if let Some(audience) = env.var("SEAL_AZURE_AUDIENCE") {
        let mut azure = AzureManagedIdentity::with_fetch(audience, fetch.clone());
        azure.client_id = env.var("AZURE_CLIENT_ID");
        azure.app_service = env.var("IDENTITY_ENDPOINT").zip(env.var("IDENTITY_HEADER").map(Bearer::new));
        return Ok(Arc::new(azure));
    }
    #[cfg(feature = "aws")]
    if let Some(aws) = AwsIdentity::detect(env).await {
        return Ok(Arc::new(aws));
    }
    let k8s = env.var("SEAL_KUBERNETES_TOKEN_FILE").unwrap_or_else(|| KubernetesIdentity::DEFAULT_PATH.to_string());
    if env.file_exists(&k8s) {
        return Ok(Arc::new(KubernetesIdentity::new(k8s)));
    }
    let gcp = GcpIdentity::with_fetch(tenant.clone(), env.var("GCE_METADATA_HOST"), fetch.clone());
    if gcp.probe(probe.as_ref()).await {
        return Ok(Arc::new(gcp));
    }
    if let (Some(url), Some(token)) =
        (env.var("ACTIONS_ID_TOKEN_REQUEST_URL"), env.var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
    {
        return Ok(Arc::new(GitHubActionsIdentity::with_fetch(tenant.clone(), url, Bearer::new(token), fetch)));
    }
    if let Some(key) = env.var("SEAL_APP_KEY") {
        return Ok(Arc::new(AppKeyIdentity::parse(&key)?));
    }
    Err(ClientError::NoIdentity(
        "none of Azure, AWS, Kubernetes, GCP, GitHub Actions or SEAL_APP_KEY is available".into(),
    ))
}

/// `SEAL_APP_KEY` format: `sealak_<base64url(32-byte Ed25519 seed)>`.
pub struct AppKeyIdentity {
    key: seal_crypto::sign::SigningKey,
}

impl AppKeyIdentity {
    pub const PREFIX: &'static str = "sealak_";

    /// From `SEAL_APP_KEY`.
    pub fn from_env() -> Result<Self, ClientError> {
        let key =
            std::env::var("SEAL_APP_KEY").map_err(|_| ClientError::NoIdentity("SEAL_APP_KEY is not set".into()))?;
        Self::parse(&key)
    }
    /// `sealak_<base64url(seed)>`. The error never repeats the key.
    pub fn parse(text: &str) -> Result<Self, ClientError> {
        let bad = || ClientError::Invalid("SEAL_APP_KEY must be sealak_ followed by 32 bytes in base64url".into());
        let encoded = text.trim().strip_prefix(Self::PREFIX).ok_or_else(bad)?;
        let seed = zeroize::Zeroizing::new(seal_proto::codec::from_b64url(encoded).map_err(|_| bad())?);
        let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| bad())?;
        Ok(Self::from_seed(seed))
    }
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { key: seal_crypto::sign::SigningKey::from_seed(seed) }
    }
    /// What an admin grants (`IdentityMatcher::AppKey`).
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }
    pub fn key_id(&self) -> KeyId {
        self.key.key_id()
    }
}

#[async_trait]
impl IdentityProvider for AppKeyIdentity {
    fn kind(&self) -> &'static str {
        "app-key"
    }
    async fn prove(&self, ctx: &ProofContext) -> Result<IdentityProof, ClientError> {
        let signature = self.key.sign(PROOF_CONTEXT_LABEL, ctx);
        let SigAlg::Ed25519 { sig } = signature.alg else {
            unreachable!("app keys are Ed25519");
        };
        Ok(IdentityProof::AppKey { key_id: signature.signer, signature: sig })
    }
}

/// An Azure managed identity's token for `audience`, the Entra app ID URI the tenant
/// registered for Seal (the grant's `IdentityMatcher::Azure::audience`). From IMDS, or from
/// `IDENTITY_ENDPOINT` with `IDENTITY_HEADER` where App Service provides them.
pub struct AzureManagedIdentity {
    audience: String,
    client_id: Option<String>,
    app_service: Option<(String, Bearer)>,
    fetch: Arc<dyn Fetch>,
}

impl AzureManagedIdentity {
    const IMDS: &'static str = "http://169.254.169.254/metadata/identity/oauth2/token";

    /// The system-assigned identity, from IMDS.
    pub fn new(audience: impl Into<String>) -> Self {
        Self::with_fetch(audience.into(), NetFetch::shared(FETCH_TIMEOUT))
    }
    /// A user-assigned identity.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }
    fn with_fetch(audience: String, fetch: Arc<dyn Fetch>) -> Self {
        Self { audience, client_id: None, app_service: None, fetch }
    }
}

#[async_trait]
impl IdentityProvider for AzureManagedIdentity {
    fn kind(&self) -> &'static str {
        "azure-managed-identity"
    }
    async fn prove(&self, _ctx: &ProofContext) -> Result<IdentityProof, ClientError> {
        let (base, api_version, header) = match &self.app_service {
            Some((endpoint, secret)) => (endpoint.as_str(), "2019-08-01", ("x-identity-header", secret.expose())),
            None => (Self::IMDS, "2018-02-01", ("metadata", "true")),
        };
        let mut url = url::Url::parse(base).map_err(|_| no_identity(self.kind(), "invalid identity endpoint"))?;
        url.query_pairs_mut().append_pair("api-version", api_version).append_pair("resource", &self.audience);
        if let Some(id) = &self.client_id {
            url.query_pairs_mut().append_pair("client_id", id);
        }
        let body = get_ok(self.fetch.as_ref(), self.kind(), url.as_str(), &[header]).await?;
        #[derive(serde::Deserialize)]
        struct Token {
            access_token: String,
        }
        let token: Token =
            serde_json::from_slice(&body).map_err(|_| no_identity(self.kind(), "no access_token in the answer"))?;
        Ok(oidc(OidcProvider::Azure, token.access_token))
    }
}

/// GitHub Actions OIDC: a fresh token for audience `seal:<tenant>` on every proof, so the
/// enclave's token-age limit holds at every extend.
pub struct GitHubActionsIdentity {
    tenant: TenantId,
    request_url: String,
    request_token: Bearer,
    fetch: Arc<dyn Fetch>,
}

impl GitHubActionsIdentity {
    /// From `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
    pub fn from_env(tenant: TenantId) -> Result<Self, ClientError> {
        let var = |name: &str| {
            std::env::var(name).ok().filter(|v| !v.is_empty()).ok_or_else(|| {
                ClientError::NoIdentity(format!("{name} is not set (needs permissions: id-token: write)"))
            })
        };
        let (url, token) = (var("ACTIONS_ID_TOKEN_REQUEST_URL")?, var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")?);
        Ok(Self::with_fetch(tenant, url, Bearer::new(token), NetFetch::shared(FETCH_TIMEOUT)))
    }
    fn with_fetch(tenant: TenantId, request_url: String, request_token: Bearer, fetch: Arc<dyn Fetch>) -> Self {
        Self { tenant, request_url, request_token, fetch }
    }
}

#[async_trait]
impl IdentityProvider for GitHubActionsIdentity {
    fn kind(&self) -> &'static str {
        "github-actions"
    }
    async fn prove(&self, ctx: &ProofContext) -> Result<IdentityProof, ClientError> {
        same_tenant(self.kind(), &self.tenant, ctx)?;
        let mut url =
            url::Url::parse(&self.request_url).map_err(|_| no_identity(self.kind(), "invalid request URL"))?;
        url.query_pairs_mut().append_pair("audience", &seal_audience(&self.tenant));
        let auth = format!("bearer {}", self.request_token.expose());
        let body = get_ok(self.fetch.as_ref(), self.kind(), url.as_str(), &[("authorization", &auth)]).await?;
        #[derive(serde::Deserialize)]
        struct Token {
            value: String,
        }
        let token: Token =
            serde_json::from_slice(&body).map_err(|_| no_identity(self.kind(), "no token in the answer"))?;
        Ok(oidc(OidcProvider::GitHub, token.value))
    }
}

/// A Kubernetes projected service account token with audience `seal:<tenant>` and
/// `expirationSeconds: 600`. The kubelet rotates the file, so it is read for every proof.
pub struct KubernetesIdentity {
    path: std::path::PathBuf,
}

impl KubernetesIdentity {
    pub const DEFAULT_PATH: &'static str = "/var/run/secrets/seal.zone/token";

    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl IdentityProvider for KubernetesIdentity {
    fn kind(&self) -> &'static str {
        "kubernetes"
    }
    async fn prove(&self, _ctx: &ProofContext) -> Result<IdentityProof, ClientError> {
        let text = tokio::fs::read_to_string(&self.path)
            .await
            .map_err(|e| no_identity(self.kind(), format!("{}: {e}", self.path.display())))?;
        let token = text.trim();
        if token.is_empty() {
            return Err(no_identity(self.kind(), format!("{} is empty", self.path.display())));
        }
        Ok(oidc(OidcProvider::Kubernetes, token.to_string()))
    }
}

/// A GCP service account's identity token from the metadata server, audience
/// `seal:<tenant>`, `format=full` (the enclave reads its `email`).
pub struct GcpIdentity {
    tenant: TenantId,
    host: String,
    fetch: Arc<dyn Fetch>,
}

impl GcpIdentity {
    /// The default service account, from `metadata.google.internal` (or `GCE_METADATA_HOST`).
    pub fn new(tenant: TenantId) -> Self {
        Self::with_fetch(tenant, std::env::var("GCE_METADATA_HOST").ok(), NetFetch::shared(FETCH_TIMEOUT))
    }
    fn with_fetch(tenant: TenantId, host: Option<String>, fetch: Arc<dyn Fetch>) -> Self {
        Self { tenant, host: host.unwrap_or_else(|| "metadata.google.internal".into()), fetch }
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}/computeMetadata/v1/{path}", self.host)
    }
    /// The metadata server answers for this instance.
    async fn probe(&self, fetch: &dyn Fetch) -> bool {
        let url = self.url("instance/service-accounts/default/email");
        matches!(fetch.get(&url, &[("metadata-flavor", "Google")]).await, Ok((200, _)))
    }
}

#[async_trait]
impl IdentityProvider for GcpIdentity {
    fn kind(&self) -> &'static str {
        "gcp-service-account"
    }
    async fn prove(&self, ctx: &ProofContext) -> Result<IdentityProof, ClientError> {
        same_tenant(self.kind(), &self.tenant, ctx)?;
        let mut url = url::Url::parse(&self.url("instance/service-accounts/default/identity"))
            .map_err(|_| no_identity(self.kind(), "invalid metadata host"))?;
        url.query_pairs_mut().append_pair("audience", &seal_audience(&self.tenant)).append_pair("format", "full");
        let body = get_ok(self.fetch.as_ref(), self.kind(), url.as_str(), &[("metadata-flavor", "Google")]).await?;
        let token = String::from_utf8(body).map_err(|_| no_identity(self.kind(), "token is not text"))?;
        Ok(oidc(OidcProvider::Gcp, token.trim().to_string()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use seal_proto::freshness::ProofTicket;
    use seal_proto::identity::ProofPurpose;

    /// A request as the fake saw it: URL and headers.
    type Recorded = (String, Vec<(String, String)>);

    /// Answers by URL prefix and records every request.
    #[derive(Default)]
    pub(crate) struct FakeFetch {
        answers: Vec<(String, u16, Vec<u8>)>,
        requests: Mutex<Vec<Recorded>>,
    }

    impl FakeFetch {
        pub(crate) fn answer(mut self, url_prefix: &str, status: u16, body: &[u8]) -> Self {
            self.answers.push((url_prefix.into(), status, body.to_vec()));
            self
        }
        pub(crate) fn requests(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Fetch for FakeFetch {
        async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<(u16, Vec<u8>), ClientError> {
            let headers = headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
            self.requests.lock().unwrap().push((url.to_string(), headers));
            self.answers
                .iter()
                .find(|(prefix, ..)| url.starts_with(prefix.as_str()))
                .map(|(_, status, body)| (*status, body.clone()))
                .ok_or_else(|| ClientError::Network(format!("no route to {url}")))
        }
    }

    #[derive(Default)]
    struct FakeEnv {
        vars: BTreeMap<String, String>,
        files: Vec<String>,
    }
    impl FakeEnv {
        fn var(mut self, name: &str, value: &str) -> Self {
            self.vars.insert(name.into(), value.into());
            self
        }
        fn file(mut self, path: &str) -> Self {
            self.files.push(path.into());
            self
        }
    }
    impl Env for FakeEnv {
        fn var(&self, name: &str) -> Option<String> {
            self.vars.get(name).cloned()
        }
        fn file_exists(&self, path: &str) -> bool {
            self.files.iter().any(|f| f == path)
        }
        fn probes_network(&self) -> bool {
            false
        }
    }

    pub(crate) fn acme() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    pub(crate) fn ctx(tenant: TenantId) -> ProofContext {
        ProofContext {
            tenant,
            purpose: ProofPurpose::Session { request_digest: [4; 32] },
            tls_spki_sha256: [5; 32],
            ticket: ProofTicket { value: [6; 32], expires_at: 1_900_000_000, mac: [7; 32] },
        }
    }

    fn header<'a>(req: &'a Recorded, name: &str) -> Option<&'a str> {
        req.1.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    fn jwt_of(proof: IdentityProof) -> (OidcProvider, String) {
        match proof {
            IdentityProof::Oidc { provider, jwt } => (provider, jwt.expose().to_string()),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn app_key_signs_the_labeled_context_digest() {
        let id = AppKeyIdentity::parse(&format!("sealak_{}", seal_proto::codec::b64url(&[9; 32]))).unwrap();
        let ctx = ctx(acme());
        let IdentityProof::AppKey { key_id, signature } = id.prove(&ctx).await.unwrap() else { panic!() };
        assert_eq!(key_id, id.key_id());
        let sig = seal_proto::signed::Signature { signer: key_id, alg: SigAlg::Ed25519 { sig: signature } };
        seal_crypto::sign::verify(&id.public_key(), PROOF_CONTEXT_LABEL, &ctx, &sig).unwrap();
        // Bound to the context: another purpose does not verify.
        let other = ProofContext { purpose: ProofPurpose::Signal { request_digest: [4; 32] }, ..ctx };
        assert!(seal_crypto::sign::verify(&id.public_key(), PROOF_CONTEXT_LABEL, &other, &sig).is_err());

        for bad in ["sealak_", "sealak_AAAAsecret", "sk_x", &format!("sealak_{}", seal_proto::codec::b64url(&[9; 31]))]
        {
            let err = AppKeyIdentity::parse(bad).err().unwrap();
            assert!(matches!(err, ClientError::Invalid(_)), "{err}");
            assert!(!err.to_string().contains("AAAAsecret"));
        }
    }

    #[tokio::test]
    async fn azure_asks_imds_for_the_configured_audience() {
        let fetch = Arc::new(FakeFetch::default().answer(
            "http://169.254.169.254/metadata/identity/oauth2/token?",
            200,
            br#"{"access_token":"eyJ.azure.jwt","expires_on":"1900000000","token_type":"Bearer"}"#,
        ));
        let id = AzureManagedIdentity::with_fetch("api://seal-acme".into(), fetch.clone()).client_id("c-1");
        assert_eq!(jwt_of(id.prove(&ctx(acme())).await.unwrap()), (OidcProvider::Azure, "eyJ.azure.jwt".into()));
        let req = &fetch.requests()[0];
        assert_eq!(
            req.0,
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api%3A%2F%2Fseal-acme&client_id=c-1"
        );
        assert_eq!(header(req, "metadata"), Some("true"));

        let refused = Arc::new(FakeFetch::default().answer("http://169.254.169.254/", 400, b"{\"error\":\"x\"}"));
        let id = AzureManagedIdentity::with_fetch("api://seal-acme".into(), refused);
        assert!(matches!(id.prove(&ctx(acme())).await, Err(ClientError::NoIdentity(_))));
    }

    #[tokio::test]
    async fn azure_uses_the_app_service_endpoint_when_set() {
        let fetch =
            Arc::new(FakeFetch::default().answer("http://127.0.0.1:41000/msi/token?", 200, br#"{"access_token":"t"}"#));
        let env = FakeEnv::default()
            .var("SEAL_AZURE_AUDIENCE", "api://seal-acme")
            .var("IDENTITY_ENDPOINT", "http://127.0.0.1:41000/msi/token")
            .var("IDENTITY_HEADER", "hdr-secret");
        let id = detect(&acme(), &env, fetch.clone(), Arc::new(FakeFetch::default())).await.unwrap();
        assert_eq!(id.kind(), "azure-managed-identity");
        id.prove(&ctx(acme())).await.unwrap();
        let req = &fetch.requests()[0];
        assert!(req.0.contains("api-version=2019-08-01&resource=api%3A%2F%2Fseal-acme"), "{}", req.0);
        assert_eq!(header(req, "x-identity-header"), Some("hdr-secret"));
    }

    #[tokio::test]
    async fn github_requests_a_fresh_token_for_the_tenant_audience_every_time() {
        let fetch = Arc::new(FakeFetch::default().answer(
            "https://pipelines.actions.githubusercontent.com/abc/idtoken?",
            200,
            br#"{"count":1,"value":"eyJ.github.jwt"}"#,
        ));
        let url = "https://pipelines.actions.githubusercontent.com/abc/idtoken?api-version=2.0".to_string();
        let id = GitHubActionsIdentity::with_fetch(acme(), url, Bearer::new("req-token".into()), fetch.clone());
        for _ in 0..2 {
            assert_eq!(jwt_of(id.prove(&ctx(acme())).await.unwrap()), (OidcProvider::GitHub, "eyJ.github.jwt".into()));
        }
        let requests = fetch.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].0,
            "https://pipelines.actions.githubusercontent.com/abc/idtoken?api-version=2.0&audience=seal%3Aacme"
        );
        assert_eq!(header(&requests[0], "authorization"), Some("bearer req-token"));
        // A context for another tenant gets no token with this tenant's audience, nor any other.
        let err = id.prove(&ctx(TenantId::new("globex").unwrap())).await.unwrap_err();
        assert!(matches!(err, ClientError::NoIdentity(_)));
        assert_eq!(fetch.requests().len(), 2);
    }

    #[tokio::test]
    async fn kubernetes_rereads_the_projected_token() {
        let dir = std::env::temp_dir().join(format!("seal-k8s-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "eyJ.k8s.one\n").unwrap();
        let id = KubernetesIdentity::new(&path);
        assert_eq!(jwt_of(id.prove(&ctx(acme())).await.unwrap()), (OidcProvider::Kubernetes, "eyJ.k8s.one".into()));
        std::fs::write(&path, "eyJ.k8s.two").unwrap();
        assert_eq!(jwt_of(id.prove(&ctx(acme())).await.unwrap()).1, "eyJ.k8s.two");
        std::fs::write(&path, "  \n").unwrap();
        assert!(matches!(id.prove(&ctx(acme())).await, Err(ClientError::NoIdentity(_))));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(id.prove(&ctx(acme())).await, Err(ClientError::NoIdentity(_))));
    }

    #[tokio::test]
    async fn gcp_asks_the_metadata_server_for_a_full_token() {
        let fetch = Arc::new(FakeFetch::default().answer(
            "http://metadata.google.internal/computeMetadata/v1/",
            200,
            b"eyJ.gcp.jwt\n",
        ));
        let id = GcpIdentity::with_fetch(acme(), None, fetch.clone());
        assert_eq!(jwt_of(id.prove(&ctx(acme())).await.unwrap()), (OidcProvider::Gcp, "eyJ.gcp.jwt".into()));
        let req = &fetch.requests()[0];
        assert_eq!(
            req.0,
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=seal%3Aacme&format=full"
        );
        assert_eq!(header(req, "metadata-flavor"), Some("Google"));
        assert!(id.prove(&ctx(TenantId::new("globex").unwrap())).await.is_err());
    }

    #[tokio::test]
    async fn detection_order() {
        let none = || Arc::new(FakeFetch::default()) as Arc<dyn Fetch>;
        let gcp = || {
            Arc::new(FakeFetch::default().answer("http://metadata.google.internal/", 200, b"sa@p.iam"))
                as Arc<dyn Fetch>
        };
        let key = format!("sealak_{}", seal_proto::codec::b64url(&[1; 32]));
        let everything = || {
            FakeEnv::default()
                .var("SEAL_AZURE_AUDIENCE", "api://x")
                .file(KubernetesIdentity::DEFAULT_PATH)
                .var("ACTIONS_ID_TOKEN_REQUEST_URL", "https://gh/x?a=b")
                .var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t")
                .var("SEAL_APP_KEY", &key)
        };
        let kind = |env: FakeEnv, probe: Arc<dyn Fetch>| async move {
            detect(&acme(), &env, none(), probe).await.map(|p| p.kind())
        };

        assert_eq!(kind(everything(), gcp()).await.unwrap(), "azure-managed-identity");
        let mut env = everything();
        env.vars.remove("SEAL_AZURE_AUDIENCE");
        assert_eq!(kind(env, gcp()).await.unwrap(), "kubernetes");
        let mut env = everything();
        env.vars.remove("SEAL_AZURE_AUDIENCE");
        env.files.clear();
        assert_eq!(kind(env, gcp()).await.unwrap(), "gcp-service-account");
        let mut env = everything();
        env.vars.remove("SEAL_AZURE_AUDIENCE");
        env.files.clear();
        assert_eq!(kind(env, none()).await.unwrap(), "github-actions");
        let env = FakeEnv::default().var("SEAL_APP_KEY", &key);
        assert_eq!(kind(env, none()).await.unwrap(), "app-key");
        // A custom token path.
        let env = FakeEnv::default().var("SEAL_KUBERNETES_TOKEN_FILE", "/t").file("/t");
        assert_eq!(kind(env, none()).await.unwrap(), "kubernetes");
        let env = FakeEnv::default().var("SEAL_APP_KEY", "garbage");
        assert!(matches!(kind(env, none()).await, Err(ClientError::Invalid(_))));
        assert!(matches!(kind(FakeEnv::default(), none()).await, Err(ClientError::NoIdentity(_))));
    }
}
