//! The client and the seal operation.

use std::future::{Future, IntoFuture};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use seal_proto::api::{
    ApiError, IngestContext, SealPayload, SealRequest, SealResponse, SignalRequest, TelemetryReceipt,
};
use seal_proto::freshness::{ProofTicket, ATTESTATION_MAX_AGE_SECS, ATTESTATION_REFRESH_SECS};
use seal_proto::identity::{IdentityProof, ProofContext, ProofPurpose};
use seal_proto::integrity::Severity;
use seal_proto::session::PlatformTier;
use seal_proto::{ErrorCode, KeyId, PlatformId, SecretVec, TenantPin};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::retry::{self, Pass};
use crate::transport::{self, ConnectError};
use crate::verify::{self, Expected, VerifiedEnclave};
use crate::{BoxFuture, ClientError, IdentityProvider, SessionBuilder, TenantId, TenantRootId, UnixTime};

/// A verified connection to the tenant's enclaves, acting as one workload identity (sealing
/// needs none).
/// Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    endpoints: Vec<url::Url>,
    expected: Expected,
    /// `ClientBuilder::identity`, else detected on the first session or signal: sealing needs
    /// none, so a client that only seals never looks. A failed detection is retried next time.
    identity: tokio::sync::OnceCell<Arc<dyn IdentityProvider>>,
    /// The identity is detected, not given.
    detected: bool,
    trust: seal_verify::Trust,
    /// The latest verified enclave and the local time it was verified at.
    enclave: RwLock<(Arc<VerifiedEnclave>, UnixTime)>,
    /// One re-verification at a time.
    refresh: tokio::sync::Mutex<()>,
    /// The endpoint that answered last; requests start there.
    current: AtomicUsize,
    /// The last proof ticket, with the TLS key of the enclave that issued it.
    ticket: Mutex<Option<([u8; 32], ProofTicket)>>,
}

/// The local clock, seconds since the Unix epoch.
pub(crate) fn now() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// An enclave error response: its `ApiError` code and message, or `Network` when the body
/// is not one (a proxy in between, a crash).
pub(crate) fn api_error(status: u16, body: &[u8]) -> ClientError {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) => ClientError::Seal { code: e.code, message: e.message },
        Err(_) => ClientError::Network(format!("enclave answered HTTP {status}")),
    }
}

/// `ResealRequired` from an enclave on `platform`, saying what to do.
pub(crate) fn reseal_required(platform: PlatformId) -> ClientError {
    let name = match platform {
        PlatformId::AzureSnpAci => "Azure (ACI)",
        PlatformId::AwsNitro => "AWS Nitro",
        PlatformId::GcpConfidentialSpace => "GCP Confidential Space",
        PlatformId::Sim => "the simulator",
    };
    ClientError::Seal {
        code: ErrorCode::ResealRequired,
        message: format!("this blob was sealed before {name} was enabled; reseal it"),
    }
}

/// Tickets are reused until shortly before they expire.
const TICKET_MARGIN_SECS: u64 = 20;

impl Client {
    /// Everything from the environment: `SEAL_ENDPOINT` (the tenant's enclave replicas,
    /// comma-separated), `SEAL_TENANT` (`<tenant>` or `<tenant>@<root id>`) and, for sessions
    /// and signals, the first workload identity `detect_identity` finds. Verifies the enclave
    /// before returning.
    pub async fn from_env() -> Result<Self, ClientError> {
        Self::builder().connect().await
    }

    /// Explicit configuration; anything not set comes from the environment as in `from_env`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Seal `secret` so only the named `apps` can use it, and only with `to`. Returns the
    /// portable blob text (`seal1.…`), safe to store anywhere. Anyone may seal: it needs no
    /// identity and no grant.
    ///
    /// `to` is the destination URL (`https://`, `postgres://`, `clickhouse://`, `rediss://`).
    /// Options chain before `.await`: `header`, `format`, `pin`, `expires`, `methods`,
    /// `deny`, `sealed_only`, `hardened_only`; end with `.with_receipt()` to get the telemetry receipt too.
    pub fn seal<'a, A, S>(&'a self, secret: &'a [u8], to: &'a str, apps: A) -> SealBuilder<'a>
    where
        A: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        SealBuilder {
            client: self,
            secret,
            to,
            apps: apps.into_iter().map(|a| a.as_ref().to_owned()).collect(),
            header: None,
            format: None,
            pins: Vec::new(),
            expires: None,
            methods: Vec::new(),
            deny: Vec::new(),
            sealed_only: false,
            hardened_only: false,
        }
    }

    /// Start a session on `blob`: the enclave opens it and the app gets a stand-in. Needs an
    /// app grant listed in the blob's policy. Options chain first (`min_tier`, `reload_with`,
    /// `on_reseal`, `endpoint_reporter`); end with `.http()` (`url`, `key`),
    /// `.database()` (`dsn`), or `.await` for a `Session` of whichever kind the blob is.
    pub fn session<'a>(&'a self, blob: &str) -> SessionBuilder<'a> {
        SessionBuilder::new(self, blob.to_owned())
    }

    /// Signal that this workload's own endpoint may be compromised. Names only this
    /// identity; under the tenant's integrity policy it may suspend the identity at once.
    /// `code` is opaque to Seal (`[a-z0-9-.]`, 1..=64).
    pub async fn signal(&self, code: &str, severity: Severity) -> Result<(), ClientError> {
        seal_proto::integrity::validate_code(code)?;
        let enclave = self.enclave().await?;
        let (context, proof) = placeholder(self.tenant());
        let mut request = SignalRequest {
            code: code.to_owned(),
            severity,
            context: Some(context),
            proof: Some(proof),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        };
        let (context, proof) = self.prove(&enclave, request.expected_purpose()).await?;
        request.context = Some(context);
        request.proof = Some(proof);
        self.call_empty(&enclave, "/v1/signals", &request).await
    }

    /// The tenant this client serves.
    pub fn tenant(&self) -> &TenantId {
        &self.inner.expected.tenant
    }

    /// The verified enclave, re-verified when its last check is `ATTESTATION_REFRESH_SECS`
    /// old. If no replica is reachable, the last one is used while its attestation is within
    /// `ATTESTATION_MAX_AGE_SECS`, and after that the endpoints are retried for up to
    /// `UNREACHABLE_WAIT_SECS`; a replica that answers but fails verification is an error.
    pub async fn enclave(&self) -> Result<Arc<VerifiedEnclave>, ClientError> {
        let cached = || self.inner.enclave.read().unwrap_or_else(|e| e.into_inner()).clone();
        let now = now();
        let (enclave, verified_at) = cached();
        if now < verified_at.saturating_add(ATTESTATION_REFRESH_SECS) {
            return Ok(enclave);
        }
        let _one = self.inner.refresh.lock().await;
        let (enclave, verified_at) = cached();
        if now < verified_at.saturating_add(ATTESTATION_REFRESH_SECS) {
            return Ok(enclave);
        }
        let inner = &self.inner;
        let verify =
            || verify_any(&inner.endpoints, inner.current.load(Ordering::Relaxed), &inner.trust, &inner.expected);
        let verified = match verify().await {
            Err(ClientError::Network(m)) if now < enclave.attested_at().saturating_add(ATTESTATION_MAX_AGE_SECS) => {
                tracing::warn!(error = %m, "re-verifying the enclave failed; using the last verified attestation");
                return Ok(enclave);
            }
            Err(missed @ ClientError::Network(_)) => {
                retry::while_unreachable(missed, || async { pass(verify().await) }).await
            }
            verified => verified,
        };
        let (fresh, index) = verified?;
        let fresh = Arc::new(fresh);
        self.inner.current.store(index, Ordering::Relaxed);
        *self.inner.enclave.write().unwrap_or_else(|e| e.into_inner()) = (fresh.clone(), now);
        Ok(fresh)
    }

    /// The enclave endpoints, starting with the one that answered last.
    pub(crate) fn endpoints_from_current(&self) -> Vec<url::Url> {
        let n = self.inner.endpoints.len();
        let start = self.inner.current.load(Ordering::Relaxed);
        (0..n).map(|i| self.inner.endpoints[(start + i) % n].clone()).collect()
    }

    /// Warns once per process when the app key and `blob` both come from environment
    /// variables: whoever can read this process's environment then holds both.
    pub(crate) async fn warn_if_env_app_key_and_blob(&self, blob: &str) {
        static WARNED: std::sync::Once = std::sync::Once::new();
        let from_env = self.inner.detected && self.identity().await.is_ok_and(|i| i.kind() == "app-key");
        if from_env && std::env::vars().any(|(_, v)| v.trim() == blob.trim()) {
            WARNED.call_once(|| {
                tracing::warn!(
                    "SEAL_APP_KEY and the blob both come from environment variables: anyone who can read this \
                     process's environment can use the secret; use a workload identity or keep the blob elsewhere"
                )
            });
        }
    }

    /// A proof context for `purpose` against `enclave` and the identity's proof over it.
    pub(crate) async fn prove(
        &self,
        enclave: &Arc<VerifiedEnclave>,
        purpose: ProofPurpose,
    ) -> Result<(ProofContext, IdentityProof), ClientError> {
        let ticket = self.ticket(enclave).await?;
        let context = ProofContext {
            tenant: self.tenant().clone(),
            purpose,
            tls_spki_sha256: *enclave.tls_spki_sha256(),
            ticket,
        };
        let proof = self.identity().await?.prove(&context).await?;
        Ok((context, proof))
    }

    /// The workload identity, detected the first time it is needed.
    async fn identity(&self) -> Result<&Arc<dyn IdentityProvider>, ClientError> {
        self.inner.identity.get_or_try_init(|| crate::identity::detect_identity(self.tenant())).await
    }

    async fn ticket(&self, enclave: &Arc<VerifiedEnclave>) -> Result<ProofTicket, ClientError> {
        let spki = *enclave.tls_spki_sha256();
        let cached = self.inner.ticket.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some((key, ticket)) = cached {
            if key == spki && now().saturating_add(TICKET_MARGIN_SECS) < ticket.expires_at {
                return Ok(ticket);
            }
        }
        let body = self.call_raw(enclave, "/v1/tickets", Vec::new()).await?;
        let ticket: ProofTicket = decode("/v1/tickets", &body)?;
        *self.inner.ticket.lock().unwrap_or_else(|e| e.into_inner()) = Some((spki, ticket.clone()));
        Ok(ticket)
    }

    /// `POST path` with a JSON body, JSON response.
    pub(crate) async fn call<B: Serialize, R: DeserializeOwned>(
        &self,
        enclave: &Arc<VerifiedEnclave>,
        path: &str,
        body: &B,
    ) -> Result<R, ClientError> {
        let body = serde_json::to_vec(body).map_err(|e| ClientError::Invalid(e.to_string()))?;
        decode(path, &self.call_raw(enclave, path, body).await?)
    }

    /// `POST path` with a JSON body, empty response.
    pub(crate) async fn call_empty<B: Serialize>(
        &self,
        enclave: &Arc<VerifiedEnclave>,
        path: &str,
        body: &B,
    ) -> Result<(), ClientError> {
        let body = serde_json::to_vec(body).map_err(|e| ClientError::Invalid(e.to_string()))?;
        self.call_raw(enclave, path, body).await.map(drop)
    }

    /// One POST over TLS pinned to `enclave`'s key. Fails over to the next endpoint when
    /// nothing was sent; when no endpoint is reachable, retries for up to `UNREACHABLE_WAIT_SECS`.
    async fn call_raw(
        &self,
        enclave: &Arc<VerifiedEnclave>,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        match self.call_once(enclave, path, &body).await {
            Pass::Answered(result) => result,
            Pass::Unreachable(missed) => {
                retry::while_unreachable(missed, || self.call_once(enclave, path, &body)).await
            }
        }
    }

    /// `call_raw`'s pass over the endpoints, from the one that answered last.
    async fn call_once(&self, enclave: &Arc<VerifiedEnclave>, path: &str, body: &[u8]) -> Pass<Vec<u8>> {
        let n = self.inner.endpoints.len();
        let start = self.inner.current.load(Ordering::Relaxed);
        let mut last = ClientError::Network("no enclave endpoints".into());
        for i in 0..n {
            let index = (start + i) % n;
            let (host, port) = match verify::host_port(&self.inner.endpoints[index]) {
                Ok(host_port) => host_port,
                Err(e) => return Pass::Answered(Err(e)),
            };
            let stream = match transport::tls_connect(enclave.client_config(), &host, port).await {
                Ok(s) => s,
                Err(ConnectError::Unreachable(m)) => {
                    last = ClientError::Network(m);
                    continue;
                }
                Err(e @ ConnectError::Pin) => return Pass::Answered(Err(e.into())),
            };
            self.inner.current.store(index, Ordering::Relaxed);
            let authority = verify::authority(&host, port);
            let headers = [("accept", "application/json")];
            let request = Some(body.to_vec());
            let exchange = transport::exchange(stream, hyper::Method::POST, &authority, path, &headers, request);
            return Pass::Answered(match tokio::time::timeout(transport::EXCHANGE_TIMEOUT, exchange).await {
                Err(_) => Err(ClientError::Network(format!("{authority}{path}: timed out"))),
                Ok(Err(e)) => Err(ClientError::Network(format!("{authority}{path}: {e}"))),
                Ok(Ok((status, body))) if (200..300).contains(&status) => Ok(body),
                Ok(Ok((status, body))) => Err(match api_error(status, &body) {
                    ClientError::Seal { code: ErrorCode::ResealRequired, .. } => reseal_required(enclave.platform()),
                    e => e,
                }),
            });
        }
        Pass::Unreachable(last)
    }
}

/// `verify_any`'s result as a pass: `Network` means no replica could be verified.
fn pass<T>(result: Result<T, ClientError>) -> Pass<T> {
    match result {
        Err(e @ ClientError::Network(_)) => Pass::Unreachable(e),
        result => Pass::Answered(result),
    }
}

fn decode<R: DeserializeOwned>(path: &str, body: &[u8]) -> Result<R, ClientError> {
    serde_json::from_slice(body).map_err(|e| ClientError::Network(format!("{path}: malformed response: {e}")))
}

/// Stand-ins for the context and proof while a request's purpose is computed: every
/// `expected_purpose()` reads only the other fields.
pub(crate) fn placeholder(tenant: &TenantId) -> (ProofContext, IdentityProof) {
    let context = ProofContext {
        tenant: tenant.clone(),
        purpose: ProofPurpose::Session { request_digest: [0; 32] },
        tls_spki_sha256: [0; 32],
        ticket: ProofTicket { value: [0; 32], expires_at: 0, mac: [0; 32] },
    };
    (context, IdentityProof::AppKey { key_id: KeyId([0; 32]), signature: Vec::new() })
}

/// The first endpoint (from `start`) that answers and verifies. A replica that answers but
/// fails verification ends the search: it is never skipped silently.
async fn verify_any(
    endpoints: &[url::Url],
    start: usize,
    trust: &seal_verify::Trust,
    expected: &Expected,
) -> Result<(VerifiedEnclave, usize), ClientError> {
    let mut last = ClientError::Network("no enclave endpoints".into());
    for i in 0..endpoints.len() {
        let index = (start + i) % endpoints.len();
        match verify::fetch(&endpoints[index], trust, expected, now()).await {
            Ok(enclave) => return Ok((enclave, index)),
            Err(e @ ClientError::Network(_)) => {
                tracing::debug!(endpoint = %endpoints[index], error = %e, "enclave endpoint unreachable");
                last = e;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// `Client::builder()`. Unset fields come from the environment.
#[derive(Default)]
pub struct ClientBuilder {
    endpoints: Vec<url::Url>,
    tenant: Option<TenantId>,
    root_id: Option<TenantRootId>,
    identity: Option<Arc<dyn IdentityProvider>>,
    trust: Option<seal_verify::Trust>,
}

impl ClientBuilder {
    /// The tenant's enclave replicas, e.g. `https://10.0.1.4:8443`. Replicas share keys and
    /// ports, so the SDK fails over between them without a load balancer.
    pub fn endpoints(mut self, endpoints: impl IntoIterator<Item = url::Url>) -> Self {
        self.endpoints = endpoints.into_iter().collect();
        self
    }
    pub fn tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
    }
    /// The tenant's root chain. Enclaves serving another chain for the same tenant name are
    /// refused, so this client cannot be steered to seal under a competing root.
    pub fn root_id(mut self, root_id: TenantRootId) -> Self {
        self.root_id = Some(root_id);
        self
    }
    /// Default: `detect_identity`, on the first session or signal (sealing needs no identity).
    pub fn identity(mut self, identity: Arc<dyn IdentityProvider>) -> Self {
        self.identity = Some(identity);
        self
    }
    /// Default: the trust shipped with this SDK build (`release-trust.json` in this crate,
    /// Seal's production trust, or the file `SEAL_RELEASE_TRUST` named at build time). `seal::Trust::from_json` reads a published
    /// `trust.json`. `releases.time_lock_secs = 0` suffices here: the guardian's certificate on
    /// the enclave's keys proves the wait already passed. `sim` builds read it from the JSON
    /// file `SEAL_TRUST` names when it is set.
    pub fn trust(mut self, trust: seal_verify::Trust) -> Self {
        self.trust = Some(trust);
        self
    }
    /// Verifies the enclave (see the crate docs) and caches the result for its attestation
    /// lifetime. When no endpoint is reachable, retries for up to `UNREACHABLE_WAIT_SECS`.
    pub async fn connect(self) -> Result<Client, ClientError> {
        let endpoints = match self.endpoints.is_empty() {
            false => self.endpoints,
            true => endpoints_from_env()?,
        };
        for endpoint in &endpoints {
            verify::host_port(endpoint)?;
        }
        let (tenant, root_id) = tenant_from_env(self.tenant, self.root_id)?;
        let trust = match self.trust {
            Some(t) => t,
            None => shipped_trust()?,
        };
        let expected = Expected { tenant, root_id };
        let verify = || verify_any(&endpoints, 0, &trust, &expected);
        let (enclave, index) = match verify().await {
            Err(missed @ ClientError::Network(_)) => {
                retry::while_unreachable(missed, || async { pass(verify().await) }).await?
            }
            verified => verified?,
        };
        Ok(Client {
            inner: Arc::new(Inner {
                endpoints,
                detected: self.identity.is_none(),
                identity: tokio::sync::OnceCell::new_with(self.identity),
                expected,
                trust,
                enclave: RwLock::new((Arc::new(enclave), now())),
                refresh: tokio::sync::Mutex::new(()),
                current: AtomicUsize::new(index),
                ticket: Mutex::new(None),
            }),
        })
    }
}

fn endpoints_from_env() -> Result<Vec<url::Url>, ClientError> {
    let text = std::env::var("SEAL_ENDPOINT").map_err(|_| ClientError::Invalid("SEAL_ENDPOINT is not set".into()))?;
    let endpoints = text
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| url::Url::parse(s).map_err(|e| ClientError::Invalid(format!("SEAL_ENDPOINT {s}: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    if endpoints.is_empty() {
        return Err(ClientError::Invalid("SEAL_ENDPOINT names no endpoint".into()));
    }
    Ok(endpoints)
}

/// The builder's tenant and root, completed from `SEAL_TENANT` (`<tenant>` or
/// `<tenant>@<root id>`). The root comes from the environment only for the same tenant.
fn tenant_from_env(
    tenant: Option<TenantId>,
    root_id: Option<TenantRootId>,
) -> Result<(TenantId, Option<TenantRootId>), ClientError> {
    let from_env = match std::env::var("SEAL_TENANT") {
        Ok(text) => Some(parse_tenant(&text)?),
        Err(_) => None,
    };
    match (tenant, from_env) {
        (Some(t), Some((env_tenant, env_root))) => {
            let root = root_id.or(env_root.filter(|_| env_tenant == t));
            Ok((t, root))
        }
        (Some(t), None) => Ok((t, root_id)),
        (None, Some((t, env_root))) => Ok((t, root_id.or(env_root))),
        (None, None) => Err(ClientError::Invalid("SEAL_TENANT is not set".into())),
    }
}

pub(crate) fn parse_tenant(text: &str) -> Result<(TenantId, Option<TenantRootId>), ClientError> {
    Ok(TenantPin::parse_partial(text)?)
}

/// The release trust `build.rs` compiled in (empty when none was given).
const RELEASE_TRUST: &str = include_str!(concat!(env!("OUT_DIR"), "/release-trust.json"));

/// The trust shipped with this build: `SEAL_RELEASE_TRUST`'s file at build time, else this
/// crate's `release-trust.json` (see build.rs).
/// `sim` builds read the file `SEAL_TRUST` names first, when it is set.
fn shipped_trust() -> Result<seal_verify::Trust, ClientError> {
    #[cfg(feature = "sim")]
    if let Some(path) = std::env::var_os("SEAL_TRUST") {
        let path = std::path::Path::new(&path);
        let text =
            std::fs::read(path).map_err(|e| ClientError::Invalid(format!("SEAL_TRUST {}: {e}", path.display())))?;
        return seal_verify::Trust::from_json(&text)
            .map_err(|e| ClientError::Invalid(format!("SEAL_TRUST {}: {e}", path.display())));
    }
    built_in_trust().unwrap_or_else(|| {
        Err(ClientError::Verification(
            "this SDK build ships no release trust; pass ClientBuilder::trust (seal::Trust::from_json)".into(),
        ))
    })
}

/// The trust `SEAL_RELEASE_TRUST` named when this build was compiled; `None` when it named
/// none. Tools that verify tenants without connecting (the CLI) start from it.
pub fn built_in_trust() -> Option<Result<seal_verify::Trust, ClientError>> {
    if RELEASE_TRUST.trim().is_empty() {
        return None;
    }
    Some(
        seal_verify::Trust::from_json(RELEASE_TRUST.as_bytes())
            .map_err(|e| ClientError::Verification(format!("the shipped release trust: {e}"))),
    )
}

/// `Client::seal(..)`: chain options, then `.await` for the blob text.
#[must_use = "a seal does nothing until you .await it"]
pub struct SealBuilder<'a> {
    client: &'a Client,
    secret: &'a [u8],
    to: &'a str,
    apps: Vec<String>,
    header: Option<String>,
    format: Option<String>,
    pins: Vec<String>,
    expires: Option<UnixTime>,
    methods: Vec<String>,
    deny: Vec<String>,
    sealed_only: bool,
    hardened_only: bool,
}

impl<'a> SealBuilder<'a> {
    /// HTTP: the header that carries the secret. Default `authorization`.
    pub fn header(mut self, header: &str) -> Self {
        self.header = Some(header.to_owned());
        self
    }
    /// HTTP: the header value, with `{key}` where the secret goes. Default `Bearer {key}`
    /// for `authorization`, `{key}` otherwise.
    pub fn format(mut self, format: &str) -> Self {
        self.format = Some(format.to_owned());
        self
    }
    /// Require this upstream key (`sha256/<base64>`) in the upstream's certificate chain.
    /// Call up to 4 times, e.g. for the current and the next key.
    pub fn pin(mut self, pin: &str) -> Self {
        self.pins.push(pin.to_owned());
        self
    }
    /// The blob stops working at this time, on every copy.
    pub fn expires(mut self, at: UnixTime) -> Self {
        self.expires = Some(at);
        self
    }
    /// HTTP: allowed methods. Default: any.
    pub fn methods<M: AsRef<str>>(mut self, methods: impl IntoIterator<Item = M>) -> Self {
        self.methods = methods.into_iter().map(|m| m.as_ref().to_ascii_uppercase()).collect();
        self
    }
    /// HTTP: refuse paths under this prefix, even inside `to` (e.g. key-management endpoints).
    pub fn deny(mut self, path_prefix: &str) -> Self {
        self.deny.push(path_prefix.to_owned());
        self
    }
    /// Only enclaves on the sealed platform tier may open this blob.
    pub fn sealed_only(mut self) -> Self {
        self.sealed_only = true;
        self
    }
    /// Only hardened sessions may use this blob: inside the SDK's channel, with the
    /// endpoint presenting verified integrity evidence at every start and extend. The
    /// blob stops working within one extend of the endpoint's attestation going silent.
    pub fn hardened_only(mut self) -> Self {
        self.hardened_only = true;
        self
    }

    /// The blob text and where telemetry recorded this seal. Keep the receipt
    /// (`receipts::append`) for `seal telemetry --receipts`.
    // The signature states `Send`, which bindings rely on.
    #[allow(clippy::manual_async_fn)]
    pub fn with_receipt(self) -> impl Future<Output = Result<(String, TelemetryReceipt), ClientError>> + Send + 'a {
        async move {
            let response = self.send().await?;
            Ok((response.blob, response.telemetry))
        }
    }

    /// The `SecretPolicy` these arguments describe; every check `SecretPolicy` makes applies.
    fn policy(&self) -> Result<seal_proto::policy::SecretPolicy, ClientError> {
        use seal_proto::policy::{HttpRules, Injection, SecretPolicy, SpkiPin};
        let apps = self.apps.iter().map(|a| seal_proto::AppName::new(a.as_str())).collect::<Result<Vec<_>, _>>()?;
        let mut policy = SecretPolicy::new(self.to, apps)?;
        if let Some(at) = self.expires {
            policy = policy.with_expiry(at);
        }
        if self.header.is_some() || self.format.is_some() || !self.methods.is_empty() || !self.deny.is_empty() {
            let injection = Injection::new(self.header.as_deref().unwrap_or("authorization"), self.format.as_deref())?;
            let rules = HttpRules {
                methods: self.methods.iter().cloned().collect(),
                deny_path_prefixes: self.deny.iter().cloned().collect(),
            };
            policy = policy.with_http(injection, rules)?;
        }
        if !self.pins.is_empty() {
            let pins = self.pins.iter().map(|p| p.parse::<SpkiPin>()).collect::<Result<Vec<_>, _>>()?;
            policy = policy.with_pins(pins)?;
        }
        if self.sealed_only {
            policy = policy.with_min_platform(PlatformTier::Sealed);
        }
        if self.hardened_only {
            policy = policy.with_min_tier(seal_proto::session::ConsumerTier::Hardened);
        }
        Ok(policy)
    }
}

impl<'a> IntoFuture for SealBuilder<'a> {
    type Output = Result<String, ClientError>;
    type IntoFuture = BoxFuture<'a, Self::Output>;

    /// The blob text (`SealBuilder::send`).
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { Ok(self.send().await?.blob) })
    }
}

impl SealBuilder<'_> {
    /// Validates the policy locally, then HPKE-seals secret and policy to the enclave's
    /// attested ingest key (`POST /v1/blobs`): plaintext `canonical(SealPayload)`, info
    /// `ingest_info(tenant)`, AAD `canonical(IngestContext)`. The returned blob must name the
    /// client's tenant and root and carry exactly the policy sent.
    async fn send(self) -> Result<SealResponse, ClientError> {
        let policy = self.policy()?;
        policy.validate_secret(self.secret)?;
        let client = self.client;
        let enclave = client.enclave().await?;
        let binding = enclave.binding();
        let tenant = client.tenant();
        let ingest = IngestContext {
            tenant: tenant.clone(),
            service_key_version: binding.service_key_version,
            tls_spki_sha256: binding.tls_spki_sha256,
        };
        let payload = zeroize::Zeroizing::new(seal_proto::codec::canonical(&SealPayload {
            secret: SecretVec::new(self.secret.to_vec()),
            policy: policy.clone(),
        }));
        let (hpke_enc, sealed_payload) = seal_crypto::hpke::seal(
            &binding.ingest_public_key,
            &seal_crypto::hpke::ingest_info(tenant),
            &seal_proto::codec::canonical(&ingest),
            &payload,
            &mut seal_crypto::UnwrapErr(seal_crypto::SysRng),
        )
        .map_err(|e| ClientError::Verification(format!("the attested ingest key: {e}")))?;
        let request = SealRequest { service_key_version: binding.service_key_version, hpke_enc, sealed_payload };
        let response: SealResponse = client.call(&enclave, "/v1/blobs", &request).await?;

        let blob = seal_proto::blob::Blob::from_str(&response.blob)
            .map_err(|e| ClientError::Verification(format!("the enclave returned no valid blob: {e}")))?;
        if &blob.header.tenant != tenant || &blob.header.root_id != enclave.root_id() || blob.policy != policy {
            return Err(ClientError::Verification("the enclave returned a blob for another tenant or policy".into()));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trust this build compiled in, when it has one, is one clients accept; without one,
    /// a client needs a trust passed in.
    #[test]
    fn shipped_trust_is_the_compiled_one() {
        if cfg!(feature = "sim") && std::env::var_os("SEAL_TRUST").is_some() {
            return;
        }
        match RELEASE_TRUST.trim().is_empty() {
            true => {
                assert!(matches!(shipped_trust(), Err(ClientError::Verification(m)) if m.contains("Trust::from_json")))
            }
            false => {
                shipped_trust().unwrap();
            }
        }
    }

    #[test]
    fn tenant_text() {
        let root = TenantRootId([3; 32]);
        assert_eq!(parse_tenant("acme").unwrap(), (TenantId::new("acme").unwrap(), None));
        assert_eq!(parse_tenant(&format!(" acme@{root} ")).unwrap(), (TenantId::new("acme").unwrap(), Some(root)));
        assert!(matches!(parse_tenant("Acme"), Err(ClientError::Invalid(_))));
        assert!(matches!(parse_tenant("acme@12"), Err(ClientError::Invalid(_))));
    }

    #[test]
    fn api_errors_keep_the_code() {
        let body =
            serde_json::to_vec(&ApiError { code: seal_proto::ErrorCode::Expired, message: "blob expired".into() })
                .unwrap();
        match api_error(410, &body) {
            ClientError::Seal { code, message } => {
                assert_eq!((code, message.as_str()), (seal_proto::ErrorCode::Expired, "blob expired"))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(api_error(502, b"<html>bad gateway</html>"), ClientError::Network(_)));
        let reseal = reseal_required(PlatformId::GcpConfidentialSpace);
        assert_eq!(reseal.code(), ErrorCode::ResealRequired);
        assert_eq!(
            reseal.to_string(),
            "ResealRequired: this blob was sealed before GCP Confidential Space was enabled; reseal it"
        );
    }

    #[test]
    fn placeholders_do_not_change_purposes() {
        let (context, proof) = placeholder(&TenantId::new("acme").unwrap());
        let a = SignalRequest {
            code: "x".into(),
            severity: Severity::High,
            context: Some(context),
            proof: Some(proof),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        }
        .expected_purpose();
        let (context, _) = placeholder(&TenantId::new("other").unwrap());
        let proof = IdentityProof::AppKey { key_id: KeyId([1; 32]), signature: vec![1] };
        let b = SignalRequest {
            code: "x".into(),
            severity: Severity::High,
            context: Some(context),
            proof: Some(proof),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        }
        .expected_purpose();
        assert_eq!(a, b);
    }
}
