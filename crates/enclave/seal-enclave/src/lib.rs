//! Seal runtime contract. Business operations do not depend on deployment topology or on
//! the cloud: everything cloud-specific arrives as one `seal_cloud::Cloud`.
//! Local providers are explicit sim-only implementations; production providers can
//! use the guardian/control service without changing these business methods.
#![forbid(unsafe_code)]

pub mod api;
pub mod ports;
mod proxy;

use async_trait::async_trait;
use seal_crypto::{ServiceKeyScope, ServiceKeys, TenantWrappingKey, TenantWrappingKeyScope};
use seal_proto::{
    api::*,
    integrity::SignedSignal,
    release::SignedServiceKeyCertificate,
    session::SignedSessionEnd,
    state::TenantBundle,
    telemetry::{SignedTelemetryBatch, TelemetryBatch, TELEMETRY_BATCH_LABEL},
    ErrorCode, PlatformId, PublicKey, ServiceKeyVersion, TenantId, UnixTime,
};
use std::collections::BTreeSet;
use std::sync::Arc;

mod runtime;

/// What every operation and port fails with: the public code, plus detail for the enclave's
/// own diagnostics. `detail` never reaches a caller and never holds a secret. `context` is why
/// a refusal happened, for the tenant's telemetry (`TelemetryEvent::Refused`): built only from
/// values the enclave checked and its own fixed sentences, never from an upstream's text.
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct ServiceError {
    pub code: ErrorCode,
    pub detail: String,
    pub context: Option<Box<seal_proto::telemetry::RefusalContext>>,
}

impl ServiceError {
    /// The same error, with the values that explain it.
    pub(crate) fn with(mut self, context: seal_proto::telemetry::RefusalContext) -> Self {
        self.context = Some(Box::new(context));
        self
    }
}

/// A `ServiceError`'s detail: one of the enclave's fixed sentences, which a malformed request
/// also gives its telemetry (`RefusalContext::Malformed`), or text built at run time (which
/// may hold an upstream's words), which stays in the log.
pub(crate) enum Detail {
    Fixed(&'static str),
    Built(String),
}

impl From<&'static str> for Detail {
    fn from(s: &'static str) -> Self {
        Detail::Fixed(s)
    }
}

impl From<String> for Detail {
    fn from(s: String) -> Self {
        Detail::Built(s)
    }
}

/// A `ServiceError` with `code` and diagnostic `detail`.
pub(crate) fn fail(code: ErrorCode, detail: impl Into<Detail>) -> ServiceError {
    match detail.into() {
        Detail::Fixed(s) => ServiceError {
            code,
            detail: s.into(),
            context: (code == ErrorCode::BadRequest)
                .then(|| Box::new(seal_proto::telemetry::RefusalContext::Malformed { what: s.into() })),
        },
        Detail::Built(detail) => ServiceError { code, detail, context: None },
    }
}

/// Locks, recovering from a poisoned lock: every value behind the crate's locks stays
/// consistent between statements.
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn rng() -> impl seal_crypto::CryptoRng {
    seal_crypto::UnwrapErr(seal_crypto::SysRng)
}

/// `N` random bytes.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    fn fill(rng: &mut impl seal_crypto::CryptoRng, bytes: &mut [u8]) {
        rng.fill_bytes(bytes)
    }
    let mut bytes = [0u8; N];
    fill(&mut rng(), &mut bytes);
    bytes
}

/// The host's clock, for what only says how recent something is to a reader that checks it
/// against its own clock (control-plane request times, an empty telemetry batch's time). The
/// enclave decides nothing by it: trusted time comes from `seal_tee::Clock`.
pub(crate) fn host_now() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Where the enclave's keys come from: the guardian (`ports::guardian::GuardianKeyProvider`),
/// which owns the attestation, release evidence and tenant approval exchange. Every key is the deployment's tenant's (`Cloud::tenant_pin`): returned
/// scopes MUST match the requested ones, and boot/key-cache code checks them before use.
/// The master key never crosses this port.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn service_keys(&self, scope: &ServiceKeyScope) -> Result<ServiceKeys, ServiceError>;
    async fn tenant_wrapping_key(&self, scope: &TenantWrappingKeyScope) -> Result<TenantWrappingKey, ServiceError>;
}

/// The signed documents of the enclave's one tenant (`Cloud::tenant_pin`); no secrets
/// or keys. `load` returns the full bundle (root chain, signed state, signals, ended
/// sessions, freshness), so the runtime can verify it before updating its monotonic cache
/// (`ports::control::ControlTenantStore` over `seal_control::client`).
/// Storage is not authorization: everything loaded is verified, and the `publish_*` methods
/// only make what this replica already applied visible to the others on their next load.
#[async_trait]
pub trait TenantStore: Send + Sync {
    async fn load(&self) -> Result<TenantBundle, ServiceError>;
    /// A signal this enclave signed. Only signals live when created
    /// (`IntegrityPolicy::is_live`, i.e. they suspend) are published; the rest exist only in
    /// telemetry.
    async fn publish_signal(&self, signal: &SignedSignal) -> Result<(), ServiceError>;
    /// A session this enclave ended early (`EndRequest` or an integrity `Verdict::End`).
    async fn publish_session_end(&self, end: &SignedSessionEnd) -> Result<(), ServiceError>;
    /// The guardian's certificate for the service keys this replica booted with. Posted once
    /// at boot, before the enclave serves anything, so the control plane can verify what this
    /// replica signs (telemetry, signals, session ends) against its telemetry keys.
    async fn publish_service_key_certificate(
        &self,
        certificate: &SignedServiceKeyCertificate,
    ) -> Result<(), ServiceError>;
}

/// Untrusted evidence about approved Seal builds. The runtime verifies signatures,
/// log inclusion and freshness against configured release trust after loading.
/// May share a file directory or remote backend with TenantStore.
#[async_trait]
pub trait ReleaseStore: Send + Sync {
    async fn load(
        &self,
        platform: PlatformId,
        measurement: &seal_proto::Measurement,
    ) -> Result<seal_proto::release::ReleaseEvidence, ServiceError>;
}

/// The telemetry port. The runtime appends an entry for every seal, session, extend, end, refusal,
/// data-plane request and integrity action; the implementation numbers entries across its
/// stream, batches them into `TelemetryBatch`es signed with the telemetry key (sealed to
/// `TenantState::telemetry_readers` when the tenant names any), following `TELEMETRY_FLUSH_SECS`
/// and `TELEMETRY_BUFFER_ENTRIES`, and marks the final batch `last` on shutdown
/// (`ports::telemetry::ControlTelemetry`: `POST /v1/tenants/{tenant}/telemetry`).
pub trait Telemetry: Send + Sync {
    /// Called once by `SealService::boot`, after the service keys arrived and before the first
    /// `append`: what batches are signed with and sealed to.
    fn start(&self, signer: TelemetrySigner);
    /// Returns where the entry will be, for the operation's `TelemetryReceipt`.
    fn append(&self, entry: seal_proto::telemetry::TelemetryEntry) -> TelemetryReceipt;
}

/// What the `Telemetry` port signs and seals batches with: this replica's telemetry key (its
/// signing operation only, never the key itself) and the tenant's current telemetry readers.
#[derive(Clone)]
pub struct TelemetrySigner {
    tenant: TenantId,
    key: Arc<seal_crypto::TelemetryKey>,
    state: Arc<seal_authz::StateCache>,
}

impl TelemetrySigner {
    pub(crate) fn new(
        tenant: TenantId,
        key: Arc<seal_crypto::TelemetryKey>,
        state: Arc<seal_authz::StateCache>,
    ) -> Self {
        Self { tenant, key, state }
    }
    /// The deployment's tenant; every batch names it.
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    /// Signs `batch` under `TELEMETRY_BATCH_LABEL`.
    pub fn sign(&self, batch: TelemetryBatch) -> SignedTelemetryBatch {
        self.key.signer().sign_into(TELEMETRY_BATCH_LABEL, batch)
    }
    /// Signs a control-plane request under `CONTROL_REQUEST_LABEL`: this replica's reads of
    /// its tenant's bundle once it holds its keys.
    pub fn sign_control_request(
        &self,
        request: seal_proto::control::ControlRequest,
    ) -> seal_proto::control::SignedControlRequest {
        self.key.signer().sign_into(seal_proto::control::CONTROL_REQUEST_LABEL, request)
    }
    /// `TenantState::telemetry_readers` of the newest verified state: batches are sealed to
    /// these keys, or travel in clear when there are none.
    pub fn readers(&self) -> BTreeSet<PublicKey> {
        self.state.get().map(|t| t.state().telemetry_readers.clone()).unwrap_or_default()
    }
}

pub struct Components {
    pub keys: Arc<dyn KeyProvider>,
    pub tenants: Arc<dyn TenantStore>,
    pub releases: Arc<dyn ReleaseStore>,
    /// The cloud this replica runs on (`seal_cloud::Cloud::detect`): its attestor, clock,
    /// dialer, tenant pin and deployment identity. The guardian, control-plane and OIDC/STS
    /// clients and `upstream` all dial through `cloud.dialer()`.
    pub cloud: seal_cloud::Cloud,
    pub upstream: Arc<dyn seal_adapter::UpstreamConnector>,
    pub telemetry: Arc<dyn Telemetry>,
    pub adapters: Vec<Arc<dyn seal_adapter::Adapter>>,
    /// In-enclave integrity detectors, compiled into the image. Runtime sessions run them
    /// on every `Session::observe` and `Session::complete`. The release image has none yet.
    pub detectors: Vec<Arc<dyn seal_integrity::Detector>>,
    /// Verifiers for opaque `EndpointReport.evidence`, one per provider, compiled into the
    /// image. Evidence from a provider without one is ignored. The release image has none yet.
    pub evidence_checks: Vec<Arc<dyn seal_integrity::EvidenceCheck>>,
}

/// How often a replica reloads its tenant's bundle. Bounds how long a grant removal, an
/// admin clearance or an external integrity signal takes to reach every replica; signals a
/// replica creates itself apply there at once. Compiled in, not a deploy setting: the
/// deployer is untrusted and could otherwise stretch cut-off times.
pub const STATE_RELOAD_SECS: u64 = 30;

// A published `SessionEnd` must outlive every token a not-yet-reloaded replica can issue.
const _: () = assert!(
    seal_proto::session::SESSION_END_RETAIN_SECS >= seal_proto::session::SESSION_TOKEN_SECS + STATE_RELOAD_SECS
);

/// Tenant wrapping keys are refetched from the guardian after this long (the guardian
/// caches a customer-managed root for no longer than this), so revoking a customer-managed key stops
/// new sessions within about this time.
pub const TENANT_KEY_CACHE_SECS: u64 = 900;

/// A Seal-hosted replica (one whose `deployments` entry has a `HostedMode`) stops once it has
/// had no live session connection and no seal, session, extend, end or signal by an
/// authenticated caller for this long (`SealService::idle_exit`); its VM then stops, and
/// Seal's front door starts it on the next connection. Customer replicas never idle out.
pub const HOSTED_IDLE_SECS: u64 = 900;

// No session token an idle replica issued is still valid when it stops, so no tunnel is left
// holding one for a replica that is gone.
const _: () = assert!(HOSTED_IDLE_SECS >= seal_proto::session::SESSION_TOKEN_SECS);

/// Telemetry batching: a replica ships a batch at least this often.
pub const TELEMETRY_FLUSH_SECS: u64 = 5;

/// Unsent telemetry entries a replica holds at most. When full it drops the oldest
/// `Request` entries first, then the oldest of any kind, and records every drop in a
/// `Dropped` entry. Requests are never blocked for telemetry.
pub const TELEMETRY_BUFFER_ENTRIES: usize = 10_000;

/// Compiled-in configuration. The deployment's tenant comes from its cloud
/// (`Cloud::tenant_pin`, `<tenant>@<root id>`): every other tenant, and any other chain for the
/// same name, is refused with `ErrorCode::NotAllowed` (tickets, seal, sessions, extends,
/// signals, session tokens), and keys are requested only for that tenant and root. The pin
/// is set by the deployer and not attested: it can only narrow what the enclave serves. The
/// pinned root means a control plane that serves a competing chain gets refused, not obeyed.
pub struct ServiceConfig {
    pub service_key_version: ServiceKeyVersion,
    pub trust: seal_verify::Trust,
    /// How often the tenant's bundle is reloaded: `STATE_RELOAD_SECS` in release builds; sim
    /// builds may set less so tests need not wait. Boot refuses zero or more than the constant.
    pub state_reload: std::time::Duration,
}

/// Owns verification/authentication, authorization, key/cache lifetimes, and sessions.
/// Operations mirror the enclave API (`seal_proto::api`): `attestation`, `ticket`, `seal`,
/// `session`, `extend`, `end`, `signal`; the data plane enters through `serve_tunnel`, on the
/// same port as the API (`api::serve` tells them apart by TLS ALPN).
/// Every operation and every refusal is recorded through the `Telemetry` port.
///
/// Background tasks, stopped when the service is dropped: the periodic attestation
/// (`ATTESTATION_REFRESH_SECS`), the state reload (`STATE_RELOAD_SECS`) and the recheck of
/// every live session on each tenant state change and when the state's `fresh_until` passes.
///
/// What the replica serves comes from the newest verified state's `deployments` entries for
/// its own deployment identity: none any more refuses every operation but `attestation` and
/// `end` (`NotAllowed`) and refuses tunnels before their TLS handshake (`admits_tunnel`), and an
/// entry with a `HostedMode` marks Seal's hosted replica, which exits when idle.
pub struct SealService {
    runtime: Arc<runtime::Runtime>,
    _tasks: runtime::Tasks,
}

impl SealService {
    /// In order: read the cloud's tenant pin; verify this release's evidence against
    /// `ServiceConfig::trust`; load and verify the tenant bundle's chain, state and freshness
    /// (chain matching the pin's root id); check `Cloud::deployment` against
    /// `TenantState::deployments`; only then request service keys and check their scope and
    /// certificate, post the certificate (`TenantStore::publish_service_key_certificate`), and
    /// verify the bundle's signals and session ends with the telemetry keys they bring. Then
    /// it hands the telemetry key to the port (`Telemetry::start`) and attests once.
    /// Afterwards, a state whose `fresh_until` has passed makes every operation fail with
    /// `Unavailable` until a fresh bundle loads: the enclave fails closed.
    pub async fn boot(config: ServiceConfig, components: Components) -> Result<Self, ServiceError> {
        let (runtime, tasks) = runtime::Runtime::boot(config, components).await?;
        Ok(Self { runtime, _tasks: tasks })
    }
    /// Whether a tunnel may connect, checked on its TLS ClientHello: a replica that serves no
    /// sessions (draining, or no longer listed) refuses before the handshake, so the
    /// tunnel tries the next replica.
    pub fn admits_tunnel(&self) -> Result<(), ServiceError> {
        runtime::conn::admit(&self.runtime)
    }
    /// Whether this replica serves its tenant as Seal's hosted replica, which only Seal's front
    /// door can reach: then the client address in the front's PROXY header is trusted (`proxy`).
    pub fn behind_front_door(&self) -> bool {
        self.runtime.hosted_now()
    }
    /// A tunnel connection after its TLS handshake (ALPN `seal_proto::tunnel::ALPN`) from
    /// `peer`, which the apps' network rules (`TenantState::app_networks`) are checked against;
    /// without one, an app with a network rule is refused. A `Connect` preamble's session must
    /// pass that recheck (live, granted, inside the networks) before anything else, and says the
    /// protocol, whose adapter serves the rest. An `Extend` preamble never reaches an
    /// adapter: it moves the expiry of this replica's live connections for the token's session
    /// (same caller, later expiry), answers `EXTEND_OK` and closes.
    pub async fn serve_tunnel(
        &self,
        stream: seal_adapter::BoxStream,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<(), ServiceError> {
        runtime::conn::serve(&self.runtime, stream, peer).await
    }
    /// The TLS configuration of the enclave's port (`api::serve`): `[leaf, CA]` with the
    /// derived key, ALPN `http/1.1` (the API) and `seal_proto::tunnel::ALPN` (tunnels).
    pub fn tls_config(&self) -> Arc<rustls::ServerConfig> {
        self.runtime.tls_config()
    }
    /// The latest periodic attestation: refreshed every `ATTESTATION_REFRESH_SECS`, binding
    /// the service keys and the trusted time (`seal_tee::Clock`). Costs no hardware report per
    /// call. `Unavailable` once the latest is `ATTESTATION_MAX_AGE_SECS` old.
    pub async fn attestation(&self) -> Result<AttestationResponse, ServiceError> {
        self.runtime.attestation()
    }
    /// A proof ticket for this enclave's tenant.
    pub async fn ticket(&self) -> Result<seal_proto::freshness::ProofTicket, ServiceError> {
        self.runtime.ticket().await
    }
    /// Wraps the DEK (`seal_crypto::blob::BlobSealer`) to the guardian-certified
    /// `TenantBundle::wrap_keys` of each of the tenant's `platforms` at or above the policy's
    /// `min_platform`, for the `current` tenant key version: `BadRequest` if no platform
    /// qualifies or no adapter of this image speaks the destination's protocol, `Unavailable`
    /// if a qualifying platform has no valid key yet. The upload's HPKE plaintext is
    /// `canonical(SealPayload)`.
    pub async fn seal(&self, request: SealRequest) -> Result<SealResponse, ServiceError> {
        self.runtime.seal(request).await
    }
    /// Authenticates the proof, opens the blob with the tenant wrapping key of its version,
    /// takes a `SessionPermit` and issues the token from it (the runtime's `issue_session`, the
    /// sole issuance path: the token carries the blob still sealed, never the plaintext). A
    /// failed artifact rule is signed, recorded and applied as an `artifact-mismatch` signal
    /// before the refusal (`IntegrityFailed`). `source` is the request's peer address and port:
    /// the apps' network rules (`TenantState::app_networks`) are checked against its address
    /// (an unknown one, `None`, passes none), and the session's telemetry records it.
    pub async fn session(
        &self,
        request: SessionRequest,
        source: Option<std::net::SocketAddr>,
    ) -> Result<SessionResponse, ServiceError> {
        self.runtime.session(request, source).await
    }
    /// Redeems the current token, authenticates the fresh proof, takes an `ExtendPermit` and
    /// issues a token for the same `session_id` valid `SESSION_TOKEN_SECS`. `source` as for
    /// `session`.
    pub async fn extend(
        &self,
        request: ExtendRequest,
        source: Option<std::net::SocketAddr>,
    ) -> Result<ExtendResponse, ServiceError> {
        self.runtime.extend(request, source).await
    }
    /// Redeems the token (expired tokens are fine: ending is idempotent), signs a
    /// `SessionEnd` with reason `SessionEnded`, ends this replica's connections of the session
    /// at once and publishes it (`TenantStore::publish_session_end`). Integrity `Verdict::End`
    /// takes the same path with reason `IntegrityFailed`.
    pub async fn end(&self, request: EndRequest) -> Result<(), ServiceError> {
        self.runtime.end(request).await
    }
    /// One endpoint, two credentials, chosen by the payload: a workload proof (the caller
    /// signals about itself — the enclave derives its identity, source, tenant and time)
    /// or an enrolled external source's signatures (the host agent today, an EDR relay
    /// tomorrow — the tenant is this replica's pin and the source is the enrolled key the
    /// signature names). Verified either way, the tenant's policy applied at once, the
    /// signal published for the other replicas.
    pub async fn signal(&self, request: SignalRequest) -> Result<(), ServiceError> {
        self.runtime.signal(request).await
    }

    /// Resolves when a Seal-hosted replica (its `deployments` entry has a `HostedMode`) has
    /// been idle for `idle` (`HOSTED_IDLE_SECS` in a release): no live session connection, and
    /// no seal, session, extend, end or signal by an authenticated caller. It is then draining:
    /// operations that have not authenticated yet fail with `Unavailable` and data-plane
    /// connections are closed, so nothing starts that could outlive it, and the caller stops
    /// serving, ships the final telemetry batch and exits. Never resolves on any other replica.
    pub async fn idle_exit(&self, idle: std::time::Duration) {
        self.runtime.idle_exit(idle).await
    }
}
