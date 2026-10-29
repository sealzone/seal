//! Runtime tests over the sim cloud: real release evidence and tenant bundles from a dev log,
//! keys derived from a platform master key the way the guardian derives them, in-memory
//! stores, a recording telemetry port, and the HTTP adapter in front of a plain local
//! upstream (`seal_adapter::testing::TestUpstream`). Times are relative to the wall clock,
//! which is the sim cloud's clock.

mod boot;
mod hosted;
mod integrity;
mod sessions;

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use seal_adapter::testing::TestUpstream;
use seal_adapter::Session;
use seal_authz::DeploymentProof;
use seal_crypto::sign::SigningKey;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeyScope, ServiceKeys, TenantWrappingKey, TenantWrappingKeyScope};
use seal_proto::api::{
    AttestationResponse, EndRequest, ExtendRequest, ExtendResponse, IngestContext, SealPayload, SealRequest,
    SealResponse, SessionRequest, SessionResponse, SignalRequest,
};
use seal_proto::freshness::ProofTicket;
use seal_proto::identity::{
    IdentityMatcher, IdentityProof, ProofContext, ProofPurpose, WorkloadIdentity, PROOF_CONTEXT_LABEL,
};
use seal_proto::integrity::{EndpointReport, Severity, SignedSignal};
use seal_proto::policy::{Protocol, SecretPolicy};
use seal_proto::release::{
    Component, LogEntry, ReleaseEvidence, ReleaseManifest, SignedServiceKeyCertificate, RELEASE_LABEL,
};
use seal_proto::session::SignedSessionEnd;
use seal_proto::signed::{SigAlg, Signed};
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, LoggedState, TenantBundle, TenantKeyVersions, TenantRoot, TenantState,
    TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::telemetry::{TelemetryEntry, TelemetryEvent};
use seal_proto::tunnel::TunnelPreamble;
use seal_proto::{
    codec, AppName, Bearer, ErrorCode, Measurement, PlatformId, SecretVec, ServiceKeyVersion, TenantId,
    TenantKeyVersion, TenantPin, TenantRootId, UnixTime,
};
use seal_tee::sim::{SimAttestor, SystemClock};
use seal_tlog::dev::DevLog;
use seal_verify::{ReleaseTrust, TenantTrust, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Components, KeyProvider, ReleaseStore, SealService, ServiceConfig, ServiceError, Telemetry, TelemetrySigner,
    TenantStore,
};

pub(super) const DAY: u64 = 86_400;
const RELEASE_KEYS: [u8; 3] = [1, 2, 3];
const REGISTRARS: [u8; 2] = [21, 22];
const ADMIN: u8 = 31;
pub(super) const CONSUMER: u8 = 42;
pub(super) const STRANGER: u8 = 43;
pub(super) const MEASUREMENT: Measurement = Measurement([0xe1; 48]);
pub(super) const SVK: ServiceKeyVersion = ServiceKeyVersion(1);
const ROOT: [u8; 32] = [0x5e; 32];
/// The name the enclave's certificate carries (`conn::CERT_NAME`).
pub(super) const TLS_NAME: &str = "enclave.seal.invalid";
/// The local key the test tunnels present.
pub(super) const LOCAL_KEY: &str = "seallk_0123456789abcdef";
pub(super) const HOST: &str = "api.example.com";
pub(super) const SECRET: &str = "sk-live-0123456789";

pub(super) fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

pub(super) fn wall() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub(super) fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}

pub(super) fn checkout() -> AppName {
    AppName::new("checkout").unwrap()
}

pub(super) fn master() -> PlatformMasterKey {
    PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes(ROOT))
}

pub(super) fn app_key(n: u8) -> IdentityMatcher {
    IdentityMatcher::AppKey { key_id: key(n).key_id(), public_key: key(n).public_key() }
}

pub(super) fn app_identity(n: u8) -> WorkloadIdentity {
    WorkloadIdentity::AppKey { key_id: key(n).key_id() }
}

pub(super) fn deployment() -> WorkloadIdentity {
    WorkloadIdentity::ConfidentialSpace { project_number: 7, service_account: "enclave@acme.iam".into() }
}

fn deployment_matcher() -> IdentityMatcher {
    hosted_matcher(None)
}

/// The deployment's entry with `hosted` as its hosted mode.
pub(super) fn hosted_matcher(hosted: Option<seal_proto::identity::HostedMode>) -> IdentityMatcher {
    IdentityMatcher::ConfidentialSpace { project_number: 7, service_account: "enclave@acme.iam".into(), hosted }
}

/// The service keys of the tenant's enclaves, as the guardian releases them.
pub(super) fn service_keys(root_id: &TenantRootId) -> ServiceKeys {
    ServiceKeys::from_released(PlatformId::Sim, &master().release_service(&acme(), root_id, SVK)).unwrap()
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("seal-enclave-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn signed<T: serde::Serialize>(label: &str, body: T, keys: &[u8]) -> Signed<T> {
    let mut s = Signed { body, signatures: vec![] };
    for &n in keys {
        key(n).cosign(label, &mut s);
    }
    s
}

/// A dev log (3 witnesses, quorum 2), its trust, and the tenant `acme` with a logged root v1.
pub(super) struct World {
    log: DevLog,
    _dir: TempDir,
    root: Signed<TenantRoot>,
    root_index: u64,
    pub root_id: TenantRootId,
    /// The state the next `publish` starts from.
    pub state: TenantState,
    /// Every published state with its log proof.
    states: Vec<LoggedState>,
}

impl World {
    pub fn new() -> Self {
        let dir = TempDir::new();
        let mut log = DevLog::open(&dir.0.join("log"), [7; 32], 3, 2).unwrap();
        let root = TenantRoot {
            tenant: acme(),
            version: 1,
            admin_keys: [AdminKey::Ed25519 { public_key: key(ADMIN).public_key() }].into(),
            threshold: 1,
            cosign_releases: false,
        };
        let root = signed(TENANT_ROOT_LABEL, root, &REGISTRARS);
        let root_index = log.append(LogEntry::TenantRoot(root.body.clone())).unwrap();
        let state = TenantState {
            tenant: acme(),
            version: 0,
            root_version: 1,
            apps: [(checkout(), [app_key(CONSUMER)].into())].into(),
            tenant_key_versions: TenantKeyVersions {
                current: TenantKeyVersion(1),
                oldest_accepted: TenantKeyVersion(1),
            },
            platforms: [PlatformId::Sim].into(),
            integrity: Default::default(),
            deployments: [deployment_matcher()].into(),
            freshness_keys: Default::default(),
            telemetry_readers: Default::default(),
            issued_at: wall() - DAY,
            pending_window_secs: 0,
            app_networks: Default::default(),
        };
        Self { log, _dir: dir, root_id: root_id(&root.body), root, root_index, state, states: Vec::new() }
    }

    /// Runs `f` with the log's clock (witness and freshness timestamps) at about `t`.
    fn at<R>(&mut self, t: UnixTime, f: impl FnOnce(&mut DevLog) -> R) -> R {
        self.log.set_clock_offset(t as i64 - wall() as i64);
        let r = f(&mut self.log);
        self.log.set_clock_offset(0);
        r
    }

    pub fn trust(&self) -> Trust {
        Trust {
            releases: ReleaseTrust {
                tlog: self.log.trust(),
                release_keys: RELEASE_KEYS.iter().map(|&n| key(n).public_key()).collect(),
                release_threshold: 2,
                required_auditor: None,
                time_lock_secs: 0,
            },
            tenants: TenantTrust {
                tlog: self.log.trust(),
                registrar_keys: REGISTRARS.iter().map(|&n| key(n).public_key()).collect(),
                registrar_threshold: 2,
            },
            guardians: [(PlatformId::Sim, master().guardian_key().public_key())].into(),
        }
    }

    /// An enclave release of `measurement`, signed by `signers`, public for 15 days, with a
    /// fresh checkpoint from a minute ago.
    pub fn release(&mut self, measurement: Measurement, signers: &[u8]) -> ReleaseEvidence {
        let manifest = ReleaseManifest {
            component: Component::Enclave,
            platform: PlatformId::Sim,
            measurement,
            service_key_version: SVK,
            version: "0.1.0".into(),
            source_commit: "0123abcd".into(),
            serves: None,
        };
        let manifest = signed(RELEASE_LABEL, manifest, signers);
        let index = self.log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        let included = self.at(wall() - 15 * DAY, |log| {
            log.checkpoint();
            log.prove(index)
        });
        let fresh = self.at(wall() - 60, |log| log.checkpoint());
        ReleaseEvidence { manifest, included, fresh, auditor: None }
    }

    /// Logs the next state version (`change` applied to the current one) with a freshness
    /// statement signed a minute ago.
    pub fn publish(&mut self, change: impl FnOnce(&mut TenantState)) -> TenantBundle {
        self.publish_fresh_at(wall() - 60, change)
    }

    /// As `publish`, with the freshness statement signed at `fresh_at`.
    pub fn publish_fresh_at(&mut self, fresh_at: UnixTime, change: impl FnOnce(&mut TenantState)) -> TenantBundle {
        self.state.version += 1;
        change(&mut self.state);
        let state = signed(TENANT_STATE_LABEL, self.state.clone(), &[ADMIN]);
        let logged = self.log.append_logged_state(&state).unwrap();
        self.states.push(logged);
        self.log.checkpoint();
        let proof = self.log.prove(self.root_index);
        let freshness = self.at(fresh_at, |log| log.freshness(&acme()).unwrap());
        let current = self.state.tenant_key_versions.current;
        TenantBundle {
            root_chain: vec![LoggedRoot { root: self.root.clone(), proof }],
            state,
            signals: vec![],
            ended_sessions: vec![],
            freshness: vec![freshness],
            wrap_keys: vec![master().tenant_wrap_key(&acme(), &self.root_id, current)],
            states: self.states.clone(),
            checkpoint: Some(self.log.checkpoint()),
            anchors: Vec::new(),
        }
    }
}

/// Which port was called, in order.
#[derive(Default)]
pub(super) struct Calls(Mutex<Vec<&'static str>>);
impl Calls {
    fn push(&self, call: &'static str) {
        self.0.lock().unwrap().push(call);
    }
    pub fn list(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

/// An in-memory control plane: serves one bundle and one release, and keeps what is published
/// (signals and session ends also go into the served bundle, as the control plane does).
pub(super) struct Stores {
    calls: Arc<Calls>,
    pub bundle: Mutex<TenantBundle>,
    release: Mutex<ReleaseEvidence>,
    pub signals: Mutex<Vec<SignedSignal>>,
    pub ends: Mutex<Vec<SignedSessionEnd>>,
    pub certificates: Mutex<Vec<SignedServiceKeyCertificate>>,
}

#[async_trait]
impl TenantStore for Stores {
    async fn load(&self) -> Result<TenantBundle, ServiceError> {
        self.calls.push("tenants.load");
        Ok(self.bundle.lock().unwrap().clone())
    }
    async fn publish_signal(&self, signal: &SignedSignal) -> Result<(), ServiceError> {
        self.signals.lock().unwrap().push(signal.clone());
        self.bundle.lock().unwrap().signals.push(signal.clone());
        Ok(())
    }
    async fn publish_session_end(&self, end: &SignedSessionEnd) -> Result<(), ServiceError> {
        self.ends.lock().unwrap().push(end.clone());
        self.bundle.lock().unwrap().ended_sessions.push(end.clone());
        Ok(())
    }
    async fn publish_service_key_certificate(
        &self,
        certificate: &SignedServiceKeyCertificate,
    ) -> Result<(), ServiceError> {
        self.calls.push("tenants.publish_service_key_certificate");
        self.certificates.lock().unwrap().push(certificate.clone());
        Ok(())
    }
}

#[async_trait]
impl ReleaseStore for Stores {
    async fn load(&self, platform: PlatformId, measurement: &Measurement) -> Result<ReleaseEvidence, ServiceError> {
        assert_eq!((platform, *measurement), (PlatformId::Sim, MEASUREMENT));
        self.calls.push("releases.load");
        Ok(self.release.lock().unwrap().clone())
    }
}

/// Keys derived from the platform master key as the guardian derives them; `root` replaces
/// the requested root id (a provider answering for another scope).
pub(super) struct Keys {
    calls: Arc<Calls>,
    root: Option<TenantRootId>,
}

#[async_trait]
impl KeyProvider for Keys {
    async fn service_keys(&self, scope: &ServiceKeyScope) -> Result<ServiceKeys, ServiceError> {
        self.calls.push("keys.service_keys");
        let root = self.root.unwrap_or(scope.root_id);
        let released = master().release_service(&scope.tenant, &root, scope.service_key_version);
        Ok(ServiceKeys::from_released(scope.platform, &released).unwrap())
    }
    async fn tenant_wrapping_key(&self, scope: &TenantWrappingKeyScope) -> Result<TenantWrappingKey, ServiceError> {
        self.calls.push("keys.tenant_wrapping_key");
        Ok(master().tenant_wrapping_key(&scope.tenant, &scope.root_id, scope.tenant_key_version))
    }
}

/// Keeps every entry; numbers them from 0 in one stream.
#[derive(Default)]
pub(super) struct Recorder {
    pub entries: Mutex<Vec<TelemetryEntry>>,
    pub signer: Mutex<Option<TelemetrySigner>>,
}

impl Telemetry for Recorder {
    fn start(&self, signer: TelemetrySigner) {
        *self.signer.lock().unwrap() = Some(signer);
    }
    fn append(&self, entry: TelemetryEntry) -> seal_proto::api::TelemetryReceipt {
        assert!(self.signer.lock().unwrap().is_some(), "an entry before Telemetry::start");
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry);
        seal_proto::api::TelemetryReceipt { stream: [9; 16], entry: entries.len() as u64 - 1 }
    }
}

type UpBody = BoxBody<Bytes, Infallible>;

/// What the upstream received: method, path, headers.
#[derive(Clone, Debug)]
pub(super) struct Seen {
    pub path: String,
    pub headers: hyper::HeaderMap,
}

/// A plain HTTP upstream: `/v1/hang` sends one chunk and never finishes; the rest answer `ok`.
async fn upstream() -> (std::net::SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let s = s.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let s = s.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        s.lock().unwrap().push(Seen { path: path.clone(), headers: req.headers().clone() });
                        let body: UpBody = if path == "/v1/hang" {
                            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
                            tokio::spawn(async move {
                                let _ = tx.send(Bytes::from_static(b"first")).await;
                                std::future::pending::<()>().await;
                                drop(tx);
                            });
                            ChannelBody(rx).boxed()
                        } else {
                            Full::new(Bytes::from_static(b"ok")).boxed()
                        };
                        Ok::<_, Infallible>(hyper::Response::new(body))
                    }
                });
                let _ =
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    (addr, seen)
}

/// A response body fed from a channel.
struct ChannelBody(tokio::sync::mpsc::Receiver<Bytes>);
impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b))))
    }
}

/// Everything boot takes, valid unless a test changes it.
pub(super) struct Boot {
    pub world: World,
    pub bundle: TenantBundle,
    pub release: ReleaseEvidence,
    pub pin: TenantPin,
    pub trust: Trust,
    /// The root id the key provider answers for, when not the requested one.
    pub keys_root: Option<TenantRootId>,
    pub deployment: WorkloadIdentity,
    pub detectors: Vec<Arc<dyn seal_integrity::Detector>>,
    pub evidence_checks: Vec<Arc<dyn seal_integrity::EvidenceCheck>>,
}

impl Boot {
    pub fn new() -> Self {
        Self::with_state(|_| {})
    }

    /// The first published state is the base state with `change` applied.
    pub fn with_state(change: impl FnOnce(&mut TenantState)) -> Self {
        let mut world = World::new();
        let release = world.release(MEASUREMENT, &RELEASE_KEYS[..2]);
        let bundle = world.publish(change);
        let pin = TenantPin { tenant: acme(), root_id: world.root_id };
        let trust = world.trust();
        Self {
            world,
            bundle,
            release,
            pin,
            trust,
            keys_root: None,
            deployment: deployment(),
            detectors: vec![],
            evidence_checks: vec![],
        }
    }

    /// Boots; on a refusal returns the error and the port calls made.
    pub async fn start(self) -> Result<Harness, (ServiceError, Vec<&'static str>)> {
        let calls = Arc::new(Calls::default());
        let stores = Arc::new(Stores {
            calls: calls.clone(),
            bundle: Mutex::new(self.bundle),
            release: Mutex::new(self.release),
            signals: Mutex::default(),
            ends: Mutex::default(),
            certificates: Mutex::default(),
        });
        let telemetry = Arc::new(Recorder::default());
        let (addr, seen) = upstream().await;
        let test_upstream = TestUpstream::new();
        test_upstream.route(HOST, addr);
        let cloud = seal_cloud::Cloud::Sim(seal_cloud::sim::Sim::new(
            SimAttestor::new(MEASUREMENT),
            SystemClock::new(0),
            self.pin,
            DeploymentProof::Attested(self.deployment),
        ));
        let components = Components {
            keys: Arc::new(Keys { calls: calls.clone(), root: self.keys_root }),
            tenants: stores.clone(),
            releases: stores.clone(),
            cloud,
            upstream: test_upstream,
            telemetry: telemetry.clone(),
            adapters: vec![Arc::new(seal_adapter_http::HttpAdapter)],
            detectors: self.detectors,
            evidence_checks: self.evidence_checks,
        };
        let config = ServiceConfig {
            service_key_version: SVK,
            trust: self.trust,
            state_reload: Duration::from_secs(crate::STATE_RELOAD_SECS),
        };
        match SealService::boot(config, components).await {
            Ok(service) => {
                Ok(Harness { world: self.world, stores, telemetry, calls, seen, service: Arc::new(service) })
            }
            Err(e) => Err((e, calls.list())),
        }
    }
}

/// A booted service and its ports, with client helpers.
pub(super) struct Harness {
    pub world: World,
    pub stores: Arc<Stores>,
    pub telemetry: Arc<Recorder>,
    pub calls: Arc<Calls>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub service: Arc<SealService>,
}

/// An app-key proof by `key(n)` for `ctx`.
fn proof(n: u8, ctx: &ProofContext) -> IdentityProof {
    let SigAlg::Ed25519 { sig } = key(n).sign(PROOF_CONTEXT_LABEL, ctx).alg else { unreachable!() };
    IdentityProof::AppKey { key_id: key(n).key_id(), signature: sig }
}

/// A connection to the enclave's HTTP port.
pub(super) struct Conn {
    pub sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    pub served: tokio::task::JoinHandle<Result<(), ServiceError>>,
}

impl Harness {
    pub async fn attestation(&self) -> AttestationResponse {
        self.service.attestation().await.unwrap()
    }

    async fn context(&self, purpose: ProofPurpose) -> ProofContext {
        let ticket: ProofTicket = self.service.ticket().await.unwrap();
        let tls_spki_sha256 = self.attestation().await.binding.tls_spki_sha256;
        ProofContext { tenant: acme(), purpose, tls_spki_sha256, ticket }
    }

    /// Seals `SECRET` for `checkout` at `https://api.example.com/v1`.
    pub async fn seal(&self) -> Result<SealResponse, ServiceError> {
        self.seal_with(|p| p).await
    }

    /// `seal` with the policy adjusted before sealing (e.g. `.with_min_tier(Hardened)`).
    pub async fn seal_with(
        &self,
        edit: impl FnOnce(SecretPolicy) -> SecretPolicy,
    ) -> Result<SealResponse, ServiceError> {
        let policy = edit(SecretPolicy::new(&format!("https://{HOST}/v1"), [checkout()]).unwrap());
        let payload = SealPayload { secret: SecretVec::new(SECRET.as_bytes().to_vec()), policy };
        let binding = self.attestation().await.binding;
        let ingest =
            IngestContext { tenant: acme(), service_key_version: SVK, tls_spki_sha256: binding.tls_spki_sha256 };
        let aad = codec::canonical(&ingest);
        let (hpke_enc, sealed_payload) = seal_crypto::hpke::seal(
            &binding.ingest_public_key,
            &seal_crypto::hpke::ingest_info(&acme()),
            &aad,
            &codec::canonical(&payload),
            &mut super::rng(),
        )
        .unwrap();
        self.service.seal(SealRequest { service_key_version: SVK, hpke_enc, sealed_payload }).await
    }

    pub async fn start(
        &self,
        consumer: u8,
        blob: &str,
        endpoint: Option<EndpointReport>,
    ) -> Result<SessionResponse, ServiceError> {
        self.start_from(consumer, blob, endpoint, None).await
    }

    /// `start` from the peer `from`.
    pub async fn start_from(
        &self,
        consumer: u8,
        blob: &str,
        endpoint: Option<EndpointReport>,
        from: Option<std::net::SocketAddr>,
    ) -> Result<SessionResponse, ServiceError> {
        let placeholder = ProofPurpose::Session { request_digest: [0; 32] };
        let mut request = SessionRequest {
            blob: blob.into(),
            context: self.context(placeholder).await,
            proof: IdentityProof::AppKey { key_id: key(consumer).key_id(), signature: vec![] },
            min_tier: None,
            endpoint,
        };
        request.context.purpose = request.expected_purpose();
        request.proof = proof(consumer, &request.context);
        self.service.session(request, from).await
    }

    /// A sealed blob and a session on it for `CONSUMER`.
    pub async fn sealed_session(&self) -> SessionResponse {
        let blob = self.seal().await.unwrap().blob;
        self.start(CONSUMER, &blob, None).await.unwrap()
    }

    pub async fn extend(
        &self,
        consumer: u8,
        token: &Bearer,
        endpoint: Option<EndpointReport>,
    ) -> Result<ExtendResponse, ServiceError> {
        let placeholder = ProofPurpose::Extend { request_digest: [0; 32] };
        let mut request = ExtendRequest {
            token: token.duplicate(),
            endpoint,
            context: self.context(placeholder).await,
            proof: IdentityProof::AppKey { key_id: key(consumer).key_id(), signature: vec![] },
        };
        request.context.purpose = request.expected_purpose();
        request.proof = proof(consumer, &request.context);
        self.service.extend(request, None).await
    }

    pub async fn end(&self, token: &Bearer) -> Result<(), ServiceError> {
        self.service.end(EndRequest { token: token.duplicate() }).await
    }

    pub async fn self_signal(&self, n: u8, code: &str, severity: Severity) -> Result<(), ServiceError> {
        let placeholder = ProofPurpose::Signal { request_digest: [0; 32] };
        let mut context = self.context(placeholder).await;
        let mut request = SignalRequest {
            code: code.into(),
            severity,
            context: Some(context.clone()),
            proof: Some(IdentityProof::AppKey { key_id: key(n).key_id(), signature: vec![] }),
            identity: None,
            observed_at: None,
            blob_id: None,
            signatures: Vec::new(),
        };
        context.purpose = request.expected_purpose();
        request.context = Some(context.clone());
        request.proof = Some(proof(n, &context));
        self.service.signal(request).await
    }

    /// A tunnel connection, trusting the replica's derived CA certificate: admitted, the handshake with
    /// the tunnel's ALPN, `serve_tunnel`; then `preamble`, if any.
    pub async fn tls(
        &self,
        preamble: Option<&TunnelPreamble>,
    ) -> (tokio_rustls::client::TlsStream<tokio::io::DuplexStream>, tokio::task::JoinHandle<Result<(), ServiceError>>)
    {
        let (client, server) = tokio::io::duplex(1 << 16);
        let service = self.service.clone();
        let served = tokio::spawn(async move {
            service.admits_tunnel()?;
            let tls = tokio_rustls::TlsAcceptor::from(service.tls_config())
                .accept(server)
                .await
                .map_err(|e| crate::fail(ErrorCode::BadRequest, e.to_string()))?;
            service.serve_tunnel(Box::new(tls), None).await
        });
        let mut roots = rustls::RootCertStore::empty();
        let ca = service_keys(&self.world.root_id).tls.ca_certificate_der(&[TLS_NAME.to_string()]).unwrap();
        roots.add(CertificateDer::from(ca)).unwrap();
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![seal_proto::tunnel::ALPN.to_vec()];
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(TLS_NAME).unwrap(), client)
            .await
            .unwrap();
        if let Some(preamble) = preamble {
            tls.write_all(&seal_proto::tunnel::encode(preamble)).await.unwrap();
        }
        (tls, served)
    }

    /// An HTTP/1.1 connection through a tunnel for `token`, whose app presents `LOCAL_KEY`.
    pub async fn connect(&self, token: &Bearer) -> Conn {
        let connect = TunnelPreamble::Connect(seal_proto::tunnel::TunnelConnect {
            token: token.duplicate(),
            local_key_sha256: <sha2::Sha256 as sha2::Digest>::digest(LOCAL_KEY.as_bytes()).into(),
        });
        self.connect_with(&connect).await
    }

    /// An HTTP/1.1 connection through a tunnel opened with `preamble`.
    pub async fn connect_with(&self, preamble: &TunnelPreamble) -> Conn {
        let (tls, served) = self.tls(Some(preamble)).await;
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(connection);
        Conn { sender, served }
    }

    /// Sends an `Extend` preamble with `token` on a new connection; the one-byte answer, if any.
    pub async fn extend_preamble(&self, token: &Bearer) -> Option<u8> {
        let (mut tls, served) = self.tls(Some(&TunnelPreamble::Extend { token: token.duplicate() })).await;
        let mut answer = Vec::new();
        let _ = tls.read_to_end(&mut answer).await;
        let _ = served.await;
        answer.first().copied()
    }

    /// The runtime's live sessions of `session_id` on this replica.
    pub fn live(&self, session_id: &[u8; 16]) -> Vec<Arc<super::live::LiveSession>> {
        self.service.runtime.live.of(session_id)
    }

    /// Why the first live session of `session_id` ended (within 5 s).
    pub async fn ended(&self, session_id: &[u8; 16]) -> ErrorCode {
        let live = self.live(session_id);
        let session = live.first().expect("a live session");
        tokio::time::timeout(Duration::from_secs(5), session.ended()).await.expect("the session ended")
    }

    /// Whether the first live session of `session_id` is still running after a moment.
    pub async fn still_live(&self, session_id: &[u8; 16]) -> bool {
        let live = self.live(session_id);
        let session = live.first().expect("a live session");
        tokio::time::timeout(Duration::from_millis(200), session.ended()).await.is_err()
    }

    /// Serves `bundle` from now on and reloads it.
    pub async fn reload(&self, bundle: TenantBundle) {
        *self.stores.bundle.lock().unwrap() = bundle;
        self.service.runtime.reload().await.unwrap();
    }

    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.telemetry.entries.lock().unwrap().iter().map(|e| e.event.clone()).collect()
    }
}

/// `GET path` with `credential` in the `authorization` header: status and body.
pub(super) async fn get(conn: &mut Conn, path: &str, credential: &str) -> (u16, String) {
    let request = hyper::Request::get(path)
        .header("host", TLS_NAME)
        .header("authorization", format!("Bearer {credential}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = conn.sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The `seal_error` of a refusal body.
pub(super) fn seal_error(body: &str) -> ErrorCode {
    let value: serde_json::Value = serde_json::from_str(body).unwrap();
    serde_json::from_value(value["seal_error"].clone()).unwrap()
}
