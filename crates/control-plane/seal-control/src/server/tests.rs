//! Route-level tests over real HTTP against the in-process dev log (`seal_tlog::dev::DevLog`)
//! and a sim guardian's real keys (`PlatformMasterKey`), plus a `ControlClient` round trip over
//! local TLS. Requests are signed by an admin key of root version 1 unless a test says
//! otherwise.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::Serialize;

use seal_crypto::keys::{Key32, PlatformMasterKey, ServiceKeys};
use seal_crypto::sign::SigningKey;
use seal_proto::control::CONTROL_REQUEST_LABEL;
use seal_proto::identity::WorkloadIdentity;
use seal_proto::integrity::{IntegrityAction, IntegritySignal, Severity, SignalSource, SignedSignal, SIGNAL_LABEL};
use seal_proto::release::{
    Component, LogEntry, ReleaseCosign, ReleaseEvidence, ReleaseManifest, SignedCheckpoint,
    SignedServiceKeyCertificate, SignedTenantWrapKey, TlogProof, RELEASE_COSIGN_LABEL, RELEASE_LABEL,
    SERVICE_KEY_CERTIFICATE_LABEL, TENANT_WRAP_KEY_LABEL,
};
use seal_proto::session::{SessionEnd, SignedSessionEnd, SESSION_END_LABEL, SESSION_END_RETAIN_SECS};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantAnchor, SignedTenantState,
    StateFreshness, TenantBundle, TenantKeyVersions, TenantRoot, TenantState, STATE_FRESHNESS_LABEL,
    TENANT_ANCHOR_LABEL, TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::telemetry::{
    SignedTelemetryBatch, TelemetryBatch, TelemetryEntries, TelemetryEntry, TelemetryEvent, TELEMETRY_BATCH_LABEL,
};
use seal_proto::{
    codec, ErrorCode, KeyId, Measurement, PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId,
    TrustedTime, UnixTime,
};
use seal_tlog::dev::DevLog;
use seal_verify::{TenantTrust, TenantVerifier};

use seal_control::client::SigningKeyCredential;

use super::store::Store;
use super::upstream::{Appended, UpstreamError, Upstreams};
use super::*;

const TOKEN: &str = "test-write-token-0123456789";
const REGISTRAR: u8 = 1;
const V1_ADMINS: [u8; 2] = [11, 12];
const V2_ADMIN: u8 = 13;
const EDR: u8 = 20;
const TENANT_FRESHNESS: u8 = 21;
const STRANGER: u8 = 99;
const CONSOLE: u8 = 30;
const CONSOLE_ORIGIN: &str = "https://console.seal.zone";

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}
fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}
fn other() -> TenantId {
    TenantId::new("other").unwrap()
}
fn wall_clock() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn signed<T: Serialize>(label: &str, body: T, keys: &[u8]) -> Signed<T> {
    let mut s = Signed { body, signatures: vec![] };
    for &n in keys {
        key(n).cosign(label, &mut s);
    }
    s
}

fn root(version: u64, admins: &[u8], threshold: u8) -> TenantRoot {
    TenantRoot {
        tenant: acme(),
        version,
        admin_keys: admins.iter().map(|&n| AdminKey::Ed25519 { public_key: key(n).public_key() }).collect(),
        threshold,
        cosign_releases: false,
    }
}

fn state(version: u64, root_version: u64) -> TenantState {
    let mut integrity = seal_proto::integrity::IntegrityPolicy::default();
    integrity.sources.insert("edr".into(), key(EDR).public_key());
    integrity.actions.insert(Severity::Medium, IntegrityAction::Deny);
    integrity.actions.insert(Severity::High, IntegrityAction::Suspend { secs: Some(60) });
    integrity.actions.insert(Severity::Critical, IntegrityAction::Suspend { secs: None });
    TenantState {
        tenant: acme(),
        version,
        root_version,
        apps: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(2), oldest_accepted: TenantKeyVersion(1) },
        platforms: [PlatformId::Sim].into(),
        integrity,
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: wall_clock(),
        pending_window_secs: 0,
        app_networks: Default::default(),
        freshness_secs: None,
    }
}

fn pmk() -> PlatformMasterKey {
    PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([9; 32]))
}

/// The dev log and a sim guardian, in process. Switches make either misbehave.
struct DevUpstreams {
    log: Mutex<DevLog>,
    guardian: PlatformMasterKey,
    log_down: AtomicBool,
    forge_wrap_keys: AtomicBool,
    wrap_key_fetches: AtomicUsize,
    anchor_fetches: AtomicUsize,
}

impl DevUpstreams {
    fn log(&self) -> std::sync::MutexGuard<'_, DevLog> {
        self.log.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl Upstreams for DevUpstreams {
    async fn log_freshness(&self, tenant: &TenantId) -> Result<Option<SignedStateFreshness>, UpstreamError> {
        if self.log_down.load(Ordering::SeqCst) {
            return Err(UpstreamError("down".into()));
        }
        Ok(self.log().freshness(tenant))
    }
    async fn log_checkpoint(&self) -> Result<SignedCheckpoint, UpstreamError> {
        if self.log_down.load(Ordering::SeqCst) {
            return Err(UpstreamError("down".into()));
        }
        Ok(self.log().checkpoint())
    }
    async fn log_append_root(&self, entry: &LogEntry) -> Result<Appended, UpstreamError> {
        if self.log_down.load(Ordering::SeqCst) {
            return Err(UpstreamError("down".into()));
        }
        self.log().append(entry.clone()).map(Appended::At).map_err(|e| UpstreamError(e.to_string()))
    }
    async fn log_append_state(&self, _tenant: &TenantId, state: &SignedTenantState) -> Result<Appended, UpstreamError> {
        if self.log_down.load(Ordering::SeqCst) {
            return Err(UpstreamError("down".into()));
        }
        Ok(self.log().append_state(state).map_or_else(Appended::Refused, Appended::At))
    }
    async fn log_proof(&self, index: u64) -> Result<TlogProof, UpstreamError> {
        Ok(self.log().prove(index))
    }
    async fn log_entry(&self, index: u64) -> Result<Option<LogEntry>, UpstreamError> {
        Ok(self.log().entry(index).cloned())
    }
    async fn wrap_key(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        root_id: &TenantRootId,
        version: TenantKeyVersion,
    ) -> Result<Option<SignedTenantWrapKey>, UpstreamError> {
        self.wrap_key_fetches.fetch_add(1, Ordering::SeqCst);
        if platform != self.guardian.platform {
            return Ok(None);
        }
        let key = self.guardian.tenant_wrap_key(tenant, root_id, version);
        if self.forge_wrap_keys.load(Ordering::SeqCst) {
            return Ok(Some(super::tests::key(STRANGER).sign_into(TENANT_WRAP_KEY_LABEL, key.body)));
        }
        Ok(Some(key))
    }

    async fn anchor(
        &self,
        platform: PlatformId,
        tenant: &TenantId,
        root_id: &TenantRootId,
        bundle: &TenantBundle,
    ) -> Result<Option<SignedTenantAnchor>, UpstreamError> {
        self.anchor_fetches.fetch_add(1, Ordering::SeqCst);
        if platform != self.guardian.platform {
            return Ok(None);
        }
        let guardian = self.guardian.guardian_key();
        let registrar_keys = vec![key(REGISTRAR).public_key()];
        let trust = TenantTrust { tlog: self.log().trust(), registrar_keys, registrar_threshold: 1 };
        let time = TrustedTime::exact(self.log().now());
        let anchor = TenantVerifier::new(trust, vec![])
            .with_anchor_keys(vec![guardian.public_key()])
            .anchor(platform, tenant, bundle, &time);
        Ok(anchor.ok().filter(|a| &a.root_id == root_id).map(|a| guardian.sign_into(TENANT_ANCHOR_LABEL, a)))
    }
}

/// A server on a loopback port over a fresh data directory, with a tenant whose root v1 and
/// state 1 are logged (not yet stored).
struct Env {
    up: Arc<DevUpstreams>,
    addr: SocketAddr,
    dir: PathBuf,
    /// Added to the wall clock for the server (the dev log takes the same offset).
    offset: Arc<AtomicI64>,
    registrar: bool,
    v1: LoggedRoot,
    s1: SignedTenantState,
    keys: ServiceKeys,
}

static DIRS: AtomicUsize = AtomicUsize::new(0);

fn fresh_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "seal-control-{name}-{}-{}",
        std::process::id(),
        DIRS.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The release keys attested reads are checked with.
fn release_trust(up: &DevUpstreams) -> seal_verify::ReleaseTrust {
    seal_verify::ReleaseTrust {
        tlog: up.log().trust(),
        release_keys: vec![key(RELEASE).public_key()],
        release_threshold: 1,
        required_auditor: None,
        time_lock_secs: 0,
    }
}

fn app(up: Arc<DevUpstreams>, dir: &std::path::Path, offset: Arc<AtomicI64>, registrar: bool) -> Arc<App> {
    let trust = up.log().trust();
    let settings = Settings {
        write_token: TOKEN.into(),
        log: trust,
        registrar: registrar.then(|| (vec![key(REGISTRAR).public_key()], 1)),
        guardians: [(PlatformId::Sim, pmk().guardian_key().public_key())].into(),
        releases: Some(release_trust(&up)),
        console_keys: vec![console_key().public_key()],
        console_origin: Some(CONSOLE_ORIGIN.into()),
        checkpoint_cache_secs: CHECKPOINT_CACHE_SECS,
    };
    let clock: Clock = Arc::new(move || wall_clock().saturating_add_signed(offset.load(Ordering::SeqCst)));
    Arc::new(App::new(settings, Store::open(&dir.join("data")).unwrap(), up, clock).unwrap())
}

const RELEASE: u8 = 40;

fn console_key() -> SigningKey {
    key(CONSOLE)
}

/// How a test request is authorized.
#[derive(Clone)]
enum Auth {
    None,
    /// Signed by this key (`SealSigned`), for the env's chain.
    Key(u8),
    /// An `Authorization` value as given.
    Header(String),
}

/// The tenant a `/v1/tenants/{tenant}/...` path names (`acme` for other paths).
fn path_tenant(path: &str) -> TenantId {
    path.strip_prefix("/v1/tenants/")
        .and_then(|rest| rest.split('/').next())
        .and_then(|t| TenantId::new(t).ok())
        .unwrap_or_else(acme)
}

/// A `SealSigned` authorization for `method path` with `body`, signed by `signer`.
fn signed_header(
    signer: &SigningKey,
    root_id: TenantRootId,
    method: &str,
    path: &str,
    body: &[u8],
    at: UnixTime,
) -> String {
    let tenant = path_tenant(path);
    let target = seal_control::client::Target { tenant: &tenant, method, path, body };
    seal_control::client::signed_authorization(&signer.sign_into(CONTROL_REQUEST_LABEL, target.request(root_id, at)))
}

/// A control token as the console issues it (`token`).
fn control_token(signer: &SigningKey, tenant: &str, root_id: TenantRootId, scope: &str, iat: UnixTime) -> String {
    let payload = format!(
        r#"{{"v":1,"kid":"{}","tenant":"{tenant}","root_id":"{root_id}","user":"u-1","scope":"{scope}","iat":{iat},"exp":{}}}"#,
        token::kid(&signer.public_key()),
        iat + 300
    );
    let message = [token::LABEL, payload.as_bytes()].concat();
    let sig = ed25519_dalek::Signer::sign(&ed25519_dalek::SigningKey::from_bytes(&signer.to_seed()), &message);
    format!("Bearer sealct_{}.{}", codec::b64url(payload.as_bytes()), codec::b64url(&sig.to_bytes()))
}

async fn spawn(app: Arc<App>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(app)).await });
    addr
}

impl Env {
    async fn new() -> Self {
        Self::with_registrar(true).await
    }

    async fn with_registrar(registrar: bool) -> Self {
        let dir = fresh_dir("routes");
        let mut log = DevLog::open(&dir.join("log"), [7; 32], 3, 2).unwrap();
        let v1 = signed(TENANT_ROOT_LABEL, root(1, &V1_ADMINS, 2), &[REGISTRAR]);
        let index = log.append(LogEntry::TenantRoot(v1.body.clone())).unwrap();
        let v1 = LoggedRoot { root: v1, proof: log.prove(index) };
        let s1 = signed(TENANT_STATE_LABEL, state(1, 1), &V1_ADMINS);
        log.append_state(&s1).unwrap();
        let up = Arc::new(DevUpstreams {
            log: Mutex::new(log),
            guardian: pmk(),
            log_down: AtomicBool::new(false),
            forge_wrap_keys: AtomicBool::new(false),
            wrap_key_fetches: AtomicUsize::new(0),
            anchor_fetches: AtomicUsize::new(0),
        });
        let offset = Arc::new(AtomicI64::new(0));
        let addr = spawn(app(up.clone(), &dir, offset.clone(), registrar)).await;
        let root_id = root_id(&v1.root.body);
        let released = pmk().release_service(&acme(), &root_id, ServiceKeyVersion(1));
        let keys = ServiceKeys::from_released(PlatformId::Sim, &released).unwrap();
        Self { up, addr, dir, offset, registrar, v1, s1, keys }
    }

    /// Restarts the server on the same data directory.
    async fn restart(&mut self) {
        self.addr = spawn(app(self.up.clone(), &self.dir, self.offset.clone(), self.registrar)).await;
    }

    fn advance(&self, secs: i64) {
        self.offset.fetch_add(secs, Ordering::SeqCst);
        self.up.log().set_clock_offset(self.offset.load(Ordering::SeqCst));
    }

    fn now(&self) -> UnixTime {
        wall_clock().saturating_add_signed(self.offset.load(Ordering::SeqCst))
    }

    fn root_id(&self) -> TenantRootId {
        root_id(&self.v1.root.body)
    }

    async fn request(&self, method: &str, path: &str, token: Option<&str>, body: Option<Vec<u8>>) -> (u16, Vec<u8>) {
        let auth = token.map_or(Auth::None, |t| Auth::Header(format!("Bearer {t}")));
        let (status, _, body) = self.send(method, path, auth, &[], body.unwrap_or_default()).await;
        (status, body)
    }

    /// Sends one request; returns its status, headers and body.
    async fn send(
        &self,
        method: &str,
        path: &str,
        auth: Auth,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (u16, hyper::HeaderMap, Vec<u8>) {
        let stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        let mut req = hyper::Request::builder().method(method).uri(path).header("host", "localhost");
        match auth {
            Auth::None => {}
            Auth::Key(n) => {
                let header = signed_header(&key(n), self.root_id(), method, path, &body, self.now());
                req = req.header("authorization", header);
            }
            Auth::Header(value) => req = req.header("authorization", value),
        }
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let req = req.header("content-type", "application/json").body(Full::new(Bytes::from(body))).unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        (status, headers, resp.into_body().collect().await.unwrap().to_bytes().to_vec())
    }

    /// GET, signed by an admin key of root version 1.
    async fn get(&self, path: &str) -> (u16, Vec<u8>) {
        self.get_as(path, Auth::Key(V1_ADMINS[0])).await
    }
    async fn get_as(&self, path: &str, auth: Auth) -> (u16, Vec<u8>) {
        let (status, _, body) = self.send("GET", path, auth, &[], Vec::new()).await;
        (status, body)
    }
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> T {
        let (status, body) = self.get(path).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }
    /// PUT with the write token.
    async fn put<T: Serialize>(&self, path: &str, body: &T) -> u16 {
        self.put_as(path, Some(TOKEN), body).await
    }
    async fn put_as<T: Serialize>(&self, path: &str, token: Option<&str>, body: &T) -> u16 {
        self.request("PUT", path, token, Some(serde_json::to_vec(body).unwrap())).await.0
    }
    /// POST without a token.
    async fn post<T: Serialize>(&self, path: &str, body: &T) -> u16 {
        self.request("POST", path, None, Some(serde_json::to_vec(body).unwrap())).await.0
    }
    /// `method` with a JSON body (none when `body` is `None`), authorized by `auth`.
    async fn call<T: Serialize>(&self, method: &str, path: &str, auth: Auth, body: Option<&T>) -> (u16, Vec<u8>) {
        let body = body.map(|b| serde_json::to_vec(b).unwrap()).unwrap_or_default();
        let (status, _, body) = self.send(method, path, auth, &[], body).await;
        (status, body)
    }

    async fn bundle(&self) -> TenantBundle {
        self.get_json("/v1/tenants/acme/bundle").await
    }

    /// Root v1, state 1 and this enclave's certificate stored.
    async fn ready(&self) {
        assert_eq!(self.put("/v1/tenants/acme/root", &self.v1).await, 204);
        assert_eq!(self.put("/v1/tenants/acme/state", &self.s1).await, 204);
        assert_eq!(self.post("/v1/tenants/acme/service-key-certificates", &self.keys.certificate).await, 204);
    }

    /// Logs root v2 (admin 13, threshold 1, signed by v1's admins).
    fn log_root_v2(&self) -> LoggedRoot {
        let v2 = signed(TENANT_ROOT_LABEL, root(2, &[V2_ADMIN], 1), &V1_ADMINS);
        let mut log = self.up.log();
        let index = log.append(LogEntry::TenantRoot(v2.body.clone())).unwrap();
        LoggedRoot { root: v2, proof: log.prove(index) }
    }

    /// Logs a state signed by v1's admins.
    fn log_state(&self, body: TenantState) -> SignedTenantState {
        let s = signed(TENANT_STATE_LABEL, body, &V1_ADMINS);
        self.up.log().append_state(&s).unwrap();
        s
    }

    fn telemetry_signer(&self) -> &SigningKey {
        self.keys.telemetry.signer()
    }

    fn verifier(&self) -> TenantVerifier {
        let trust = TenantTrust {
            tlog: self.up.log().trust(),
            registrar_keys: vec![key(REGISTRAR).public_key()],
            registrar_threshold: 1,
        };
        let telemetry = self.keys.telemetry_public_keys.iter().map(|(_, k)| *k).collect();
        TenantVerifier::new(trust, telemetry).with_anchor_keys(vec![pmk().guardian_key().public_key()])
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn signal_body(
    tenant: TenantId,
    source: SignalSource,
    severity: Severity,
    observed_at: UnixTime,
    n: u8,
) -> IntegritySignal {
    IntegritySignal {
        tenant,
        identity: WorkloadIdentity::AppKey { key_id: KeyId([n; 32]) },
        source,
        code: "edr-high".into(),
        severity,
        observed_at,
        blob_id: None,
    }
}

fn enclave_source() -> SignalSource {
    SignalSource::Enclave { detector: "sqli".into() }
}

fn edr_source() -> SignalSource {
    SignalSource::External { source: "edr".into() }
}

fn session_end(tenant: TenantId, n: u8, ended_at: UnixTime) -> SessionEnd {
    SessionEnd { tenant, session_id: [n; 16], reason: ErrorCode::SessionEnded, ended_at }
}

fn batch(stream: u8, sequence: u64, at: UnixTime) -> TelemetryBatch {
    TelemetryBatch {
        tenant: acme(),
        stream: [stream; 16],
        sequence,
        first_entry: sequence,
        count: 1,
        from: at,
        to: at,
        entries: TelemetryEntries::Clear {
            entries: vec![TelemetryEntry {
                at,
                tenant: acme(),
                identity: None,
                event: TelemetryEvent::Dropped { requests: sequence, other: 0 },
            }],
        },
        last: false,
    }
}

fn manifest(m: u8) -> ReleaseManifest {
    ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement: Measurement([m; 48]),
        service_key_version: ServiceKeyVersion(1),
        version: "0.1.0".into(),
        source_commit: "0000000".into(),
        serves: None,
    }
}

#[tokio::test]
async fn roots_need_the_token_and_must_extend_the_chain() {
    let env = Env::new().await;
    assert_eq!(env.put_as("/v1/tenants/acme/root", None, &env.v1).await, 401);
    assert_eq!(env.put_as("/v1/tenants/acme/root", Some("wrong-token-0123456789"), &env.v1).await, 401);
    assert_eq!(env.put("/v1/tenants/other/root", &env.v1).await, 400, "root for another tenant");
    assert_eq!(env.request("PUT", "/v1/tenants/acme/root", Some(TOKEN), Some(b"{".to_vec())).await.0, 400);
    let v2 = env.log_root_v2();
    assert_eq!(env.put("/v1/tenants/acme/root", &v2).await, 409, "v2 before v1");

    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204);
    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204, "the same link again is a no-op");
    let mut competing = env.v1.clone();
    competing.root.body.threshold = 1;
    assert_eq!(env.put("/v1/tenants/acme/root", &competing).await, 409, "another version 1");

    // v2 signed by only one of v1's two required admins.
    let mut weak = v2.clone();
    weak.root.signatures.truncate(1);
    assert_eq!(env.put("/v1/tenants/acme/root", &weak).await, 400);
    // A proof that does not include this root.
    let mut unlogged = v2.clone();
    unlogged.proof = env.v1.proof.clone();
    assert_eq!(env.put("/v1/tenants/acme/root", &unlogged).await, 400);

    // PUT paths take only PUT.
    assert_eq!(
        env.request("POST", "/v1/tenants/acme/root", Some(TOKEN), Some(serde_json::to_vec(&v2).unwrap())).await.0,
        405
    );
    assert_eq!(env.put("/v1/tenants/acme/root", &v2).await, 204);
    let v3 = signed(TENANT_ROOT_LABEL, root(3, &[V2_ADMIN], 1), &[V2_ADMIN]);
    let index = env.up.log().append(LogEntry::TenantRoot(v3.body.clone())).unwrap();
    let v3 = LoggedRoot { root: v3, proof: env.up.log().prove(index) };
    assert_eq!(env.put("/v1/tenants/acme/root", &v3).await, 204);
}

#[tokio::test]
async fn version_1_needs_the_registrar_when_one_is_configured() {
    let env = Env::new().await;
    let unregistered = signed(TENANT_ROOT_LABEL, root(1, &V1_ADMINS, 2), &[STRANGER]);
    let index = env.up.log().append(LogEntry::TenantRoot(unregistered.body.clone())).unwrap();
    let link = LoggedRoot { root: unregistered, proof: env.up.log().prove(index) };
    assert_eq!(env.put("/v1/tenants/acme/root", &link).await, 400);

    let open = Env::with_registrar(false).await;
    let index = open.up.log().append(LogEntry::TenantRoot(link.root.body.clone())).unwrap();
    let link = LoggedRoot { root: link.root, proof: open.up.log().prove(index) };
    assert_eq!(open.put("/v1/tenants/acme/root", &link).await, 204);
}

#[tokio::test]
async fn states_must_be_logged_signed_and_increasing() {
    let env = Env::new().await;
    assert_eq!(env.put("/v1/tenants/acme/state", &env.s1).await, 409, "no root chain yet");
    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204);
    assert_eq!(env.put_as("/v1/tenants/acme/state", None, &env.s1).await, 401);

    let mut unsigned = env.s1.clone();
    unsigned.signatures.truncate(1);
    assert_eq!(env.put("/v1/tenants/acme/state", &unsigned).await, 400, "below the admin threshold");
    let wrong_root = signed(TENANT_STATE_LABEL, state(2, 2), &V1_ADMINS);
    assert_eq!(env.put("/v1/tenants/acme/state", &wrong_root).await, 409, "for a root version not in the chain");

    // State 1 is in the log already: the log refuses it again, and it is found there.
    assert_eq!(env.put("/v1/tenants/acme/state", &env.s1).await, 204);
    assert_eq!(env.put("/v1/tenants/acme/state", &env.s1).await, 204, "the same state again is a no-op");

    let mut same_version = state(1, 1);
    same_version.issued_at += 1;
    let same_version = signed(TENANT_STATE_LABEL, same_version, &V1_ADMINS);
    assert_eq!(env.put("/v1/tenants/acme/state", &same_version).await, 409, "version does not increase");

    let s2 = env.log_state(state(2, 1));
    let s3 = env.log_state(state(3, 1));
    assert_eq!(env.put("/v1/tenants/acme/state", &s2).await, 409, "the log's latest is 3");
    assert_eq!(env.put("/v1/tenants/acme/state", &s3).await, 204);
    assert_eq!(env.put("/v1/tenants/acme/state", &s2).await, 409, "older than the stored one");

    env.up.log_down.store(true, Ordering::SeqCst);
    let s4 = env.log_state(state(4, 1));
    assert_eq!(env.put("/v1/tenants/acme/state", &s4).await, 503, "the log is unreachable");
    env.up.log_down.store(false, Ordering::SeqCst);
    assert_eq!(env.put("/v1/tenants/acme/state", &s4).await, 204);
    assert_eq!(env.bundle().await.state, s4);

    // Not in the log: the control plane logs it.
    let s5 = signed(TENANT_STATE_LABEL, state(5, 1), &V1_ADMINS);
    assert_eq!(env.put("/v1/tenants/acme/state", &s5).await, 204);
    assert!(for_state(&env.up.log().freshness(&acme()).unwrap(), &s5.body));
    // Refused by the log, and not in it.
    env.log_state(state(7, 1));
    let s6 = signed(TENANT_STATE_LABEL, state(6, 1), &V1_ADMINS);
    assert_eq!(env.put("/v1/tenants/acme/state", &s6).await, 409);
}

#[tokio::test]
async fn the_bundle_is_complete_and_verifies() {
    let env = Env::new().await;
    assert_eq!(env.get("/v1/tenants/acme/bundle").await.0, 401, "no chain: no admin key signs for it");
    env.ready().await;
    let bundle = env.bundle().await;
    assert_eq!(bundle.root_chain, vec![env.v1.clone()]);
    assert_eq!(bundle.state, env.s1);
    assert_eq!(bundle.freshness.len(), 1, "the log's statement");
    let mut versions: Vec<_> = bundle.wrap_keys.iter().map(|k| k.body.tenant_key_version.0).collect();
    versions.sort_unstable();
    assert_eq!(versions, vec![1, 2], "every accepted tenant key version of the sim platform");
    for k in &bundle.wrap_keys {
        assert_eq!(*k, pmk().tenant_wrap_key(&acme(), &env.root_id(), k.body.tenant_key_version));
    }
    let verified = env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap();
    assert_eq!(verified.state().version, 1);
    assert_eq!(*verified.root_id(), env.root_id());
}

#[tokio::test]
async fn wrap_keys_are_fetched_once_checked_and_retried() {
    let env = Env::new().await;
    env.ready().await;
    env.up.forge_wrap_keys.store(true, Ordering::SeqCst);
    assert!(env.bundle().await.wrap_keys.is_empty(), "keys the guardian key did not sign are dropped");
    assert_eq!(env.up.wrap_key_fetches.load(Ordering::SeqCst), 2);
    env.up.forge_wrap_keys.store(false, Ordering::SeqCst);
    assert!(env.bundle().await.wrap_keys.is_empty(), "not asked again within the retry window");
    assert_eq!(env.up.wrap_key_fetches.load(Ordering::SeqCst), 2);

    env.advance(WRAP_KEY_RETRY_SECS as i64 + 1);
    assert_eq!(env.bundle().await.wrap_keys.len(), 2);
    assert_eq!(env.up.wrap_key_fetches.load(Ordering::SeqCst), 4);
    assert_eq!(env.bundle().await.wrap_keys.len(), 2);
    assert_eq!(env.up.wrap_key_fetches.load(Ordering::SeqCst), 4, "cached");

    let mut env = env;
    env.restart().await;
    assert_eq!(env.bundle().await.wrap_keys.len(), 2);
    assert_eq!(env.up.wrap_key_fetches.load(Ordering::SeqCst), 4, "cached on disk");
}

#[tokio::test]
async fn the_log_statement_is_refreshed_hourly_and_kept_while_the_log_is_down() {
    let env = Env::new().await;
    env.ready().await;
    let first = env.bundle().await.freshness[0].clone();
    env.advance(600);
    assert_eq!(env.bundle().await.freshness[0], first, "not due yet");

    env.advance(LOG_FRESHNESS_REFRESH_SECS as i64);
    let second = env.bundle().await.freshness[0].clone();
    assert!(second.body.signed_at > first.body.signed_at);

    env.up.log_down.store(true, Ordering::SeqCst);
    env.advance(LOG_FRESHNESS_REFRESH_SECS as i64);
    let bundle = env.bundle().await;
    assert_eq!(bundle.freshness, vec![second], "the cached statement while the log is unreachable");
}

#[tokio::test]
async fn a_short_freshness_window_refreshes_the_log_statement_sooner() {
    assert_eq!(log_freshness_refresh(seal_proto::state::STATE_FRESHNESS_SECS), LOG_FRESHNESS_REFRESH_SECS);
    let env = Env::new().await;
    env.ready().await;
    let mut body = state(2, 1);
    body.freshness_secs = Some(400);
    let s2 = env.log_state(body);
    assert_eq!(env.put("/v1/tenants/acme/state", &s2).await, 204);
    let first = env.bundle().await.freshness[0].clone();
    assert_eq!(first.body.version, 2);
    env.advance(50);
    assert_eq!(env.bundle().await.freshness[0], first, "not due yet");

    env.advance(50);
    let bundle = env.bundle().await;
    assert!(bundle.freshness[0].body.signed_at > first.body.signed_at, "due after a quarter of the window");
    let verified = env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap();
    assert_eq!(verified.fresh_until(), bundle.freshness[0].body.signed_at + 400);
}

#[tokio::test]
async fn tenant_freshness_statements_need_a_freshness_key_and_the_latest_state() {
    let env = Env::new().await;
    env.ready().await;
    let statement = |body: &TenantState, signed_at: UnixTime, signer: u8| -> SignedStateFreshness {
        let s = StateFreshness {
            tenant: body.tenant.clone(),
            version: body.version,
            digest: codec::labeled_digest(TENANT_STATE_LABEL, body),
            signed_at,
        };
        key(signer).sign_into(STATE_FRESHNESS_LABEL, s)
    };
    let now = env.now();
    assert_eq!(
        env.post("/v1/tenants/acme/freshness", &statement(&env.s1.body, now, TENANT_FRESHNESS)).await,
        403,
        "state 1 names no freshness keys"
    );

    let mut body = state(2, 1);
    body.freshness_keys.insert(key(TENANT_FRESHNESS).public_key());
    assert_eq!(
        env.get_as("/v1/tenants/acme/bundle", Auth::Key(TENANT_FRESHNESS)).await.0,
        401,
        "not yet a freshness key"
    );
    let s2 = env.log_state(body);
    assert_eq!(env.put("/v1/tenants/acme/state", &s2).await, 204);
    // A freshness signer reads the state it signs for, and nothing else.
    assert_eq!(env.get_as("/v1/tenants/acme/bundle", Auth::Key(TENANT_FRESHNESS)).await.0, 200);
    assert_eq!(env.get_as("/v1/tenants/acme/telemetry", Auth::Key(TENANT_FRESHNESS)).await.0, 403);
    assert_eq!(env.post("/v1/tenants/acme/freshness", &statement(&s2.body, now, STRANGER)).await, 403);
    assert_eq!(
        env.post("/v1/tenants/acme/freshness", &statement(&env.s1.body, now, TENANT_FRESHNESS)).await,
        409,
        "for an older state"
    );
    assert_eq!(
        env.post("/v1/tenants/acme/freshness", &statement(&s2.body, now + 3_600, TENANT_FRESHNESS)).await,
        400,
        "dated in the future"
    );
    let mut other_tenant = statement(&s2.body, now, TENANT_FRESHNESS);
    other_tenant.body.tenant = other();
    assert_eq!(env.post("/v1/tenants/acme/freshness", &other_tenant).await, 400);

    let older = statement(&s2.body, now - 100, TENANT_FRESHNESS);
    let newer = statement(&s2.body, now, TENANT_FRESHNESS);
    assert_eq!(env.post("/v1/tenants/acme/freshness", &newer).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/freshness", &older).await, 204);
    let bundle = env.bundle().await;
    assert_eq!(bundle.freshness.len(), 2);
    assert_eq!(bundle.freshness[1], newer, "the newest tenant-run statement");
    env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap();
}

#[tokio::test]
async fn service_key_certificates_need_the_platforms_guardian() {
    let env = Env::new().await;
    let cert = env.keys.certificate.clone();
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &cert).await, 409, "no root chain yet");
    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204);

    let forged: SignedServiceKeyCertificate = key(STRANGER).sign_into(SERVICE_KEY_CERTIFICATE_LABEL, cert.body.clone());
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &forged).await, 403);
    let mut other_platform = cert.body.clone();
    other_platform.platform = PlatformId::AzureSnpAci;
    let other_platform = pmk().guardian_key().sign_into(SERVICE_KEY_CERTIFICATE_LABEL, other_platform);
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &other_platform).await, 403, "no guardian for it");
    let other_chain = pmk().release_service(&acme(), &TenantRootId([3; 32]), ServiceKeyVersion(1));
    let other_chain = ServiceKeys::from_released(PlatformId::Sim, &other_chain).unwrap().certificate;
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &other_chain).await, 409);
    assert_eq!(env.post("/v1/tenants/other/service-key-certificates", &cert).await, 400);

    let none: Vec<SignedServiceKeyCertificate> = env.get_json("/v1/tenants/acme/service-key-certificates").await;
    assert!(none.is_empty(), "refused certificates are not stored");
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &cert).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &cert).await, 204, "dedup");
    let v2 = pmk().release_service(&acme(), &env.root_id(), ServiceKeyVersion(2));
    let v2 = ServiceKeys::from_released(PlatformId::Sim, &v2).unwrap().certificate;
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &v2).await, 204);

    let all: Vec<SignedServiceKeyCertificate> = env.get_json("/v1/tenants/acme/service-key-certificates").await;
    assert_eq!(all, vec![cert, v2]);
    let none: Vec<SignedServiceKeyCertificate> = env.get_json("/v1/tenants/other/service-key-certificates").await;
    assert!(none.is_empty());
}

#[tokio::test]
async fn signals_verify_against_telemetry_or_source_keys() {
    let env = Env::new().await;
    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204);
    assert_eq!(env.put("/v1/tenants/acme/state", &env.s1).await, 204);
    let now = env.now();
    let enclave: SignedSignal =
        env.telemetry_signer().sign_into(SIGNAL_LABEL, signal_body(acme(), enclave_source(), Severity::High, now, 1));
    assert_eq!(env.post("/v1/tenants/acme/signals", &enclave).await, 403, "no certificate posted yet");
    assert_eq!(env.post("/v1/tenants/acme/service-key-certificates", &env.keys.certificate).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/signals", &enclave).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/signals", &enclave).await, 204, "dedup");

    let forged = key(STRANGER).sign_into(SIGNAL_LABEL, signal_body(acme(), SignalSource::Sdk, Severity::High, now, 2));
    assert_eq!(env.post("/v1/tenants/acme/signals", &forged).await, 403, "forged enclave signature");
    let edr = key(EDR).sign_into(SIGNAL_LABEL, signal_body(acme(), edr_source(), Severity::Critical, now, 3));
    assert_eq!(env.post("/v1/tenants/acme/signals", &edr).await, 204);
    let edr_as_enclave =
        key(EDR).sign_into(SIGNAL_LABEL, signal_body(acme(), enclave_source(), Severity::High, now, 4));
    assert_eq!(env.post("/v1/tenants/acme/signals", &edr_as_enclave).await, 403);
    let unknown = key(EDR).sign_into(
        SIGNAL_LABEL,
        signal_body(acme(), SignalSource::External { source: "nobody".into() }, Severity::High, now, 5),
    );
    assert_eq!(env.post("/v1/tenants/acme/signals", &unknown).await, 403, "a source the state does not name");
    let mut bad_code = signal_body(acme(), edr_source(), Severity::High, now, 6);
    bad_code.code = "Not A Code".into();
    assert_eq!(env.post("/v1/tenants/acme/signals", &key(EDR).sign_into(SIGNAL_LABEL, bad_code)).await, 400);
    let elsewhere = key(EDR).sign_into(SIGNAL_LABEL, signal_body(other(), edr_source(), Severity::High, now, 7));
    assert_eq!(env.post("/v1/tenants/acme/signals", &elsewhere).await, 400);

    // Stored but not live: a timed suspension that ran out, and a severity that only denies.
    let stale = env
        .telemetry_signer()
        .sign_into(SIGNAL_LABEL, signal_body(acme(), SignalSource::Sdk, Severity::High, now - 120, 8));
    let deny = env
        .telemetry_signer()
        .sign_into(SIGNAL_LABEL, signal_body(acme(), SignalSource::Sdk, Severity::Medium, now, 9));
    assert_eq!(env.post("/v1/tenants/acme/signals", &stale).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/signals", &deny).await, 204);

    let bundle = env.bundle().await;
    assert_eq!(bundle.signals, vec![enclave.clone(), edr.clone()]);
    let verified = env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap();
    assert_eq!(verified.signals().len(), 2);

    env.advance(61);
    assert_eq!(env.bundle().await.signals, vec![edr], "the timed suspension ran out");
}

#[tokio::test]
async fn session_ends_verify_and_leave_the_bundle_once_not_live() {
    let env = Env::new().await;
    env.ready().await;
    let now = env.now();
    let sign = |end: SessionEnd| -> SignedSessionEnd { env.telemetry_signer().sign_into(SESSION_END_LABEL, end) };
    let live = sign(session_end(acme(), 1, now));
    let ended_long_ago = sign(session_end(acme(), 2, now - SESSION_END_RETAIN_SECS - 1));
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &live).await, 204);
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &live).await, 204, "dedup");
    let mut again = session_end(acme(), 1, now + 1);
    again.reason = ErrorCode::IntegrityFailed;
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &sign(again)).await, 204, "first per session wins");
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &ended_long_ago).await, 204);

    let forged = key(STRANGER).sign_into(SESSION_END_LABEL, session_end(acme(), 3, now));
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &forged).await, 403);
    let mut bad_reason = session_end(acme(), 4, now);
    bad_reason.reason = ErrorCode::Internal;
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &sign(bad_reason)).await, 400);
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &sign(session_end(other(), 5, now))).await, 400);

    assert_eq!(env.bundle().await.ended_sessions, vec![live]);
    env.advance(SESSION_END_RETAIN_SECS as i64);
    assert!(env.bundle().await.ended_sessions.is_empty());
}

#[tokio::test]
async fn telemetry_appends_verified_batches_and_reads_by_time_stream_and_sequence() {
    let env = Env::new().await;
    env.ready().await;
    let sign =
        |b: TelemetryBatch| -> SignedTelemetryBatch { env.telemetry_signer().sign_into(TELEMETRY_BATCH_LABEL, b) };
    let b_2_0 = sign(batch(2, 0, 300));
    let b_1_1 = sign(batch(1, 1, 200));
    let b_1_0 = sign(batch(1, 0, 100));
    for b in [&b_2_0, &b_1_1, &b_1_0] {
        assert_eq!(env.post("/v1/tenants/acme/telemetry", b).await, 204);
    }
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &b_1_0).await, 204, "the same batch again");
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &sign(batch(1, 0, 101))).await, 409, "another batch, same place");
    let forged = key(STRANGER).sign_into(TELEMETRY_BATCH_LABEL, batch(3, 0, 100));
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &forged).await, 403);
    let mut miscounted = batch(3, 0, 100);
    miscounted.count = 2;
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &sign(miscounted)).await, 400);
    let mut backwards = batch(3, 0, 100);
    backwards.from = 101;
    assert_eq!(env.post("/v1/tenants/acme/telemetry", &sign(backwards)).await, 400);

    let all: Vec<SignedTelemetryBatch> = env.get_json("/v1/tenants/acme/telemetry?since=0").await;
    assert_eq!(all, vec![b_1_0.clone(), b_1_1.clone(), b_2_0.clone()]);
    let recent: Vec<SignedTelemetryBatch> = env.get_json("/v1/tenants/acme/telemetry?since=200").await;
    assert_eq!(recent, vec![b_1_1.clone(), b_2_0.clone()]);
    // Pages: by `limit`, continued `after` the last batch.
    let first: Vec<SignedTelemetryBatch> = env.get_json("/v1/tenants/acme/telemetry?since=0&limit=2").await;
    assert_eq!(first, vec![b_1_0.clone(), b_1_1.clone()]);
    let after = format!("{}-1", "01".repeat(16));
    let next: Vec<SignedTelemetryBatch> =
        env.get_json(&format!("/v1/tenants/acme/telemetry?since=0&limit=2&after={after}")).await;
    assert_eq!(next, vec![b_2_0.clone()]);
    let end: Vec<SignedTelemetryBatch> =
        env.get_json(&format!("/v1/tenants/acme/telemetry?since=0&after={}-0", "02".repeat(16))).await;
    assert!(end.is_empty());
    assert_eq!(env.get("/v1/tenants/acme/telemetry?after=zz-1").await.0, 400);
    assert_eq!(env.get("/v1/tenants/other/telemetry?since=0").await.0, 401, "no admin of acme reads other");
    assert_eq!(env.get("/v1/tenants/acme/telemetry?since=soon").await.0, 400);
}

#[tokio::test]
async fn release_cosigns_need_the_token_and_the_latest_roots_admins() {
    let env = Env::new().await;
    let m = Measurement([5; 48]);
    let path = format!("/v1/tenants/acme/release-cosigns/{m}");
    let cosign = signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: acme(), measurement: m }, &V1_ADMINS);
    assert_eq!(env.put(&path, &cosign).await, 409, "no root chain yet");
    assert_eq!(env.call("PUT", &path, Auth::Key(V1_ADMINS[0]), Some(&cosign)).await.0, 401, "no chain to sign for");
    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204);
    assert_eq!(env.get(&path).await.0, 404);
    assert_eq!(env.put_as(&path, None, &cosign).await, 401);
    let weak = signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: acme(), measurement: m }, &V1_ADMINS[..1]);
    assert_eq!(env.put(&path, &weak).await, 400);
    let elsewhere =
        signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: acme(), measurement: Measurement([6; 48]) }, &V1_ADMINS);
    assert_eq!(env.put(&path, &elsewhere).await, 400);
    assert_eq!(env.put(&path, &cosign).await, 204);
    let stored: Signed<ReleaseCosign> = env.get_json(&path).await;
    assert_eq!(stored, cosign);
    assert_eq!(env.get("/v1/tenants/acme/release-cosigns/zz").await.0, 400);
}

#[tokio::test]
async fn releases_need_the_token_and_log_inclusion() {
    let env = Env::new().await;
    let manifest = signed(RELEASE_LABEL, manifest(5), &[STRANGER]);
    let (included, fresh) = {
        let mut log = env.up.log();
        let index = log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        (log.prove(index), log.checkpoint())
    };
    let evidence = ReleaseEvidence { manifest, included, fresh, auditor: None };
    let path = format!("/v1/releases/sim/{}", Measurement([5; 48]));
    assert_eq!(env.get(&path).await.0, 404);
    assert_eq!(env.put_as(&path, None, &evidence).await, 401);
    assert_eq!(env.put(&format!("/v1/releases/sim/{}", Measurement([6; 48])), &evidence).await, 400);
    assert_eq!(env.put(&format!("/v1/releases/azure_snp_aci/{}", Measurement([5; 48])), &evidence).await, 400);
    assert_eq!(env.put("/v1/releases/nowhere/00", &evidence).await, 400);
    let mut unlogged = evidence.clone();
    unlogged.included = env.v1.proof.clone();
    assert_eq!(env.put(&path, &unlogged).await, 400);
    let mut unsigned = evidence.clone();
    unsigned.fresh.cosignatures.clear();
    assert_eq!(env.put(&path, &unsigned).await, 400);
    assert_eq!(env.put(&path, &evidence).await, 204);
    let stored: ReleaseEvidence = env.get_json(&path).await;
    assert_eq!(stored, evidence);
    let listed: Vec<ReleaseEvidence> = env.get_json("/v1/releases/sim").await;
    assert_eq!(listed, vec![evidence]);
    let none: Vec<ReleaseEvidence> = env.get_json("/v1/releases/azure_snp_aci").await;
    assert!(none.is_empty());
}

#[tokio::test]
async fn release_templates_need_the_token_and_the_release() {
    let env = Env::new().await;
    let template = serde_json::json!({"resources": []});
    let unknown = format!("/v1/releases/sim/{}/template", Measurement([6; 48]));
    assert_eq!(env.put(&unknown, &template).await, 409, "no evidence for that release");
    let manifest = signed(RELEASE_LABEL, manifest(5), &[STRANGER]);
    let (included, fresh) = {
        let mut log = env.up.log();
        let index = log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        (log.prove(index), log.checkpoint())
    };
    let evidence = ReleaseEvidence { manifest, included, fresh, auditor: None };
    assert_eq!(env.put(&format!("/v1/releases/sim/{}", Measurement([5; 48])), &evidence).await, 204);
    let path = format!("/v1/releases/sim/{}/template", Measurement([5; 48]));
    assert_eq!(env.get(&path).await.0, 404);
    assert_eq!(env.put_as(&path, None, &template).await, 401);
    assert_eq!(env.put(&path, &serde_json::json!([1])).await, 400);
    assert_eq!(env.put(&path, &template).await, 204);
    let stored: serde_json::Value = env.get_json(&path).await;
    assert_eq!(stored, template);
    let listed: Vec<ReleaseEvidence> = env.get_json("/v1/releases/sim").await;
    assert_eq!(listed, vec![evidence], "templates are not listed as releases");
}

#[tokio::test]
async fn the_checkpoint_is_proxied_verified_and_briefly_cached() {
    let env = Env::new().await;
    let first: SignedCheckpoint = env.get_json("/v1/checkpoint").await;
    LogVerifier::new(env.up.log().trust()).checkpoint(&first).unwrap();
    env.up.log_down.store(true, Ordering::SeqCst);
    let cached: SignedCheckpoint = env.get_json("/v1/checkpoint").await;
    assert_eq!(cached, first);
    env.advance(CHECKPOINT_CACHE_SECS as i64);
    assert_eq!(env.get("/v1/checkpoint").await.0, 503);
}

#[tokio::test]
async fn documents_survive_a_restart() {
    let mut env = Env::new().await;
    env.ready().await;
    let signal = key(EDR).sign_into(SIGNAL_LABEL, signal_body(acme(), edr_source(), Severity::Critical, env.now(), 1));
    assert_eq!(env.post("/v1/tenants/acme/signals", &signal).await, 204);
    let before = env.bundle().await;
    env.restart().await;
    let after = env.bundle().await;
    assert_eq!(after.root_chain, before.root_chain);
    assert_eq!(after.state, before.state);
    assert_eq!(after.signals, before.signals);
    assert_eq!(after.freshness, before.freshness);
    // The certificate survived too: enclave-signed documents still verify.
    let end = env.telemetry_signer().sign_into(SESSION_END_LABEL, session_end(acme(), 1, env.now()));
    assert_eq!(env.post("/v1/tenants/acme/session-ends", &end).await, 204);
}

/// PEM of one DER certificate.
fn pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

#[tokio::test]
async fn the_client_round_trips_every_endpoint_over_tls() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use seal_control::client::ControlClient;
    use seal_net::{BakedRootsConnector, HttpsClient, TcpDialer};

    let env = Env::new().await;
    // The server's TLS identity: a CA and leaf for `localhost`.
    let names = vec!["localhost".to_string()];
    let tls = &env.keys.tls;
    let ca = tls.ca_certificate_der(&names).unwrap();
    let identity = tls::TlsIdentity {
        chain: vec![CertificateDer::from(tls.leaf_certificate_der(&names).unwrap()), CertificateDer::from(ca.clone())],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.private_key_pkcs8_der().to_vec())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = app(env.up.clone(), &env.dir.join("tls"), env.offset.clone(), true);
    let listener = tls::TlsListener::new(listener, identity.server_config().unwrap()).unwrap();
    tokio::spawn(async move { axum::serve(listener, router(server)).await });

    let connector = BakedRootsConnector::with_extra_roots(Arc::new(TcpDialer), pem(&ca).as_bytes()).unwrap();
    let https = Arc::new(HttpsClient::new(Arc::new(connector)));
    let base = url::Url::parse(&format!("https://localhost:{port}/")).unwrap();
    let operator = ControlClient::new(base.clone(), https.clone(), Some(TOKEN.into()));
    let admin = ControlClient::new(base.clone(), https.clone(), None)
        .with_credential(Arc::new(SigningKeyCredential::new(key(V1_ADMINS[0]), env.root_id())));
    let telemetry_key = SigningKey::from_seed(&env.telemetry_signer().to_seed());
    let enclave = ControlClient::new(base.clone(), https.clone(), None)
        .with_credential(Arc::new(SigningKeyCredential::new(telemetry_key, env.root_id())));
    let anyone = ControlClient::new(base, https, None);
    let tenant = acme();

    assert_eq!(admin.get_bundle(&tenant).await.unwrap_err().code(), ErrorCode::NotAllowed, "no chain yet");
    assert_eq!(anyone.put_root(&tenant, &env.v1).await.unwrap_err().code(), ErrorCode::NotAllowed);
    admin.put_root(&tenant, &env.v1).await.unwrap();
    let logged = LoggedState { state: env.s1.clone(), proof: env.up.log().prove(1) };
    operator.put_state(&tenant, &logged).await.unwrap();
    assert_eq!(anyone.get_bundle(&tenant).await.unwrap_err().code(), ErrorCode::NotAllowed);
    assert_eq!(enclave.get_bundle(&tenant).await.unwrap_err().code(), ErrorCode::NotAllowed, "no certificate yet");
    anyone.post_service_key_certificate(&tenant, &env.keys.certificate).await.unwrap();
    assert_eq!(anyone.get_service_key_certificates(&tenant).await.unwrap(), vec![env.keys.certificate.clone()]);
    let documents = admin.get_documents(&tenant, None).await.unwrap();
    assert_eq!((documents.roots, documents.states), (vec![env.v1.clone()], vec![logged]));

    let now = env.now();
    let signal = env
        .telemetry_signer()
        .sign_into(SIGNAL_LABEL, signal_body(acme(), SignalSource::Sdk, Severity::Critical, now, 1));
    anyone.post_signal(&tenant, &signal).await.unwrap();
    let forged =
        key(STRANGER).sign_into(SIGNAL_LABEL, signal_body(acme(), SignalSource::Sdk, Severity::Critical, now, 2));
    assert_eq!(anyone.post_signal(&tenant, &forged).await.unwrap_err().code(), ErrorCode::NotAllowed);
    let end = env.telemetry_signer().sign_into(SESSION_END_LABEL, session_end(acme(), 1, now));
    anyone.post_session_end(&tenant, &end).await.unwrap();
    let b = env.telemetry_signer().sign_into(TELEMETRY_BATCH_LABEL, batch(1, 0, now));
    anyone.post_telemetry(&tenant, &b).await.unwrap();
    assert_eq!(admin.get_telemetry(&tenant, now).await.unwrap(), vec![b]);
    assert!(admin.get_telemetry(&tenant, now + 1).await.unwrap().is_empty());
    assert_eq!(
        enclave.get_telemetry(&tenant, now).await.unwrap_err().code(),
        ErrorCode::NotAllowed,
        "enclaves never read it"
    );

    let tenant_statement = key(TENANT_FRESHNESS).sign_into(
        STATE_FRESHNESS_LABEL,
        StateFreshness {
            tenant: acme(),
            version: 1,
            digest: codec::labeled_digest(TENANT_STATE_LABEL, &env.s1.body),
            signed_at: now,
        },
    );
    assert_eq!(anyone.post_freshness(&tenant, &tenant_statement).await.unwrap_err().code(), ErrorCode::NotAllowed);

    let bundle = enclave.get_bundle(&tenant).await.unwrap();
    assert_eq!(
        serde_json::to_value(&bundle).unwrap(),
        serde_json::to_value(admin.get_bundle(&tenant).await.unwrap()).unwrap()
    );
    assert_eq!(bundle.signals, vec![signal]);
    assert_eq!(bundle.ended_sessions, vec![end]);
    assert_eq!(bundle.wrap_keys.len(), 2);
    env.verifier().verify(&tenant, &bundle, &TrustedTime::exact(env.now())).unwrap();

    let m = Measurement([5; 48]);
    let cosign = signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: acme(), measurement: m }, &V1_ADMINS);
    admin.put_release_cosign(&tenant, &m, &cosign).await.unwrap();
    assert_eq!(anyone.get_release_cosign(&tenant, &m).await.unwrap(), cosign);

    let manifest = signed(RELEASE_LABEL, manifest(5), &[STRANGER]);
    let (included, fresh) = {
        let mut log = env.up.log();
        let index = log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        (log.prove(index), log.checkpoint())
    };
    let evidence = ReleaseEvidence { manifest, included, fresh, auditor: None };
    assert_eq!(admin.put_release(PlatformId::Sim, &m, &evidence).await.unwrap_err().code(), ErrorCode::NotAllowed);
    operator.put_release(PlatformId::Sim, &m, &evidence).await.unwrap();
    assert_eq!(anyone.get_release(PlatformId::Sim, &m).await.unwrap(), evidence);
    assert_eq!(anyone.get_releases(PlatformId::Sim).await.unwrap(), vec![evidence.clone()]);
    let template = serde_json::json!({"resources": []});
    assert_eq!(
        admin.put_release_template(PlatformId::Sim, &m, &template).await.unwrap_err().code(),
        ErrorCode::NotAllowed
    );
    operator.put_release_template(PlatformId::Sim, &m, &template).await.unwrap();
    assert_eq!(anyone.get_release_template(PlatformId::Sim, &m).await.unwrap(), template);
    assert_eq!(anyone.get_release(PlatformId::AzureSnpAci, &m).await.unwrap_err().code(), ErrorCode::BadRequest, "404");

    let checkpoint = anyone.get_checkpoint().await.unwrap();
    LogVerifier::new(env.up.log().trust()).checkpoint(&checkpoint).unwrap();
}

/// The HTTP upstreams against the dev log's and guardian's real paths, over plain loopback
/// HTTP (sim builds).
#[cfg(feature = "sim")]
#[tokio::test]
async fn http_upstreams_use_the_log_and_guardian_paths() {
    use axum::extract::Path as P;
    use axum::routing::get;

    let env = Env::new().await;
    let up = env.up.clone();
    let (fresh_up, cp_up) = (up.clone(), up.clone());
    let log = Router::new()
        .route(
            "/v1/tenants/{tenant}/freshness",
            get(move |P(t): P<TenantId>| async move {
                match fresh_up.log().freshness(&t) {
                    Some(s) => Json(s).into_response(),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }),
        )
        .route("/v1/checkpoint", get(move || async move { Json(cp_up.log().checkpoint()) }))
        .route(
            "/v1/wrap-keys/{tenant}/{root_id}/{version}",
            get(|P((t, r, v)): P<(TenantId, TenantRootId, u32)>| async move {
                Json(pmk().tenant_wrap_key(&t, &r, TenantKeyVersion(v)))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, log).await });

    let base = url::Url::parse(&format!("http://127.0.0.1:{}/", addr.port())).unwrap();
    let https = Arc::new(seal_net::HttpsClient::new(Arc::new(seal_net::BakedRootsConnector::new(Arc::new(
        seal_net::TcpDialer,
    )))));
    let http = upstream::HttpUpstreams::new(https, &base, [(PlatformId::Sim, base.clone())].into());
    let statement = http.log_freshness(&acme()).await.unwrap().unwrap();
    assert!(for_state(&statement, &env.s1.body));
    assert_eq!(http.log_freshness(&other()).await.unwrap(), None);
    let checkpoint = http.log_checkpoint().await.unwrap();
    LogVerifier::new(up.log().trust()).checkpoint(&checkpoint).unwrap();
    let key = http.wrap_key(PlatformId::Sim, &acme(), &env.root_id(), TenantKeyVersion(2)).await.unwrap();
    assert_eq!(key, Some(pmk().tenant_wrap_key(&acme(), &env.root_id(), TenantKeyVersion(2))));
    assert_eq!(http.wrap_key(PlatformId::AwsNitro, &acme(), &env.root_id(), TenantKeyVersion(2)).await.unwrap(), None);
}

#[tokio::test]
async fn grants_proposals_and_telemetry_need_a_credential_and_public_data_does_not() {
    let env = Env::new().await;
    env.ready().await;
    for path in [
        "/v1/tenants/acme/bundle",
        "/v1/tenants/acme/documents",
        "/v1/tenants/acme/proposals",
        "/v1/tenants/acme/telemetry",
    ] {
        assert_eq!(env.get_as(path, Auth::None).await.0, 401, "{path}");
        assert_eq!(env.get(path).await.0, 200, "{path}");
    }
    for path in ["/v1/tenants/acme/service-key-certificates".to_string(), "/v1/checkpoint".to_string()] {
        assert_eq!(env.get_as(&path, Auth::None).await.0, 200, "{path}");
    }
    let m = Measurement([5; 48]);
    assert_eq!(
        env.get_as(&format!("/v1/tenants/acme/release-cosigns/{m}"), Auth::None).await.0,
        404,
        "public, none yet"
    );
    assert_eq!(env.get_as(&format!("/v1/releases/sim/{m}"), Auth::None).await.0, 404, "public, none yet");
    let keys: Vec<SignedServiceKeyCertificate> =
        serde_json::from_slice(&env.get_as("/v1/tenants/acme/service-key-certificates", Auth::None).await.1).unwrap();
    assert_eq!(keys, vec![env.keys.certificate.clone()]);
    // The write token reads nothing.
    let operator = Auth::Header(format!("Bearer {TOKEN}"));
    assert_eq!(env.get_as("/v1/tenants/acme/bundle", operator).await.0, 403);
    assert_eq!(env.get_as("/v1/tenants/acme/bundle", Auth::Header("Basic eA".into())).await.0, 401);
}

#[tokio::test]
async fn bundles_carry_states_from_the_guardians_anchor() {
    let env = Env::new().await;
    env.ready().await;
    let versions = |b: &TenantBundle| b.states.iter().map(|s| s.state.body.version).collect::<Vec<_>>();
    let bundle = env.bundle().await;
    assert_eq!(versions(&bundle), [1]);
    assert!(bundle.checkpoint.is_some(), "the log's witnessed time");
    assert_eq!(bundle.anchors.iter().map(|a| a.body.version).collect::<Vec<_>>(), [1]);
    let fetches = env.up.anchor_fetches.load(Ordering::SeqCst);
    env.bundle().await;
    assert_eq!(env.up.anchor_fetches.load(Ordering::SeqCst), fetches, "an anchor is renewed hourly");

    let s2 = signed(TENANT_STATE_LABEL, state(2, 1), &V1_ADMINS);
    assert_eq!(env.put("/v1/tenants/acme/state", &s2).await, 204);
    let bundle = env.bundle().await;
    assert_eq!(versions(&bundle), [1, 2], "from the anchored state");
    assert_eq!(env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap().state().version, 2);

    // An hour on, the guardian anchors state 2 and the bundle starts there.
    env.advance(ANCHOR_REFRESH_SECS as i64 + 1);
    let bundle = env.bundle().await;
    assert_eq!(bundle.anchors.iter().map(|a| a.body.version).collect::<Vec<_>>(), [2]);
    assert_eq!(versions(&bundle), [2]);
    assert_eq!(env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap().state().version, 2);
}

#[tokio::test]
async fn signed_requests_name_one_request_on_one_chain() {
    let env = Env::new().await;
    env.ready().await;
    let now = env.now();
    let admin = key(V1_ADMINS[1]);
    let header = |signer: &SigningKey, root: TenantRootId, method: &str, path: &str, at: UnixTime| {
        Auth::Header(signed_header(signer, root, method, path, b"", at))
    };
    let bundle = "/v1/tenants/acme/bundle";
    assert_eq!(env.get_as(bundle, header(&admin, env.root_id(), "GET", bundle, now)).await.0, 200);
    assert_eq!(env.get_as(bundle, header(&key(STRANGER), env.root_id(), "GET", bundle, now)).await.0, 401);
    let telemetry = "/v1/tenants/acme/telemetry?since=0";
    assert_eq!(
        env.get_as(telemetry, header(&admin, env.root_id(), "GET", bundle, now)).await.0,
        401,
        "signed for another path"
    );
    assert_eq!(
        env.get_as(bundle, header(&admin, env.root_id(), "PUT", bundle, now)).await.0,
        401,
        "for another method"
    );
    assert_eq!(env.get_as(bundle, header(&admin, env.root_id(), "GET", bundle, now - 301)).await.0, 401, "not recent");
    assert_eq!(
        env.get_as(bundle, header(&admin, env.root_id(), "GET", bundle, now + 330)).await.0,
        401,
        "from the future"
    );
    assert_eq!(
        env.get_as(bundle, header(&admin, TenantRootId([3; 32]), "GET", bundle, now)).await.0,
        403,
        "another chain"
    );
    let other = "/v1/tenants/other/bundle";
    assert_eq!(env.get_as(other, header(&admin, env.root_id(), "GET", other, now)).await.0, 401, "no chain for other");

    // The tenant's enclaves read the bundle with their certified telemetry key, nothing else.
    let enclave = SigningKey::from_seed(&env.telemetry_signer().to_seed());
    assert_eq!(env.get_as(bundle, header(&enclave, env.root_id(), "GET", bundle, now)).await.0, 200);
    assert_eq!(env.get_as(telemetry, header(&enclave, env.root_id(), "GET", telemetry, now)).await.0, 403);
    let documents = "/v1/tenants/acme/documents";
    assert_eq!(env.get_as(documents, header(&enclave, env.root_id(), "GET", documents, now)).await.0, 403);

    // A body other than the one signed.
    let path = format!("/v1/tenants/acme/release-cosigns/{}", Measurement([5; 48]));
    let cosign =
        signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: acme(), measurement: Measurement([5; 48]) }, &V1_ADMINS);
    let auth = Auth::Header(signed_header(&admin, env.root_id(), "PUT", &path, b"{}", now));
    assert_eq!(env.call("PUT", &path, auth, Some(&cosign)).await.0, 401);
    assert_eq!(env.call("PUT", &path, Auth::Key(V1_ADMINS[1]), Some(&cosign)).await.0, 204);
    assert_eq!(env.call("PUT", &path, Auth::Key(STRANGER), Some(&cosign)).await.0, 401);
}

#[tokio::test]
async fn control_tokens_admit_their_tenant_chain_and_scope() {
    let env = Env::new().await;
    env.ready().await;
    let now = env.now();
    let token =
        |scope: &str, iat: UnixTime| Auth::Header(control_token(&console_key(), "acme", env.root_id(), scope, iat));
    for path in [
        "/v1/tenants/acme/bundle",
        "/v1/tenants/acme/documents?since_version=1",
        "/v1/tenants/acme/proposals",
        "/v1/tenants/acme/telemetry",
    ] {
        assert_eq!(env.get_as(path, token("read", now)).await.0, 200, "{path}");
        assert_eq!(env.get_as(path, token("submit", now)).await.0, 200, "{path}");
    }
    let bundle = "/v1/tenants/acme/bundle";
    assert_eq!(env.get_as(bundle, token("read", now - 300)).await.0, 401, "expired");
    let other_chain = Auth::Header(control_token(&console_key(), "acme", TenantRootId([3; 32]), "read", now));
    assert_eq!(env.get_as(bundle, other_chain).await.0, 403);
    let other_tenant = Auth::Header(control_token(&console_key(), "other", env.root_id(), "read", now));
    assert_eq!(env.get_as(bundle, other_tenant).await.0, 403);
    let unknown_key = Auth::Header(control_token(&key(STRANGER), "acme", env.root_id(), "read", now));
    assert_eq!(env.get_as(bundle, unknown_key).await.0, 401);

    // `read` cannot propose; `submit` can, but a token signs nothing: the document needs its
    // admin signatures to be submitted.
    let s2 = state(2, 1);
    let unsigned = Signed { body: s2.clone(), signatures: vec![] };
    let path = format!("/v1/tenants/acme/proposals/{}", Proposed::State(unsigned.clone()).id());
    assert_eq!(env.call("PUT", &path, token("read", now), Some(&unsigned)).await.0, 403);
    assert_eq!(env.call("PUT", &path, token("submit", now), Some(&unsigned)).await.0, 200);
    let (status, _) = env.call::<()>("POST", &format!("{path}/submit"), token("submit", now), None).await;
    assert_eq!(status, 409, "no signatures yet");
    let signed_s2 = signed(TENANT_STATE_LABEL, s2, &V1_ADMINS);
    assert_eq!(env.call("PUT", &path, token("submit", now), Some(&signed_s2)).await.0, 200);
    let (status, body) = env.call::<()>("POST", &format!("{path}/submit"), token("submit", now), None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(env.bundle().await.state.body.version, 2);
}

/// Admins 11 and 12 sign one after another (threshold 2), then rotate the root to admin 13
/// and re-sign the state under it, each through proposals.
#[tokio::test]
async fn proposals_collect_signatures_one_admin_at_a_time() {
    let env = Env::new().await;
    env.ready().await;
    let list = |body: Vec<u8>| serde_json::from_slice::<Vec<Proposal>>(&body).unwrap();

    let body = state(2, 1);
    let path = format!(
        "/v1/tenants/acme/proposals/{}",
        Proposed::State(Signed { body: body.clone(), signatures: vec![] }).id()
    );
    let by = |n: u8| signed(TENANT_STATE_LABEL, body.clone(), &[n]);
    let (status, response) = env.call("PUT", &path, Auth::Key(V1_ADMINS[0]), Some(&by(V1_ADMINS[0]))).await;
    assert_eq!(status, 200);
    let proposal: Proposal = serde_json::from_slice(&response).unwrap();
    assert_eq!(proposal.id, path.rsplit('/').next().unwrap());
    let Proposed::State(held) = &proposal.document else { panic!("a state proposal") };
    assert_eq!(held.signatures.len(), 1);
    assert_eq!(
        env.call::<()>("POST", &format!("{path}/submit"), Auth::Key(V1_ADMINS[0]), None).await.0,
        409,
        "below the threshold"
    );

    // Junk is refused: another body under this id, a stranger's signature, a bad id.
    assert_eq!(
        env.call("PUT", &path, Auth::Key(V1_ADMINS[0]), Some(&signed(TENANT_STATE_LABEL, state(3, 1), &[]))).await.0,
        400
    );
    assert_eq!(env.call("PUT", &path, Auth::Key(V1_ADMINS[0]), Some(&by(STRANGER))).await.0, 403);
    let mut forged = by(V1_ADMINS[1]);
    forged.signatures[0].signer = key(V1_ADMINS[0]).key_id();
    assert_eq!(env.call("PUT", &path, Auth::Key(V1_ADMINS[0]), Some(&forged)).await.0, 403);
    assert_eq!(
        env.call("PUT", "/v1/tenants/acme/proposals/ABC", Auth::Key(V1_ADMINS[0]), Some(&by(V1_ADMINS[0]))).await.0,
        400
    );
    let older = signed(TENANT_STATE_LABEL, state(1, 1), &[]);
    let older_path = format!("/v1/tenants/acme/proposals/{}", Proposed::State(older.clone()).id());
    assert_eq!(
        env.call("PUT", &older_path, Auth::Key(V1_ADMINS[0]), Some(&older)).await.0,
        409,
        "not above the current state"
    );

    // The second admin signs from elsewhere; the signatures merge.
    assert_eq!(env.call("PUT", &path, Auth::Key(V1_ADMINS[1]), Some(&by(V1_ADMINS[1]))).await.0, 200);
    let open = list(env.get("/v1/tenants/acme/proposals").await.1);
    assert_eq!(open.len(), 1);
    let Proposed::State(held) = &open[0].document else { panic!("a state proposal") };
    assert_eq!(held.signatures.len(), 2);
    let (status, response) = env.call::<()>("POST", &format!("{path}/submit"), Auth::Key(V1_ADMINS[1]), None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let Submitted::State(logged) = serde_json::from_slice(&response).unwrap() else { panic!("a state") };
    assert_eq!(logged.state.body, body);
    LogVerifier::new(env.up.log().trust())
        .inclusion(&state_leaf(env.root_id(), &logged.state.body), &logged.proof)
        .unwrap();
    assert_eq!(env.bundle().await.state, logged.state);
    assert!(list(env.get("/v1/tenants/acme/proposals").await.1).is_empty(), "submitted proposals are gone");
    assert_eq!(env.call::<()>("POST", &format!("{path}/submit"), Auth::Key(V1_ADMINS[1]), None).await.0, 404);

    // Root version 2 (admin 13) and state 3 under it, collected before either is submitted.
    let root2 = root(2, &[V2_ADMIN], 1);
    let root_path = format!(
        "/v1/tenants/acme/proposals/{}",
        Proposed::Root(Signed { body: root2.clone(), signatures: vec![] }).id()
    );
    let state3 = state(3, 2);
    let state_path = format!(
        "/v1/tenants/acme/proposals/{}",
        Proposed::State(Signed { body: state3.clone(), signatures: vec![] }).id()
    );
    let signed_state3 = signed(TENANT_STATE_LABEL, state3.clone(), &[V2_ADMIN]);
    assert_eq!(
        env.call("PUT", &state_path, Auth::Key(V1_ADMINS[0]), Some(&signed_state3)).await.0,
        403,
        "no root proposal names admin 13 yet"
    );
    for n in V1_ADMINS {
        assert_eq!(
            env.call("PUT", &root_path, Auth::Key(n), Some(&signed(TENANT_ROOT_LABEL, root2.clone(), &[n]))).await.0,
            200
        );
    }
    assert_eq!(env.call("PUT", &state_path, Auth::Key(V1_ADMINS[0]), Some(&signed_state3)).await.0, 200);
    assert_eq!(list(env.get("/v1/tenants/acme/proposals").await.1).len(), 2);
    let (status, response) =
        env.call::<()>("POST", &format!("{root_path}/submit"), Auth::Key(V1_ADMINS[0]), None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let Submitted::Root(link) = serde_json::from_slice(&response).unwrap() else { panic!("a root") };
    assert_eq!(link.root.body, root2);
    // Admin 11 is no longer an admin: admin 13 submits.
    assert_eq!(env.call::<()>("POST", &format!("{state_path}/submit"), Auth::Key(V1_ADMINS[0]), None).await.0, 401);
    let (status, response) = env.call::<()>("POST", &format!("{state_path}/submit"), Auth::Key(V2_ADMIN), None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
    let (status, body) = env.get_as("/v1/tenants/acme/bundle", Auth::Key(V2_ADMIN)).await;
    assert_eq!(status, 200);
    let bundle: TenantBundle = serde_json::from_slice(&body).unwrap();
    assert_eq!(bundle.root_chain.len(), 2);
    assert_eq!(bundle.state.body.version, 3);
    env.verifier().verify(&acme(), &bundle, &TrustedTime::exact(env.now())).unwrap();

    let (status, body) = env.get_as("/v1/tenants/acme/documents?since_version=1", Auth::Key(V2_ADMIN)).await;
    assert_eq!(status, 200);
    let documents: Documents = serde_json::from_slice(&body).unwrap();
    assert_eq!(documents.roots.len(), 2, "every root, every time");
    assert_eq!(documents.states.iter().map(|s| s.state.body.version).collect::<Vec<_>>(), vec![2, 3]);
    assert!(documents.checkpoint.is_some());

    // Withdrawing.
    let state4 = signed(TENANT_STATE_LABEL, state(4, 2), &[]);
    let path4 = format!("/v1/tenants/acme/proposals/{}", Proposed::State(state4.clone()).id());
    assert_eq!(env.call("PUT", &path4, Auth::Key(V2_ADMIN), Some(&state4)).await.0, 200);
    assert_eq!(env.call::<()>("DELETE", &path4, Auth::Key(V2_ADMIN), None).await.0, 204);
    assert_eq!(env.call::<()>("DELETE", &path4, Auth::Key(V2_ADMIN), None).await.0, 404);
}

#[tokio::test]
async fn states_put_unlogged_are_logged_or_found_in_the_log() {
    let env = Env::new().await;
    assert_eq!(env.put("/v1/tenants/acme/root", &env.v1).await, 204);
    // State 1 is in the log already (`Env::new`): the log refuses it again, and the control
    // plane finds it there.
    assert_eq!(env.put("/v1/tenants/acme/state", &env.s1).await, 204);
    // State 2 is not: the control plane logs it.
    let s2 = signed(TENANT_STATE_LABEL, state(2, 1), &V1_ADMINS);
    assert_eq!(env.put("/v1/tenants/acme/state", &s2).await, 204);
    let (_, body) = env.get("/v1/tenants/acme/documents").await;
    let documents: Documents = serde_json::from_slice(&body).unwrap();
    assert_eq!(documents.states.len(), 2);
    let verifier = LogVerifier::new(env.up.log().trust());
    for logged in &documents.states {
        verifier.inclusion(&state_leaf(env.root_id(), &logged.state.body), &logged.proof).unwrap();
    }
    // A proof for another entry is refused.
    let s3 = signed(TENANT_STATE_LABEL, state(3, 1), &V1_ADMINS);
    let wrong = LoggedState { state: s3, proof: documents.states[0].proof.clone() };
    assert_eq!(env.put("/v1/tenants/acme/state", &wrong).await, 400);
}

#[tokio::test]
async fn cors_admits_the_console_origin_only() {
    let env = Env::new().await;
    env.ready().await;
    let preflight = [
        ("origin", CONSOLE_ORIGIN),
        ("access-control-request-method", "PUT"),
        ("access-control-request-headers", "authorization, content-type"),
    ];
    let (status, headers, _) =
        env.send("OPTIONS", "/v1/tenants/acme/proposals/00", Auth::None, &preflight, vec![]).await;
    assert_eq!(status, 204);
    assert_eq!(headers["access-control-allow-origin"], CONSOLE_ORIGIN);
    assert!(headers["access-control-allow-methods"].to_str().unwrap().contains("PUT"));
    assert!(headers["access-control-allow-headers"].to_str().unwrap().contains("authorization"));
    assert!(!headers.contains_key("access-control-allow-credentials"));

    let elsewhere = [("origin", "https://evil.example"), ("access-control-request-method", "PUT")];
    let (status, headers, _) =
        env.send("OPTIONS", "/v1/tenants/acme/proposals/00", Auth::None, &elsewhere, vec![]).await;
    assert_eq!(status, 405);
    assert!(!headers.contains_key("access-control-allow-origin"));

    let (status, headers, _) = env
        .send("GET", "/v1/tenants/acme/bundle", Auth::Key(V1_ADMINS[0]), &[("origin", CONSOLE_ORIGIN)], vec![])
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers["access-control-allow-origin"], CONSOLE_ORIGIN);
    let (status, headers, _) = env
        .send(
            "GET",
            "/v1/tenants/acme/bundle",
            Auth::Key(V1_ADMINS[0]),
            &[("origin", "https://console.seal.zone.evil.example")],
            vec![],
        )
        .await;
    assert_eq!(status, 200);
    assert!(!headers.contains_key("access-control-allow-origin"));
    let (_, headers, _) = env.send("GET", "/v1/checkpoint", Auth::None, &[], vec![]).await;
    assert!(!headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn the_tls_certificate_is_reloaded_when_its_files_change() {
    let dir = fresh_dir("tls");
    std::fs::create_dir_all(&dir).unwrap();
    let (chain, key_file) = (dir.join("chain.pem"), dir.join("key.pem"));
    let identity = |tenant: &str| {
        let released =
            pmk().release_service(&TenantId::new(tenant).unwrap(), &TenantRootId([1; 32]), ServiceKeyVersion(1));
        let tls = ServiceKeys::from_released(PlatformId::Sim, &released).unwrap().tls;
        let names = vec!["localhost".to_string()];
        let leaf = tls.leaf_certificate_der(&names).unwrap();
        let key = pem_block("PRIVATE KEY", &tls.private_key_pkcs8_der());
        (leaf, pem(&tls.leaf_certificate_der(&names).unwrap()), key)
    };
    let (leaf_a, chain_a, key_a) = identity("first");
    let (leaf_b, chain_b, key_b) = identity("second");
    std::fs::write(&chain, &chain_a).unwrap();
    std::fs::write(&key_file, &key_a).unwrap();
    let cert = tls::ReloadingCert::load(&chain, &key_file).unwrap();
    let served = |cert: &tls::ReloadingCert| cert.current().cert[0].to_vec();
    assert_eq!(served(&cert), leaf_a);
    assert!(!cert.reload().unwrap(), "unchanged");

    // A renewal writes the chain first: a chain whose key is not the key file's is skipped.
    std::fs::write(&chain, &chain_b).unwrap();
    assert!(cert.reload().is_err());
    assert_eq!(served(&cert), leaf_a);
    std::fs::write(&key_file, &key_b).unwrap();
    assert!(cert.reload().unwrap());
    assert_eq!(served(&cert), leaf_b);
    std::fs::write(&chain, "garbage").unwrap();
    assert!(cert.reload().is_err());
    assert_eq!(served(&cert), leaf_b, "the current pair stays");
    let _ = cert.server_config().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// PEM of `der` under `label`.
fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A boot read: sim evidence from a released enclave build, committing to the request.
#[cfg(feature = "sim")]
#[tokio::test]
async fn enclaves_read_their_bundle_at_boot_by_attesting() {
    use seal_proto::control::{AttestedControlRequest, ATTESTED_SCHEME};

    let env = Env::new().await;
    env.ready().await;
    let measurement = Measurement([5; 48]);
    let enclave_release = signed(RELEASE_LABEL, manifest(5), &[RELEASE]);
    let evidence = {
        let mut log = env.up.log();
        let index = log.append(LogEntry::Release(enclave_release.body.clone())).unwrap();
        ReleaseEvidence {
            manifest: enclave_release,
            included: log.prove(index),
            fresh: log.checkpoint(),
            auditor: None,
        }
    };
    let bundle = "/v1/tenants/acme/bundle";
    let attested = |measurement: Measurement, path: &str, root_id: TenantRootId, tamper: bool| {
        let tenant = acme();
        let target = seal_control::client::Target { tenant: &tenant, method: "GET", path, body: b"" };
        let request = target.request(root_id, env.now());
        let mut report_data = codec::labeled_digest(CONTROL_REQUEST_LABEL, &request);
        if tamper {
            report_data[0] ^= 1;
        }
        let document = seal_attest::sim::Document { measurement, report_data, tcb: Default::default() };
        let evidence = seal_proto::Evidence::Sim { document: seal_attest::sim::sign(&document) };
        let json = serde_json::to_vec(&AttestedControlRequest { request, evidence }).unwrap();
        Auth::Header(format!("{ATTESTED_SCHEME} {}", codec::b64url(&json)))
    };
    assert_eq!(
        env.get_as(bundle, attested(measurement, bundle, env.root_id(), false)).await.0,
        401,
        "no such release stored"
    );
    assert_eq!(env.put(&format!("/v1/releases/sim/{measurement}"), &evidence).await, 204);
    assert_eq!(env.get_as(bundle, attested(measurement, bundle, env.root_id(), false)).await.0, 200);
    assert_eq!(
        env.get_as(bundle, attested(measurement, bundle, env.root_id(), true)).await.0,
        401,
        "commits to another request"
    );
    assert_eq!(
        env.get_as(bundle, attested(Measurement([6; 48]), bundle, env.root_id(), false)).await.0,
        401,
        "not released"
    );
    assert_eq!(
        env.get_as(bundle, attested(measurement, bundle, TenantRootId([3; 32]), false)).await.0,
        403,
        "pinned to another chain"
    );
    let telemetry = "/v1/tenants/acme/telemetry";
    assert_eq!(
        env.get_as(telemetry, attested(measurement, telemetry, env.root_id(), false)).await.0,
        403,
        "the bundle only"
    );

    // A guardian release is not an enclave build.
    let mut guardian = manifest(7);
    guardian.component = Component::Guardian;
    let guardian = signed(RELEASE_LABEL, guardian, &[RELEASE]);
    let evidence = {
        let mut log = env.up.log();
        let index = log.append(LogEntry::Release(guardian.body.clone())).unwrap();
        ReleaseEvidence { manifest: guardian, included: log.prove(index), fresh: log.checkpoint(), auditor: None }
    };
    assert_eq!(env.put(&format!("/v1/releases/sim/{}", Measurement([7; 48])), &evidence).await, 204);
    assert_eq!(env.get_as(bundle, attested(Measurement([7; 48]), bundle, env.root_id(), false)).await.0, 401);
}
