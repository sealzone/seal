//! Fixtures for the port tests: a dev log with real release evidence and tenant bundles (times
//! relative to the wall clock, which is the sim guardian's clock), a sim guardian booted from a
//! root file, an in-memory control plane, and an untrusted TLS-terminating proxy in front of
//! each, reached through `seal_net::HttpsClient` like the enclave does.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use seal_control::client::ControlClient;
use seal_crypto::sign::SigningKey;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
use seal_guardian::client::GuardianClient;
#[cfg(feature = "sim")]
use seal_guardian::keysource::FileKeySource;
use seal_guardian::{Guardian, GuardianConfig};
#[cfg(feature = "sim")]
use seal_guardian::{GuardianComponents, KeySource};
use seal_net::{BakedRootsConnector, BoxStream, Dialer, HttpsClient, NetError};
use seal_proto::release::{
    Component, LogEntry, ReleaseCosign, ReleaseEvidence, ReleaseManifest, RELEASE_COSIGN_LABEL, RELEASE_LABEL,
};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, SignedTenantState, TenantBundle, TenantKeyVersions, TenantRoot, TenantState,
    TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::{
    Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId, UnixTime,
};
use seal_tlog::dev::DevLog;
use seal_verify::{ReleaseTrust, TenantTrust, Trust};

pub const DAY: u64 = 86_400;
pub const TIME_LOCK: u64 = 14 * DAY;
pub const RELEASE_KEYS: [u8; 3] = [1, 2, 3];
pub const REGISTRARS: [u8; 2] = [21, 22];
pub const ADMINS: [u8; 2] = [31, 32];

pub const ENCLAVE: Measurement = Measurement([0xe1; 48]);
pub const GUARDIAN: Measurement = Measurement([0x91; 48]);
pub const ROOT: [u8; 32] = [0x5e; 32];
/// The release's service key version.
pub const SERVICE_KEY_VERSION: ServiceKeyVersion = ServiceKeyVersion(2);

pub const GUARDIAN_HOST: &str = "guardian.test";
pub const CONTROL_HOST: &str = "control.test";

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

pub fn wall() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-enclave-{}-{n}", std::process::id()));
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

pub fn signed<T: serde::Serialize>(label: &str, body: T, keys: &[u8]) -> Signed<T> {
    let mut s = Signed { body, signatures: vec![] };
    for &n in keys {
        key(n).cosign(label, &mut s);
    }
    s
}

pub fn enclave_manifest() -> ReleaseManifest {
    ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement: ENCLAVE,
        service_key_version: SERVICE_KEY_VERSION,
        version: "0.1.0".into(),
        source_commit: "0123abcd".into(),
        serves: None,
    }
}

pub fn versions(oldest: u32, current: u32) -> TenantKeyVersions {
    TenantKeyVersions { current: TenantKeyVersion(current), oldest_accepted: TenantKeyVersion(oldest) }
}

/// A tenant's root v1 (registrar-signed, admins 31 and 32, threshold 1) and one state, both logged.
pub struct Tenant {
    pub id: TenantId,
    pub root_id: TenantRootId,
    root: Signed<TenantRoot>,
    root_index: u64,
    state: SignedTenantState,
}

/// A dev log (3 witnesses, quorum 2) and the trust that goes with it.
pub struct World {
    pub log: DevLog,
    pub now: UnixTime,
    _dir: TempDir,
}

impl World {
    pub fn new() -> Self {
        let dir = TempDir::new();
        let log = DevLog::open(&dir.0.join("log"), [7; 32], 3, 2).unwrap();
        Self { log, now: wall(), _dir: dir }
    }

    fn at<R>(&mut self, t: UnixTime, f: impl FnOnce(&mut DevLog) -> R) -> R {
        self.log.set_clock_offset(t as i64 - wall() as i64);
        f(&mut self.log)
    }

    pub fn trust(&self) -> Trust {
        Trust {
            releases: ReleaseTrust {
                tlog: self.log.trust(),
                release_keys: RELEASE_KEYS.iter().map(|&n| key(n).public_key()).collect(),
                release_threshold: 2,
                required_auditor: None,
                time_lock_secs: TIME_LOCK,
            },
            tenants: TenantTrust {
                tlog: self.log.trust(),
                registrar_keys: REGISTRARS.iter().map(|&n| key(n).public_key()).collect(),
                registrar_threshold: 2,
            },
            guardians: BTreeMap::from([(PlatformId::Sim, guardian_key(ROOT))]),
        }
    }

    /// Serves `Sim`, runs on `Sim`.
    pub fn guardian_config(&self) -> GuardianConfig {
        GuardianConfig { platform: PlatformId::Sim, runs_on: PlatformId::Sim, trust: self.trust() }
    }

    /// The enclave's release: public since 15 days ago (past the time lock), fresh checkpoint
    /// a minute ago, signed by release keys 1 and 2.
    pub fn release(&mut self) -> ReleaseEvidence {
        let manifest = signed(RELEASE_LABEL, enclave_manifest(), &RELEASE_KEYS[..2]);
        let index = self.log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        let included_at = self.now - 15 * DAY;
        let included = self.at(included_at, |log| {
            log.checkpoint();
            log.prove(index)
        });
        let fresh_at = self.now - 60;
        let fresh = self.at(fresh_at, |log| log.checkpoint());
        ReleaseEvidence { manifest, included, fresh, auditor: None }
    }

    pub fn tenant(&mut self, name: &str, cosign_releases: bool, versions: TenantKeyVersions) -> Tenant {
        let id = TenantId::new(name).unwrap();
        let root = TenantRoot {
            tenant: id.clone(),
            version: 1,
            admin_keys: ADMINS.iter().map(|&n| AdminKey::Ed25519 { public_key: key(n).public_key() }).collect(),
            threshold: 1,
            cosign_releases,
        };
        let root = signed(TENANT_ROOT_LABEL, root, &REGISTRARS);
        let root_index = self.log.append(LogEntry::TenantRoot(root.body.clone())).unwrap();
        let state = TenantState {
            tenant: id.clone(),
            version: 1,
            root_version: 1,
            apps: Default::default(),
            producers: Default::default(),
            tenant_key_versions: versions,
            platforms: [PlatformId::Sim].into(),
            integrity: Default::default(),
            deployments: Default::default(),
            freshness_keys: Default::default(),
            telemetry_readers: Default::default(),
            issued_at: self.now - DAY,
            pending_window_secs: 0,
            app_networks: Default::default(),
        };
        let state = signed(TENANT_STATE_LABEL, state, &ADMINS[..1]);
        self.log.append_state(&state).unwrap();
        Tenant { id, root_id: root_id(&root.body), root, root_index, state }
    }

    /// The tenant's chain, state and the log's freshness statement from a minute ago.
    pub fn bundle(&mut self, tenant: &Tenant) -> TenantBundle {
        self.log.checkpoint();
        let proof = self.log.prove(tenant.root_index);
        let fresh_at = self.now - 60;
        let freshness = self.at(fresh_at, |log| log.freshness(&tenant.id).unwrap());
        TenantBundle {
            root_chain: vec![LoggedRoot { root: tenant.root.clone(), proof }],
            state: tenant.state.clone(),
            signals: vec![],
            ended_sessions: vec![],
            freshness: vec![freshness],
            wrap_keys: vec![],
            states: Vec::new(),
            checkpoint: None,
            anchors: Vec::new(),
        }
    }
}

/// A tenant admin's co-signature of the enclave release.
pub fn cosign(tenant: &TenantId) -> Signed<ReleaseCosign> {
    signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: tenant.clone(), measurement: ENCLAVE }, &ADMINS[..1])
}

pub fn master(root: [u8; 32]) -> PlatformMasterKey {
    PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes(root))
}

pub fn guardian_key(root: [u8; 32]) -> PublicKey {
    master(root).guardian_key().public_key()
}

/// The enclave's attestor: sim evidence for `ENCLAVE`.
#[cfg(feature = "sim")]
pub fn enclave_attestor() -> Arc<seal_tee::Attestor> {
    Arc::new(seal_tee::Attestor::Sim(seal_tee::sim::SimAttestor::new(ENCLAVE)))
}

/// A sim guardian for `config` whose root file holds `root`.
#[cfg(feature = "sim")]
pub async fn boot_guardian(config: GuardianConfig, root: [u8; 32], dir: &TempDir) -> Guardian {
    use seal_tee::sim::{SimAttestor, SystemClock};
    use seal_tee::{Attestor, Clock};

    let path = dir.0.join("guardian-root");
    std::fs::write(&path, root).unwrap();
    let components = GuardianComponents {
        key_source: KeySource::File(FileKeySource::new(path, GUARDIAN)),
        attestor: Attestor::Sim(SimAttestor::new(GUARDIAN)),
        clock: Clock::System(SystemClock::new(0)),
    };
    Guardian::boot(config, components).await.unwrap()
}

/// Serves `guardian` (plain HTTP) behind a TLS proxy.
pub async fn serve_guardian(guardian: Guardian) -> Proxy {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(seal_guardian::server::serve(Arc::new(guardian), listener));
    Proxy::start(addr).await
}

/// Serves `router` (plain HTTP) behind a TLS proxy.
pub async fn serve_router(router: axum::Router) -> Proxy {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Proxy::start(addr).await
}

/// Dials one address whatever the host.
struct FixedDialer(SocketAddr);

#[async_trait::async_trait]
impl Dialer for FixedDialer {
    async fn dial(&self, _host: &str, _port: u16) -> Result<BoxStream, NetError> {
        let stream = tokio::net::TcpStream::connect(self.0).await.map_err(|e| NetError::Connect {
            host: self.0.to_string(),
            port: self.0.port(),
            reason: e.to_string(),
        })?;
        Ok(Box::new(stream))
    }
}

/// The proxies' TLS identity: a deterministic CA and a leaf for both test hosts.
fn proxy_tls() -> seal_crypto::TlsKey {
    let keys = master([0x77; 32]).release_service(
        &TenantId::new("proxy").unwrap(),
        &TenantRootId([0; 32]),
        ServiceKeyVersion(1),
    );
    ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap().tls
}

fn proxy_names() -> Vec<String> {
    vec![GUARDIAN_HOST.to_string(), CONTROL_HOST.to_string()]
}

fn pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

/// An untrusted TLS-terminating proxy in front of a plain-TCP backend. Counts the connections
/// it forwards.
pub struct Proxy {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
}

impl Proxy {
    async fn start(backend: SocketAddr) -> Self {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let tls = proxy_tls();
        let names = proxy_names();
        let chain = vec![
            CertificateDer::from(tls.leaf_certificate_der(&names).unwrap()),
            CertificateDer::from(tls.ca_certificate_der(&names).unwrap()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.private_key_pkcs8_der().to_vec()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else { return };
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(backend).await else { return };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                });
            }
        });
        Self { addr, connections }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// An `HttpsClient` that reaches this proxy for any host and trusts the proxy's CA.
    pub fn https(&self) -> Arc<HttpsClient> {
        let ca = pem(&proxy_tls().ca_certificate_der(&proxy_names()).unwrap());
        let connector = BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(self.addr)), ca.as_bytes()).unwrap();
        Arc::new(HttpsClient::new(Arc::new(connector)))
    }

    pub fn guardian_client(&self, guardian_key: PublicKey) -> GuardianClient {
        GuardianClient::new(url::Url::parse(&format!("https://{GUARDIAN_HOST}/")).unwrap(), self.https(), guardian_key)
    }

    pub fn control_client(&self) -> Arc<ControlClient> {
        Arc::new(ControlClient::new(url::Url::parse(&format!("https://{CONTROL_HOST}/")).unwrap(), self.https(), None))
    }
}

/// An in-memory control plane: answers GETs from `documents` (by path, query included; 404
/// when absent) and records their `Authorization`, records every POST and answers
/// `post_status` (204 by default).
#[derive(Default)]
pub struct FakeControl {
    pub documents: Mutex<HashMap<String, Vec<u8>>>,
    pub authorizations: Mutex<Vec<(String, Option<String>)>>,
    pub posts: Mutex<Vec<(String, Vec<u8>)>>,
    pub post_status: Mutex<Option<u16>>,
}

impl FakeControl {
    pub fn put(&self, path: &str, document: &impl serde::Serialize) {
        self.documents.lock().unwrap().insert(path.to_string(), serde_json::to_vec(document).unwrap());
    }

    pub fn posts_to(&self, path: &str) -> Vec<serde_json::Value> {
        self.posts
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, body)| serde_json::from_slice(body).unwrap())
            .collect()
    }

    pub async fn serve(self: &Arc<Self>) -> Proxy {
        let router = axum::Router::new().fallback(fake_control).with_state(self.clone());
        serve_router(router).await
    }
}

async fn fake_control(State(control): State<Arc<FakeControl>>, request: Request) -> Response {
    let path = request.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
    let method = request.method().clone();
    let authorization = request.headers().get("authorization").map(|v| v.to_str().unwrap_or_default().to_string());
    let body = axum::body::to_bytes(request.into_body(), 1 << 20).await.unwrap_or_else(|_| Bytes::new());
    if method == Method::GET {
        control.authorizations.lock().unwrap().push((path.clone(), authorization));
        return match control.documents.lock().unwrap().get(&path) {
            Some(document) => (StatusCode::OK, document.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    control.posts.lock().unwrap().push((path, body.to_vec()));
    let status = control.post_status.lock().unwrap().unwrap_or(204);
    StatusCode::from_u16(status).unwrap().into_response()
}
