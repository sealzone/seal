//! Fixtures: real keys, a `DevLog` with real proofs for release evidence and tenant bundles,
//! times relative to the wall clock (the guardian's sim clock is the system clock).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use seal_crypto::sign::SigningKey;
use seal_guardian::GuardianConfig;
use seal_proto::codec::labeled_digest;
use seal_proto::freshness::GuardianChallenge;
use seal_proto::release::{
    Component, KeyPurpose, KeyRequest, KeyRequestBinding, LogEntry, ReleaseConstraints, ReleaseCosign, ReleaseEvidence,
    ReleaseManifest, GUARDIAN_PROTOCOL_VERSION, KEY_REQUEST_BINDING_LABEL, RELEASE_COSIGN_LABEL, RELEASE_LABEL,
};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, LoggedState, SignedTenantState, TenantBundle, TenantKeyVersions, TenantRoot,
    TenantState, TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::{
    Evidence, Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId, UnixTime,
};
use seal_tlog::dev::DevLog;
use seal_verify::{ReleaseTrust, TenantTrust, Trust};

pub const DAY: u64 = 86_400;
pub const TIME_LOCK: u64 = 14 * DAY;
pub const RELEASE_KEYS: [u8; 3] = [1, 2, 3];
pub const REGISTRARS: [u8; 2] = [21, 22];
pub const ADMINS: [u8; 2] = [31, 32];

pub const ENCLAVE: Measurement = Measurement([0xe1; 48]);
pub const GUARDIAN_OLD: Measurement = Measurement([0x91; 48]);
pub const GUARDIAN_NEW: Measurement = Measurement([0x92; 48]);

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

pub fn wall() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}

pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-guardian-{}-{n}", std::process::id()));
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

pub fn enclave_manifest(measurement: Measurement) -> ReleaseManifest {
    ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement,
        service_key_version: ServiceKeyVersion(2),
        version: "0.1.0".into(),
        source_commit: "0123abcd".into(),
        serves: None,
    }
}

pub fn guardian_manifest(measurement: Measurement, serves: Option<PlatformId>) -> ReleaseManifest {
    ReleaseManifest { component: Component::Guardian, serves, ..enclave_manifest(measurement) }
}

/// A tenant with root v1 (registrar-signed, admins 31 and 32, threshold 1) and one state, both logged.
pub struct Tenant {
    pub id: TenantId,
    pub root_id: TenantRootId,
    root: Signed<TenantRoot>,
    root_index: u64,
    state: SignedTenantState,
    states: Vec<LoggedState>,
}

/// A dev log (3 witnesses, quorum 2) and the trust that goes with it.
pub struct World {
    pub log: DevLog,
    /// The wall clock when the world was made; fixture times are relative to it.
    pub now: UnixTime,
    _dir: TempDir,
}

impl World {
    pub fn new() -> Self {
        let dir = TempDir::new();
        let log = DevLog::open(&dir.0.join("log"), [7; 32], 3, 2).unwrap();
        Self { log, now: wall(), _dir: dir }
    }

    /// Runs `f` with the log's clock (witness and freshness timestamps) at about `t`.
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
            guardians: BTreeMap::new(),
        }
    }

    /// Serves `Sim`, runs on `Sim`.
    pub fn config(&self) -> GuardianConfig {
        GuardianConfig { platform: PlatformId::Sim, runs_on: PlatformId::Sim, trust: self.trust() }
    }

    pub fn set_policy(&mut self, policy: ReleaseConstraints) {
        self.log.set_policy(policy).unwrap();
    }

    /// Public since 15 days ago (past the time lock), fresh checkpoint a minute ago.
    pub fn release(&mut self, manifest: ReleaseManifest) -> ReleaseEvidence {
        let now = self.now;
        self.release_at(manifest, now - 15 * DAY, now - 60)
    }

    /// Signed by release keys 1 and 2, included in a checkpoint the witnesses stamped at
    /// `included_at`, with a fresh checkpoint stamped at `fresh_at`.
    pub fn release_at(
        &mut self,
        manifest: ReleaseManifest,
        included_at: UnixTime,
        fresh_at: UnixTime,
    ) -> ReleaseEvidence {
        let manifest = signed(RELEASE_LABEL, manifest, &RELEASE_KEYS[..2]);
        let index = self.log.append(LogEntry::Release(manifest.body.clone())).unwrap();
        let included = self.at(included_at, |log| {
            log.checkpoint();
            log.prove(index)
        });
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
            tenant_key_versions: versions,
            platforms: [PlatformId::Sim].into(),
            integrity: Default::default(),
            deployments: Default::default(),
            freshness_keys: Default::default(),
            telemetry_readers: Default::default(),
            issued_at: self.now - DAY,
            pending_window_secs: 0,
            app_networks: Default::default(),
            freshness_secs: None,
        };
        let state = signed(TENANT_STATE_LABEL, state, &ADMINS[..1]);
        let issued = self.now - DAY;
        let logged = self.at(issued, |log| log.append_logged_state(&state).unwrap());
        Tenant { id, root_id: root_id(&root.body), root, root_index, state, states: vec![logged] }
    }

    /// Logs the tenant's next state, `edit`ed from its latest, public at about `at`.
    pub fn publish(&mut self, tenant: &mut Tenant, at: UnixTime, edit: impl FnOnce(&mut TenantState)) {
        let mut next = tenant.state.body.clone();
        next.version += 1;
        next.issued_at = at;
        edit(&mut next);
        let state = signed(TENANT_STATE_LABEL, next, &ADMINS[..1]);
        let logged = self.at(at, |log| log.append_logged_state(&state).unwrap());
        tenant.states.push(logged);
        tenant.state = state;
    }

    /// The tenant's chain, states, the log's freshness statement for the latest signed at
    /// `fresh_at`, and a checkpoint witnessed then.
    pub fn bundle_at(&mut self, tenant: &Tenant, fresh_at: UnixTime) -> TenantBundle {
        self.log.checkpoint();
        let proof = self.log.prove(tenant.root_index);
        let freshness = self.at(fresh_at, |log| log.freshness(&tenant.id).unwrap());
        let checkpoint = self.at(fresh_at, |log| log.checkpoint());
        TenantBundle {
            root_chain: vec![LoggedRoot { root: tenant.root.clone(), proof }],
            state: tenant.state.clone(),
            signals: vec![],
            ended_sessions: vec![],
            freshness: vec![freshness],
            wrap_keys: vec![],
            states: tenant.states.clone(),
            checkpoint: Some(checkpoint),
            anchors: Vec::new(),
        }
    }

    /// Fresh as of a minute ago.
    pub fn bundle(&mut self, tenant: &Tenant) -> TenantBundle {
        let at = self.now - 60;
        self.bundle_at(tenant, at)
    }
}

pub fn versions(oldest: u32, current: u32) -> TenantKeyVersions {
    TenantKeyVersions { current: TenantKeyVersion(current), oldest_accepted: TenantKeyVersion(oldest) }
}

/// A tenant admin's (`signer`) co-signature of `measurement` for `tenant`.
pub fn cosign(tenant: &TenantId, measurement: Measurement, signer: u8) -> Signed<ReleaseCosign> {
    signed(RELEASE_COSIGN_LABEL, ReleaseCosign { tenant: tenant.clone(), measurement }, &[signer])
}

pub fn binding(challenge: GuardianChallenge, ephemeral: PublicKey, purpose: KeyPurpose) -> KeyRequestBinding {
    KeyRequestBinding {
        protocol_version: GUARDIAN_PROTOCOL_VERSION,
        challenge,
        ephemeral_public_key: ephemeral,
        purpose,
    }
}

pub fn report_data(binding: &KeyRequestBinding) -> [u8; 32] {
    labeled_digest(KEY_REQUEST_BINDING_LABEL, binding)
}

pub fn request(
    evidence: Evidence,
    binding: KeyRequestBinding,
    release: ReleaseEvidence,
    tenant: Option<TenantBundle>,
) -> KeyRequest {
    KeyRequest { protocol_version: GUARDIAN_PROTOCOL_VERSION, evidence, binding, release, tenant, tenant_cosign: None }
}

pub fn service(tenant: &Tenant) -> KeyPurpose {
    KeyPurpose::Service { tenant: tenant.id.clone(), root_id: tenant.root_id }
}

pub fn tenant_keys(tenant: &Tenant, versions: &[u32]) -> KeyPurpose {
    KeyPurpose::Tenant {
        tenant: tenant.id.clone(),
        root_id: tenant.root_id,
        tenant_key_versions: versions.iter().map(|&v| TenantKeyVersion(v)).collect(),
    }
}

/// Sim-only fixtures: guardians booted from a root file, requesters with sim evidence, and a
/// TLS-terminating proxy for the plain-HTTP server.
#[cfg(feature = "sim")]
pub mod sim {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use base64::Engine as _;
    use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
    use seal_guardian::client::GuardianClient;
    use seal_guardian::keysource::FileKeySource;
    use seal_guardian::{Guardian, GuardianComponents, GuardianConfig, KeySource};
    use seal_net::{BakedRootsConnector, BoxStream, Dialer, HttpsClient, NetError};
    use seal_proto::{Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantRootId};
    use seal_tee::sim::{SimAttestor, SystemClock};
    use seal_tee::{Attestor, Clock};

    use super::TempDir;

    pub const ROOT: [u8; 32] = [0x5e; 32];
    pub const HOST: &str = "guardian.test";

    pub fn attestor(measurement: Measurement) -> Attestor {
        Attestor::Sim(SimAttestor::new(measurement))
    }

    pub fn master(root: [u8; 32]) -> PlatformMasterKey {
        PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes(root))
    }

    pub fn guardian_key(root: [u8; 32]) -> PublicKey {
        master(root).guardian_key().public_key()
    }

    /// A guardian measuring `measurement` whose root file holds `root`.
    pub async fn boot(config: GuardianConfig, root: [u8; 32], measurement: Measurement, dir: &TempDir) -> Guardian {
        let path = dir.0.join(format!("root-{}", super::wall_nanos()));
        std::fs::write(&path, root).unwrap();
        let components = GuardianComponents {
            key_source: KeySource::File(FileKeySource::new(path, measurement)),
            attestor: attestor(measurement),
            clock: Clock::System(SystemClock::new(0)),
        };
        Guardian::boot(config, components).await.unwrap()
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

    /// The proxy's TLS identity: a deterministic CA and a leaf for `HOST`.
    fn proxy_tls() -> seal_crypto::TlsKey {
        let keys = master([0x77; 32]).release_service(
            &TenantId::new("proxy").unwrap(),
            &TenantRootId([0; 32]),
            ServiceKeyVersion(1),
        );
        ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap().tls
    }

    fn pem(der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
    }

    /// An untrusted TLS-terminating proxy in front of `backend` (plain TCP): returns its address.
    pub async fn tls_proxy(backend: SocketAddr) -> SocketAddr {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let tls = proxy_tls();
        let names = vec![HOST.to_string()];
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
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else { return };
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(backend).await else { return };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                });
            }
        });
        addr
    }

    /// An `HttpsClient` that reaches `proxy` for any host and trusts the proxy's CA.
    pub fn https(proxy: SocketAddr) -> Arc<HttpsClient> {
        let tls = proxy_tls();
        let ca = pem(&tls.ca_certificate_der(&[HOST.to_string()]).unwrap());
        let connector = BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(proxy)), ca.as_bytes()).unwrap();
        Arc::new(HttpsClient::new(Arc::new(connector)))
    }

    pub fn client(proxy: SocketAddr, guardian_key: PublicKey) -> GuardianClient {
        GuardianClient::new(url::Url::parse(&format!("https://{HOST}/")).unwrap(), https(proxy), guardian_key)
    }

    /// Serves `guardian` on a local port behind a TLS proxy; returns the proxy's address.
    pub async fn serve(guardian: Guardian) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(seal_guardian::server::serve(Arc::new(guardian), listener));
        tls_proxy(addr).await
    }
}

pub fn wall_nanos() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}
