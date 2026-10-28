//! Test fixtures: real tenant bundles verified by `seal-verify`, keys, blobs, and a local
//! HTTPS server that answers for any host name (a test CA the client trusts as a sim build).
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use seal_crypto::sign::SigningKey;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
use seal_proto::blob::Blob;
use seal_proto::identity::{AuthenticationScope, IdentityMatcher, ProofAssurance, WorkloadIdentity};
use seal_proto::integrity::{IntegritySignal, SIGNAL_LABEL};
use seal_proto::policy::SecretPolicy;
use seal_proto::release::LogEntry;
use seal_proto::session::ConsumerTier;
use seal_proto::session::{SessionEnd, SESSION_END_LABEL};
use seal_proto::signed::Signed;
use seal_proto::state::{
    AdminKey, LoggedRoot, TenantBundle, TenantKeyVersions, TenantRoot, TenantState, TENANT_ROOT_LABEL,
    TENANT_STATE_LABEL,
};
use seal_proto::{
    AppName, PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId, TrustedTime, UnixTime,
};
use seal_tlog::dev::DevLog;
use seal_verify::{TenantTrust, TenantVerifier, VerifiedTenant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::AuthenticatedCaller;

/// Base time of every fixture.
pub const T: UnixTime = 1_900_000_000;
const REGISTRAR: u8 = 21;
const TELEMETRY: u8 = 50;

pub fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}
pub fn other_tenant() -> TenantId {
    TenantId::new("bravo").unwrap()
}
pub fn app(name: &str) -> AppName {
    AppName::new(name).unwrap()
}
pub fn at(t: UnixTime) -> TrustedTime {
    TrustedTime::exact(t)
}
pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}
pub fn rng() -> impl seal_crypto::CryptoRng {
    seal_crypto::UnwrapErr(seal_crypto::SysRng)
}

/// The app-key matcher and identity of `key(n)`.
pub fn app_key(n: u8) -> (IdentityMatcher, WorkloadIdentity) {
    let k = key(n);
    (
        IdentityMatcher::AppKey { key_id: k.key_id(), public_key: k.public_key() },
        WorkloadIdentity::AppKey { key_id: k.key_id() },
    )
}

/// A caller authenticated against `matched` (request-bound, no expiry unless given).
pub fn caller(
    identity: WorkloadIdentity,
    matched: &[IdentityMatcher],
    expires_at: Option<UnixTime>,
) -> AuthenticatedCaller {
    AuthenticatedCaller {
        identity,
        scope: AuthenticationScope {
            matched_grants: matched.to_vec(),
            expires_at,
            assurance: ProofAssurance::RequestBound,
        },
    }
}

pub fn service_keys() -> ServiceKeys {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([7; 32]));
    let released = master.release_service(&acme(), &TenantRootId([1; 32]), ServiceKeyVersion(1));
    ServiceKeys::from_released(PlatformId::Sim, &released).unwrap()
}

pub fn master() -> PlatformMasterKey {
    PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([8; 32]))
}

/// A blob for `apps` sealed by `producer` under `root_id` and tenant key version `v`.
pub fn blob(
    root_id: &TenantRootId,
    v: u32,
    producer: WorkloadIdentity,
    apps: &[&str],
    expires_at: Option<UnixTime>,
) -> Blob {
    let wrap = master().tenant_wrap_key(&acme(), root_id, TenantKeyVersion(v)).body;
    let recipients = [wrap];
    let sealer = seal_crypto::blob::BlobSealer::new(&recipients).unwrap();
    let mut policy = SecretPolicy::new("https://api.example.com/v1", apps.iter().map(|a| app(a))).unwrap();
    if let Some(e) = expires_at {
        policy = policy.with_expiry(e);
    }
    sealer.seal(b"sk-test", policy, producer, T, &mut rng()).unwrap()
}

/// `blob` with `min_tier` in the sealed policy (the `--hardened-only` floor).
pub fn hardened_blob(
    root_id: &TenantRootId,
    v: u32,
    producer: WorkloadIdentity,
    apps: &[&str],
    min_tier: ConsumerTier,
) -> Blob {
    let wrap = master().tenant_wrap_key(&acme(), root_id, TenantKeyVersion(v)).body;
    let recipients = [wrap];
    let sealer = seal_crypto::blob::BlobSealer::new(&recipients).unwrap();
    let policy =
        SecretPolicy::new("https://api.example.com/v1", apps.iter().map(|a| app(a))).unwrap().with_min_tier(min_tier);
    sealer.seal(b"sk-test", policy, producer, T, &mut rng()).unwrap()
}

pub fn open(blob: &Blob) -> seal_crypto::blob::OpenedBlob {
    let h = &blob.header;
    let key = master().tenant_wrapping_key(&h.tenant, &h.root_id, h.tenant_key_version);
    seal_crypto::blob::BlobCipher::new(&key).open(blob).unwrap()
}

pub fn base_state(version: u64) -> TenantState {
    TenantState {
        tenant: acme(),
        version,
        root_version: 1,
        apps: Default::default(),
        producers: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(1), oldest_accepted: TenantKeyVersion(1) },
        platforms: [PlatformId::Sim].into(),
        integrity: Default::default(),
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: T,
        pending_window_secs: 0,
        app_networks: Default::default(),
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("seal-authz-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn signed<B: serde::Serialize>(label: &str, body: B, n: u8) -> Signed<B> {
    let mut s = Signed { body, signatures: vec![] };
    key(n).cosign(label, &mut s);
    s
}

/// One tenant's root chain in a dev log; each `verified` call logs a newer state.
pub struct Fixture {
    log: DevLog,
    _dir: TempDir,
    v1: Signed<TenantRoot>,
    root_index: u64,
    admin: u8,
}

impl Fixture {
    /// A root v1 with the single admin `key(admin)`; different admins give different root ids.
    pub fn new(admin: u8) -> Self {
        let dir = TempDir::new();
        let mut log = DevLog::open(&dir.0, [admin; 32], 1, 1).unwrap();
        let root = TenantRoot {
            tenant: acme(),
            version: 1,
            admin_keys: [AdminKey::Ed25519 { public_key: key(admin).public_key() }].into(),
            threshold: 1,
            cosign_releases: false,
        };
        let v1 = signed(TENANT_ROOT_LABEL, root, REGISTRAR);
        let root_index = log.append(LogEntry::TenantRoot(v1.body.clone())).unwrap();
        Self { log, _dir: dir, v1, root_index, admin }
    }

    pub fn root_id(&self) -> TenantRootId {
        seal_proto::state::root_id(&self.v1.body)
    }

    fn wall() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    /// Logs `state` (eight days before `T`, past every pending window, and fresh from `T`) and
    /// verifies a bundle of it with `signals` and `ends`, signed by the telemetry key the
    /// verifier trusts.
    pub fn verified(&mut self, state: TenantState, signals: &[IntegritySignal], ends: &[SessionEnd]) -> VerifiedTenant {
        let state = signed(TENANT_STATE_LABEL, state, self.admin);
        self.log.set_clock_offset(T as i64 - 8 * 86_400 - Self::wall());
        let logged = self.log.append_logged_state(&state).unwrap();
        let root_proof = self.log.prove(self.root_index);
        let freshness = loop {
            self.log.set_clock_offset(T as i64 - Self::wall());
            let f = self.log.freshness(&acme()).unwrap();
            if f.body.signed_at == T {
                break f;
            }
        };
        let bundle = TenantBundle {
            root_chain: vec![LoggedRoot { root: self.v1.clone(), proof: root_proof }],
            state,
            signals: signals.iter().map(|s| signed(SIGNAL_LABEL, s.clone(), TELEMETRY)).collect(),
            ended_sessions: ends.iter().map(|e| signed(SESSION_END_LABEL, e.clone(), TELEMETRY)).collect(),
            freshness: vec![freshness],
            wrap_keys: vec![],
            states: vec![logged],
            checkpoint: Some(self.log.checkpoint()),
            anchors: Vec::new(),
        };
        let trust = TenantTrust {
            tlog: self.log.trust(),
            registrar_keys: vec![key(REGISTRAR).public_key()],
            registrar_threshold: 1,
        };
        TenantVerifier::new(trust, vec![key(TELEMETRY).public_key()]).verify(&acme(), &bundle, &at(T)).unwrap()
    }
}

/// A verified tenant with `state` in a fresh chain.
pub fn verified(state: TenantState) -> VerifiedTenant {
    Fixture::new(31).verified(state, &[], &[])
}

// ---- Local HTTPS ----

mod pki {
    use p256::ecdsa::{DerSignature, SigningKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder, CertificateBuilder};
    use x509_cert::certificate::TbsCertificate;
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::der::Encode;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoRef;
    use x509_cert::time::{Time, Validity};
    use x509_cert::SubjectPublicKeyInfo;

    const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

    struct Profile {
        issuer: Name,
        subject: Name,
        ca: bool,
        sans: Vec<GeneralName>,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _spk: SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let subject = tbs.subject();
            let mut exts =
                vec![(&BasicConstraints { ca: self.ca, path_len_constraint: None }).to_extension(subject, &[])?];
            let usage =
                if self.ca { KeyUsages::KeyCertSign | KeyUsages::CRLSign } else { KeyUsages::DigitalSignature.into() };
            exts.push((&KeyUsage(usage)).to_extension(subject, &[])?);
            if !self.ca {
                exts.push((&ExtendedKeyUsage(vec![SERVER_AUTH])).to_extension(subject, &[])?);
                exts.push((&SubjectAltName(self.sans.clone())).to_extension(subject, &[])?);
            }
            Ok(exts)
        }
    }

    fn key(label: &str) -> SigningKey {
        SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap()
    }

    fn build(profile: Profile, serial: u32, subject_key: &SigningKey, signer: &SigningKey) -> CertificateDer<'static> {
        let now = SystemTime::now();
        let day = Duration::from_secs(86_400);
        let validity = Validity::new(Time::try_from(now - day).unwrap(), Time::try_from(now + day).unwrap());
        let spki = SubjectPublicKeyInfo::from_key(subject_key.verifying_key()).unwrap();
        let builder = CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki).unwrap();
        let cert = builder.build::<_, DerSignature>(signer).unwrap();
        CertificateDer::from(cert.to_der().unwrap())
    }

    /// A root CA (as PEM) and a leaf for `hosts` with its key.
    pub fn issue(hosts: &[&str]) -> (String, CertificateDer<'static>, PrivateKeyDer<'static>) {
        use p256::pkcs8::EncodePrivateKey;
        use x509_cert::der::{pem::LineEnding, Decode, EncodePem};
        let root_name = Name::from_str("CN=Seal authz test root,O=Seal Test,C=US").unwrap();
        let root_key = key("authz-root");
        let root = build(
            Profile { issuer: root_name.clone(), subject: root_name.clone(), ca: true, sans: vec![] },
            1,
            &root_key,
            &root_key,
        );
        let leaf_key = key("authz-leaf");
        let sans = hosts.iter().map(|h| GeneralName::DnsName(Ia5String::new(h).unwrap())).collect();
        let leaf = build(
            Profile { issuer: root_name, subject: Name::from_str("CN=authz-leaf").unwrap(), ca: false, sans },
            2,
            &leaf_key,
            &root_key,
        );
        let pem = x509_cert::Certificate::from_der(root.as_ref()).unwrap().to_pem(LineEnding::LF).unwrap();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec()));
        (pem, leaf, key_der)
    }
}

/// Hosts the test server holds a certificate for.
pub const HOSTS: &[&str] = &[
    "login.microsoftonline.com",
    "token.actions.githubusercontent.com",
    "accounts.google.com",
    "www.googleapis.com",
    "k8s.example.com",
    "sts.amazonaws.com",
    "sts.us-east-1.amazonaws.com",
];

/// One request the server saw.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub host: String,
    /// Path and query.
    pub target: String,
    /// Lowercase names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Recorded responses by (host, path without query); everything else is a 404.
#[derive(Clone, Default)]
pub struct Routes(Arc<Mutex<HashMap<(String, String), Response>>>);

/// Status and body.
type Response = (u16, Vec<u8>);

impl Routes {
    pub fn set(&self, host: &str, path: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.0.lock().unwrap().insert((host.into(), path.into()), (status, body.into()));
    }
}

pub struct Server {
    pub routes: Routes,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub https: Arc<seal_net::HttpsClient>,
}

impl Server {
    /// Requests seen for `host`.
    pub fn seen_for(&self, host: &str) -> Vec<Seen> {
        self.seen.lock().unwrap().iter().filter(|s| s.host == host).cloned().collect()
    }
    pub fn requests(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

struct FixedDialer(SocketAddr);

#[async_trait::async_trait]
impl seal_net::Dialer for FixedDialer {
    async fn dial(&self, _host: &str, _port: u16) -> Result<seal_net::BoxStream, seal_net::NetError> {
        seal_net::TcpDialer.dial(&self.0.ip().to_string(), self.0.port()).await
    }
}

async fn read_request(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<Seen> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.ok()?;
        head.push(byte[0]);
    }
    let text = String::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let len = headers.iter().find(|(n, _)| n == "content-length").map_or(0, |(_, v)| v.parse().unwrap());
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.ok()?;
    let host = headers.iter().find(|(n, _)| n == "host").map(|(_, v)| v.clone()).unwrap_or_default();
    Some(Seen { method, host, target, headers, body })
}

/// Serves `HOSTS` on a loopback port; `https` trusts the test root on top of the baked roots.
pub async fn server() -> Server {
    let (root_pem, leaf, key) = pki::issue(HOSTS);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Routes::default();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (r, s) = (routes.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (acceptor, routes, seen) = (acceptor.clone(), r.clone(), s.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let Some(req) = read_request(&mut tls).await else { return };
                let path = req.target.split('?').next().unwrap_or_default().to_string();
                let (status, body) =
                    routes.0.lock().unwrap().get(&(req.host.clone(), path)).cloned().unwrap_or((404, b"{}".to_vec()));
                seen.lock().unwrap().push(req);
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    let connector =
        seal_net::BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(addr)), root_pem.as_bytes()).unwrap();
    Server { routes, seen, https: Arc::new(seal_net::HttpsClient::new(Arc::new(connector))) }
}

/// A blob's text form.
pub fn blob_text(blob: &Blob) -> String {
    let text = blob.to_string();
    assert_eq!(&Blob::from_str(&text).unwrap(), blob);
    text
}
