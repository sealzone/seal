// The in-test enclave the integration tests share, `include!`d by each (`fake_enclave.rs`):
// real sim evidence binding a real `TlsKey` chain and service keys, a release from
// the `dev` log, a guardian certificate from a test platform master key, and canned answers on
// every enclave route. The enclave side checks every proof the SDK sends (ticket, TLS key,
// purpose, app-key signature) and opens sealed uploads with the ingest key.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use seal::identity::AppKeyIdentity;
use seal::{Client, ClientError, ErrorCode, Session, Severity};
use seal_crypto::sign::SigningKey;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
use seal_proto::api::*;
use seal_proto::blob::Blob;
use seal_proto::codec::{canonical, labeled_digest};
use seal_proto::identity::{IdentityProof, ProofContext, ProofPurpose, WorkloadIdentity, PROOF_CONTEXT_LABEL};
use seal_proto::policy::SecretPolicy;
use seal_proto::release::{Component, LogEntry, ReleaseEvidence, ReleaseManifest, RELEASE_LABEL};
use seal_proto::session::{ConsumerTier, PlatformTier, SessionInfo};
use seal_proto::signed::{SigAlg, Signature, Signed};
use seal_proto::tunnel::{find_local_key, TunnelPreamble, ALPN, EXTEND_OK, MAGIC};
use seal_proto::{
    AppName, Bearer, Measurement, PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId, TrustedTime,
    UnixTime,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MEASUREMENT: Measurement = Measurement([0xe1; 48]);
const ROOT: TenantRootId = TenantRootId([6; 32]);
const NAMES: &[&str] = &["acme.enclave.seal.zone"];
const APP_KEY_SEED: [u8; 32] = [42; 32];

fn now() -> UnixTime {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}
fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}
fn master(seed: u8) -> PlatformMasterKey {
    PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([seed; 32]))
}
fn service_keys(master: &PlatformMasterKey) -> ServiceKeys {
    ServiceKeys::from_released(PlatformId::Sim, &master.release_service(&acme(), &ROOT, ServiceKeyVersion(1))).unwrap()
}
fn release_key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}
fn rng() -> seal_crypto::UnwrapErr<seal_crypto::SysRng> {
    seal_crypto::UnwrapErr(seal_crypto::SysRng)
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "sealzone-fake-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
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

/// How the fake enclave misbehaves when asked for its attestation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Attest {
    Honest,
    /// Evidence for another measurement than the release's (still binding the right keys).
    TamperedMeasurement,
    /// Binding and certificate for another key set than the one the TLS server presents.
    WrongTlsKey,
    /// A certificate nobody signed.
    UnsignedCertificate,
    /// No certificate field at all.
    NoCertificate,
    /// Attested 200 s ago.
    Stale,
    /// A certificate signed by another platform's guardian.
    ForeignGuardian,
}

/// What the fake enclave saw.
#[derive(Default)]
struct Seen {
    sealed: Vec<(Vec<u8>, SecretPolicy)>,
    sessions: Vec<SessionRequestSummary>,
    extends: Vec<String>,
    ends: Vec<String>,
    signals: Vec<(String, Severity)>,
    connects: Vec<(String, [u8; 32])>,
    /// Tunnel connections whose TLS handshake completed.
    tunnel_handshakes: usize,
    tunnel_extends: Vec<String>,
}

struct SessionRequestSummary {
    blob: String,
    endpoint_artifact: Option<String>,
}

struct Enclave {
    keys: ServiceKeys,
    /// Signs the attestation of `Attest::WrongTlsKey`.
    other_keys: ServiceKeys,
    master: PlatformMasterKey,
    release: ReleaseEvidence,
    attest: Mutex<Attest>,
    seen: Mutex<Seen>,
    /// Session tokens' lifetime from start.
    session_secs: Mutex<u64>,
    /// `/v1/sessions/extend` answers this instead of a token.
    extend_error: Mutex<Option<ErrorCode>>,
    /// `/v1/sessions/end` answers this (after recording the end).
    end_error: Mutex<Option<ErrorCode>>,
    /// `/v1/sessions` answers `Expired` for this blob.
    expired_blob: Mutex<Option<String>>,
    /// `/v1/sessions` returns this as `resealed`.
    resealed: Mutex<Option<String>>,
    tokens: AtomicU32,
}

struct Fixture {
    enclave: Arc<Enclave>,
    api: SocketAddr,
    trust: seal_verify::Trust,
    _dir: TempDir,
}

fn tls_config(keys: &ServiceKeys) -> Arc<rustls::ServerConfig> {
    let names: Vec<String> = NAMES.iter().map(|n| n.to_string()).collect();
    let chain = vec![
        CertificateDer::from(keys.tls.leaf_certificate_der(&names).unwrap()),
        CertificateDer::from(keys.tls.ca_certificate_der(&names).unwrap()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys.tls.private_key_pkcs8_der().to_vec()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec(), ALPN.to_vec()];
    Arc::new(config)
}

impl Fixture {
    async fn new() -> Self {
        let dir = TempDir::new();
        let mut log = seal_tlog::dev::DevLog::open(&dir.0.join("log"), [7; 32], 3, 2).unwrap();
        let manifest = ReleaseManifest {
            component: Component::Enclave,
            platform: PlatformId::Sim,
            measurement: MEASUREMENT,
            service_key_version: ServiceKeyVersion(1),
            version: "0.1.0".into(),
            source_commit: "0123abcd".into(),
            serves: None,
        };
        let mut signed = Signed { body: manifest, signatures: vec![] };
        for n in [1, 2] {
            release_key(n).cosign(RELEASE_LABEL, &mut signed);
        }
        let index = log.append(LogEntry::Release(signed.body.clone())).unwrap();
        let included = log.prove(index);
        let fresh = log.checkpoint();
        let release = ReleaseEvidence { manifest: signed, included, fresh, auditor: None };

        let master = master(8);
        let trust = seal_verify::Trust {
            releases: seal_verify::ReleaseTrust {
                tlog: log.trust(),
                release_keys: [1, 2, 3].iter().map(|&n| release_key(n).public_key()).collect(),
                release_threshold: 2,
                required_auditor: None,
                time_lock_secs: 0,
            },
            tenants: seal_verify::TenantTrust { tlog: log.trust(), registrar_keys: vec![], registrar_threshold: 1 },
            guardians: BTreeMap::from([(PlatformId::Sim, master.guardian_key().public_key())]),
        };

        let keys = service_keys(&master);
        let tls = tls_config(&keys);
        let api = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let enclave = Arc::new(Enclave {
            keys,
            other_keys: service_keys(&self::master(9)),
            master,
            release,
            attest: Mutex::new(Attest::Honest),
            seen: Mutex::default(),
            session_secs: Mutex::new(600),
            extend_error: Mutex::new(None),
            end_error: Mutex::new(None),
            expired_blob: Mutex::new(None),
            resealed: Mutex::new(None),
            tokens: AtomicU32::new(0),
        });
        let api_addr = api.local_addr().unwrap();
        tokio::spawn(serve(enclave.clone(), api, tls));
        Fixture { enclave, api: api_addr, trust, _dir: dir }
    }

    fn endpoint(&self) -> url::Url {
        format!("https://{}", self.api).parse().unwrap()
    }

    fn builder(&self) -> seal::ClientBuilder {
        Client::builder()
            .endpoints([self.endpoint()])
            .tenant(acme())
            .root_id(ROOT)
            .trust(self.trust.clone())
            .identity(Arc::new(AppKeyIdentity::from_seed(&APP_KEY_SEED)))
    }

    async fn client(&self) -> Client {
        self.builder().connect().await.unwrap()
    }

    async fn client_result(&self) -> Result<Client, ClientError> {
        self.builder().connect().await
    }

    fn attest(&self, mode: Attest) {
        *self.enclave.attest.lock().unwrap() = mode;
    }

    fn seen<R>(&self, f: impl FnOnce(&Seen) -> R) -> R {
        f(&self.enclave.seen.lock().unwrap())
    }

    /// A real blob for `to`, sealed to the fake's tenant wrap key.
    fn blob(&self, to: &str) -> String {
        let policy = SecretPolicy::new(to, [AppName::new("checkout").unwrap()]).unwrap();
        self.enclave.blob(b"sk-test", policy)
    }
}

impl Enclave {
    fn blob(&self, secret: &[u8], policy: SecretPolicy) -> String {
        let wrap = [self.master.tenant_wrap_key(&acme(), &ROOT, TenantKeyVersion(1)).body];
        let producer = WorkloadIdentity::AppKey { key_id: AppKeyIdentity::from_seed(&APP_KEY_SEED).key_id() };
        let sealer = seal_crypto::blob::BlobSealer::new(&wrap).unwrap();
        sealer.seal(secret, policy, producer, now(), &mut rng()).unwrap().to_string()
    }

    fn attestation(&self) -> serde_json::Value {
        let mode = *self.attest.lock().unwrap();
        let keys = if mode == Attest::WrongTlsKey { &self.other_keys } else { &self.keys };
        let binding = AttestationBinding {
            attested_at: if mode == Attest::Stale { now() - 200 } else { now() },
            service_key_version: ServiceKeyVersion(1),
            tls_spki_sha256: keys.tls.spki_sha256(),
            ingest_public_key: keys.ingest.public_key(),
            telemetry_public_keys: keys.telemetry_public_keys.clone(),
        };
        let measurement = if mode == Attest::TamperedMeasurement { Measurement([0xe2; 48]) } else { MEASUREMENT };
        let document = seal_attest::sim::Document {
            measurement,
            report_data: labeled_digest(ATTESTATION_BINDING_LABEL, &binding),
            tcb: Default::default(),
        };
        let mut certificate = keys.certificate.clone();
        match mode {
            Attest::UnsignedCertificate => certificate.signatures.clear(),
            Attest::ForeignGuardian => {
                certificate = master(3)
                    .guardian_key()
                    .sign_into(seal_proto::release::SERVICE_KEY_CERTIFICATE_LABEL, keys.certificate.body.clone())
            }
            _ => {}
        }
        let response = AttestationResponse {
            evidence: seal_proto::Evidence::Sim { document: seal_attest::sim::sign(&document) },
            binding,
            release: self.release.clone(),
            certificate,
        };
        let mut json = serde_json::to_value(&response).unwrap();
        if mode == Attest::NoCertificate {
            json.as_object_mut().unwrap().remove("certificate");
        }
        json
    }

    /// The enclave's side of `RequestAuthenticator` for app keys.
    fn check_proof(&self, ctx: &ProofContext, proof: &IdentityProof, purpose: ProofPurpose) -> Result<(), ApiError> {
        let denied = |m: &str| ApiError { code: ErrorCode::NotAllowed, message: m.into() };
        if ctx.tenant != acme() || ctx.tls_spki_sha256 != self.keys.tls.spki_sha256() || ctx.purpose != purpose {
            return Err(denied("context"));
        }
        self.keys.ticket.verify(&acme(), &ctx.ticket, &TrustedTime::exact(now())).map_err(|_| denied("ticket"))?;
        let IdentityProof::AppKey { key_id, signature } = proof else { return Err(denied("proof kind")) };
        let id = AppKeyIdentity::from_seed(&APP_KEY_SEED);
        let sig = Signature { signer: *key_id, alg: SigAlg::Ed25519 { sig: signature.clone() } };
        seal_crypto::sign::verify(&id.public_key(), PROOF_CONTEXT_LABEL, ctx, &sig).map_err(|_| denied("signature"))
    }

    fn token(&self) -> String {
        format!("sealtok_{}", self.tokens.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn route(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, ApiError> {
        let bad = |e: serde_json::Error| ApiError { code: ErrorCode::BadRequest, message: e.to_string() };
        match path {
            "/v1/tickets" => json(&self.keys.ticket.issue(&acme(), &TrustedTime::exact(now()), &mut rng())),
            "/v1/blobs" => {
                let request: SealRequest = serde_json::from_slice(body).map_err(bad)?;
                self.check_proof(&request.context, &request.proof, request.expected_purpose())?;
                let aad = canonical(&request.ingest_context());
                let opened = seal_crypto::hpke::open_ingest(
                    &self.keys.ingest,
                    &request.hpke_enc,
                    &request.sealed_payload,
                    &seal_crypto::hpke::ingest_info(&acme()),
                    &aad,
                )
                .map_err(|_| ApiError { code: ErrorCode::BadRequest, message: "open".into() })?;
                let payload: SealPayload = seal_proto::codec::from_canonical(opened.expose()).unwrap();
                let blob = self.blob(payload.secret.expose(), payload.policy.clone());
                self.seen.lock().unwrap().sealed.push((payload.secret.expose().to_vec(), payload.policy));
                let blob_id = blob.parse::<Blob>().unwrap().header.blob_id;
                json(&SealResponse { blob, blob_id, telemetry: TelemetryReceipt { stream: [1; 16], entry: 1 } })
            }
            "/v1/sessions" => {
                let request: SessionRequest = serde_json::from_slice(body).map_err(bad)?;
                self.check_proof(&request.context, &request.proof, request.expected_purpose())?;
                self.seen.lock().unwrap().sessions.push(SessionRequestSummary {
                    blob: request.blob.clone(),
                    endpoint_artifact: request
                        .endpoint
                        .as_ref()
                        .and_then(|e| e.artifact.as_ref())
                        .map(|a| a.name.clone()),
                });
                if self.expired_blob.lock().unwrap().as_deref() == Some(request.blob.as_str()) {
                    return Err(ApiError { code: ErrorCode::Expired, message: "blob expired".into() });
                }
                let blob: Blob = request.blob.parse().unwrap();
                let entry = self.seen.lock().unwrap().sessions.len() as u64;
                let info = SessionInfo {
                    session_id: [3; 16],
                    platform: PlatformTier::Sim,
                    tier: ConsumerTier::Base,
                    tenant: acme(),
                    app: AppName::new("checkout").unwrap(),
                    blob_id: blob.header.blob_id,
                    expires_at: now() + *self.session_secs.lock().unwrap(),
                };
                json(&SessionResponse {
                    token: Bearer::new(self.token()),
                    info,
                    destination: blob.policy.destination().clone(),
                    resealed: self.resealed.lock().unwrap().clone(),
                    injection: blob.policy.injection().cloned(),
                    telemetry: TelemetryReceipt { stream: [2; 16], entry },
                })
            }
            "/v1/sessions/extend" => {
                let request: ExtendRequest = serde_json::from_slice(body).map_err(bad)?;
                self.check_proof(&request.context, &request.proof, request.expected_purpose())?;
                self.seen.lock().unwrap().extends.push(request.token.expose().to_string());
                if let Some(code) = *self.extend_error.lock().unwrap() {
                    return Err(ApiError { code, message: "ended".into() });
                }
                json(&ExtendResponse { token: Bearer::new(self.token()), expires_at: now() + 600 })
            }
            "/v1/sessions/end" => {
                let request: EndRequest = serde_json::from_slice(body).map_err(bad)?;
                self.seen.lock().unwrap().ends.push(request.token.expose().to_string());
                match *self.end_error.lock().unwrap() {
                    Some(code) => Err(ApiError { code, message: "post session end: control plane down".into() }),
                    None => Ok(Vec::new()),
                }
            }
            "/v1/signals" => {
                let request: SignalRequest = serde_json::from_slice(body).map_err(bad)?;
                let (context, proof) = match (&request.context, &request.proof) {
                    (Some(context), Some(proof)) => (context, proof),
                    _ => {
                        return Err(ApiError {
                            code: ErrorCode::BadRequest,
                            message: "a self-signal needs its proof".into(),
                        })
                    }
                };
                self.check_proof(context, proof, request.expected_purpose())?;
                self.seen.lock().unwrap().signals.push((request.code.clone(), request.severity));
                Ok(Vec::new())
            }
            _ => Err(ApiError { code: ErrorCode::BadRequest, message: "no such route".into() }),
        }
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ApiError> {
    Ok(serde_json::to_vec(value).unwrap())
}

/// The enclave's one port: tunnels (ALPN `seal_proto::tunnel::ALPN`) to `tunnel`, the rest to
/// the API. Its connections live in this task: aborting it closes them, as a replica stopping
/// does.
async fn serve(enclave: Arc<Enclave>, listener: TcpListener, tls: Arc<rustls::ServerConfig>) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let tcp = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((tcp, _)) => tcp,
                Err(_) => return,
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let (enclave, tls) = (enclave.clone(), tls.clone());
        connections.spawn(async move {
            let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
            let Ok(start) = acceptor.await else { return };
            let is_tunnel = start.client_hello().alpn().is_some_and(|mut a| a.any(|p| p == ALPN));
            let Ok(tls) = start.into_stream(tls).await else { return };
            if is_tunnel {
                enclave.seen.lock().unwrap().tunnel_handshakes += 1;
                return tunnel(enclave, tls).await;
            }
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let enclave = enclave.clone();
                async move {
                    let path = req.uri().path().to_string();
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    let (status, body) = if path == "/v1/attestation" {
                        (200, serde_json::to_vec(&enclave.attestation()).unwrap())
                    } else {
                        match enclave.route(&path, &body) {
                            Ok(b) => (200, b),
                            Err(e) => (e.code.http_status(), serde_json::to_vec(&e).unwrap()),
                        }
                    };
                    Ok::<_, hyper::Error>(
                        Response::builder().status(status).body(Full::new(Bytes::from(body))).unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await;
        });
    }
}

/// A tunnel: the preamble, then an HTTP responder that checks the local key against the
/// preamble's hash on every request.
async fn tunnel(enclave: Arc<Enclave>, mut tls: tokio_rustls::server::TlsStream<TcpStream>) {
    let mut head = [0u8; 12];
    if tls.read_exact(&mut head).await.is_err() || &head[..8] != MAGIC {
        return;
    }
    let mut body = vec![0u8; u32::from_be_bytes(head[8..].try_into().unwrap()) as usize];
    tls.read_exact(&mut body).await.unwrap();
    let (token, local_key_sha256) = match seal_proto::codec::from_canonical(&body).unwrap() {
        TunnelPreamble::Extend { token } => {
            enclave.seen.lock().unwrap().tunnel_extends.push(token.expose().to_string());
            let _ = tls.write_all(&[EXTEND_OK]).await;
            let _ = tls.shutdown().await;
            return;
        }
        TunnelPreamble::Connect(c) => (c.token.expose().to_string(), c.local_key_sha256),
    };
    enclave.seen.lock().unwrap().connects.push((token.clone(), local_key_sha256));
    let mut buf = Vec::new();
    loop {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut chunk = [0u8; 4096];
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let request = String::from_utf8_lossy(&buf[..end]).to_string();
        buf.drain(..end);
        let ok = request.lines().any(|line| {
            find_local_key(line).is_some_and(|k| <[u8; 32]>::from(Sha256::digest(k.as_bytes())) == local_key_sha256)
        });
        let (status, reply) = if ok { ("200 OK", format!("via {token}")) } else { ("401 Unauthorized", String::new()) };
        let response = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\n\r\n{reply}", reply.len());
        if tls.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// The tunnel's loopback address, from a session's URL.
fn tunnel_addr(url: &str) -> SocketAddr {
    let url = url::Url::parse(url).unwrap();
    assert_eq!(url.scheme(), "http");
    format!("{}:{}", url.host_str().unwrap(), url.port().unwrap()).parse().unwrap()
}

/// One HTTP/1.1 request on an open app connection; returns status line and body.
async fn http(conn: &mut TcpStream, path: &str, key: &str) -> (String, String) {
    let request = format!("GET {path} HTTP/1.1\r\nhost: app\r\nx-api-key: {key}\r\n\r\n");
    conn.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = conn.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed");
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len: usize =
                text.lines().find_map(|l| l.strip_prefix("content-length: ")).map_or(0, |l| l.trim().parse().unwrap());
            if text.len() >= end + 4 + len {
                return (text.lines().next().unwrap().to_string(), text[end + 4..end + 4 + len].to_string());
            }
        }
    }
}

async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}
