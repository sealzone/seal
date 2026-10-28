//! `GcpKmsKeySource` and `GcpKms::store` against fake STS, IAM Credentials and Cloud KMS
//! endpoints: one in-test TLS server answering for all three Google hosts under a test CA
//! (seal-net's `sim` extra roots), and attestation tokens from a fake `AttestationTokens`.
//! The `live_` test runs the same code against Google itself.
#![cfg(feature = "sim")]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use common::sim::{attestor, guardian_key};
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys, SysRng, UnwrapErr};
use seal_guardian::keysource::{
    root_aad, AttestationTokens, GcpKms, GcpKmsKeySource, KmsWrappedRoot, LauncherTokens, WorkloadIdentity,
};
use seal_guardian::{Guardian, GuardianComponents, GuardianError, KeySource};
use seal_net::{BakedRootsConnector, BoxStream, Dialer, HttpsClient, NetError};
use seal_proto::{PlatformId, ServiceKeyVersion, TenantId, TenantRootId};
use seal_tee::sim::SystemClock;
use seal_tee::{Attestor, Clock};
use serde_json::{json, Value};

const PROVIDER: &str = "projects/123/locations/global/workloadIdentityPools/seal-pool/providers/seal-cs";
const SA: &str = "guardian@seal-test.iam.gserviceaccount.com";
const KEY_A: &str = "projects/seal-test/locations/us-east4/keyRings/ring/cryptoKeys/root-a";
const KEY_B: &str = "projects/seal-test/locations/us-central1/keyRings/ring/cryptoKeys/root-b";
const HOSTS: [&str; 3] = ["sts.googleapis.com", "iamcredentials.googleapis.com", "cloudkms.googleapis.com"];
const FEDERATED: &str = "federated-token";
const IMPERSONATED: &str = "service-account-token";

/// The attestation token the fake launcher issues for `audience`.
fn attestation_token(audience: &str) -> String {
    format!("cs-token-for:{audience}")
}

struct FakeTokens;

#[async_trait::async_trait]
impl AttestationTokens for FakeTokens {
    async fn token(&self, _: &Attestor, audience: &str) -> Result<String, GuardianError> {
        Ok(attestation_token(audience))
    }
}

struct FailingTokens;

#[async_trait::async_trait]
impl AttestationTokens for FailingTokens {
    async fn token(&self, _: &Attestor, _: &str) -> Result<String, GuardianError> {
        Err(GuardianError::Root("launcher: no socket".into()))
    }
}

/// A Google API error body, as Cloud KMS and IAM Credentials write them.
fn api_error(code: u16, status: &str, message: &str) -> String {
    json!({"error": {"code": code, "message": message, "status": status}}).to_string()
}

/// An STS (OAuth) error body.
fn oauth_error(error: &str, description: &str) -> String {
    json!({"error": error, "error_description": description}).to_string()
}

/// What the fake Google does: real checks of each request, plus canned answers for requests
/// whose path contains a key of `overrides`.
#[derive(Default)]
struct State {
    /// Bearer token Cloud KMS accepts.
    kms_bearer: String,
    overrides: BTreeMap<String, (u16, String)>,
    /// ciphertext → (key, aad, plaintext).
    ciphertexts: HashMap<Vec<u8>, (String, String, Vec<u8>)>,
    /// `host path` of every request, in order.
    calls: Vec<String>,
}

#[derive(Clone)]
struct Google(Arc<Mutex<State>>);

impl Google {
    fn new(kms_bearer: &str) -> Self {
        Self(Arc::new(Mutex::new(State { kms_bearer: kms_bearer.into(), ..State::default() })))
    }
    fn answer(&self, path_contains: &str, status: u16, body: &str) {
        self.0.lock().unwrap().overrides.insert(path_contains.into(), (status, body.into()));
    }
    fn calls(&self) -> Vec<String> {
        self.0.lock().unwrap().calls.clone()
    }

    fn handle(&self, host: &str, path: &str, auth: Option<&str>, body: &[u8]) -> (u16, String) {
        let mut state = self.0.lock().unwrap();
        state.calls.push(format!("{host} {path}"));
        if let Some(answer) = state.overrides.iter().find(|(k, _)| path.contains(k.as_str())).map(|(_, v)| v.clone()) {
            return answer;
        }
        let (status, value) = state.answer(host, path, auth, body);
        (status, value.to_string())
    }
}

impl State {
    fn answer(&mut self, host: &str, path: &str, auth: Option<&str>, body: &[u8]) -> (u16, Value) {
        let Ok(req) = serde_json::from_slice::<Value>(body) else { return (400, json!({"error": "bad json"})) };
        let bearer = auth.and_then(|a| a.strip_prefix("Bearer "));
        let json = |body: String| serde_json::from_str::<Value>(&body).unwrap();
        let denied = || (403, json(api_error(403, "PERMISSION_DENIED", "Permission denied.")));
        match (host, path) {
            ("sts.googleapis.com", "/v1/token") => {
                let audience = format!("//iam.googleapis.com/{PROVIDER}");
                let ok = req["grantType"] == "urn:ietf:params:oauth:grant-type:token-exchange"
                    && req["audience"] == audience.as_str()
                    && req["scope"] == "https://www.googleapis.com/auth/cloud-platform"
                    && req["requestedTokenType"] == "urn:ietf:params:oauth:token-type:access_token"
                    && req["subjectTokenType"] == "urn:ietf:params:oauth:token-type:jwt"
                    && req["subjectToken"] == attestation_token(&audience).as_str()
                    && auth.is_none();
                if !ok {
                    return (400, json(oauth_error("invalid_grant", "bad subject token")));
                }
                let issued = "urn:ietf:params:oauth:token-type:access_token";
                let token = json!({"access_token": FEDERATED, "issued_token_type": issued, "token_type": "Bearer"});
                (200, token)
            }
            ("iamcredentials.googleapis.com", p)
                if p == format!("/v1/projects/-/serviceAccounts/{SA}:generateAccessToken") =>
            {
                if bearer != Some(FEDERATED)
                    || req["scope"] != json!(["https://www.googleapis.com/auth/cloud-platform"])
                {
                    return denied();
                }
                (200, json!({"accessToken": IMPERSONATED, "expireTime": "2030-01-01T00:00:00Z"}))
            }
            ("cloudkms.googleapis.com", p) => {
                if bearer != Some(self.kms_bearer.as_str()) {
                    return denied();
                }
                let aad = req["additionalAuthenticatedData"].as_str().unwrap_or_default().to_string();
                if let Some(key) = p.strip_prefix("/v1/").and_then(|p| p.strip_suffix(":encrypt")) {
                    let plaintext = STANDARD.decode(req["plaintext"].as_str().unwrap_or_default()).unwrap();
                    let ciphertext = Key32::generate(&mut UnwrapErr(SysRng)).expose().to_vec();
                    self.ciphertexts.insert(ciphertext.clone(), (key.to_string(), aad, plaintext));
                    let name = format!("{key}/cryptoKeyVersions/1");
                    return (200, json!({"name": name, "ciphertext": STANDARD.encode(ciphertext)}));
                }
                if let Some(key) = p.strip_prefix("/v1/").and_then(|p| p.strip_suffix(":decrypt")) {
                    let ciphertext =
                        STANDARD.decode(req["ciphertext"].as_str().unwrap_or_default()).unwrap_or_default();
                    return match self.ciphertexts.get(&ciphertext) {
                        Some((k, a, plaintext)) if k == key && *a == aad => {
                            (200, json!({"plaintext": STANDARD.encode(plaintext), "usedPrimary": true}))
                        }
                        _ => (400, json(api_error(400, "INVALID_ARGUMENT", "Decryption failed."))),
                    };
                }
                (404, json(api_error(404, "NOT_FOUND", "not found")))
            }
            _ => (404, json!({"error": "not found"})),
        }
    }
}

/// The fake's TLS identity: a deterministic CA and one leaf naming all three Google hosts.
fn google_tls() -> seal_crypto::TlsKey {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([0x60; 32]));
    let keys = master.release_service(&TenantId::new("google").unwrap(), &TenantRootId([0; 32]), ServiceKeyVersion(1));
    ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap().tls
}

fn names() -> Vec<String> {
    HOSTS.iter().map(|h| h.to_string()).collect()
}

async fn serve(google: Google) -> SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let tls = google_tls();
    let chain = vec![
        CertificateDer::from(tls.leaf_certificate_der(&names()).unwrap()),
        CertificateDer::from(tls.ca_certificate_der(&names()).unwrap()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.private_key_pkcs8_der().to_vec()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let (acceptor, google) = (acceptor.clone(), google.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else { return };
                let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let google = google.clone();
                    async move {
                        let host =
                            req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
                        let auth = req.headers().get("authorization").and_then(|h| h.to_str().ok()).map(str::to_owned);
                        let path = req.uri().path().to_string();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let (status, body) = google.handle(&host, &path, auth.as_deref(), &body);
                        let resp =
                            hyper::Response::builder().status(status).body(Full::new(Bytes::from(body))).unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    addr
}

/// Dials `addr` whatever the host, so the real Google URLs reach the fake.
struct FixedDialer(SocketAddr);

#[async_trait::async_trait]
impl Dialer for FixedDialer {
    async fn dial(&self, _: &str, _: u16) -> Result<BoxStream, NetError> {
        let stream = tokio::net::TcpStream::connect(self.0).await.map_err(|e| NetError::Connect {
            host: self.0.to_string(),
            port: self.0.port(),
            reason: e.to_string(),
        })?;
        Ok(Box::new(stream))
    }
}

fn https(addr: SocketAddr) -> Arc<HttpsClient> {
    let der = google_tls().ca_certificate_der(&names()).unwrap();
    let b64 = STANDARD.encode(der);
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"));
    let connector = BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(addr)), pem.as_bytes()).unwrap();
    Arc::new(HttpsClient::new(Arc::new(connector)))
}

fn identity(service_account: Option<&str>) -> WorkloadIdentity {
    WorkloadIdentity { provider: PROVIDER.into(), service_account: service_account.map(str::to_owned) }
}

/// A fake Google and a `GcpKms` serving `Sim` that reaches it with fake attestation tokens.
async fn setup(service_account: Option<&str>) -> (Google, GcpKms) {
    let google = Google::new(if service_account.is_some() { IMPERSONATED } else { FEDERATED });
    let addr = serve(google.clone()).await;
    let kms =
        GcpKms::new(PlatformId::Sim, identity(service_account), https(addr)).unwrap().with_tokens(Arc::new(FakeTokens));
    (google, kms)
}

fn keys() -> Vec<String> {
    vec![KEY_A.into(), KEY_B.into()]
}

fn root() -> Key32 {
    Key32::from_bytes(common::sim::ROOT)
}

fn sim() -> Attestor {
    attestor(GUARDIAN_OLD)
}

fn root_err(result: Result<impl Sized, GuardianError>) -> String {
    match result {
        Err(GuardianError::Root(reason)) => reason,
        Err(other) => panic!("expected a Root error, got {other}"),
        Ok(_) => panic!("expected a Root error"),
    }
}

async fn open(kms: GcpKms, roots: Vec<KmsWrappedRoot>) -> Result<Key32, GuardianError> {
    KeySource::GcpKms(GcpKmsKeySource::new(kms, roots)?).root_secret(&sim()).await
}

/// The ceremony stores a root under both keys; a guardian then boots from the copies to the
/// same platform master key, with and without service account impersonation.
#[tokio::test]
async fn ceremony_then_boot() {
    for service_account in [None, Some(SA)] {
        let (google, kms) = setup(service_account).await;
        let roots = kms.store(&root(), &keys(), &sim()).await.unwrap();
        assert_eq!(roots.iter().map(|r| r.key_name.as_str()).collect::<Vec<_>>(), [KEY_A, KEY_B]);
        let stored = google.0.lock().unwrap().ciphertexts.values().map(|(_, aad, _)| aad.clone()).collect::<Vec<_>>();
        assert!(stored.iter().all(|aad| STANDARD.decode(aad).unwrap() == b"seal-guardian/root/v1/sim"));

        let world = World::new();
        let components = GuardianComponents {
            key_source: KeySource::GcpKms(GcpKmsKeySource::new(kms, roots).unwrap()),
            attestor: sim(),
            clock: Clock::System(SystemClock::new(0)),
        };
        let guardian = Guardian::boot(world.config(), components).await.unwrap();
        let identity = guardian.identity([1; 32]).await.unwrap();
        assert_eq!(identity.guardian_key, guardian_key(common::sim::ROOT));

        let calls = google.calls();
        let impersonations = calls.iter().filter(|c| c.contains(":generateAccessToken")).count();
        assert_eq!(impersonations, if service_account.is_some() { 2 } else { 0 }, "{calls:?}");
        // Ceremony: STS, encrypt and verify per key. Boot: STS, then the first copy opens.
        assert_eq!(calls.iter().filter(|c| c.contains(":encrypt")).count(), 2);
        assert_eq!(calls.iter().filter(|c| c.contains(":decrypt")).count(), 3);
    }
}

#[tokio::test]
async fn falls_back_to_the_next_copy() {
    let (google, kms) = setup(None).await;
    let roots = kms.store(&root(), &keys(), &sim()).await.unwrap();
    google.answer("root-a:decrypt", 503, &api_error(503, "UNAVAILABLE", "The service is unavailable."));
    assert_eq!(open(kms, roots).await.unwrap().expose(), root().expose());
}

#[tokio::test]
async fn kms_refusing_every_copy_fails_boot() {
    let (google, kms) = setup(None).await;
    let roots = kms.store(&root(), &keys(), &sim()).await.unwrap();
    let denied = "Permission 'cloudkms.cryptoKeyVersions.useToDecrypt' denied";
    google.answer(":decrypt", 403, &api_error(403, "PERMISSION_DENIED", denied));
    let reason = root_err(open(kms, roots).await);
    assert!(reason.contains("root-a: decrypt: HTTP 403 (PERMISSION_DENIED: Permission"), "{reason}");
    assert!(reason.contains("root-b: decrypt: HTTP 403"), "{reason}");
}

#[tokio::test]
async fn sts_refusal() {
    let (google, kms) = setup(None).await;
    let rejected = "The given credential is rejected by the attribute condition.";
    google.answer("/v1/token", 400, &oauth_error("invalid_grant", rejected));
    let reason = root_err(kms.store(&root(), &keys(), &sim()).await);
    assert_eq!(reason, format!("gcp kms: sts: HTTP 400 (invalid_grant: {rejected})"));
    assert_eq!(google.calls().len(), 1, "nothing after a refused exchange");
}

#[tokio::test]
async fn impersonation_refusal() {
    let (google, kms) = setup(Some(SA)).await;
    let denied = "Permission 'iam.serviceAccounts.getAccessToken' denied";
    google.answer(":generateAccessToken", 403, &api_error(403, "PERMISSION_DENIED", denied));
    let reason = root_err(kms.store(&root(), &keys(), &sim()).await);
    assert!(reason.starts_with("gcp kms: iamcredentials: HTTP 403 (PERMISSION_DENIED"), "{reason}");
}

#[tokio::test]
async fn attestation_token_failure() {
    let (google, kms) = setup(None).await;
    let kms = kms.with_tokens(Arc::new(FailingTokens));
    assert_eq!(root_err(kms.store(&root(), &keys(), &sim()).await), "launcher: no socket");
    assert!(google.calls().is_empty());
}

/// Outside Confidential Space the launcher's tokens refuse before anything goes out.
#[tokio::test]
async fn launcher_tokens_need_confidential_space() {
    let reason = root_err(LauncherTokens.token(&sim(), "//iam.googleapis.com/x").await);
    assert!(reason.contains("not Sim"), "{reason}");
}

#[tokio::test]
async fn wrong_length_root() {
    let (google, kms) = setup(None).await;
    let roots = kms.store(&root(), &keys(), &sim()).await.unwrap();
    let short = STANDARD.encode([7u8; 31]);
    google.answer(":decrypt", 200, &format!(r#"{{"plaintext":"{short}"}}"#));
    let reason = root_err(open(kms, roots).await);
    assert!(reason.contains("root-a: decrypted 31 bytes, not a 32-byte root"), "{reason}");
}

#[tokio::test]
async fn malformed_responses() {
    let cases = [
        ("/v1/token", "not json", "sts: malformed response"),
        ("/v1/token", r#"{"token_type":"Bearer"}"#, "sts: malformed response: missing field `access_token`"),
        ("/v1/token", r#"{"access_token":"t","token_type":"mac"}"#, "sts: no bearer access token"),
        ("/v1/token", r#"{"access_token":"","token_type":"Bearer"}"#, "sts: no bearer access token"),
        (":generateAccessToken", r#"{"expireTime":"x"}"#, "iamcredentials: malformed response"),
        (":decrypt", r#"{"plaintext":"!!not base64!!"}"#, "decrypt: malformed response"),
        (":decrypt", r#"{"plaintext":42}"#, "decrypt: malformed response"),
        (":decrypt", r#"{}"#, "decrypt: malformed response: missing field `plaintext`"),
    ];
    for (path, body, expected) in cases {
        let (google, kms) = setup(Some(SA)).await;
        let roots = kms.store(&root(), &keys(), &sim()).await.unwrap();
        google.answer(path, 200, body);
        let reason = root_err(open(kms, roots).await);
        assert!(reason.contains(expected), "{path} {body}: {reason}");
    }
}

#[tokio::test]
async fn store_refusals() {
    let other_key = "projects/p/locations/l/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1";
    let cases = [
        (":encrypt", 403, api_error(403, "PERMISSION_DENIED", "denied"), "root-a: encrypt: HTTP 403"),
        (":encrypt", 200, json!({"name": other_key, "ciphertext": "AAAA"}).to_string(), "answered for another key"),
        (":decrypt", 200, json!({"plaintext": STANDARD.encode([9u8; 32])}).to_string(), "does not open to the root"),
        ("root-b:decrypt", 400, api_error(400, "INVALID_ARGUMENT", "Decryption failed."), "root-b: decrypt: HTTP 400"),
    ];
    for (path, status, body, expected) in cases {
        let (google, kms) = setup(None).await;
        google.answer(path, status, &body);
        let reason = root_err(kms.store(&root(), &keys(), &sim()).await);
        assert!(reason.contains(expected), "{path}: {reason}");
    }
}

/// A root wrapped for one served platform does not open for another: the AAD names it.
#[tokio::test]
async fn wrapped_root_is_bound_to_the_served_platform() {
    let (google, kms) = setup(None).await;
    let roots = kms.store(&root(), &keys(), &sim()).await.unwrap();
    let addr = serve(google.clone()).await;
    let other = GcpKms::new(PlatformId::GcpConfidentialSpace, identity(None), https(addr))
        .unwrap()
        .with_tokens(Arc::new(FakeTokens));
    let reason = root_err(open(other, roots).await);
    assert!(reason.contains("decrypt: HTTP 400 (INVALID_ARGUMENT: Decryption failed.)"), "{reason}");
    assert_eq!(root_aad(PlatformId::GcpConfidentialSpace), "seal-guardian/root/v1/gcp_confidential_space");
}

#[tokio::test]
async fn malformed_configuration() {
    let (_, kms) = setup(None).await;
    let https = https("127.0.0.1:9".parse().unwrap());
    for provider in [
        "projects/p/locations/global/workloadIdentityPools/pool/providers/prov",
        "projects/123/locations/global/workloadIdentityPools/pool/providers/prov?x=1",
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov",
    ] {
        let identity = WorkloadIdentity { provider: provider.into(), service_account: None };
        assert!(GcpKms::new(PlatformId::Sim, identity, https.clone()).is_err(), "{provider}");
    }
    for sa in
        ["guardian", "guardian@example.com", "Guardian@p.iam.gserviceaccount.com", "a/b@p.iam.gserviceaccount.com"]
    {
        assert!(GcpKms::new(PlatformId::Sim, identity(Some(sa)), https.clone()).is_err(), "{sa}");
    }
    for key in [
        "projects/p/locations/l/keyRings/r",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k:x",
    ] {
        assert!(kms.store(&root(), &[key.to_string()], &sim()).await.is_err(), "{key}");
    }
    assert!(kms.store(&root(), &[], &sim()).await.is_err());
    assert!(GcpKmsKeySource::new(kms, vec![]).is_err());
}

/// Against Google: `SEAL_GCP_LIVE_PROVIDER`, `SEAL_GCP_LIVE_KEY`, optional
/// `SEAL_GCP_LIVE_SERVICE_ACCOUNT`, and `SEAL_GCP_LIVE_TOKEN`, an OIDC token that the provider
/// accepts and whose audience is `//iam.googleapis.com/<provider>` (on Confidential Space, the
/// launcher's; off it, a provider for `https://accounts.google.com` and
/// `gcloud auth print-identity-token --impersonate-service-account <sa> --audiences <audience>`).
/// Stores a fresh root under the key, then opens it.
#[tokio::test]
#[ignore = "live: needs Google credentials, see the doc comment"]
async fn live_store_then_open() {
    struct LiveToken(String);
    #[async_trait::async_trait]
    impl AttestationTokens for LiveToken {
        async fn token(&self, _: &Attestor, _: &str) -> Result<String, GuardianError> {
            Ok(self.0.clone())
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let identity = WorkloadIdentity {
        provider: var("SEAL_GCP_LIVE_PROVIDER"),
        service_account: std::env::var("SEAL_GCP_LIVE_SERVICE_ACCOUNT").ok().filter(|s| !s.is_empty()),
    };
    let https = Arc::new(HttpsClient::new(Arc::new(BakedRootsConnector::new(Arc::new(seal_net::TcpDialer)))));
    let tokens = Arc::new(LiveToken(var("SEAL_GCP_LIVE_TOKEN")));
    let kms = GcpKms::new(PlatformId::Sim, identity, https).unwrap().with_tokens(tokens);
    let root = Key32::generate(&mut UnwrapErr(SysRng));
    let roots = kms.store(&root, &[var("SEAL_GCP_LIVE_KEY")], &sim()).await.unwrap();
    println!("wrapped root: {} bytes", roots[0].wrapped_root.len());
    assert_eq!(open(kms, roots).await.unwrap().expose(), root.expose());
}
