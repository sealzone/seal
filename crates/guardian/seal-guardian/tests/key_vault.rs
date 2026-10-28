//! `KeyVaultKeySource` and `KeyVault::store` against a fake Key Vault: one in-test TLS server
//! answering for two vault hosts under a test CA (seal-net's `sim` extra roots), release JWSs
//! signed by an RSA certificate under another test CA (`with_extra_jws_roots`), and host_data,
//! attestation and access tokens from a fake `VaultCredentials`. The fake wraps released keys
//! as Key Vault does: RSA-OAEP-SHA256 of an AES-256 key to the runtime key, then AES-KWP of
//! the key's PKCS#8 DER.
#![cfg(feature = "sim")]

mod common;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use common::sim::{attestor, guardian_key};
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use rsa::pkcs8::EncodePrivateKey as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys, SysRng, UnwrapErr};
use seal_guardian::keysource::{
    release_policy, root_aad, KeyVault, KeyVaultKeySource, VaultCredentials, VaultKey, VaultKeyName,
};
use seal_guardian::{Guardian, GuardianComponents, GuardianError, KeySource};
use seal_net::{BakedRootsConnector, BoxStream, Dialer, HttpsClient, NetError};
use seal_proto::{PlatformId, ServiceKeyVersion, TenantId, TenantRootId};
use seal_tee::sim::SystemClock;
use seal_tee::{Attestor, Clock};
use serde_json::{json, Value};
use sha2::Sha256;

const VAULT_A: &str = "https://seal-a.vault.azure.net";
const VAULT_B: &str = "https://seal-b.vault.azure.net";
const HOSTS: [&str; 2] = ["seal-a.vault.azure.net", "seal-b.vault.azure.net"];
const KEY: &str = "guardian-root";
const MAA: &str = "https://sharedeus.eus.attest.azure.net";
const HOST_DATA: [u8; 32] = [0x4d; 32];
const ACCESS: &str = "vault-access-token";

/// RSA keys are slow to generate: each one once per test binary.
fn rsa_key(slot: usize, bits: usize) -> RsaPrivateKey {
    static KEYS: OnceLock<Mutex<BTreeMap<usize, RsaPrivateKey>>> = OnceLock::new();
    let keys = KEYS.get_or_init(Default::default);
    keys.lock()
        .unwrap()
        .entry(slot)
        .or_insert_with(|| RsaPrivateKey::new(&mut UnwrapErr(SysRng), bits).unwrap())
        .clone()
}

/// Fake MAA token: the runtime data itself, so the fake vault can wrap to its key.
struct FakeCredentials {
    host_data: [u8; 32],
}

#[async_trait::async_trait]
impl VaultCredentials for FakeCredentials {
    fn host_data(&self, _: &Attestor) -> Result<[u8; 32], GuardianError> {
        Ok(self.host_data)
    }
    async fn maa_token(&self, _: &Attestor, maa_endpoint: &str, runtime_data: &[u8]) -> Result<String, GuardianError> {
        assert_eq!(maa_endpoint, MAA);
        Ok(format!("maa.{}", URL_SAFE_NO_PAD.encode(runtime_data)))
    }
    async fn vault_token(&self) -> Result<String, GuardianError> {
        Ok(ACCESS.into())
    }
}

struct FailingCredentials;

#[async_trait::async_trait]
impl VaultCredentials for FailingCredentials {
    fn host_data(&self, _: &Attestor) -> Result<[u8; 32], GuardianError> {
        Ok(HOST_DATA)
    }
    async fn maa_token(&self, _: &Attestor, _: &str, _: &[u8]) -> Result<String, GuardianError> {
        Err(GuardianError::Root("maa: HTTP 400 (Bad Request)".into()))
    }
    async fn vault_token(&self) -> Result<String, GuardianError> {
        Ok(ACCESS.into())
    }
}

/// One key version in the fake vault.
#[derive(Clone)]
struct Version {
    id: String,
    key: RsaPrivateKey,
    kty: String,
    exportable: bool,
    policy: Value,
    immutable: bool,
}

impl Version {
    fn new(slot: usize, n: u8) -> Self {
        Self {
            id: format!("{n:02x}").repeat(16),
            key: rsa_key(slot, 3072),
            // What Key Vault names a released RSA-HSM key.
            kty: "RSA".into(),
            exportable: true,
            policy: release_policy(&HOST_DATA, MAA),
            immutable: true,
        }
    }

    fn bundle(&self, vault: &str, key_hsm: Option<String>) -> Value {
        let public = self.key.to_public_key();
        let mut key = json!({
            "kid": format!("{vault}/keys/{KEY}/{}", self.id),
            "kty": self.kty,
            "key_ops": ["encrypt", "decrypt"],
            "n": URL_SAFE_NO_PAD.encode(public.n().to_be_bytes_trimmed_vartime()),
            "e": URL_SAFE_NO_PAD.encode(public.e().to_be_bytes_trimmed_vartime()),
        });
        if let Some(key_hsm) = key_hsm {
            key["key_hsm"] = key_hsm.into();
        }
        json!({
            "key": key,
            "attributes": {"enabled": true, "exportable": self.exportable, "recoveryLevel": "Recoverable"},
            "release_policy": {
                "contentType": "application/json; charset=utf-8",
                "data": URL_SAFE_NO_PAD.encode(self.policy.to_string()),
                "immutable": self.immutable,
            },
        })
    }
}

/// The JWS signer: an RSA key and a certificate for both vault hosts under `jws_ca`.
struct JwsSigner {
    key: RsaPrivateKey,
    chain: Vec<Vec<u8>>,
}

#[derive(Default)]
struct State {
    /// (vault URL) → versions, the last one current.
    keys: BTreeMap<String, Vec<Version>>,
    overrides: BTreeMap<String, (u16, String)>,
    /// Edits to the release payload before signing.
    edit_payload: Option<fn(&mut Value)>,
    /// The JWS signer; `None` signs with an untrusted one.
    untrusted_signer: bool,
    calls: Vec<String>,
}

#[derive(Clone)]
struct Vault(Arc<Mutex<State>>);

impl Vault {
    fn new() -> Self {
        let state = State {
            keys: BTreeMap::from([
                (VAULT_A.into(), vec![Version::new(0, 1)]),
                (VAULT_B.into(), vec![Version::new(1, 2)]),
            ]),
            ..State::default()
        };
        Self(Arc::new(Mutex::new(state)))
    }
    fn answer(&self, path_contains: &str, status: u16, body: &str) {
        self.0.lock().unwrap().overrides.insert(path_contains.into(), (status, body.into()));
    }
    fn edit(&self, vault: &str, f: impl FnOnce(&mut Version)) {
        f(self.0.lock().unwrap().keys.get_mut(vault).unwrap().last_mut().unwrap());
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
        if auth != Some(&format!("Bearer {ACCESS}")) {
            return (401, error("Unauthorized", "no token"));
        }
        let vault = format!("https://{host}");
        let Some(versions) = state.keys.get(&vault).cloned() else { return (404, error("NotFound", "vault")) };
        let path = path.split('?').next().unwrap_or_default();
        let rest = path.strip_prefix(&format!("/keys/{KEY}")).unwrap_or("!");
        // `/release` releases the current version, `/<version>/release` that one.
        let version = match rest {
            "/release" => versions.last(),
            _ => match rest.strip_prefix('/').and_then(|r| r.strip_suffix("/release")) {
                Some(id) => versions.iter().find(|v| v.id == id),
                None => return (404, error("KeyNotFound", "no such key")),
            },
        };
        let Some(version) = version else { return (404, error("KeyNotFound", "no such version")) };
        let id = &version.id;
        let req: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(req["enc"], "RSA_AES_KEY_WRAP_256");
        // The fake MAA's token is the runtime data; a real vault checks it against the policy.
        let runtime = req["target"].as_str().and_then(|t| t.strip_prefix("maa.")).unwrap();
        let runtime: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(runtime).unwrap()).unwrap();
        let jwk = &runtime["keys"][0];
        assert_eq!(jwk["key_ops"], json!(["encrypt"]));
        let uint = |f: &str| {
            let b = URL_SAFE_NO_PAD.decode(jwk[f].as_str().unwrap()).unwrap();
            rsa::BoxedUint::from_be_slice(&b, (b.len() * 8) as u32).unwrap()
        };
        let runtime_key = RsaPublicKey::new(uint("n"), uint("e")).unwrap();
        let key_hsm = key_hsm(&runtime_key, jwk["kid"].as_str().unwrap(), &version.key);
        let mut payload = json!({
            "request": {"api-version": "7.4", "enc": "CKM_RSA_AES_KEY_WRAP", "kid": format!("{vault}/keys/{KEY}/{id}")},
            "response": {"key": version.bundle(&vault, Some(key_hsm))},
        });
        if let Some(edit) = state.edit_payload {
            edit(&mut payload);
        }
        let jws = sign_jws(&payload, &jws_signer(state.untrusted_signer));
        (200, json!({"value": jws}).to_string())
    }
}

fn error(code: &str, message: &str) -> String {
    json!({"error": {"code": code, "message": message}}).to_string()
}

/// Key Vault's `key_hsm`: RSA-OAEP-SHA256(KEK) under the runtime key ‖ AES-KWP(KEK, PKCS#8).
fn key_hsm(runtime: &RsaPublicKey, kid: &str, key: &RsaPrivateKey) -> String {
    let kek = Key32::generate(&mut UnwrapErr(SysRng));
    let mut ciphertext = runtime.encrypt(&mut UnwrapErr(SysRng), Oaep::<Sha256>::new(), kek.expose()).unwrap();
    let der = key.to_pkcs8_der().unwrap();
    let kwp = <aes_kw::KwpAes256 as aes_kw::KeyInit>::new(kek.expose().into());
    let mut buf = vec![0; der.as_bytes().len() + 16];
    ciphertext.extend_from_slice(kwp.wrap_key(der.as_bytes(), &mut buf).unwrap());
    let json = json!({
        "schema_version": "1.0",
        "header": {"kid": kid, "alg": "dir", "enc": "CKM_RSA_AES_KEY_WRAP"},
        "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
        "generator": "fake key vault",
    });
    URL_SAFE_NO_PAD.encode(json.to_string())
}

fn sign_jws(payload: &Value, signer: &JwsSigner) -> String {
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    let x5c: Vec<String> = signer.chain.iter().map(|c| STANDARD.encode(c)).collect();
    let header = json!({"alg": "RS256", "x5c": x5c});
    let input =
        format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(payload.to_string()));
    let sig = rsa::pkcs1v15::SigningKey::<Sha256>::new(signer.key.clone()).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Test PKI for the JWS: a P-256 CA (`label`) and an RSA leaf for both vault hosts.
mod pki {
    use std::time::{Duration, SystemTime};

    use super::*;
    use p256::ecdsa::{DerSignature, SigningKey};
    use sha2::Digest as _;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder, CertificateBuilder};
    use x509_cert::certificate::TbsCertificate;
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::der::Encode as _;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoRef;
    use x509_cert::time::{Time, Validity};
    use x509_cert::SubjectPublicKeyInfo;

    struct Profile {
        issuer: Name,
        subject: Name,
        ca: bool,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _: &Name) -> Name {
            self.issuer.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _: SubjectPublicKeyInfoRef<'_>,
            _: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let subject = tbs.subject();
            let mut exts =
                vec![(&BasicConstraints { ca: self.ca, path_len_constraint: None }).to_extension(subject, &[])?];
            let usage =
                if self.ca { KeyUsages::KeyCertSign | KeyUsages::CRLSign } else { KeyUsages::DigitalSignature.into() };
            exts.push((&KeyUsage(usage)).to_extension(subject, &[])?);
            if !self.ca {
                let server_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
                exts.push((&ExtendedKeyUsage(vec![server_auth])).to_extension(subject, &[])?);
                let sans = HOSTS.iter().map(|h| GeneralName::DnsName(Ia5String::new(*h).unwrap())).collect();
                exts.push((&SubjectAltName(sans)).to_extension(subject, &[])?);
            }
            Ok(exts)
        }
    }

    fn validity() -> Validity {
        let now = SystemTime::now();
        let day = Duration::from_secs(86_400);
        Validity::new(Time::try_from(now - day).unwrap(), Time::try_from(now + day).unwrap())
    }

    fn ca_key(label: &str) -> SigningKey {
        SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap()
    }

    fn name(cn: &str) -> Name {
        Name::from_str(&format!("CN={cn},O=Seal Test,C=US")).unwrap()
    }

    pub fn ca(label: &str) -> Vec<u8> {
        let key = ca_key(label);
        let spki = SubjectPublicKeyInfo::from_key(key.verifying_key()).unwrap();
        let profile = Profile { issuer: name(label), subject: name(label), ca: true };
        let cert = CertificateBuilder::new(profile, SerialNumber::from(1u32), validity(), spki).unwrap();
        cert.build::<_, DerSignature>(&key).unwrap().to_der().unwrap()
    }

    pub fn rsa_leaf(ca_label: &str, key: &RsaPublicKey) -> Vec<u8> {
        let spki = SubjectPublicKeyInfo::from_key(key).unwrap();
        let profile = Profile { issuer: name(ca_label), subject: name("vault signing"), ca: false };
        let cert = CertificateBuilder::new(profile, SerialNumber::from(2u32), validity(), spki).unwrap();
        cert.build::<_, DerSignature>(&ca_key(ca_label)).unwrap().to_der().unwrap()
    }

    pub fn pem(der: &[u8]) -> String {
        let b64 = STANDARD.encode(der);
        let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
    }
}

const JWS_CA: &str = "fake key vault JWS CA";

fn jws_signer(untrusted: bool) -> JwsSigner {
    let key = rsa_key(9, 2048);
    let ca = if untrusted { "an untrusted CA" } else { JWS_CA };
    JwsSigner { chain: vec![pki::rsa_leaf(ca, &key.to_public_key()), pki::ca(ca)], key }
}

/// The fake's TLS identity: a deterministic CA and one leaf naming both vault hosts.
fn vault_tls() -> seal_crypto::TlsKey {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([0x61; 32]));
    let keys =
        master.release_service(&TenantId::new("keyvault").unwrap(), &TenantRootId([0; 32]), ServiceKeyVersion(1));
    ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap().tls
}

fn names() -> Vec<String> {
    HOSTS.iter().map(|h| h.to_string()).collect()
}

async fn serve(vault: Vault) -> SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let tls = vault_tls();
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
            let (acceptor, vault) = (acceptor.clone(), vault.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else { return };
                let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let vault = vault.clone();
                    async move {
                        let host =
                            req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
                        let auth = req.headers().get("authorization").and_then(|h| h.to_str().ok()).map(str::to_owned);
                        let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        // Key generation in the handler is slow: off the runtime's threads.
                        let (status, body) =
                            tokio::task::spawn_blocking(move || vault.handle(&host, &path, auth.as_deref(), &body))
                                .await
                                .unwrap();
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

/// Dials `addr` whatever the host, so the real vault URLs reach the fake.
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
    let pem = pki::pem(&vault_tls().ca_certificate_der(&names()).unwrap());
    let connector = BakedRootsConnector::with_extra_roots(Arc::new(FixedDialer(addr)), pem.as_bytes()).unwrap();
    Arc::new(HttpsClient::new(Arc::new(connector)))
}

/// A fake vault and a `KeyVault` serving `Sim` that reaches it with fake credentials.
async fn setup() -> (Vault, KeyVault) {
    let vault = Vault::new();
    let addr = serve(vault.clone()).await;
    (vault, key_vault(addr, PlatformId::Sim))
}

fn key_vault(addr: SocketAddr, platform: PlatformId) -> KeyVault {
    KeyVault::new(platform, MAA.into(), https(addr))
        .unwrap()
        .with_credentials(Arc::new(FakeCredentials { host_data: HOST_DATA }))
        .with_extra_jws_roots(pki::pem(&pki::ca(JWS_CA)).as_bytes())
        .unwrap()
}

fn keys() -> Vec<VaultKeyName> {
    [VAULT_A, VAULT_B].map(|v| VaultKeyName { vault_url: v.into(), key_name: KEY.into() }).to_vec()
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

async fn open(vault: KeyVault, copies: Vec<VaultKey>) -> Result<Key32, GuardianError> {
    KeySource::KeyVault(KeyVaultKeySource::new(vault, copies)?).root_secret(&sim()).await
}

/// The ceremony wraps a root under both vaults' keys (checking each by a release); a guardian
/// then boots from the copies to the same platform master key.
#[tokio::test]
async fn ceremony_then_boot() {
    let (vault, kv) = setup().await;
    let copies = kv.store(&root(), &keys(), &sim()).await.unwrap();
    assert_eq!(copies.iter().map(|c| c.vault_url.as_str()).collect::<Vec<_>>(), [VAULT_A, VAULT_B]);
    assert_eq!(copies[0].key_version, "01".repeat(16));
    // RSA-OAEP-SHA256 under the vault key, labelled with the served platform.
    let wrapped = copies[0].wrapped_root.as_ref().unwrap();
    let opened =
        rsa_key(0, 3072).decrypt(Oaep::<Sha256>::new_with_label(root_aad(PlatformId::Sim).into_bytes()), wrapped);
    assert_eq!(opened.unwrap(), root().expose());

    let world = World::new();
    let components = GuardianComponents {
        key_source: KeySource::KeyVault(KeyVaultKeySource::new(kv, copies).unwrap()),
        attestor: sim(),
        clock: Clock::System(SystemClock::new(0)),
    };
    let guardian = Guardian::boot(world.config(), components).await.unwrap();
    assert_eq!(guardian.identity([1; 32]).await.unwrap().guardian_key, guardian_key(common::sim::ROOT));

    // Ceremony: the current version of each key. Boot: the first copy's pinned version opens.
    let calls = vault.calls();
    let current = format!("/keys/{KEY}/release?api-version=7.4");
    let pinned = format!("/keys/{KEY}/{}/release?api-version=7.4", "01".repeat(16));
    assert_eq!(
        calls,
        [format!("{} {current}", HOSTS[0]), format!("{} {current}", HOSTS[1]), format!("{} {pinned}", HOSTS[0])]
    );
}

#[tokio::test]
async fn falls_back_to_the_next_copy() {
    let (vault, kv) = setup().await;
    let copies = kv.store(&root(), &keys(), &sim()).await.unwrap();
    vault.answer(&format!("/keys/{KEY}/{}/release", "01".repeat(16)), 503, &error("ServiceUnavailable", "busy"));
    assert_eq!(open(kv, copies).await.unwrap().expose(), root().expose());
}

#[tokio::test]
async fn every_copy_refused_fails_boot() {
    let (vault, kv) = setup().await;
    let copies = kv.store(&root(), &keys(), &sim()).await.unwrap();
    vault.answer("/release", 403, &error("Forbidden", "Target environment attestation statement cannot be verified."));
    let reason = root_err(open(kv, copies).await);
    assert!(reason.contains("seal-a.vault.azure.net/keys/guardian-root/0101"), "{reason}");
    assert!(reason.contains("release: HTTP 403 (Forbidden: Target environment"), "{reason}");
    assert!(reason.contains("seal-b.vault.azure.net"), "{reason}");
}

/// The ceremony wraps only under a key whose release policy is immutable and pins this
/// guardian; anything else is refused before the root leaves the TEE.
#[tokio::test]
async fn the_ceremony_refuses_keys_others_could_release() {
    type Edit = fn(&mut Version);
    let cases: [(Edit, &str); 7] = [
        (|v| v.immutable = false, "release policy is not immutable"),
        (|v| v.policy = release_policy(&[0; 32], MAA), "does not require x-ms-sevsnpvm-hostdata"),
        (|v| v.policy = release_policy(&HOST_DATA, "https://mine.eus.attest.azure.net"), "authority"),
        (|v| v.exportable = false, "not exportable"),
        (|v| v.kty = "oct-HSM".into(), "oct-HSM keys are not implemented"),
        (|v| v.kty = "EC-HSM".into(), "an EC-HSM key, not RSA-HSM"),
        (|v| v.key = rsa_key(5, 2048), "below 3072"),
    ];
    for (edit, expected) in cases {
        let (vault, kv) = setup().await;
        vault.edit(VAULT_B, edit);
        let reason = root_err(kv.store(&root(), &keys(), &sim()).await);
        assert!(reason.contains("seal-b.vault.azure.net") && reason.contains(expected), "{expected}: {reason}");
    }
}

/// What a release answers is checked: the JWS's certificate and signature, the key version it
/// names, and the policy it carries.
#[tokio::test]
async fn release_answers_are_checked() {
    let (_, kv) = setup().await;
    let copies = kv.store(&root(), &keys()[..1], &sim()).await.unwrap();
    type Edit = fn(&mut Value);
    let edits: [(Edit, &str); 4] = [
        (
            |p| p["response"]["key"]["key"]["kid"] = format!("{VAULT_A}/keys/{KEY}/{}", "ff".repeat(16)).into(),
            "not the pinned key version",
        ),
        (|p| p["response"]["key"]["release_policy"]["immutable"] = false.into(), "not immutable"),
        (|p| p["response"]["key"]["release_policy"]["data"] = URL_SAFE_NO_PAD.encode("{}").into(), "release policy"),
        (|p| p["response"]["key"]["key"]["kty"] = "oct-HSM".into(), "oct-HSM keys are not implemented"),
    ];
    for (edit, expected) in edits {
        let vault = Vault::new();
        vault.0.lock().unwrap().edit_payload = Some(edit);
        let addr = serve(vault).await;
        let reason = root_err(open(key_vault(addr, PlatformId::Sim), copies.clone()).await);
        assert!(reason.contains(expected), "{expected}: {reason}");
    }
    let vault = Vault::new();
    vault.0.lock().unwrap().untrusted_signer = true;
    let addr = serve(vault.clone()).await;
    let reason = root_err(open(key_vault(addr, PlatformId::Sim), copies.clone()).await);
    assert!(reason.contains("the JWS certificate does not certify seal-a.vault.azure.net"), "{reason}");

    // A signature over another payload.
    let vault = Vault::new();
    let addr = serve(vault.clone()).await;
    let jws = {
        let signer = jws_signer(false);
        let good = sign_jws(&json!({"x": 1}), &signer);
        let other = sign_jws(&json!({"x": 2}), &signer);
        let (head, _) = good.rsplit_once('.').unwrap();
        format!("{head}.{}", other.rsplit_once('.').unwrap().1)
    };
    vault.answer("/release", 200, &json!({"value": jws}).to_string());
    let reason = root_err(open(key_vault(addr, PlatformId::Sim), copies).await);
    assert!(reason.contains("the JWS signature does not verify"), "{reason}");
}

/// A copy wrapped for one served platform does not open for another: the OAEP label names it.
#[tokio::test]
async fn a_copy_is_bound_to_the_served_platform() {
    let (vault, kv) = setup().await;
    let copies = kv.store(&root(), &keys(), &sim()).await.unwrap();
    let addr = serve(vault).await;
    let reason = root_err(open(key_vault(addr, PlatformId::AzureSnpAci), copies).await);
    assert!(reason.contains("the wrapped root does not open"), "{reason}");
}

#[tokio::test]
async fn substituted_copies_do_not_open() {
    let (_, kv) = setup().await;
    let mut copies = kv.store(&root(), &keys(), &sim()).await.unwrap();
    for copy in &mut copies {
        copy.wrapped_root.as_mut().unwrap()[10] ^= 1;
    }
    let reason = root_err(open(kv, copies).await);
    assert_eq!(reason.matches("the wrapped root does not open").count(), 2, "{reason}");
}

#[tokio::test]
async fn an_oct_copy_is_refused_by_name() {
    let (_, kv) = setup().await;
    let copy =
        VaultKey { vault_url: VAULT_A.into(), key_name: KEY.into(), key_version: "01".repeat(16), wrapped_root: None };
    let reason = root_err(open(kv, vec![copy]).await);
    assert!(reason.contains("Managed HSM oct-HSM keys are not implemented"), "{reason}");
}

#[tokio::test]
async fn attestation_failure_stops_before_any_release() {
    let (vault, kv) = setup().await;
    let kv = kv.with_credentials(Arc::new(FailingCredentials));
    assert_eq!(root_err(kv.store(&root(), &keys(), &sim()).await), "maa: HTTP 400 (Bad Request)");
    assert!(vault.calls().is_empty());
}

#[tokio::test]
async fn malformed_configuration() {
    let (_, kv) = setup().await;
    let copy = |url: &str, version: &str| VaultKey {
        vault_url: url.into(),
        key_name: KEY.into(),
        key_version: version.into(),
        wrapped_root: Some(vec![1]),
    };
    assert!(KeyVaultKeySource::new(key_vault("127.0.0.1:9".parse().unwrap(), PlatformId::Sim), vec![]).is_err());
    for (url, version) in [
        ("https://seal-a.vault.azure.net", "1"),
        ("https://seal-a.vault.azure.net", "../release"),
        ("https://seal-a.managedhsm.azure.net", "01010101010101010101010101010101"),
        ("https://evil.example/x", "01010101010101010101010101010101"),
    ] {
        let vault = key_vault("127.0.0.1:9".parse().unwrap(), PlatformId::Sim);
        assert!(KeyVaultKeySource::new(vault, vec![copy(url, version)]).is_err(), "{url} {version}");
    }
    assert!(kv.store(&root(), &[], &sim()).await.is_err());
    let bad = VaultKeyName { vault_url: VAULT_A.into(), key_name: "a/b".into() };
    assert!(kv.store(&root(), &[bad], &sim()).await.is_err());
}

/// Outside an ACI group the default credentials refuse before anything goes out.
#[tokio::test]
async fn aci_credentials_need_aci() {
    let https = Arc::new(HttpsClient::new(Arc::new(BakedRootsConnector::new(Arc::new(seal_net::TcpDialer)))));
    let kv = KeyVault::new(PlatformId::Sim, MAA.into(), https).unwrap();
    let reason = root_err(kv.store(&root(), &keys(), &sim()).await);
    assert!(reason.contains("needs an ACI confidential group, not Sim"), "{reason}");
}
