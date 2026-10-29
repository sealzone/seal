//! Enclave verification and the pinned TLS config it produces.
//! `GET /v1/attestation` → check evidence (`seal_attest::verify`, which accepts Azure, Nitro
//! and Confidential Space, and sim evidence only in `sim` builds), release (M-of-N + log, revocations), that `report_data ==
//! labeled_digest(ATTESTATION_BINDING_LABEL, binding)`, and that `binding.attested_at` is
//! within `ATTESTATION_MAX_AGE_SECS` of the local clock; then the guardian's `ServiceKeyCertificate`
//! (`seal_verify::verify_service_certificate`): its TLS key, ingest key and telemetry keys must
//! equal the binding's, and its tenant and root must equal the client's tenant and root id (`ClientBuilder::{tenant, root_id}`)
//! when set (and, for a session, the blob header's). Without the certificate, an enclave
//! could attest to keys it made up itself, which a release still inside its time lock or one
//! its tenant never co-signed would do. Then build a rustls config that accepts only
//! `binding.tls_spki_sha256`.
//!
//! The attestation is fetched over TLS that accepts any key but records the one presented; the
//! response counts only if that key is the attested one, so the whole response came from
//! the attested enclave.
//! The client re-verifies every `ATTESTATION_REFRESH_SECS`.
//!
//! That periodic attestation proves which keys an approved release holds, not that a
//! connection ends in one: every replica shares the keys, and a holder of keys copied out of a
//! build since revoked could present the TLS key and replay a fresh attestation. So before a
//! request that carries anything secret (a sealed secret, an identity proof, a session
//! token), the client challenges the TLS connection it will send it on (`challenge`): a fresh
//! nonce in `GET /v1/attestation?nonce=`, answered with a `ChallengedAttestation` whose
//! challenge key signed the nonce and the connection's TLS 1.3 exporter
//! (`seal_verify::attestation::verify_challenged`), for the keys this client verified. Any
//! failure, an enclave that cannot answer included, is a `Verification` error before the
//! request is sent. Tunnel connections are challenged the same way, through their preamble
//! (`tunnel`). A replica's challenge evidence changes once per attestation period, so each
//! `VerifiedEnclave` keeps the answers it has verified in full; an answer with the same
//! evidence, binding, key, release and certificate costs one signature check while its
//! attestation is within `ATTESTATION_MAX_AGE_SECS`.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime as TlsTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use seal_proto::api::{
    AttestationBinding, AttestationChallenge, AttestationResponse, ChallengedAttestation, ATTESTATION_CHALLENGE_LABEL,
    ATTESTATION_EXPORTER_LABEL,
};
use seal_proto::freshness::ATTESTATION_MAX_AGE_SECS;
use seal_proto::release::ServiceKeyCertificate;
use seal_proto::{Measurement, PlatformId, TenantId, TenantRootId, UnixTime};
use sha2::{Digest, Sha256};

use crate::transport;
use crate::ClientError;

/// An enclave whose attestation, release, binding and guardian certificate checked out.
/// Cheap to share; the client replaces it on every re-verification.
pub struct VerifiedEnclave {
    binding: AttestationBinding,
    certificate: ServiceKeyCertificate,
    measurement: Measurement,
    release_version: String,
    config: Arc<rustls::ClientConfig>,
    tunnel_config: Arc<rustls::ClientConfig>,
    /// Challenged attestations verified in full (`check_challenged`): the digest of everything
    /// but the signature, and the `attested_at` of its binding.
    challenged: Mutex<Vec<([u8; 32], UnixTime)>>,
}

/// Verified challenge evidence kept per enclave: a few replicas, each with its current and
/// previous attestation.
const CHALLENGED_KEPT: usize = 16;

impl std::fmt::Debug for VerifiedEnclave {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("VerifiedEnclave")
            .field("platform", &self.certificate.platform)
            .field("tenant", &self.certificate.tenant)
            .field("release", &self.release_version)
            .field("attested_at", &self.binding.attested_at)
            .finish_non_exhaustive()
    }
}

impl VerifiedEnclave {
    /// The attested binding: time, service key version, TLS key, ingest key, telemetry keys.
    pub fn binding(&self) -> &AttestationBinding {
        &self.binding
    }
    /// The guardian's certificate, already checked against the binding and the tenant.
    pub fn certificate(&self) -> &ServiceKeyCertificate {
        &self.certificate
    }
    pub fn platform(&self) -> PlatformId {
        self.certificate.platform
    }
    pub fn tenant(&self) -> &TenantId {
        &self.certificate.tenant
    }
    pub fn root_id(&self) -> &TenantRootId {
        &self.certificate.root_id
    }
    pub fn measurement(&self) -> &Measurement {
        &self.measurement
    }
    /// The release's human version (`ReleaseManifest::version`).
    pub fn release_version(&self) -> &str {
        &self.release_version
    }
    pub fn attested_at(&self) -> UnixTime {
        self.binding.attested_at
    }
    pub fn tls_spki_sha256(&self) -> &[u8; 32] {
        &self.binding.tls_spki_sha256
    }
    /// A rustls config that accepts only the attested TLS key (no name check: the key is
    /// the identity). Session resumption is off, so every connection checks the key.
    pub fn client_config(&self) -> Arc<rustls::ClientConfig> {
        self.config.clone()
    }
    /// `client_config` offering the tunnel's ALPN (`seal_proto::tunnel::ALPN`), which the
    /// enclave's port serves tunnels on.
    pub(crate) fn tunnel_config(&self) -> Arc<rustls::ClientConfig> {
        self.tunnel_config.clone()
    }
}

/// Who the client expects to talk to.
#[derive(Clone, Debug)]
pub(crate) struct Expected {
    pub tenant: TenantId,
    pub root_id: Option<TenantRootId>,
}

fn fail(what: impl std::fmt::Display) -> ClientError {
    ClientError::Verification(what.to_string())
}

/// SHA-256 of the SubjectPublicKeyInfo DER of a certificate.
pub(crate) fn spki_sha256(cert_der: &[u8]) -> Option<[u8; 32]> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
    let spki = cert.tbs_certificate().subject_public_key_info().to_der().ok()?;
    Some(Sha256::digest(spki).into())
}

/// Every check on an attestation response, given the key the TLS connection presented. Pure:
/// the presented key against the attested one, then `seal_verify::attestation::verify`.
pub(crate) fn check(
    response: &AttestationResponse,
    presented_spki: &[u8; 32],
    trust: &seal_verify::Trust,
    expected: &Expected,
    now: UnixTime,
) -> Result<VerifiedEnclave, ClientError> {
    if presented_spki != &response.binding.tls_spki_sha256 {
        return Err(fail("the enclave presented a TLS key other than the attested one"));
    }
    let verified = seal_verify::attestation::verify(response, trust, &expected.tenant, expected.root_id.as_ref(), now)
        .map_err(fail)?;
    let config = pinned_config(Pin::Key(verified.binding.tls_spki_sha256));
    let mut tunnel_config = (*config).clone();
    tunnel_config.alpn_protocols = vec![seal_proto::tunnel::ALPN.to_vec()];
    Ok(VerifiedEnclave {
        binding: verified.binding,
        certificate: verified.certificate,
        measurement: verified.measurement,
        release_version: verified.release_version,
        config,
        tunnel_config: Arc::new(tunnel_config),
        challenged: Mutex::default(),
    })
}

/// The TLS exporter `ChallengedAttestation` binds (`ATTESTATION_EXPORTER_LABEL`, no context).
/// TLS 1.3 only: a TLS 1.2 exporter without the extended master secret can be made equal on two
/// connections by whoever ends one of them.
pub(crate) fn tls_exporter<IO>(stream: &tokio_rustls::client::TlsStream<IO>) -> Result<[u8; 32], ClientError> {
    let conn = stream.get_ref().1;
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(fail("the enclave connection is not TLS 1.3, so it cannot be challenged"));
    }
    conn.export_keying_material([0u8; 32], ATTESTATION_EXPORTER_LABEL, None)
        .map_err(|e| fail(format!("TLS exporter: {e}")))
}

/// Every check on a challenged attestation (module docs), given the nonce sent and the
/// connection's exporter. The answer must attest exactly `enclave`'s keys, tenant and root:
/// the request that follows was prepared for those. When `enclave` has verified the same
/// attested parts before and they are still within `ATTESTATION_MAX_AGE_SECS`, only the
/// signature over this nonce and exporter is checked.
pub(crate) fn check_challenged(
    response: &ChallengedAttestation,
    nonce: &[u8; 32],
    tls_exporter: &[u8; 32],
    enclave: &VerifiedEnclave,
    trust: &seal_verify::Trust,
    expected: &Expected,
    now: UnixTime,
) -> Result<(), ClientError> {
    let attested = seal_proto::codec::digest(&(
        &response.evidence,
        &response.binding,
        &response.challenge_key,
        &response.release,
        &response.certificate,
    ));
    let lock = || enclave.challenged.lock().unwrap_or_else(|e| e.into_inner());
    let fresh = response.binding.attested_at.abs_diff(now) <= ATTESTATION_MAX_AGE_SECS;
    if fresh && lock().iter().any(|(digest, _)| *digest == attested) {
        let challenge = AttestationChallenge { nonce: *nonce, tls_exporter: *tls_exporter };
        return seal_crypto::sign::verify(
            &response.challenge_key,
            ATTESTATION_CHALLENGE_LABEL,
            &challenge,
            &response.signature,
        )
        .map_err(|_| fail("challenged attestation: the signature does not verify for this nonce and connection"));
    }
    let verified = seal_verify::attestation::verify_challenged(
        response,
        nonce,
        tls_exporter,
        trust,
        &expected.tenant,
        expected.root_id.as_ref(),
        now,
    )
    .map_err(|e| fail(format!("challenged attestation: {e}")))?;
    let (ours, theirs) = (&enclave.binding, &verified.binding);
    if theirs.tls_spki_sha256 != ours.tls_spki_sha256
        || theirs.ingest_public_key != ours.ingest_public_key
        || theirs.service_key_version != ours.service_key_version
        || verified.certificate.root_id != enclave.certificate.root_id
    {
        return Err(fail("the challenged attestation is for other keys than the verified enclave's"));
    }
    let mut known = lock();
    known.retain(|(_, at)| at.abs_diff(now) <= ATTESTATION_MAX_AGE_SECS);
    if known.len() >= CHALLENGED_KEPT {
        known.remove(0);
    }
    known.push((attested, theirs.attested_at));
    Ok(())
}

/// Challenges `conn` (TLS pinned to `enclave`'s key, whose exporter is `tls_exporter`) with a
/// fresh nonce and checks the answer (`check_challenged`). A network failure is `Network`;
/// an enclave error is its code; anything else, an enclave that answers without the
/// challenge included, is `Verification`.
pub(crate) async fn challenge(
    conn: &mut transport::Http1,
    authority: &str,
    tls_exporter: &[u8; 32],
    enclave: &VerifiedEnclave,
    trust: &seal_verify::Trust,
    expected: &Expected,
) -> Result<(), ClientError> {
    let nonce = *seal_crypto::Key32::generate(&mut seal_crypto::UnwrapErr(seal_crypto::SysRng)).expose();
    let path = format!("/v1/attestation?nonce={}", seal_proto::codec::b64url(&nonce));
    let (status, body) = conn
        .send(hyper::Method::GET, authority, &path, &[("accept", "application/json")], None)
        .await
        .map_err(|e| ClientError::Network(format!("{authority}: attestation challenge: {e}")))?;
    if status != 200 {
        return Err(crate::client::api_error(status, &body));
    }
    let response: ChallengedAttestation = serde_json::from_slice(&body)
        .map_err(|_| fail("the enclave did not answer the attestation challenge (a release older than this SDK?)"))?;
    check_challenged(&response, &nonce, tls_exporter, enclave, trust, expected, crate::client::now())
}

/// Fetches `GET /v1/attestation` from `endpoint` and checks it (`check`). Network failures
/// are `Network`; everything about the response itself is `Verification`.
pub(crate) async fn fetch(
    endpoint: &url::Url,
    trust: &seal_verify::Trust,
    expected: &Expected,
    now: UnixTime,
) -> Result<VerifiedEnclave, ClientError> {
    let (host, port) = host_port(endpoint)?;
    let seen = Arc::new(Mutex::new(None));
    let config = pinned_config(Pin::Record(seen.clone()));
    let stream = transport::tls_connect(config, &host, port).await?;
    let presented =
        seen.lock().unwrap_or_else(|e| e.into_inner()).ok_or_else(|| fail("no TLS certificate presented"))?;
    let authority = authority(&host, port);
    let (status, body) = tokio::time::timeout(
        transport::EXCHANGE_TIMEOUT,
        transport::exchange(
            stream,
            hyper::Method::GET,
            &authority,
            "/v1/attestation",
            &[("accept", "application/json")],
            None,
        ),
    )
    .await
    .map_err(|_| ClientError::Network(format!("{authority}: attestation timed out")))?
    .map_err(|e| ClientError::Network(format!("{authority}: {e}")))?;
    if status != 200 {
        return Err(crate::client::api_error(status, &body));
    }
    let response: AttestationResponse =
        serde_json::from_slice(&body).map_err(|e| fail(format!("attestation response: {e}")))?;
    check(&response, &presented, trust, expected, now)
}

/// Host and port of an `https://` endpoint URL.
pub(crate) fn host_port(endpoint: &url::Url) -> Result<(String, u16), ClientError> {
    if endpoint.scheme() != "https" {
        return Err(ClientError::Invalid(format!("enclave endpoint {endpoint} is not https://")));
    }
    let host = endpoint.host_str().ok_or_else(|| ClientError::Invalid(format!("{endpoint} has no host")))?;
    Ok((host.to_string(), endpoint.port_or_known_default().unwrap_or(443)))
}

pub(crate) fn authority(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// What the verifier accepts.
#[derive(Debug)]
enum Pin {
    /// Only a leaf with this SPKI hash.
    Key([u8; 32]),
    /// Any leaf; its SPKI hash is recorded for the caller to compare.
    Record(Arc<Mutex<Option<[u8; 32]>>>),
}

#[derive(Debug)]
struct PinVerifier {
    pin: Pin,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: TlsTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented =
            spki_sha256(end_entity).ok_or(rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        match &self.pin {
            Pin::Key(want) if *want == presented => Ok(ServerCertVerified::assertion()),
            Pin::Key(_) => Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)),
            Pin::Record(seen) => {
                *seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(presented);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn pinned_config(pin: Pin) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier { pin, provider: provider.clone() });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("ring supports TLS 1.2 and 1.3")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys};
    use seal_proto::ServiceKeyVersion;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn service_keys(seed: u8) -> ServiceKeys {
        let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([seed; 32]));
        let released =
            master.release_service(&TenantId::new("acme").unwrap(), &TenantRootId([1; 32]), ServiceKeyVersion(1));
        ServiceKeys::from_released(PlatformId::Sim, &released).unwrap()
    }

    /// A TLS server presenting `keys`' `[leaf, CA]` that answers every connection with `ok`.
    async fn server(keys: &ServiceKeys) -> u16 {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let names = vec!["acme.enclave.seal.zone".to_string()];
        let chain = vec![
            CertificateDer::from(keys.tls.leaf_certificate_der(&names).unwrap()),
            CertificateDer::from(keys.tls.ca_certificate_der(&names).unwrap()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keys.tls.private_key_pkcs8_der().to_vec()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let _ = tls.write_all(b"ok").await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        port
    }

    #[test]
    fn spki_of_the_leaf_is_the_attested_key() {
        let keys = service_keys(1);
        let leaf = keys.tls.leaf_certificate_der(&["e.example".into()]).unwrap();
        assert_eq!(spki_sha256(&leaf), Some(keys.tls.spki_sha256()));
        assert_eq!(spki_sha256(b"not a certificate"), None);
    }

    #[tokio::test]
    async fn pinned_config_accepts_only_the_attested_key() {
        let keys = service_keys(1);
        let port = server(&keys).await;

        let mut tls =
            transport::tls_connect(pinned_config(Pin::Key(keys.tls.spki_sha256())), "127.0.0.1", port).await.unwrap();
        let mut got = Vec::new();
        tls.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ok");

        let other = service_keys(2).tls.spki_sha256();
        let err = transport::tls_connect(pinned_config(Pin::Key(other)), "127.0.0.1", port).await.unwrap_err();
        assert!(matches!(err, transport::ConnectError::Pin), "{err:?}");

        let seen = Arc::new(Mutex::new(None));
        transport::tls_connect(pinned_config(Pin::Record(seen.clone())), "localhost", port).await.unwrap();
        assert_eq!(*seen.lock().unwrap(), Some(keys.tls.spki_sha256()));
    }
}
