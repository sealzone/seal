//! An enclave's `GET /v1/attestation`, checked: the evidence (`seal_attest::verify`), that it
//! commits to the binding, the binding's age, the release (M-of-N + log, revocations, TCB) and
//! the guardian's `ServiceKeyCertificate` over the binding's keys, naming the expected tenant
//! (and root, when given). Without the certificate, an enclave could attest to keys it made
//! up itself, which a release still inside its time lock or one its tenant never co-signed
//! would do.
//!
//! What `verify` does not check is which TLS key served the response: the SDK compares the key
//! its connection presented with `binding.tls_spki_sha256` itself. Nor does a periodic
//! attestation prove that the connection ends in an attested replica: anyone holding the
//! service keys (copied out of a build since revoked, say) can present the TLS key and replay
//! one. `verify_challenged` checks a `ChallengedAttestation` (`GET /v1/attestation?nonce=`),
//! whose challenge key signed the caller's nonce and the connection's TLS exporter, and which
//! only a replica of an approved release can answer on that connection.
//!
//! A caller that only encrypts to `binding.ingest_public_key` (the browser, through a relay)
//! has no connection to the replica to bind: it is safe while nobody outside an approved
//! replica holds the ingest key, that is, until a revocation that also raises
//! `min_service_key_version`.

use seal_proto::api::{
    AttestationBinding, AttestationChallenge, AttestationKeyBinding, AttestationResponse, ChallengedAttestation,
    ATTESTATION_BINDING_LABEL, ATTESTATION_CHALLENGE_LABEL, ATTESTATION_KEY_LABEL,
};
use seal_proto::codec::labeled_digest;
use seal_proto::freshness::ATTESTATION_MAX_AGE_SECS;
use seal_proto::release::{Component, ReleaseEvidence, ServiceKeyCertificate, SignedServiceKeyCertificate};
use seal_proto::{Evidence, Measurement, TenantId, TenantRootId, TrustedTime, UnixTime};

use crate::{verify_service_certificate, ReleaseVerifier, Trust};

/// An attestation whose evidence, release, binding and guardian certificate checked out.
#[derive(Clone, Debug)]
pub struct VerifiedAttestation {
    pub binding: AttestationBinding,
    /// Already checked against the binding and the tenant.
    pub certificate: ServiceKeyCertificate,
    pub measurement: Measurement,
    /// The release's human version (`ReleaseManifest::version`).
    pub release_version: String,
}

/// Why an attestation did not verify; the message is safe to show.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct AttestationError(pub String);

fn fail(what: impl std::fmt::Display) -> AttestationError {
    AttestationError(what.to_string())
}

/// Every check on `response` but the TLS key that served it (above). Pure.
pub fn verify(
    response: &AttestationResponse,
    trust: &Trust,
    tenant: &TenantId,
    root_id: Option<&TenantRootId>,
    now: UnixTime,
) -> Result<VerifiedAttestation, AttestationError> {
    let attested = Attested {
        evidence: &response.evidence,
        binding: &response.binding,
        release: &response.release,
        certificate: &response.certificate,
    };
    attested.verify(labeled_digest(ATTESTATION_BINDING_LABEL, &response.binding), trust, tenant, root_id, now)
}

/// Every check on a `ChallengedAttestation` but the TLS key that served it: the challenge key
/// signed `nonce` (the caller's) and `tls_exporter` (of the caller's connection, label
/// `ATTESTATION_EXPORTER_LABEL`), and the evidence commits to the binding and that key; then
/// everything `verify` checks. Pure.
pub fn verify_challenged(
    response: &ChallengedAttestation,
    nonce: &[u8; 32],
    tls_exporter: &[u8; 32],
    trust: &Trust,
    tenant: &TenantId,
    root_id: Option<&TenantRootId>,
    now: UnixTime,
) -> Result<VerifiedAttestation, AttestationError> {
    let challenge = AttestationChallenge { nonce: *nonce, tls_exporter: *tls_exporter };
    seal_crypto::sign::verify(&response.challenge_key, ATTESTATION_CHALLENGE_LABEL, &challenge, &response.signature)
        .map_err(|_| fail("the challenge's signature does not verify for this nonce and connection"))?;
    let key_binding =
        AttestationKeyBinding { binding: response.binding.clone(), challenge_key: response.challenge_key };
    let attested = Attested {
        evidence: &response.evidence,
        binding: &response.binding,
        release: &response.release,
        certificate: &response.certificate,
    };
    attested.verify(labeled_digest(ATTESTATION_KEY_LABEL, &key_binding), trust, tenant, root_id, now)
}

/// The parts both responses share.
struct Attested<'a> {
    evidence: &'a Evidence,
    binding: &'a AttestationBinding,
    release: &'a ReleaseEvidence,
    certificate: &'a SignedServiceKeyCertificate,
}

impl Attested<'_> {
    /// Every check, with `report_data` the digest the evidence must commit to.
    fn verify(
        &self,
        report_data: [u8; 32],
        trust: &Trust,
        tenant: &TenantId,
        root_id: Option<&TenantRootId>,
        now: UnixTime,
    ) -> Result<VerifiedAttestation, AttestationError> {
        let time = TrustedTime::exact(now);
        let binding = self.binding;

        let evidence = seal_attest::verify(self.evidence, &time).map_err(|e| fail(format!("evidence: {e}")))?;
        if evidence.report_data != report_data {
            return Err(fail("the evidence does not commit to this binding"));
        }
        if binding.attested_at.abs_diff(now) > ATTESTATION_MAX_AGE_SECS {
            return Err(fail(format!(
                "attestation from {} is more than {ATTESTATION_MAX_AGE_SECS} s from this clock ({now})",
                binding.attested_at
            )));
        }

        let release = ReleaseVerifier::new(trust.releases.clone())
            .verify(self.release, &time)
            .map_err(|e| fail(format!("release: {e}")))?;
        let manifest = release.manifest();
        if manifest.component != Component::Enclave {
            return Err(fail("the release is not an enclave release"));
        }
        if manifest.platform != evidence.platform || manifest.measurement != evidence.measurement {
            return Err(fail("the evidence's measurement is not the release's"));
        }
        if manifest.service_key_version != binding.service_key_version {
            return Err(fail("the binding's service key version is not the release's"));
        }
        ReleaseVerifier::check_tcb(release.constraints(), evidence.platform, &evidence.tcb)
            .map_err(|e| fail(format!("release: {e}")))?;

        let cert = verify_service_certificate(&trust.guardians, self.certificate).map_err(fail)?;
        if cert.platform != evidence.platform
            || cert.service_key_version != binding.service_key_version
            || cert.tls_spki_sha256 != binding.tls_spki_sha256
            || cert.ingest_public_key != binding.ingest_public_key
            || cert.telemetry_public_keys != binding.telemetry_public_keys
        {
            return Err(fail("the guardian's certificate is for other keys than the attested ones"));
        }
        if &cert.tenant != tenant {
            return Err(fail(format!("the enclave serves tenant {}, not {}", cert.tenant, tenant)));
        }
        if root_id.is_some_and(|r| r != &cert.root_id) {
            return Err(fail(format!("the enclave serves another root chain of {} ({})", cert.tenant, cert.root_id)));
        }

        Ok(VerifiedAttestation {
            binding: binding.clone(),
            certificate: cert.clone(),
            measurement: evidence.measurement,
            release_version: manifest.version.clone(),
        })
    }
}
