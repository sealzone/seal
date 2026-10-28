//! An enclave's `GET /v1/attestation`, checked: the evidence (`seal_attest::verify`), that it
//! commits to the binding, the binding's age, the release (M-of-N + log, revocations, TCB) and
//! the guardian's `ServiceKeyCertificate` over the binding's keys, naming the expected tenant
//! (and root, when given). Without the certificate, an enclave could attest to keys it made
//! up itself, which a release still inside its time lock or one its tenant never co-signed
//! would do.
//!
//! What it does not check is which TLS key served the response: the SDK compares the key its
//! connection presented with `binding.tls_spki_sha256` itself. A caller that only encrypts to
//! `binding.ingest_public_key` (the browser, through a relay) needs no more: only an enclave
//! of this release, certified by the guardian for this tenant, holds that key.

use seal_proto::api::{AttestationBinding, AttestationResponse, ATTESTATION_BINDING_LABEL};
use seal_proto::codec::labeled_digest;
use seal_proto::freshness::ATTESTATION_MAX_AGE_SECS;
use seal_proto::release::{Component, ServiceKeyCertificate};
use seal_proto::{Measurement, TenantId, TenantRootId, TrustedTime, UnixTime};

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
    let time = TrustedTime::exact(now);
    let binding = &response.binding;

    let evidence = seal_attest::verify(&response.evidence, &time).map_err(|e| fail(format!("evidence: {e}")))?;
    if evidence.report_data != labeled_digest(ATTESTATION_BINDING_LABEL, binding) {
        return Err(fail("the evidence does not commit to this binding"));
    }
    if binding.attested_at.abs_diff(now) > ATTESTATION_MAX_AGE_SECS {
        return Err(fail(format!(
            "attestation from {} is more than {ATTESTATION_MAX_AGE_SECS} s from this clock ({now})",
            binding.attested_at
        )));
    }

    let release = ReleaseVerifier::new(trust.releases.clone())
        .verify(&response.release, &time)
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

    let cert = verify_service_certificate(&trust.guardians, &response.certificate).map_err(fail)?;
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
