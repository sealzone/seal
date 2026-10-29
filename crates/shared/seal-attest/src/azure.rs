//! Azure confidential containers on ACI (AMD SEV-SNP).
//!
//! Hardware evidence (the report and its VCEK):
//! - Baked per chip family: AMD's ARK and ASK (Milan, Genoa, Turin). The evidence carries only
//!   the VCEK, so both are baked. The family is the one whose ASK verifies the VCEK; on report
//!   versions 3 and later the report's CPUID family/model must agree (version 2 has none).
//! - ARK → ASK → VCEK at `time`; report signature ECDSA P-384 over the raw report bytes
//!   (never a re-encoding), `sig_algo` = 1, signing key = VCEK.
//! - The VCEK is bound to the report: its TCB extensions (`1.3.6.1.4.1.3704.1.3.{1,2,3,8,9}`)
//!   equal REPORTED_TCB, and its hwID (`…1.4`) equals CHIP_ID (masked chip IDs are refused).
//!   Without this, a VCEK of older firmware would pass `min_tcb`.
//! - Guest policy debug bit off; VMPL exactly 0.
//! - `tcb` from REPORTED_TCB by family: Milan/Genoa byte 0 `bootloader`, 1 `tee`, 6 `snp`,
//!   7 `microcode`; Turin byte 0 `fmc`, 1 `bootloader`, 2 `tee`, 3 `snp`, 7 `microcode`. Each
//!   is named after the family (`milan.snp`, `genoa.snp`, `turin.snp`), since each family
//!   numbers its firmware on its own scale: a floor for one family never applies to another.
//! - `report_data[0..32]` = Seal's binding, bytes 32..64 zero.
//!
//! Microsoft's UVM endorsement (COSE_Sign1, PS384), in either live format:
//! - legacy (UVM up to 0.2.9): protected text labels `iss`/`feed`, JSON payload with
//!   `x-ms-sevsnpvm-launchmeasurement` and `x-ms-sevsnpvm-guestsvn` (string or integer);
//! - CWT (0.2.10 and later): protected label 15 with `iss`, `sub` (the feed), `iat` and `svn`;
//!   the payload is the raw 48-byte launch measurement (COSE hash envelope, SHA-384).
//! - Issuer exactly
//!   `did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2`:
//!   the x5chain's root has that fingerprint and its leaf that EKU. Feed `ContainerPlat-AMD-UVM`.
//! - The x5chain is checked at the endorsement's own signed time, not at `time`: Microsoft's
//!   signing certificates last about a year, and current endorsements outlive them.
//! - Its launch measurement equals the report's MEASUREMENT; `uvm_svn` is its svn. The
//!   production floor (at least 100) is a `min_tcb` entry, not code.
//! - `Measurement = SHA-384("azure-snp-aci" || host_data)`, host_data = SHA-256 of the
//!   base64-decoded container security policy.
//!
//! Checks run cheapest first: the report's own fields, then the AMD chain and the VCEK
//! binding, then the report signature, then the endorsement.

mod endorsement;
mod report;
#[cfg(test)]
mod tests;

use seal_proto::release::Tcb;
use seal_proto::{Measurement, PlatformId, TrustedTime};
use sha2::{Digest, Sha384};

use crate::x509::reject;
use crate::{AttestError, VerifiedEvidence};

/// Hashed in front of `host_data` in `Measurement`.
const MEASUREMENT_LABEL: &[u8] = b"azure-snp-aci";

pub(crate) fn verify(
    report: &[u8],
    vcek_der: &[u8],
    uvm_endorsement: &str,
    time: &TrustedTime,
) -> Result<VerifiedEvidence, AttestError> {
    let hardware = report::verify(report, vcek_der, time.earliest(), time.latest())?;
    let uvm = endorsement::verify(uvm_endorsement)?;
    if uvm.launch_measurement != hardware.measurement {
        return Err(reject("UVM endorsement launch measurement does not match the report"));
    }
    let mut tcb = hardware.tcb;
    tcb.insert("uvm_svn".to_owned(), uvm.svn);
    Ok(VerifiedEvidence {
        platform: PlatformId::AzureSnpAci,
        measurement: measurement(&hardware.host_data),
        tcb: Tcb(tcb),
        report_data: hardware.report_data,
        deployment: None,
    })
}

/// The baked AMD ASK and ARK (PEM, ASK first) that certify `vcek_der`, for services that want
/// the whole chain (Microsoft Azure Attestation's `VcekCertChain`). `None` if no baked ASK
/// signed it. Checks only the signature: `verify` does the rest.
pub fn amd_chain_pem(vcek_der: &[u8]) -> Option<&'static str> {
    report::chain_pem_for(vcek_der)
}

/// Every `Tcb` component Azure evidence can carry: `uvm_svn` and each family's
/// `family.component`.
pub(crate) fn tcb_components() -> Vec<String> {
    let mut names = report::tcb_components();
    names.push("uvm_svn".to_owned());
    names
}

/// `Measurement` for a confidential-container policy hash (`host_data`).
pub fn measurement(host_data: &[u8; 32]) -> Measurement {
    Measurement(Sha384::new().chain_update(MEASUREMENT_LABEL).chain_update(host_data).finalize().into())
}
