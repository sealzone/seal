//! TEE evidence: what an enclave or guardian produces about itself. The variant is the
//! platform, so the platform and its evidence can never disagree. Verified by
//! `seal_attest::verify`; produced by `seal_tee::Attestor`. Not to be confused with
//! `integrity::EndpointEvidence`, which is about the app's endpoint, not a TEE.
//!
//! Every variant commits to 32 bytes of report data (an `AttestationBinding`,
//! `KeyRequestBinding` or guardian identity digest).

use serde::{Deserialize, Serialize};

use crate::{codec, PlatformId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum Evidence {
    /// SNP attestation report (report data in its first 32 bytes), the VCEK certificate and
    /// Microsoft's UVM endorsement (base64 COSE_Sign1, `reference-info-base64`).
    AzureSnpAci {
        #[serde(with = "codec::bytes_b64")]
        report: Vec<u8>,
        #[serde(with = "codec::bytes_b64")]
        vcek_der: Vec<u8>,
        uvm_endorsement: String,
    },
    /// NSM attestation document (COSE_Sign1), report data in `user_data`.
    AwsNitro {
        #[serde(with = "codec::bytes_b64")]
        document: Vec<u8>,
    },
    /// Confidential Space attestation token of type PKI, report data as its one nonce.
    GcpConfidentialSpace { token: String },
    /// Simulator document. Only `sim` builds accept it.
    Sim {
        #[serde(with = "codec::bytes_b64")]
        document: Vec<u8>,
    },
}

impl Evidence {
    pub fn platform(&self) -> PlatformId {
        match self {
            Evidence::AzureSnpAci { .. } => PlatformId::AzureSnpAci,
            Evidence::AwsNitro { .. } => PlatformId::AwsNitro,
            Evidence::GcpConfidentialSpace { .. } => PlatformId::GcpConfidentialSpace,
            Evidence::Sim { .. } => PlatformId::Sim,
        }
    }
}
