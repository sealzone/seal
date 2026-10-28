//! Simulator evidence (feature `sim`, never in production), signed with Ed25519 by the dev
//! root derived from `DEV_ROOT_SEED`. The seed is public on purpose: sim evidence proves
//! nothing, and production builds refuse it before looking at it.
//!
//! `Evidence::Sim::document` is the canonical CBOR (`seal_proto::codec::canonical`) of the
//! map `{"document": Document, "signature": bstr(64)}`, where `Document` is the map
//! `{"measurement": bstr(48), "report_data": bstr(32), "tcb": {text: uint}}` and `signature`
//! is the Ed25519 signature by the dev root over the 32 bytes
//! `labeled_digest(LABEL, document)`. Unknown keys and trailing bytes are refused.
//! `seal_tee`'s sim attestor produces it with `sign`.

use ed25519_dalek::{Signer, SigningKey};
use seal_proto::codec::{self, labeled_digest};
use seal_proto::release::Tcb;
use seal_proto::{Measurement, PlatformId};
use serde::{Deserialize, Serialize};

use crate::x509::reject;
use crate::{AttestError, VerifiedEvidence};

/// Seed of the simulator's dev root key, shared with `seal_tee`'s sim attestor.
pub const DEV_ROOT_SEED: [u8; 32] = *b"seal/sim/dev-root/v1............";

/// Label of the signed digest.
pub const LABEL: &str = "seal/sim/evidence/v1";

/// What simulator evidence claims; `verify` returns it as `VerifiedEvidence`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub measurement: Measurement,
    #[serde(with = "codec::array_b64")]
    pub report_data: [u8; 32],
    /// Usually empty; tests set components to exercise `min_tcb`.
    pub tcb: Tcb,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    document: Document,
    #[serde(with = "codec::array_b64")]
    signature: [u8; 64],
}

fn dev_root() -> SigningKey {
    SigningKey::from_bytes(&DEV_ROOT_SEED)
}

/// The `Evidence::Sim` document bytes for `document`, signed by the dev root.
pub fn sign(document: &Document) -> Vec<u8> {
    let signature = dev_root().sign(&labeled_digest(LABEL, document)).to_bytes();
    codec::canonical(&Envelope { document: document.clone(), signature })
}

pub(crate) fn verify(document: &[u8]) -> Result<VerifiedEvidence, AttestError> {
    let mut rest = document;
    let envelope: Envelope = ciborium::from_reader(&mut rest).map_err(|e| reject(format!("sim evidence: {e}")))?;
    if !rest.is_empty() {
        return Err(reject("sim evidence: trailing bytes"));
    }
    let signature = ed25519_dalek::Signature::from_bytes(&envelope.signature);
    dev_root()
        .verifying_key()
        .verify_strict(&labeled_digest(LABEL, &envelope.document), &signature)
        .map_err(|_| reject("sim evidence: signature does not verify"))?;
    let Document { measurement, report_data, tcb } = envelope.document;
    Ok(VerifiedEvidence { platform: PlatformId::Sim, measurement, tcb, report_data, deployment: None })
}
