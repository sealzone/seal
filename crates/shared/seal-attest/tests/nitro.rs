//! The NitroTPM document recorded on a live EC2 instance (source in `tests/data/README.md`)
//! through `seal_attest::nitro::verify_tpm`. Synthetic documents for each refusal are in
//! `src/nitro/tests.rs`.

use seal_attest::{nitro, verify, AttestError};
use seal_proto::{Evidence, TrustedTime};

/// `timestamp` of `tpm.cbor`, 2026-10-28T05:39:46Z. Its leaf certificate is valid from
/// 05:39:43 to 08:39:46.
const MADE: TrustedTime = TrustedTime { now: 1_793_165_986, radius: 2 };

fn document() -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/nitro/tpm.cbor", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn recorded_tpm_document_verifies() {
    let doc = nitro::verify_tpm(&document(), &MADE).unwrap();
    assert_eq!(doc.instance_id, "i-028581aad8f99d0b0");
    assert_eq!(doc.region, "us-east-1");
    assert_eq!(doc.module_id, "i-028581aad8f99d0b0-tpm0000000000000000");
    assert_eq!(doc.timestamp_ms, 1_793_165_986_667);
    assert_eq!(doc.nonce, b"sealnonce-0123456789abcdef0123456789abcdef");
    assert_eq!(doc.user_data.as_deref(), Some(b"sealuserdata".as_slice()));
    assert_eq!(doc.public_key, None);
    assert_eq!(doc.pcrs.len(), 24);
    // The boot of the AMI it ran (Amazon Linux 2023, standard boot), and AWS's fixed PCR0.
    assert!(hex::encode(doc.pcrs[&4]).starts_with("95a0cd16db81b751dcccc11d"));
    assert!(hex::encode(doc.pcrs[&0]).starts_with("6e901b16932f6e036747d7a5"));
}

#[test]
fn recorded_tpm_document_expires_with_its_leaf() {
    let after = TrustedTime { now: 1_793_165_986 + 3 * 3600 + 60, radius: 0 };
    let r = nitro::verify_tpm(&document(), &after);
    assert!(matches!(&r, Err(AttestError::Rejected(m)) if m.contains("certificate not valid")), "{r:?}");
}

#[test]
fn recorded_tpm_document_is_not_enclave_evidence() {
    let r = verify(&Evidence::AwsNitro { document: document() }, &MADE);
    assert!(matches!(&r, Err(AttestError::Rejected(m)) if m.contains("no pcrs")), "{r:?}");
}

#[test]
fn recorded_tpm_document_tampered_refused() {
    let mut doc = document();
    let at = doc.windows(12).position(|w| w == b"sealuserdata").unwrap();
    doc[at] ^= 1;
    let r = nitro::verify_tpm(&doc, &MADE);
    assert!(matches!(&r, Err(AttestError::Rejected(m)) if m.contains("signature does not verify")), "{r:?}");
}
