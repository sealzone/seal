//! Synthetic documents signed by the test chains in `tests/data/nitro/test-ca` (one refusal
//! each). The recorded NitroTPM document through `verify_tpm` is in `tests/nitro.rs`; sources
//! in `tests/data/README.md`.

use ciborium::Value;
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use p384::ecdsa::signature::Signer;
use proptest::prelude::*;
use seal_proto::release::Tcb;
use seal_proto::{PlatformId, TrustedTime};
use sha2::{Digest, Sha256};

use super::{
    baked_root, instance_of, is_region, measurement, verify_enclave_with_root, verify_tpm_with_root, TpmDocument,
    ROOT_PEM,
};
use crate::x509::Cert;
use crate::AttestError;

macro_rules! data {
    ($path:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/nitro/test-ca/", $path)).as_slice()
    };
}

/// 2026-10-28T05:39:46Z: inside every test certificate's validity except `expired-leaf`.
const AT: TrustedTime = TrustedTime { now: 1_793_165_986, radius: 10 };

const MODULE_ID: &str = "i-0123456789abcdef0-tpm0123456789abcdef";

fn pem(bytes: &[u8]) -> Cert {
    Cert::parse_pem_chain(bytes, "test").unwrap().remove(0)
}

fn root() -> Cert {
    pem(data!("root.pem"))
}

fn key() -> p384::ecdsa::SigningKey {
    p384::ecdsa::SigningKey::from_slice(data!("leaf-key.raw")).unwrap()
}

fn pcr(i: u8) -> Vec<u8> {
    vec![i + 1; 48]
}

/// The fields of a valid document: an enclave's (`pcrs`) or a NitroTPM's (`nitrotpm_pcrs`).
fn fields(pcrs_key: &str) -> Vec<(Value, Value)> {
    let pcrs = (0..24).map(|i| (Value::Integer(i.into()), Value::Bytes(pcr(i)))).collect();
    vec![
        (Value::Text("module_id".into()), Value::Text(MODULE_ID.into())),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (Value::Text("timestamp".into()), Value::Integer(1_793_165_986_000u64.into())),
        (Value::Text(pcrs_key.into()), Value::Map(pcrs)),
        (Value::Text("certificate".into()), Value::Bytes(pem(data!("leaf.pem")).der)),
        (
            Value::Text("cabundle".into()),
            Value::Array(vec![Value::Bytes(root().der), Value::Bytes(pem(data!("intermediate.pem")).der)]),
        ),
        (Value::Text("public_key".into()), Value::Null),
        (Value::Text("user_data".into()), Value::Bytes((0..32).collect())),
        (Value::Text("nonce".into()), Value::Bytes(b"seal-nonce".to_vec())),
    ]
}

fn set(fields: &mut Vec<(Value, Value)>, name: &str, value: Value) {
    match fields.iter_mut().find(|(k, _)| *k == Value::Text(name.into())) {
        Some(entry) => entry.1 = value,
        None => fields.push((Value::Text(name.into()), value)),
    }
}

fn remove(fields: &mut Vec<(Value, Value)>, name: &str) {
    fields.retain(|(k, _)| *k != Value::Text(name.into()));
}

fn sign_with(fields: Vec<(Value, Value)>, alg: iana::Algorithm, key: &p384::ecdsa::SigningKey) -> Vec<u8> {
    sign_payload(encode(fields), alg, key)
}

fn encode(fields: Vec<(Value, Value)>) -> Vec<u8> {
    let mut payload = Vec::new();
    ciborium::into_writer(&Value::Map(fields), &mut payload).unwrap();
    payload
}

fn sign_payload(payload: Vec<u8>, alg: iana::Algorithm, key: &p384::ecdsa::SigningKey) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(alg).build())
        .payload(payload)
        .create_signature(b"", |tbs| {
            let sig: p384::ecdsa::Signature = key.sign(tbs);
            sig.to_bytes().to_vec()
        })
        .build()
        .to_tagged_vec()
        .unwrap()
}

fn sign(fields: Vec<(Value, Value)>) -> Vec<u8> {
    sign_with(fields, iana::Algorithm::ES384, &key())
}

fn with(pcrs_key: &str, f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut v = fields(pcrs_key);
    f(&mut v);
    sign(v)
}

fn tpm(f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Result<TpmDocument, AttestError> {
    verify_tpm_with_root(&with("nitrotpm_pcrs", f), &AT, &root())
}

fn enclave(f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Result<crate::VerifiedEvidence, AttestError> {
    verify_enclave_with_root(&with("pcrs", f), &AT, &root())
}

#[track_caller]
fn assert_rejected<T: std::fmt::Debug>(r: Result<T, AttestError>, needle: &str) {
    match r {
        Err(AttestError::Rejected(msg)) => assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}"),
        other => panic!("expected a rejection mentioning {needle:?}, got {other:?}"),
    }
}

#[test]
fn baked_root_matches_aws() {
    assert_eq!(
        hex::encode(Sha256::digest(ROOT_PEM)),
        "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0"
    );
    // AWS's published fingerprint of the DER.
    assert_eq!(
        hex::encode(Sha256::digest(baked_root().unwrap().der)),
        "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
    );
}

#[test]
fn synthetic_tpm_document_verifies() {
    let doc = tpm(|_| {}).unwrap();
    assert_eq!(doc.instance_id, "i-0123456789abcdef0");
    assert_eq!(doc.region, "us-east-1");
    assert_eq!(doc.module_id, MODULE_ID);
    assert_eq!(doc.timestamp_ms, 1_793_165_986_000);
    assert_eq!(doc.pcrs.len(), 24);
    assert_eq!(doc.pcrs[&4].as_slice(), pcr(4));
    assert_eq!(doc.nonce, b"seal-nonce");
    assert_eq!(doc.user_data, Some((0..32).collect()));
    assert_eq!(doc.public_key, None);
}

#[test]
fn synthetic_enclave_document_verifies() {
    let v = enclave(|_| {}).unwrap();
    assert_eq!(v.platform, PlatformId::AwsNitro);
    let p = |i| pcr(i).try_into().unwrap();
    assert_eq!(v.measurement, measurement(&p(0), &p(1), &p(2)));
    assert_eq!(v.report_data, std::array::from_fn(|i| i as u8));
    assert_eq!(v.tcb, Tcb::default());
    assert_eq!(v.deployment, None);
}

#[test]
fn measurement_definition() {
    let (a, b, c) = ([1u8; 48], [2u8; 48], [3u8; 48]);
    let expected: [u8; 48] = sha2::Sha384::new()
        .chain_update(b"aws-nitro")
        .chain_update(a)
        .chain_update(b)
        .chain_update(c)
        .finalize()
        .into();
    assert_eq!(measurement(&a, &b, &c).0, expected);
}

#[test]
fn enclave_and_tpm_documents_do_not_pass_as_each_other() {
    assert_rejected(verify_enclave_with_root(&with("nitrotpm_pcrs", |_| {}), &AT, &root()), "no pcrs");
    assert_rejected(verify_tpm_with_root(&with("pcrs", |_| {}), &AT, &root()), "no nitrotpm_pcrs");
}

#[test]
fn debug_enclave_refused() {
    let r = enclave(|f| {
        let pcrs = (0..3).map(|i| (Value::Integer(i.into()), Value::Bytes(vec![0; 48]))).collect();
        set(f, "pcrs", Value::Map(pcrs));
    });
    assert!(matches!(r, Err(AttestError::DebugMode)), "{r:?}");
}

#[test]
fn enclave_binding_must_be_32_bytes() {
    assert_rejected(enclave(|f| set(f, "user_data", Value::Bytes(vec![0; 31]))), "not 32 bytes");
    assert_rejected(enclave(|f| remove(f, "user_data")), "no user_data");
}

#[test]
fn wrong_chain_refused() {
    let other_root = pem(data!("other-root.pem"));
    assert_rejected(verify_tpm_with_root(&with("nitrotpm_pcrs", |_| {}), &AT, &other_root), "does not start with");
    assert_rejected(
        verify_tpm_with_root(&with("nitrotpm_pcrs", |_| {}), &AT, &baked_root().unwrap()),
        "does not start with",
    );
    assert_rejected(
        tpm(|f| {
            set(
                f,
                "cabundle",
                Value::Array(vec![Value::Bytes(root().der), Value::Bytes(pem(data!("not-ca-intermediate.pem")).der)]),
            );
            set(f, "certificate", Value::Bytes(pem(data!("under-not-ca-leaf.pem")).der));
        }),
        "is not a CA",
    );
    // The leaf without the intermediate that signed it.
    assert_rejected(tpm(|f| set(f, "cabundle", Value::Array(vec![Value::Bytes(root().der)]))), "issuer does not match");
    assert_rejected(tpm(|f| set(f, "cabundle", Value::Array(vec![]))), "cabundle is empty");
    // A CA as the leaf.
    assert_rejected(
        tpm(|f| {
            set(f, "cabundle", Value::Array(vec![Value::Bytes(root().der)]));
            set(f, "certificate", Value::Bytes(pem(data!("intermediate.pem")).der));
        }),
        "certificate is a CA",
    );
}

#[test]
fn expired_refused() {
    assert_rejected(
        tpm(|f| set(f, "certificate", Value::Bytes(pem(data!("expired-leaf.pem")).der))),
        "certificate not valid",
    );
    let late = TrustedTime { now: 2_200_000_000, radius: 0 };
    assert_rejected(verify_tpm_with_root(&with("nitrotpm_pcrs", |_| {}), &late, &root()), "not valid");
}

#[test]
fn leaf_key_must_have_signed() {
    assert_rejected(
        tpm(|f| set(f, "certificate", Value::Bytes(pem(data!("other-key-leaf.pem")).der))),
        "signature does not verify",
    );
    let other = p384::ecdsa::SigningKey::from_slice(&[7u8; 48]).unwrap();
    let doc = sign_with(fields("nitrotpm_pcrs"), iana::Algorithm::ES384, &other);
    assert_rejected(verify_tpm_with_root(&doc, &AT, &root()), "signature does not verify");
}

#[test]
fn algorithms_other_than_es384_refused() {
    let doc = sign_with(fields("nitrotpm_pcrs"), iana::Algorithm::ES256, &key());
    assert_rejected(verify_tpm_with_root(&doc, &AT, &root()), "not signed with ES384");
}

#[test]
fn tampered_payload_refused() {
    let doc = with("nitrotpm_pcrs", |_| {});
    let at = doc.windows(10).position(|w| w == b"seal-nonce").unwrap();
    let mut tampered = doc.clone();
    tampered[at] ^= 1;
    assert_rejected(verify_tpm_with_root(&tampered, &AT, &root()), "signature does not verify");
}

#[test]
fn module_id_and_common_name_must_agree() {
    for bad in [
        "i-0123456789abcdef0",
        "i-0123456789abcdef0-tpm0123",
        "i-0123456789ABCDEF0-tpm0123456789abcdef",
        "x-0123456789abcdef0-tpm0123456789abcdef",
    ] {
        assert_rejected(tpm(|f| set(f, "module_id", Value::Text(bad.into()))), "is not <instance id>");
    }
    // The certificate names another instance.
    assert_rejected(
        tpm(|f| set(f, "certificate", Value::Bytes(pem(data!("other-cn-leaf.pem")).der))),
        "is not <module_id>.<region>.aws",
    );
}

#[test]
fn tpm_needs_a_nonce_and_every_pcr() {
    assert_rejected(tpm(|f| remove(f, "nonce")), "no nonce");
    assert_rejected(tpm(|f| set(f, "nonce", Value::Null)), "no nonce");
    assert_rejected(
        tpm(|f| {
            let pcrs = (0..23).map(|i| (Value::Integer(i.into()), Value::Bytes(pcr(i)))).collect();
            set(f, "nitrotpm_pcrs", Value::Map(pcrs));
        }),
        "no PCR23",
    );
}

#[test]
fn malformed_fields_refused() {
    assert_rejected(tpm(|f| set(f, "digest", Value::Text("SHA256".into()))), "digest is not SHA384");
    assert_rejected(tpm(|f| set(f, "nonce", Value::Bytes(vec![0; 1025]))), "at most 1024 bytes");
    assert_rejected(tpm(|f| set(f, "user_data", Value::Text("x".into()))), "user_data is not a byte string");
    assert_rejected(tpm(|f| set(f, "timestamp", Value::Integer((-1).into()))), "timestamp is not a u64");
    assert_rejected(tpm(|f| remove(f, "module_id")), "no module_id");
    assert_rejected(
        tpm(|f| set(f, "nitrotpm_pcrs", Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![1; 32]))]))),
        "PCR0 is not 48 bytes",
    );
    assert_rejected(
        tpm(|f| set(f, "nitrotpm_pcrs", Value::Map(vec![(Value::Integer(32.into()), Value::Bytes(pcr(0)))]))),
        "not 0..32",
    );
    assert_rejected(tpm(|f| f.push((Value::Text("nonce".into()), Value::Bytes(vec![1])))), "repeats nonce");
    assert_rejected(tpm(|f| f.push((Value::Integer(1.into()), Value::Null))), "not text");
    assert_rejected(verify_tpm_with_root(b"not cbor", &AT, &root()), "not a COSE_Sign1");
}

// --- arbitrary and mutated input ---

/// Up to eight byte overwrites.
fn mutations() -> impl Strategy<Value = Vec<(prop::sample::Index, u8)>> {
    proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8)
}

fn mutate(bytes: &[u8], at: &[(prop::sample::Index, u8)]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for (i, b) in at {
        let i = i.index(out.len());
        out[i] = *b;
    }
    out
}

/// Both kinds, checked against the test root.
fn both(document: &[u8]) {
    let _ = verify_enclave_with_root(document, &AT, &root());
    let _ = verify_tpm_with_root(document, &AT, &root());
}

const PCRS_KEYS: [&str; 2] = ["pcrs", "nitrotpm_pcrs"];

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        both(&bytes);
        let _ = super::verify_tpm(&bytes, &AT);
        // Signed, so the payload reaches the CBOR field checks.
        both(&sign_payload(bytes.clone(), iana::Algorithm::ES384, &key()));
        let text = String::from_utf8_lossy(&bytes);
        let _ = (instance_of(&text), is_region(&text));
    }

    #[test]
    fn mutated_documents_never_panic(at in mutations(), kind in 0..3usize) {
        let document = match PCRS_KEYS.get(kind) {
            Some(k) => with(k, |_| {}),
            None => include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/nitro/tpm.cbor")).to_vec(),
        };
        let document = mutate(&document, &at);
        both(&document);
        let _ = super::verify_tpm(&document, &TrustedTime { now: 1_793_165_986, radius: 2 });
    }

    /// Re-signed after the change, so the payload reaches every check and the signature verifies.
    #[test]
    fn mutated_payloads_never_panic(at in mutations(), kind in 0..2usize) {
        let payload = mutate(&encode(fields(PCRS_KEYS[kind])), &at);
        both(&sign_payload(payload, iana::Algorithm::ES384, &key()));
    }

    /// A changed certificate in an otherwise valid, signed document.
    #[test]
    fn mutated_certificates_never_panic(at in mutations(), kind in 0..2usize, entry in 0..3usize) {
        let document = with(PCRS_KEYS[kind], |f| {
            for (k, v) in f.iter_mut() {
                match (k, v, entry) {
                    (Value::Text(k), Value::Bytes(der), 0) if k == "certificate" => *der = mutate(der, &at),
                    (Value::Text(k), Value::Array(bundle), 1 | 2) if k == "cabundle" => {
                        if let Value::Bytes(der) = &mut bundle[entry - 1] {
                            *der = mutate(der, &at);
                        }
                    }
                    _ => {}
                }
            }
        });
        both(&document);
    }
}
