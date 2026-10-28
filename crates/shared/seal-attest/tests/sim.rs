//! Simulator evidence: accepted only with the `sim` feature.

use seal_attest::{verify, AttestError};
use seal_proto::{Evidence, PlatformId, TrustedTime};

/// `sim::sign` of the document in `vector_document`, frozen: the attestor in `seal-tee` and
/// this verifier must agree on the bytes.
const VECTOR: &[u8] = include_bytes!("data/sim/evidence.cbor");

const NOW: TrustedTime = TrustedTime { now: 1_793_000_000, radius: 0 };

fn evidence(document: Vec<u8>) -> Evidence {
    Evidence::Sim { document }
}

#[cfg(not(feature = "sim"))]
#[test]
fn sim_evidence_is_refused_without_the_feature() {
    assert!(matches!(verify(&evidence(VECTOR.to_vec()), &NOW), Err(AttestError::Unsupported(PlatformId::Sim))));
    assert!(matches!(verify(&evidence(vec![]), &NOW), Err(AttestError::Unsupported(PlatformId::Sim))));
}

#[cfg(feature = "sim")]
mod with_sim {
    use ciborium::Value;
    use ed25519_dalek::Signer;
    use seal_attest::sim::{sign, Document, DEV_ROOT_SEED, LABEL};
    use seal_attest::VerifiedEvidence;
    use seal_proto::codec::labeled_digest;
    use seal_proto::release::Tcb;
    use seal_proto::Measurement;

    use super::*;

    fn vector_document() -> Document {
        Document {
            measurement: Measurement([0x11; 48]),
            report_data: [0x22; 32],
            tcb: Tcb([("svn".to_string(), 1)].into_iter().collect()),
        }
    }

    #[track_caller]
    fn assert_rejected(document: Vec<u8>, needle: &str) {
        match verify(&evidence(document), &NOW) {
            Err(AttestError::Rejected(msg)) => {
                assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}")
            }
            other => panic!("expected a rejection mentioning {needle:?}, got {other:?}"),
        }
    }

    fn cbor(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out).unwrap();
        out
    }

    fn vector_value() -> Value {
        ciborium::from_reader(VECTOR).unwrap()
    }

    fn entry<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
        let Value::Map(m) = v else { panic!("map") };
        &mut m.iter_mut().find(|(k, _)| k.as_text() == Some(key)).unwrap().1
    }

    #[test]
    fn round_trip() {
        let document = Document { measurement: Measurement([0xAB; 48]), report_data: [9; 32], tcb: Tcb::default() };
        let v = verify(&evidence(sign(&document)), &NOW).unwrap();
        assert_eq!(
            v,
            VerifiedEvidence {
                platform: PlatformId::Sim,
                measurement: document.measurement,
                tcb: Tcb::default(),
                report_data: [9; 32],
                deployment: None,
            }
        );
    }

    #[test]
    fn frozen_vector() {
        assert_eq!(sign(&vector_document()), VECTOR);
        let v = verify(&evidence(VECTOR.to_vec()), &NOW).unwrap();
        assert_eq!(v.measurement, Measurement([0x11; 48]));
        assert_eq!(v.report_data, [0x22; 32]);
        assert_eq!(v.tcb, vector_document().tcb);
    }

    #[test]
    fn signature_must_be_the_dev_roots() {
        // Any change to the document breaks the signature.
        let mut v = vector_value();
        *entry(entry(&mut v, "document"), "report_data") = Value::Bytes(vec![0x23; 32]);
        assert_rejected(cbor(&v), "signature does not verify");

        let mut v = vector_value();
        let Value::Bytes(sig) = entry(&mut v, "signature") else { panic!() };
        sig[0] ^= 1;
        assert_rejected(cbor(&v), "signature does not verify");

        // Signed by another key.
        let other = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut v = vector_value();
        let forged = other.sign(&labeled_digest(LABEL, &vector_document())).to_bytes();
        *entry(&mut v, "signature") = Value::Bytes(forged.to_vec());
        assert_rejected(cbor(&v), "signature does not verify");

        // The dev root, but another label.
        let dev = ed25519_dalek::SigningKey::from_bytes(&DEV_ROOT_SEED);
        let mut v = vector_value();
        let forged = dev.sign(&labeled_digest("seal/sim/other/v1", &vector_document())).to_bytes();
        *entry(&mut v, "signature") = Value::Bytes(forged.to_vec());
        assert_rejected(cbor(&v), "signature does not verify");
    }

    #[test]
    fn malformed_documents_are_refused() {
        assert_rejected(vec![], "sim evidence");
        assert_rejected(b"garbage".to_vec(), "sim evidence");
        assert_rejected([VECTOR, &[0]].concat(), "trailing bytes");

        let mut v = vector_value();
        let Value::Map(m) = &mut v else { panic!() };
        m.push((Value::from("extra"), Value::from(1)));
        assert_rejected(cbor(&v), "sim evidence");

        let mut v = vector_value();
        *entry(entry(&mut v, "document"), "measurement") = Value::Bytes(vec![0x11; 32]);
        assert_rejected(cbor(&v), "sim evidence");

        let mut v = vector_value();
        *entry(&mut v, "signature") = Value::Bytes(vec![0; 63]);
        assert_rejected(cbor(&v), "sim evidence");
    }
}
