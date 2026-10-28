//! Passkey (WebAuthn ES256) admin signatures.
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use seal_crypto::sign::{admin_key_id, verify_admin};
use seal_crypto::CryptoError;
use seal_proto::codec::{b64url, labeled_digest};
use seal_proto::signed::{SigAlg, Signature};
use seal_proto::state::AdminKey;
use sha2::{Digest, Sha256};

const LABEL: &str = "seal/tenant-state/v1";
const MSG: &str = "the tenant state";
const RP_ID: &str = "seal.zone";

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).unwrap()
}
fn admin() -> AdminKey {
    let sec1 = signing_key().verifying_key().to_sec1_point(false).as_bytes().to_vec();
    AdminKey::WebAuthnEs256 { sec1, rp_id: RP_ID.into() }
}

struct Assertion {
    rp_id: String,
    flags: u8,
    kind: String,
    challenge: String,
    origin: String,
    cross_origin: Option<bool>,
}

impl Default for Assertion {
    fn default() -> Self {
        Self {
            rp_id: RP_ID.into(),
            flags: 0x05,
            kind: "webauthn.get".into(),
            challenge: b64url(&labeled_digest(LABEL, &MSG)),
            origin: "https://admin.seal.zone".into(),
            cross_origin: Some(false),
        }
    }
}

impl Assertion {
    fn parts(&self) -> (Vec<u8>, Vec<u8>) {
        let mut auth = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        auth.push(self.flags);
        auth.extend_from_slice(&7u32.to_be_bytes());
        let mut client = serde_json::json!({ "type": self.kind, "challenge": self.challenge, "origin": self.origin });
        if let Some(c) = self.cross_origin {
            client["crossOrigin"] = c.into();
        }
        (auth, serde_json::to_vec(&client).unwrap())
    }
    fn sign(&self) -> Signature {
        let (auth, client) = self.parts();
        signature(auth, client)
    }
}

fn signature(authenticator_data: Vec<u8>, client_data_json: Vec<u8>) -> Signature {
    let signed = [&authenticator_data[..], &Sha256::digest(&client_data_json)[..]].concat();
    let sig: DerSignature = signing_key().sign(&signed);
    Signature {
        signer: admin_key_id(&admin()),
        alg: SigAlg::WebAuthnEs256 { authenticator_data, client_data_json, sig: sig.as_bytes().to_vec() },
    }
}

fn check(sig: &Signature) -> Result<(), CryptoError> {
    verify_admin(&admin(), LABEL, &MSG, sig)
}

#[test]
fn a_valid_assertion_verifies() {
    check(&Assertion::default().sign()).unwrap();
    check(&Assertion { origin: "https://seal.zone".into(), cross_origin: None, ..Default::default() }.sign()).unwrap();
    // Extra flags (BE, BS, AT) are fine.
    check(&Assertion { flags: 0x1d, ..Default::default() }.sign()).unwrap();
    // The signature is over a different message under another label.
    assert_eq!(
        verify_admin(&admin(), "seal/other/v1", &MSG, &Assertion::default().sign()),
        Err(CryptoError::BadSignature)
    );
    assert_eq!(verify_admin(&admin(), LABEL, &"other", &Assertion::default().sign()), Err(CryptoError::BadSignature));
}

#[test]
fn flags_are_required() {
    for flags in [0x00, 0x01, 0x04, 0x40] {
        assert_eq!(
            check(&Assertion { flags, ..Default::default() }.sign()),
            Err(CryptoError::BadSignature),
            "{flags:#x}"
        );
    }
}

#[test]
fn rp_id_and_origin_are_checked() {
    assert_eq!(
        check(&Assertion { rp_id: "evil.zone".into(), ..Default::default() }.sign()),
        Err(CryptoError::BadSignature)
    );
    for origin in
        ["https://evil.zone", "http://seal.zone", "https://notseal.zone", "https://seal.zone.evil", "seal.zone"]
    {
        assert_eq!(
            check(&Assertion { origin: origin.into(), ..Default::default() }.sign()),
            Err(CryptoError::BadSignature),
            "{origin}"
        );
    }
    assert_eq!(
        check(&Assertion { cross_origin: Some(true), ..Default::default() }.sign()),
        Err(CryptoError::BadSignature)
    );
    // The key's RP ID must match what the authenticator scoped the credential to.
    let other_rp = match admin() {
        AdminKey::WebAuthnEs256 { sec1, .. } => AdminKey::WebAuthnEs256 { sec1, rp_id: "admin.seal.zone".into() },
        k => k,
    };
    assert_eq!(verify_admin(&other_rp, LABEL, &MSG, &Assertion::default().sign()), Err(CryptoError::BadSignature));
}

#[test]
fn client_data_is_checked() {
    assert_eq!(
        check(&Assertion { kind: "webauthn.create".into(), ..Default::default() }.sign()),
        Err(CryptoError::BadSignature)
    );
    assert_eq!(
        check(&Assertion { challenge: b64url(&[0; 32]), ..Default::default() }.sign()),
        Err(CryptoError::BadSignature)
    );
    // Padded base64 is a different string.
    let padded = format!("{}=", Assertion::default().challenge);
    assert_eq!(check(&Assertion { challenge: padded, ..Default::default() }.sign()), Err(CryptoError::BadSignature));
    let (auth, _) = Assertion::default().parts();
    assert_eq!(check(&signature(auth.clone(), b"not json".to_vec())), Err(CryptoError::BadSignature));
    let dup = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","challenge":"x","origin":"https://seal.zone"}}"#,
        Assertion::default().challenge
    );
    assert_eq!(check(&signature(auth, dup.into_bytes())), Err(CryptoError::BadSignature));
}

#[test]
fn tampering_is_refused() {
    let SigAlg::WebAuthnEs256 { authenticator_data, client_data_json, sig } = Assertion::default().sign().alg else {
        unreachable!()
    };
    let with = |a: Vec<u8>, c: Vec<u8>, s: Vec<u8>| Signature {
        signer: admin_key_id(&admin()),
        alg: SigAlg::WebAuthnEs256 { authenticator_data: a, client_data_json: c, sig: s },
    };
    // The sign counter is covered by the signature.
    let mut a = authenticator_data.clone();
    a[36] ^= 1;
    assert_eq!(check(&with(a, client_data_json.clone(), sig.clone())), Err(CryptoError::BadSignature));
    // So is clientDataJSON (an added space keeps it valid JSON with the same fields).
    let mut c = client_data_json.clone();
    c.push(b' ');
    assert_eq!(check(&with(authenticator_data.clone(), c, sig.clone())), Err(CryptoError::BadSignature));
    let mut s = sig.clone();
    let n = s.len() - 1;
    s[n] ^= 1;
    assert_eq!(check(&with(authenticator_data.clone(), client_data_json.clone(), s)), Err(CryptoError::BadSignature));
    assert_eq!(
        check(&with(authenticator_data[..36].to_vec(), client_data_json.clone(), sig.clone())),
        Err(CryptoError::BadSignature)
    );
    assert_eq!(
        check(&with(authenticator_data.clone(), client_data_json.clone(), vec![])),
        Err(CryptoError::BadSignature)
    );

    // High-S signatures (which authenticators emit) verify like their low-S twin.
    let parsed = p256::ecdsa::Signature::from_der(&sig).unwrap();
    let (r, s_low) = (parsed.r(), parsed.s());
    let high = p256::ecdsa::Signature::from_scalars(r, -*s_low).unwrap();
    let high_der = high.to_der().as_bytes().to_vec();
    check(&with(authenticator_data.clone(), client_data_json.clone(), high_der)).unwrap();
}

#[test]
fn key_shape_and_algorithm_must_match() {
    let sig = Assertion::default().sign();
    let compressed = AdminKey::WebAuthnEs256 {
        sec1: signing_key().verifying_key().to_sec1_point(true).as_bytes().to_vec(),
        rp_id: RP_ID.into(),
    };
    assert_eq!(verify_admin(&compressed, LABEL, &MSG, &sig), Err(CryptoError::BadSignature));
    let ed = AdminKey::Ed25519 { public_key: seal_proto::PublicKey([1; 32]) };
    assert_eq!(verify_admin(&ed, LABEL, &MSG, &sig), Err(CryptoError::BadSignature));
    let ed25519_sig = seal_crypto::sign::SigningKey::from_seed(&[1; 32]).sign(LABEL, &MSG);
    assert_eq!(check(&ed25519_sig), Err(CryptoError::BadSignature));
}
