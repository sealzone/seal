//! Decoding and verifying attacker-chosen input never panics: blobs (text and CBOR), session
//! tokens, proof tickets, JWS tokens and JWK sets, WebAuthn and Ed25519 signatures, and sealed
//! telemetry. Each starts from a valid value and mutates it, so the mutation reaches the AEAD,
//! HPKE, signature and claims code rather than stopping at a length check.
mod common;

use std::str::FromStr;

use common::*;
use p256::ecdsa::signature::Signer;
use proptest::prelude::*;
use seal_crypto::blob::{BlobCipher, BlobSealer};
use seal_crypto::jws::{self, Jwk, JwkSet, JwsAlg};
use seal_crypto::sign::{verify, verify_admin, SigningKey};
use seal_crypto::telemetry::{open_entries, seal_entries, TelemetryReaderKey};
use seal_crypto::{ServiceKeys, TicketKey};
use seal_proto::blob::Blob;
use seal_proto::codec::{b64url, canonical, from_b64url, from_canonical};
use seal_proto::freshness::ProofTicket;
use seal_proto::session::TOKEN_PREFIX;
use seal_proto::signed::{SigAlg, Signature};
use seal_proto::state::AdminKey;
use seal_proto::telemetry::{TelemetryBatch, TelemetryEntry, TelemetryEvent};
use seal_proto::{BlobId, PlatformId, ServiceKeyVersion, TenantKeyVersion, TrustedTime};

fn edit(bytes: &mut Vec<u8>, edits: &[(prop::sample::Index, u8)], cut: Option<prop::sample::Index>) {
    if bytes.is_empty() {
        return;
    }
    for (at, byte) in edits {
        let i = at.index(bytes.len());
        bytes[i] = *byte;
    }
    if let Some(cut) = cut {
        bytes.truncate(cut.index(bytes.len()));
    }
}

fn edits() -> impl Strategy<Value = Vec<(prop::sample::Index, u8)>> {
    proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4)
}

fn service_keys() -> ServiceKeys {
    ServiceKeys::from_released(
        PlatformId::Sim,
        &master(PlatformId::Sim).release_service(&tenant(), &root_id(), ServiceKeyVersion(1)),
    )
    .unwrap()
}

fn blob() -> Blob {
    let recipients = wrap_keys(&[PlatformId::Sim], 1);
    BlobSealer::new(&recipients).unwrap().seal(b"sk-live-0123456789abcdef", policy(), 7, &mut sys_rng()).unwrap()
}

fn open(blob: &Blob) {
    let key = master(PlatformId::Sim).tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(1));
    let _ = BlobCipher::new(&key).open(blob);
}

const KID: &str = "k1";

fn es256_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap()
}

fn es256_jwk() -> serde_json::Value {
    let point = es256_key().verifying_key().to_sec1_point(false);
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "kid": KID, "use": "sig", "alg": "ES256",
        "x": b64url(point.x().unwrap()), "y": b64url(point.y().unwrap()),
    })
}

fn es256_token() -> String {
    let header = b64url(br#"{"alg":"ES256","typ":"JWT","kid":"k1"}"#);
    let payload = b64url(br#"{"iss":"https://issuer.example","aud":"seal:acme","exp":1900000000}"#);
    let input = format!("{header}.{payload}");
    let sig: p256::ecdsa::Signature = es256_key().sign(input.as_bytes());
    format!("{input}.{}", b64url(&sig.to_bytes()))
}

fn check_jws(token: &str, jwks: &[u8]) {
    let _ = jws::peek_header(token);
    let _ = jws::peek_payload(token);
    if let Ok(set) = JwkSet::from_json(jwks) {
        for key in set.keys() {
            let _ = jws::verify(token, key, key.alg());
            let _ = jws::verify(token, key, JwsAlg::Rs256);
        }
    }
    let key = Jwk::from_json(&es256_jwk()).unwrap();
    let _ = jws::verify(token, &key, JwsAlg::Es256);
}

fn webauthn_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[0x43; 32]).unwrap()
}

fn webauthn_admin() -> AdminKey {
    let sec1 = webauthn_key().verifying_key().to_sec1_point(false).as_bytes().to_vec();
    AdminKey::WebAuthnEs256 { sec1, rp_id: "seal.zone".into() }
}

/// A valid passkey assertion over `labeled_digest("seal/test/v1", 1u8)`, as CBOR.
fn webauthn_signature() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut auth = Sha256::digest(b"seal.zone").to_vec();
    auth.push(0x05);
    auth.extend_from_slice(&7u32.to_be_bytes());
    let challenge = b64url(&seal_proto::codec::labeled_digest("seal/test/v1", &1u8));
    let client = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get", "challenge": challenge, "origin": "https://console.seal.zone", "crossOrigin": false,
    }))
    .unwrap();
    let signed = [&auth[..], &Sha256::digest(&client)[..]].concat();
    let sig: p256::ecdsa::DerSignature = webauthn_key().sign(&signed);
    let signature = Signature {
        signer: seal_crypto::sign::admin_key_id(&webauthn_admin()),
        alg: SigAlg::WebAuthnEs256 { authenticator_data: auth, client_data_json: client, sig: sig.as_bytes().to_vec() },
    };
    assert!(verify_admin(&webauthn_admin(), "seal/test/v1", &1u8, &signature).is_ok());
    canonical(&signature)
}

fn check_signature(bytes: &[u8]) {
    let Ok(sig) = from_canonical::<Signature>(bytes) else { return };
    let ed = SigningKey::from_seed(&[0x44; 32]);
    let _ = verify(&ed.public_key(), "seal/test/v1", &1u8, &sig);
    let _ = verify_admin(&webauthn_admin(), "seal/test/v1", &1u8, &sig);
    let _ = verify_admin(&AdminKey::Ed25519 { public_key: ed.public_key() }, "seal/test/v1", &1u8, &sig);
}

fn telemetry_reader() -> TelemetryReaderKey {
    TelemetryReaderKey::from_seed(&[0x45; 32])
}

fn sealed_batch() -> TelemetryBatch {
    let entries = vec![TelemetryEntry {
        at: 10,
        tenant: tenant(),
        identity: None,
        event: TelemetryEvent::Seal {
            blob_id: BlobId([1; 8]),
            destination: "https://api.example".into(),
            apps: [app()].into(),
        },
    }];
    let sealed =
        seal_entries(&tenant(), [1; 16], 2, 30, &entries, &[telemetry_reader().public_key()], &mut sys_rng()).unwrap();
    TelemetryBatch {
        tenant: tenant(),
        stream: [1; 16],
        sequence: 2,
        first_entry: 30,
        count: 1,
        from: 10,
        to: 10,
        entries: sealed,
        last: false,
    }
}

#[test]
fn seeds_are_valid() {
    let keys = service_keys();
    let b = blob();
    let token = keys.token.issue(&claims(b.clone(), ServiceKeyVersion(1)), &mut sys_rng());
    assert!(keys.token.redeem(token.expose()).is_ok());
    assert!(Blob::from_str(&b.to_string()).is_ok());
    let jwks = serde_json::to_vec(&serde_json::json!({ "keys": [es256_jwk()] })).unwrap();
    let set = JwkSet::from_json(&jwks).unwrap();
    assert!(jws::verify(&es256_token(), set.find(Some(KID)).unwrap(), JwsAlg::Es256).is_ok());
    assert!(open_entries(&telemetry_reader(), &sealed_batch()).is_ok());
    webauthn_signature();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let text = String::from_utf8_lossy(&bytes);
        let keys = service_keys();
        let _ = keys.token.redeem(&text);
        let _ = keys.token.redeem(&format!("{TOKEN_PREFIX}{}", b64url(&bytes)));
        if let Ok(blob) = Blob::from_str(&text) {
            open(&blob);
        }
        if let Ok(blob) = from_canonical::<Blob>(&bytes) {
            open(&blob);
        }
        check_jws(&text, &bytes);
        check_signature(&bytes);
        if let Ok(batch) = from_canonical::<TelemetryBatch>(&bytes) {
            let _ = open_entries(&telemetry_reader(), &batch);
        }
        if bytes.len() >= 64 {
            let ticket = ProofTicket {
                value: bytes[..32].try_into().unwrap(),
                expires_at: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
                mac: bytes[32..64].try_into().unwrap(),
            };
            let _ = TicketKey::verify(&keys.ticket, &tenant(), &ticket, &TrustedTime { now: u64::MAX, radius: u64::MAX });
        }
        if let Ok(key) = Jwk::rsa(None, &bytes, &[1, 0, 1]) {
            let _ = jws::verify(&text, &key, JwsAlg::Rs256);
        }
        let _ = Jwk::p256(None, &bytes[..bytes.len().min(32)], &bytes[bytes.len().min(32)..]);
    }

    #[test]
    fn mutated_blobs_never_panic(edits in edits(), cut in proptest::option::of(any::<prop::sample::Index>()), text in any::<bool>()) {
        let b = blob();
        if text {
            let mut s = b.to_string().into_bytes();
            edit(&mut s, &edits, cut);
            if let Ok(blob) = Blob::from_str(&String::from_utf8_lossy(&s)) {
                open(&blob);
            }
        } else {
            let mut cbor = canonical(&b);
            edit(&mut cbor, &edits, cut);
            if let Ok(blob) = from_canonical::<Blob>(&cbor) {
                let _ = Blob::from_str(&blob.to_string());
                open(&blob);
            }
        }
    }

    #[test]
    fn mutated_tokens_never_panic(edits in edits(), cut in proptest::option::of(any::<prop::sample::Index>())) {
        let keys = service_keys();
        let token = keys.token.issue(&claims(blob(), ServiceKeyVersion(1)), &mut sys_rng());
        let mut raw = from_b64url(token.expose().strip_prefix(TOKEN_PREFIX).unwrap()).unwrap();
        edit(&mut raw, &edits, cut);
        let _ = keys.token.redeem(&format!("{TOKEN_PREFIX}{}", b64url(&raw)));
        let mut text = token.expose().as_bytes().to_vec();
        edit(&mut text, &edits, None);
        let _ = keys.token.redeem(&String::from_utf8_lossy(&text));
    }

    #[test]
    fn mutated_jws_never_panic(edits in edits(), cut in proptest::option::of(any::<prop::sample::Index>()), target in 0..4u8) {
        let mut token = es256_token().into_bytes();
        let mut jwks = serde_json::to_vec(&serde_json::json!({ "keys": [es256_jwk()] })).unwrap();
        match target {
            0 => edit(&mut token, &edits, cut),
            1 => edit(&mut jwks, &edits, cut),
            _ => {
                // Inside one decoded part, so the JSON and signature checks see the change.
                let token_text = es256_token();
                let mut parts: Vec<Vec<u8>> = token_text.split('.').map(|p| from_b64url(p).unwrap()).collect();
                let part = &mut parts[usize::from(target - 1).min(2)];
                edit(part, &edits, cut);
                token = parts.iter().map(|p| b64url(p)).collect::<Vec<_>>().join(".").into_bytes();
            }
        }
        check_jws(&String::from_utf8_lossy(&token), &jwks);
    }

    #[test]
    fn mutated_signatures_never_panic(edits in edits(), cut in proptest::option::of(any::<prop::sample::Index>()), ed in any::<bool>()) {
        let mut sig = if ed {
            canonical(&SigningKey::from_seed(&[0x44; 32]).sign("seal/test/v1", &1u8))
        } else {
            webauthn_signature()
        };
        edit(&mut sig, &edits, cut);
        check_signature(&sig);
    }

    #[test]
    fn mutated_telemetry_never_panic(edits in edits(), cut in proptest::option::of(any::<prop::sample::Index>())) {
        let mut cbor = canonical(&sealed_batch());
        edit(&mut cbor, &edits, cut);
        if let Ok(batch) = from_canonical::<TelemetryBatch>(&cbor) {
            let _ = open_entries(&telemetry_reader(), &batch);
        }
    }

    #[test]
    fn mutated_released_keys_never_panic(edits in edits(), cut in proptest::option::of(any::<prop::sample::Index>()), tenant_keys in any::<bool>()) {
        let master = master(PlatformId::Sim);
        let released = if tenant_keys {
            master.release_tenant(&tenant(), &root_id(), &[TenantKeyVersion(1), TenantKeyVersion(2)])
        } else {
            master.release_service(&tenant(), &root_id(), ServiceKeyVersion(1))
        };
        let mut cbor = canonical(&released);
        edit(&mut cbor, &edits, cut);
        if let Ok(keys) = from_canonical(&cbor) {
            let _ = ServiceKeys::from_released(PlatformId::Sim, &keys);
            let _ = seal_crypto::TenantWrappingKey::from_released(PlatformId::Sim, &keys);
        }
    }
}
