//! Ed25519 over `labeled_digest(label, msg)`.
//!
//! Ed25519 verification is strict (`verify_strict`: canonical `S`, no small-order keys or `R`).
//! Passkey (`SigAlg::WebAuthnEs256`) verification checks, in order: authenticator data of at
//! least 37 bytes whose RP ID hash is SHA-256 of the key's `rp_id`; the UP (0x01) and UV (0x04)
//! flags; `clientDataJSON` with `type == "webauthn.get"`, `challenge == base64url(message)`,
//! an `https` origin whose host is `rp_id` or a subdomain of it, and no `crossOrigin: true`;
//! then the ES256 signature (DER, either `S` half) over
//! `authenticator_data || SHA-256(client_data_json)`.

use std::collections::BTreeSet;

use ed25519_dalek::Signer as _;
use serde::Serialize;
use sha2::{Digest, Sha256};

use seal_proto::codec::{self, labeled_digest};
use seal_proto::signed::{SigAlg, Signature, Signed};
use seal_proto::state::AdminKey;
use seal_proto::{KeyId, PublicKey};

use crate::CryptoError;

pub struct SigningKey(pub(crate) ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate(rng: &mut impl rand::CryptoRng) -> Self {
        Self(ed25519_dalek::SigningKey::generate(rng))
    }
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }
    pub fn key_id(&self) -> KeyId {
        key_id(&self.public_key())
    }
    /// For key files: the 32-byte seed. Callers must zeroize.
    pub fn to_seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.0.to_bytes())
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SigningKey({})", seal_proto::KeyId(self.key_id().0))
    }
}

/// `KeyId` of an Ed25519 public key: SHA-256 of its 32 bytes.
pub fn key_id(public_key: &PublicKey) -> KeyId {
    KeyId(Sha256::digest(public_key.0).into())
}

impl SigningKey {
    /// `signer` is `self.key_id()`.
    pub fn sign<T: Serialize>(&self, label: &str, msg: &T) -> Signature {
        let digest = labeled_digest(label, msg);
        Signature { signer: self.key_id(), alg: SigAlg::Ed25519 { sig: self.0.sign(&digest).to_bytes().to_vec() } }
    }
}

fn verify_ed25519(public_key: &PublicKey, message: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key.0).map_err(|_| CryptoError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| CryptoError::BadSignature)?;
    key.verify_strict(message, &sig).map_err(|_| CryptoError::BadSignature)
}

/// Ed25519 only (release, log, witness, registrar, telemetry keys). `sig.signer` must be
/// `key_id(public_key)`.
pub fn verify<T: Serialize>(public_key: &PublicKey, label: &str, msg: &T, sig: &Signature) -> Result<(), CryptoError> {
    verify_digest(public_key, &labeled_digest(label, msg), sig)
}

fn verify_digest(public_key: &PublicKey, message: &[u8; 32], sig: &Signature) -> Result<(), CryptoError> {
    let SigAlg::Ed25519 { sig: bytes } = &sig.alg else {
        return Err(CryptoError::BadSignature);
    };
    if sig.signer != key_id(public_key) {
        return Err(CryptoError::BadSignature);
    }
    verify_ed25519(public_key, message, bytes)
}

/// `KeyId` of an admin key: an Ed25519 key's plain `key_id` (so `SigningKey::sign` names it
/// correctly), a passkey's SHA-256 of `canonical(key)`.
pub fn admin_key_id(key: &AdminKey) -> KeyId {
    match key {
        AdminKey::Ed25519 { public_key } => key_id(public_key),
        AdminKey::WebAuthnEs256 { .. } => KeyId(codec::digest(key)),
    }
}

/// Ed25519 or passkey (WebAuthn ES256, rules in `seal_proto::signed::SigAlg` and this module's
/// docs). The algorithm must match the key's kind, and `sig.signer` must be `admin_key_id(key)`,
/// so callers find the key by `signer` and a signature never counts for another key.
pub fn verify_admin<T: Serialize>(key: &AdminKey, label: &str, msg: &T, sig: &Signature) -> Result<(), CryptoError> {
    if sig.signer != admin_key_id(key) {
        return Err(CryptoError::BadSignature);
    }
    let message = labeled_digest(label, msg);
    match (key, &sig.alg) {
        (AdminKey::Ed25519 { public_key }, SigAlg::Ed25519 { sig }) => verify_ed25519(public_key, &message, sig),
        (
            AdminKey::WebAuthnEs256 { sec1, rp_id },
            SigAlg::WebAuthnEs256 { authenticator_data, client_data_json, sig },
        ) => webauthn::verify(sec1, rp_id, &message, authenticator_data, client_data_json, sig),
        _ => Err(CryptoError::BadSignature),
    }
}

mod webauthn {
    use p256::ecdsa::signature::Verifier;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};

    use crate::CryptoError;

    const FLAG_UP: u8 = 0x01;
    const FLAG_UV: u8 = 0x04;

    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
        #[serde(rename = "crossOrigin", default)]
        cross_origin: Option<bool>,
    }

    /// The host of an `https://host[:port]` origin.
    fn origin_host(origin: &str) -> Option<&str> {
        let rest = origin.strip_prefix("https://")?;
        let host = match rest.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => rest,
        };
        (!host.is_empty() && !host.contains(['/', '?', '#', '@'])).then_some(host)
    }

    fn origin_matches(origin: &str, rp_id: &str) -> bool {
        let Some(host) = origin_host(origin) else { return false };
        let host = host.to_ascii_lowercase();
        let rp_id = rp_id.to_ascii_lowercase();
        host == rp_id || host.strip_suffix(&rp_id).is_some_and(|prefix| prefix.ends_with('.'))
    }

    pub(super) fn verify(
        sec1: &[u8],
        rp_id: &str,
        message: &[u8; 32],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        sig: &[u8],
    ) -> Result<(), CryptoError> {
        let bad = |_| CryptoError::BadSignature;
        if authenticator_data.len() < 37 || rp_id.is_empty() {
            return Err(CryptoError::BadSignature);
        }
        let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        if authenticator_data[..32] != rp_id_hash {
            return Err(CryptoError::BadSignature);
        }
        let flags = authenticator_data[32];
        if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
            return Err(CryptoError::BadSignature);
        }
        let client: ClientData = serde_json::from_slice(client_data_json).map_err(|_| CryptoError::BadSignature)?;
        if client.kind != "webauthn.get"
            || client.challenge != seal_proto::codec::b64url(message)
            || !origin_matches(&client.origin, rp_id)
            || client.cross_origin == Some(true)
        {
            return Err(CryptoError::BadSignature);
        }
        if sec1.len() != 65 || sec1[0] != 0x04 {
            return Err(CryptoError::BadSignature);
        }
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).map_err(bad)?;
        let sig = p256::ecdsa::Signature::from_der(sig).map_err(bad)?;
        let sig = sig.normalize_s();
        let signed = [authenticator_data, &Sha256::digest(client_data_json)[..]].concat();
        key.verify(&signed, &sig).map_err(bad)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn origins() {
            assert!(origin_matches("https://seal.zone", "seal.zone"));
            assert!(origin_matches("https://app.seal.zone", "seal.zone"));
            assert!(origin_matches("https://seal.zone:8443", "seal.zone"));
            assert!(origin_matches("https://Seal.Zone", "seal.zone"));
            assert!(!origin_matches("http://seal.zone", "seal.zone"));
            assert!(!origin_matches("https://evilseal.zone", "seal.zone"));
            assert!(!origin_matches("https://seal.zone.evil", "seal.zone"));
            assert!(!origin_matches("https://seal.zone/path", "seal.zone"));
            assert!(!origin_matches("https://user@seal.zone", "seal.zone"));
            assert!(!origin_matches("https://", "seal.zone"));
        }
    }
}

/// Wraps `body` with one signature.
impl SigningKey {
    pub fn sign_into<T: Serialize>(&self, label: &str, body: T) -> Signed<T> {
        let sig = self.sign(label, &body);
        Signed { body, signatures: vec![sig] }
    }
}

/// Adds a signature to an existing `Signed<T>` (M-of-N collection). Replaces any signature
/// already naming this key, so a key appears at most once.
impl SigningKey {
    pub fn cosign<T: Serialize>(&self, label: &str, signed: &mut Signed<T>) {
        let sig = self.sign(label, &signed.body);
        signed.signatures.retain(|s| s.signer != sig.signer);
        signed.signatures.push(sig);
    }
}

/// Accepts if at least `threshold` signatures verify under DISTINCT keys from `trusted`.
/// Unknown signers and duplicates are ignored, never counted; so is a known signer's invalid
/// signature. A `threshold` of 0 is refused (`Malformed`): it would accept anything.
pub fn verify_threshold<T: Serialize>(
    trusted: &[PublicKey],
    threshold: usize,
    label: &str,
    signed: &Signed<T>,
) -> Result<(), CryptoError> {
    if threshold == 0 {
        return Err(CryptoError::Malformed("signature threshold 0".into()));
    }
    let message = labeled_digest(label, &signed.body);
    let mut counted = BTreeSet::new();
    for sig in &signed.signatures {
        if counted.contains(&sig.signer) {
            continue;
        }
        let Some(key) = trusted.iter().find(|k| key_id(k) == sig.signer) else {
            continue;
        };
        if verify_digest(key, &message, sig).is_ok() {
            counted.insert(sig.signer);
            if counted.len() >= threshold {
                return Ok(());
            }
        }
    }
    Err(CryptoError::Threshold { have: counted.len(), need: threshold })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_seed(&[n; 32])
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let k = key(1);
        let sig = k.sign("seal/test/v1", &"hello");
        verify(&k.public_key(), "seal/test/v1", &"hello", &sig).unwrap();
        assert_eq!(sig.signer, key_id(&k.public_key()));
        assert_eq!(SigningKey::from_seed(&k.to_seed()).public_key(), k.public_key());
        // Other label, message, key, signer id, or a flipped bit.
        assert_eq!(verify(&k.public_key(), "seal/other/v1", &"hello", &sig), Err(CryptoError::BadSignature));
        assert_eq!(verify(&k.public_key(), "seal/test/v1", &"hellO", &sig), Err(CryptoError::BadSignature));
        assert_eq!(verify(&key(2).public_key(), "seal/test/v1", &"hello", &sig), Err(CryptoError::BadSignature));
        let mut wrong_id = sig.clone();
        wrong_id.signer = KeyId([0; 32]);
        assert_eq!(verify(&k.public_key(), "seal/test/v1", &"hello", &wrong_id), Err(CryptoError::BadSignature));
        let mut flipped = sig.clone();
        let SigAlg::Ed25519 { sig: b } = &mut flipped.alg else { unreachable!() };
        b[10] ^= 1;
        assert_eq!(verify(&k.public_key(), "seal/test/v1", &"hello", &flipped), Err(CryptoError::BadSignature));
        let mut short = sig.clone();
        short.alg = SigAlg::Ed25519 { sig: vec![0; 63] };
        assert_eq!(verify(&k.public_key(), "seal/test/v1", &"hello", &short), Err(CryptoError::BadSignature));
        // A passkey signature is not an Ed25519 signature.
        let mut webauthn = sig;
        webauthn.alg = SigAlg::WebAuthnEs256 { authenticator_data: vec![], client_data_json: vec![], sig: vec![] };
        assert_eq!(verify(&k.public_key(), "seal/test/v1", &"hello", &webauthn), Err(CryptoError::BadSignature));
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 8032 section 7.1, TEST 1-3: the raw Ed25519 under `sign`/`verify`.
    #[test]
    fn ed25519_rfc8032() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, msg, sig) in cases {
            let k = SigningKey::from_seed(&unhex(seed).try_into().unwrap());
            let public = PublicKey(unhex(public).try_into().unwrap());
            assert_eq!(k.public_key(), public);
            let (msg, sig) = (unhex(msg), unhex(sig));
            assert_eq!(k.0.sign(&msg).to_bytes().to_vec(), sig);
            verify_ed25519(&public, &msg, &sig).unwrap();
            let mut bad = sig.clone();
            bad[63] ^= 0x10;
            assert_eq!(verify_ed25519(&public, &msg, &bad), Err(CryptoError::BadSignature));
        }
    }

    #[test]
    fn debug_shows_only_the_key_id() {
        let k = key(1);
        assert_eq!(format!("{k:?}"), format!("SigningKey({})", k.key_id()));
    }

    #[test]
    fn threshold_counts_distinct_trusted_valid_signers() {
        let label = "seal/test/v1";
        let (a, b, c, outsider) = (key(1), key(2), key(3), key(9));
        let trusted = [a.public_key(), b.public_key(), c.public_key()];
        let mut signed = a.sign_into(label, 42u32);
        verify_threshold(&trusted, 1, label, &signed).unwrap();
        assert_eq!(verify_threshold(&trusted, 2, label, &signed), Err(CryptoError::Threshold { have: 1, need: 2 }));

        // Duplicates never count twice, whether pushed raw or through cosign.
        a.cosign(label, &mut signed);
        assert_eq!(signed.signatures.len(), 1);
        signed.signatures.push(signed.signatures[0].clone());
        assert_eq!(verify_threshold(&trusted, 2, label, &signed), Err(CryptoError::Threshold { have: 1, need: 2 }));

        // Unknown signers are ignored.
        outsider.cosign(label, &mut signed);
        assert_eq!(verify_threshold(&trusted, 2, label, &signed), Err(CryptoError::Threshold { have: 1, need: 2 }));

        // A trusted key listed twice is still one key.
        let doubled = [a.public_key(), a.public_key()];
        assert_eq!(verify_threshold(&doubled, 2, label, &signed), Err(CryptoError::Threshold { have: 1, need: 2 }));

        // An invalid signature from a known key does not count.
        let mut forged = b.sign(label, &43u32);
        forged.signer = b.key_id();
        signed.signatures.push(forged);
        assert_eq!(verify_threshold(&trusted, 2, label, &signed), Err(CryptoError::Threshold { have: 1, need: 2 }));

        b.cosign(label, &mut signed);
        c.cosign(label, &mut signed);
        verify_threshold(&trusted, 3, label, &signed).unwrap();
        assert_eq!(verify_threshold(&trusted, 4, label, &signed), Err(CryptoError::Threshold { have: 3, need: 4 }));
        // Wrong label: nothing counts.
        assert_eq!(
            verify_threshold(&trusted, 1, "seal/x/v1", &signed),
            Err(CryptoError::Threshold { have: 0, need: 1 })
        );
        // Threshold 0 is refused, and an empty trusted set accepts nothing.
        assert!(matches!(verify_threshold(&trusted, 0, label, &signed), Err(CryptoError::Malformed(_))));
        assert_eq!(verify_threshold(&[], 1, label, &signed), Err(CryptoError::Threshold { have: 0, need: 1 }));
        // A changed body breaks every signature.
        signed.body = 44;
        assert_eq!(verify_threshold(&trusted, 1, label, &signed), Err(CryptoError::Threshold { have: 0, need: 1 }));
    }

    #[test]
    fn admin_ed25519() {
        let k = key(4);
        let admin = AdminKey::Ed25519 { public_key: k.public_key() };
        // An Ed25519 admin key is named by its plain key id, which `sign` writes as `signer`.
        assert_eq!(admin_key_id(&admin), k.key_id());
        let sig = k.sign("seal/test/v1", &1u8);
        verify_admin(&admin, "seal/test/v1", &1u8, &sig).unwrap();
        assert!(verify_admin(&admin, "seal/test/v1", &2u8, &sig).is_err());
        // A valid signature that names another signer does not count.
        let mut renamed = sig.clone();
        renamed.signer = KeyId(codec::digest(&admin));
        assert!(verify_admin(&admin, "seal/test/v1", &1u8, &renamed).is_err());
        let passkey = AdminKey::WebAuthnEs256 { sec1: vec![4; 65], rp_id: "seal.zone".into() };
        assert!(verify_admin(&passkey, "seal/test/v1", &1u8, &sig).is_err());
    }

    proptest! {
        #[test]
        fn any_message_round_trips_and_any_bit_flip_fails(msg in proptest::collection::vec(any::<u8>(), 0..64), bit in 0usize..512) {
            let k = key(5);
            let sig = k.sign("seal/test/v1", &msg);
            prop_assert!(verify(&k.public_key(), "seal/test/v1", &msg, &sig).is_ok());
            let mut bad = sig.clone();
            let SigAlg::Ed25519 { sig: b } = &mut bad.alg else { unreachable!() };
            b[bit / 8] ^= 1 << (bit % 8);
            prop_assert!(verify(&k.public_key(), "seal/test/v1", &msg, &bad).is_err());
        }
    }
}
