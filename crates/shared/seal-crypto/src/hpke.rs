//! HPKE base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM (RFC 9180).
//!
//! One single-shot message per encapsulation: `enc` is the 32-byte ephemeral public key and the
//! ciphertext carries the 16-byte tag. Uses: secrets are sealed to the ingest key
//! (`ingest_info`), the guardian seals `ReleasedKeys` to a requester's ephemeral key
//! (`KEY_RELEASE_INFO`), and blob sealing wraps DEKs to tenant wrap keys
//! (`DEK_WRAP_INFO || platform`, `open_wrap`).

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::{CryptoError, EphemeralKey, IngestKey, SecretBytes};

pub const INGEST_INFO_PREFIX: &[u8] = b"seal/ingest/v1";
pub const KEY_RELEASE_INFO: &[u8] = b"seal/key-release/v1";

type Kem = X25519HkdfSha256;

/// HPKE-open a DEK wrap with a tenant wrapping key (`info = DEK_WRAP_INFO || platform`).
pub(crate) fn open_wrap(
    key: &crate::TenantWrappingKey,
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    open(&key.secret, enc, ct, info, aad)
}

/// Returns `(encapsulated_key, ciphertext)`. `Malformed` when the recipient key is a
/// low-order point (the shared secret would be all zeros).
pub fn seal(
    recipient_public_key: &seal_proto::PublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl rand::CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&recipient_public_key.0)
        .map_err(|_| CryptoError::Malformed("HPKE recipient public key".into()))?;
    let (enc, ct) =
        hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, Kem>(&OpModeS::Base, &pk, info, plaintext, aad, rng)
            .map_err(|_| CryptoError::Malformed("HPKE recipient public key".into()))?;
    Ok((enc.to_bytes().to_vec(), ct))
}

pub fn open_ingest(
    key: &IngestKey,
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    open(&key.secret, enc, ct, info, aad)
}

pub fn open_ephemeral(
    key: &EphemeralKey,
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    open(&key.0, enc, ct, info, aad)
}

/// `INGEST_INFO_PREFIX || tenant`.
pub fn ingest_info(tenant: &seal_proto::TenantId) -> Vec<u8> {
    [INGEST_INFO_PREFIX, tenant.as_str().as_bytes()].concat()
}

/// Every failure (bad `enc`, low-order `enc`, wrong key, tampered ciphertext, `info` or `aad`)
/// is `Decrypt`.
pub(crate) fn open(
    secret: &x25519_dalek::StaticSecret,
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let sk_bytes = Zeroizing::new(secret.to_bytes());
    let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(sk_bytes.as_ref()).map_err(|_| CryptoError::Decrypt)?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| CryptoError::Decrypt)?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &sk, &enc, info, ct, aad)
        .map(SecretBytes::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// The receiver key pair RFC 9180's `DeriveKeyPair(ikm)` gives, for the RFC test vectors.
#[cfg(test)]
pub(crate) fn derive_keypair(ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let (sk, pk) = <Kem as hpke::Kem>::derive_keypair(ikm);
    (sk.to_bytes().into(), pk.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rng() -> impl rand::CryptoRng {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng)
    }

    #[test]
    fn round_trip_and_tamper() {
        let key = EphemeralKey::generate(&mut rng());
        let (enc, ct) = seal(&key.public_key(), KEY_RELEASE_INFO, b"aad", b"secret", &mut rng()).unwrap();
        assert_eq!(enc.len(), 32);
        assert_eq!(ct.len(), 6 + 16);
        assert_eq!(open_ephemeral(&key, &enc, &ct, KEY_RELEASE_INFO, b"aad").unwrap().expose(), b"secret");

        let other = EphemeralKey::generate(&mut rng());
        assert_eq!(open_ephemeral(&other, &enc, &ct, KEY_RELEASE_INFO, b"aad").unwrap_err(), CryptoError::Decrypt);
        assert_eq!(open_ephemeral(&key, &enc, &ct, b"other", b"aad").unwrap_err(), CryptoError::Decrypt);
        assert_eq!(open_ephemeral(&key, &enc, &ct, KEY_RELEASE_INFO, b"aaD").unwrap_err(), CryptoError::Decrypt);
        assert_eq!(open_ephemeral(&key, &enc[..31], &ct, KEY_RELEASE_INFO, b"aad").unwrap_err(), CryptoError::Decrypt);
        assert_eq!(open_ephemeral(&key, &[0; 32], &ct, KEY_RELEASE_INFO, b"aad").unwrap_err(), CryptoError::Decrypt);
        assert_eq!(open_ephemeral(&key, &enc, &ct[..15], KEY_RELEASE_INFO, b"aad").unwrap_err(), CryptoError::Decrypt);
        let mut bad_enc = enc.clone();
        bad_enc[0] ^= 1;
        assert_eq!(open_ephemeral(&key, &bad_enc, &ct, KEY_RELEASE_INFO, b"aad").unwrap_err(), CryptoError::Decrypt);
    }

    /// X25519 scalar clamping (RFC 7748): the `hpke` crate stores private keys clamped.
    fn clamp(mut k: Vec<u8>) -> Vec<u8> {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        k
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The RFC 9180 test-vector suite (CFRG `test-vectors.json`, the source of RFC 9180
    /// Appendix A) for exactly our suite: mode_base, KEM 0x0020 DHKEM(X25519, HKDF-SHA256),
    /// KDF 0x0001 HKDF-SHA256, AEAD 0x0002 AES-256-GCM; its first encryption (sequence 0) is
    /// what a single-shot open decrypts.
    #[test]
    fn rfc9180_x25519_sha256_aes256gcm_base() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let ikm_r = unhex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee");
        let ikm_e = unhex("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9");
        let sk_rm = unhex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d");
        let pk_rm = unhex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
        let enc = unhex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
        let aad = unhex("436f756e742d30");
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let ct = unhex("e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a");

        let (sk, pk) = derive_keypair(&ikm_r);
        assert_eq!((sk.to_vec(), pk.to_vec()), (clamp(sk_rm.clone()), pk_rm.clone()));
        assert_eq!(derive_keypair(&ikm_e).1.to_vec(), enc);

        let key = EphemeralKey(x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(sk_rm).unwrap()));
        assert_eq!(key.public_key().0.to_vec(), pk_rm);
        assert_eq!(open_ephemeral(&key, &enc, &ct, &info, &aad).unwrap().expose(), &pt[..]);
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(open_ephemeral(&key, &enc, &bad, &info, &aad).unwrap_err(), CryptoError::Decrypt);
    }

    /// RFC 9180 A.1.1 (the same KEM and KDF with AES-128-GCM): checks the published key
    /// schedule inputs our KEM reproduces.
    #[test]
    fn rfc9180_a1_keys() {
        let (sk, pk) = derive_keypair(&unhex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"));
        assert_eq!(sk.to_vec(), clamp(unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")));
        assert_eq!(pk.to_vec(), unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"));
        let (_, pk_e) = derive_keypair(&unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"));
        assert_eq!(pk_e.to_vec(), unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"));
    }

    #[test]
    fn low_order_recipient_is_refused() {
        // The all-zero point is low order: the DH output would be all zeros.
        let err = seal(&seal_proto::PublicKey([0; 32]), b"", b"", b"x", &mut rng()).unwrap_err();
        assert!(matches!(err, CryptoError::Malformed(_)));
    }

    #[test]
    fn ingest_info_is_prefix_then_tenant() {
        assert_eq!(ingest_info(&seal_proto::TenantId::new("acme").unwrap()), b"seal/ingest/v1acme");
    }

    proptest! {
        #[test]
        fn any_plaintext_round_trips_and_any_bit_flip_fails(
            pt in proptest::collection::vec(any::<u8>(), 0..256),
            aad in proptest::collection::vec(any::<u8>(), 0..32),
            bit in any::<prop::sample::Index>(),
        ) {
            let key = IngestKey { secret: x25519_dalek::StaticSecret::from([3; 32]) };
            let (enc, mut ct) = seal(&key.public_key(), INGEST_INFO_PREFIX, &aad, &pt, &mut rng()).unwrap();
            let opened = open_ingest(&key, &enc, &ct, INGEST_INFO_PREFIX, &aad).unwrap();
            prop_assert_eq!(opened.expose(), &pt[..]);
            let i = bit.index(ct.len() * 8);
            ct[i / 8] ^= 1 << (i % 8);
            prop_assert_eq!(open_ingest(&key, &enc, &ct, INGEST_INFO_PREFIX, &aad).unwrap_err(), CryptoError::Decrypt);
        }
    }
}
