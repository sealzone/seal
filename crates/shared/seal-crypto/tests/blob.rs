//! Sealing and opening blobs across platforms, scopes and tampering.
mod common;

use common::*;
use proptest::prelude::*;
use seal_crypto::blob::{BlobCipher, BlobSealer};
use seal_crypto::CryptoError;
use seal_proto::blob::{Blob, DekWrap};
use seal_proto::session::PlatformTier;
use seal_proto::{PlatformId, TenantId, TenantKeyVersion, TenantRootId};

const PLATFORMS: [PlatformId; 3] = [PlatformId::AzureSnpAci, PlatformId::AwsNitro, PlatformId::GcpConfidentialSpace];

fn seal(secret: &[u8]) -> Blob {
    let recipients = wrap_keys(&PLATFORMS, 2);
    BlobSealer::new(&recipients).unwrap().seal(secret, policy(), 1_900_000_000, &mut sys_rng()).unwrap()
}

fn open_on(platform: PlatformId, blob: &Blob) -> Result<Vec<u8>, CryptoError> {
    let key = master(platform).tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(2));
    BlobCipher::new(&key).open(blob).map(|o| o.secret().to_vec())
}

#[test]
fn every_recipient_platform_opens_the_blob() {
    let blob = seal(b"sk-live-123");
    assert_eq!(blob.header.version, seal_proto::blob::BLOB_VERSION);
    assert_eq!(blob.header.tenant, tenant());
    assert_eq!(blob.header.root_id, root_id());
    assert_eq!(blob.header.tenant_key_version, TenantKeyVersion(2));
    assert_eq!(blob.header.created_at, 1_900_000_000);
    assert_eq!(blob.wraps.iter().map(DekWrap::platform).collect::<Vec<_>>(), PLATFORMS);
    blob.check_structure().unwrap();
    for p in PLATFORMS {
        assert_eq!(open_on(p, &blob).unwrap(), b"sk-live-123");
    }
    let key = master(PlatformId::AwsNitro).tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(2));
    let opened = BlobCipher::new(&key).open(&blob).unwrap();
    assert_eq!(opened.blob(), &blob);
    assert!(!format!("{opened:?}").contains("sk-live"));
    // Text form round-trips and still opens.
    let back: Blob = blob.to_string().parse().unwrap();
    assert_eq!(open_on(PlatformId::AzureSnpAci, &back).unwrap(), b"sk-live-123");
}

#[test]
fn fresh_ids_dek_and_nonces_every_time() {
    let (a, b) = (seal(b"x"), seal(b"x"));
    assert_ne!(a.header.blob_id, b.header.blob_id);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_ne!(a.wraps, b.wraps);
}

#[test]
fn platforms_without_a_wrap_cannot_open() {
    assert_eq!(open_on(PlatformId::Sim, &seal(b"x")), Err(CryptoError::NoWrapForPlatform));
}

#[test]
fn scope_mismatches_are_refused() {
    let blob = seal(b"x");
    let m = master(PlatformId::AzureSnpAci);
    let other_tenant = TenantId::new("bravo").unwrap();
    for key in [
        m.tenant_wrapping_key(&other_tenant, &root_id(), TenantKeyVersion(2)),
        m.tenant_wrapping_key(&tenant(), &TenantRootId([1; 32]), TenantKeyVersion(2)),
        m.tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(1)),
    ] {
        assert!(matches!(BlobCipher::new(&key).open(&blob), Err(CryptoError::Malformed(_))));
    }
    // A header rewritten to the key's scope still fails: the header is the wraps' and the
    // secret's associated data.
    let key = m.tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(3));
    let mut moved = blob.clone();
    moved.header.tenant_key_version = TenantKeyVersion(3);
    assert_eq!(BlobCipher::new(&key).open(&moved).unwrap_err(), CryptoError::Decrypt);
    // Another root's master key derives other wrap keys.
    let other_master = seal_crypto::PlatformMasterKey::from_root_secret(
        PlatformId::AzureSnpAci,
        &seal_crypto::Key32::from_bytes([9; 32]),
    );
    let key = other_master.tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(2));
    assert_eq!(BlobCipher::new(&key).open(&blob).unwrap_err(), CryptoError::Decrypt);
}

#[test]
fn every_tamper_is_refused() {
    let blob = seal(b"secret");
    let decrypt = Err(CryptoError::Decrypt);
    let open = |b: &Blob| open_on(PlatformId::AwsNitro, b);

    let mut t = blob.clone();
    t.header.blob_id.0[0] ^= 1;
    assert_eq!(open(&t), decrypt);
    let mut t = blob.clone();
    t.header.created_at += 1;
    assert_eq!(open(&t), decrypt);
    let mut t = blob.clone();
    t.nonce[0] ^= 1;
    assert_eq!(open(&t), decrypt);
    let mut t = blob.clone();
    t.ciphertext[0] ^= 1;
    assert_eq!(open(&t), decrypt);
    let mut t = blob.clone();
    t.ciphertext.pop();
    assert_eq!(open(&t), decrypt);
    let mut t = blob.clone();
    let DekWrap::Hpke { wrapped_dek, .. } = &mut t.wraps[1];
    wrapped_dek[3] ^= 1;
    assert_eq!(open(&t), decrypt);
    let mut t = blob.clone();
    let DekWrap::Hpke { enc, .. } = &mut t.wraps[1];
    enc[3] ^= 1;
    assert_eq!(open(&t), decrypt);
    // Another platform's wrap relabelled as this platform's.
    let mut t = blob.clone();
    let DekWrap::Hpke { platform, .. } = &mut t.wraps[0];
    *platform = PlatformId::AwsNitro;
    t.wraps.remove(1);
    assert_eq!(open(&t), decrypt);
    // Two wraps for one platform.
    let mut t = blob.clone();
    t.wraps.push(t.wraps[1].clone());
    assert!(matches!(open(&t), Err(CryptoError::Malformed(_))));

    // A changed policy no longer matches the sealed digest; a matching digest breaks the AEAD.
    let other_policy = seal_proto::policy::SecretPolicy::new("https://api.anthropic.com/v1", [app()]).unwrap();
    let mut t = blob.clone();
    t.policy = other_policy.clone();
    assert!(matches!(open(&t), Err(CryptoError::Malformed(_))));
    t.header.policy_digest = seal_proto::codec::labeled_digest(seal_proto::blob::POLICY_LABEL, &other_policy);
    assert_eq!(open(&t), decrypt);
    // Unsupported header version.
    let mut t = blob.clone();
    t.header.version = 1;
    assert!(matches!(open(&t), Err(CryptoError::Malformed(_))));
}

#[test]
fn sealer_validates_recipients() {
    assert!(matches!(BlobSealer::new(&[]), Err(CryptoError::Malformed(_))));
    let base = wrap_keys(&[PlatformId::AzureSnpAci, PlatformId::AwsNitro], 2);
    let mut mixed_version = base.clone();
    mixed_version[1] = wrap_keys(&[PlatformId::AwsNitro], 3).remove(0);
    let mut mixed_tenant = base.clone();
    mixed_tenant[1].tenant = TenantId::new("bravo").unwrap();
    let mut mixed_root = base.clone();
    mixed_root[1].root_id = TenantRootId([1; 32]);
    let mut duplicate = base.clone();
    duplicate[1] = duplicate[0].clone();
    for bad in [mixed_version, mixed_tenant, mixed_root, duplicate] {
        assert!(matches!(BlobSealer::new(&bad), Err(CryptoError::Malformed(_))));
    }
    // An unusable (low-order) recipient key.
    let mut low_order = base.clone();
    low_order[0].public_key = seal_proto::PublicKey([0; 32]);
    let err = BlobSealer::new(&low_order).unwrap().seal(b"x", policy(), 0, &mut sys_rng()).unwrap_err();
    assert!(matches!(err, CryptoError::Malformed(_)));
}

#[test]
fn recipients_below_min_platform_are_refused() {
    let sealed_only = policy().with_min_platform(PlatformTier::Sealed);
    let with_sim = wrap_keys(&[PlatformId::AzureSnpAci, PlatformId::Sim], 1);
    let err = BlobSealer::new(&with_sim).unwrap().seal(b"x", sealed_only.clone(), 0, &mut sys_rng());
    assert!(matches!(err, Err(CryptoError::Malformed(_))));
    let sealed = wrap_keys(&[PlatformId::AzureSnpAci], 1);
    BlobSealer::new(&sealed).unwrap().seal(b"x", sealed_only, 0, &mut sys_rng()).unwrap();
    // No minimum: any platform.
    BlobSealer::new(&with_sim).unwrap().seal(b"x", policy(), 0, &mut sys_rng()).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn any_secret_round_trips_and_any_ciphertext_bit_flip_fails(
        secret in proptest::collection::vec(any::<u8>(), 0..512),
        bit in any::<prop::sample::Index>(),
    ) {
        let recipients = wrap_keys(&[PlatformId::Sim], 1);
        let mut blob = BlobSealer::new(&recipients).unwrap().seal(&secret, policy(), 7, &mut sys_rng()).unwrap();
        let key = master(PlatformId::Sim).tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(1));
        let opened = BlobCipher::new(&key).open(&blob).unwrap();
        prop_assert_eq!(opened.secret(), &secret[..]);
        let i = bit.index(blob.ciphertext.len() * 8);
        blob.ciphertext[i / 8] ^= 1 << (i % 8);
        prop_assert_eq!(BlobCipher::new(&key).open(&blob).unwrap_err(), CryptoError::Decrypt);
    }
}
