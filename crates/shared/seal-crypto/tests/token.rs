//! Session tokens: format, round trip, tampering, key and version separation.
mod common;

use common::*;
use seal_crypto::blob::BlobSealer;
use seal_crypto::{CryptoError, ServiceKeys};
use seal_proto::codec::{b64url, from_b64url};
use seal_proto::session::TOKEN_PREFIX;
use seal_proto::{PlatformId, ServiceKeyVersion, TenantId};

fn service_keys(v: u32) -> ServiceKeys {
    ServiceKeys::from_released(
        PlatformId::Sim,
        &master(PlatformId::Sim).release_service(&tenant(), &root_id(), ServiceKeyVersion(v)),
    )
    .unwrap()
}

fn blob() -> seal_proto::blob::Blob {
    let recipients = wrap_keys(&[PlatformId::Sim], 1);
    BlobSealer::new(&recipients).unwrap().seal(b"x", policy(), producer(), 1, &mut sys_rng()).unwrap()
}

fn raw(token: &str) -> Vec<u8> {
    from_b64url(token.strip_prefix(TOKEN_PREFIX).unwrap()).unwrap()
}
fn rebuild(raw: &[u8]) -> String {
    format!("{TOKEN_PREFIX}{}", b64url(raw))
}

#[test]
fn round_trip_and_format() {
    let keys = service_keys(3);
    let claims = claims(blob(), ServiceKeyVersion(3));
    let token = keys.token.issue(&claims, &mut sys_rng());
    let s = token.expose();
    assert!(s.starts_with("sealtok_"));
    assert!(!format!("{token:?}").contains(&s[8..]));
    let bytes = raw(s);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..5], &3u32.to_be_bytes());

    let back = keys.token.redeem(s).unwrap();
    assert_eq!(seal_proto::codec::canonical(&back), seal_proto::codec::canonical(&claims));
    // Every token has its own salt and nonce.
    let again = keys.token.issue(&claims, &mut sys_rng());
    assert_ne!(again.expose(), s);
    assert_ne!(raw(again.expose())[5..49], bytes[5..49]);
    // The same seed on another replica redeems it.
    assert!(service_keys(3).token.redeem(s).is_ok());
}

#[test]
fn tampering_and_wrong_keys_are_refused() {
    let keys = service_keys(2);
    let token = keys.token.issue(&claims(blob(), ServiceKeyVersion(2)), &mut sys_rng());
    let bytes = raw(token.expose());
    for i in [0usize, 4, 5, 36, 37, 48, 49, bytes.len() - 1] {
        let mut t = bytes.clone();
        t[i] ^= 1;
        let err = keys.token.redeem(&rebuild(&t)).unwrap_err();
        // Byte 0 is the format version: changing it is a parse error, never a decryption.
        if i == 0 {
            assert!(matches!(err, CryptoError::Malformed(_)), "{i}");
        } else {
            assert_eq!(err, CryptoError::Decrypt, "{i}");
        }
    }
    // Another version's key, or another tenant's.
    assert_eq!(service_keys(1).token.redeem(token.expose()).unwrap_err(), CryptoError::Decrypt);
    let other = ServiceKeys::from_released(
        PlatformId::Sim,
        &master(PlatformId::Sim).release_service(&TenantId::new("bravo").unwrap(), &root_id(), ServiceKeyVersion(2)),
    )
    .unwrap();
    assert_eq!(other.token.redeem(token.expose()).unwrap_err(), CryptoError::Decrypt);
    // Rewriting the version in the header to route to another key fails too.
    let mut t = bytes.clone();
    t[1..5].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(service_keys(1).token.redeem(&rebuild(&t)).unwrap_err(), CryptoError::Decrypt);
}

#[test]
fn malformed_tokens() {
    let keys = service_keys(1);
    let token = keys.token.issue(&claims(blob(), ServiceKeyVersion(1)), &mut sys_rng());
    let s = token.expose();
    for bad in [
        "",
        "sealtok_",
        "sealtok_!!!",
        &s[8..],
        &s.replacen("sealtok_", "sealtak_", 1),
        &rebuild(&raw(s)[..64]),
        &format!("{s}="),
    ] {
        assert!(matches!(keys.token.redeem(bad), Err(CryptoError::Malformed(_))), "{bad}");
    }
    assert!(matches!(keys.token.redeem("sealtok_AQ"), Err(CryptoError::Malformed(_))));
}

#[test]
fn claims_naming_another_version_are_refused() {
    let keys = service_keys(2);
    let token = keys.token.issue(&claims(blob(), ServiceKeyVersion(5)), &mut sys_rng());
    assert!(matches!(keys.token.redeem(token.expose()), Err(CryptoError::Malformed(_))));
}
