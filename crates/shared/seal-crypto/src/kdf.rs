//! HKDF labels. Changing any of these changes every derived key: never edit, only add.
//! Every derivation's `info` is `label || len-prefixed fields`, platform first. Fields:
//! - tenant wrapping key (an X25519 seed): platform, tenant, root id, tenant key version;
//! - service seeds (token, ingest, telemetry, TLS, ticket): platform, tenant, root id, service key
//!   version. No key below the platform master key is shared across tenants or roots;
//! - guardian key, challenge key: platform only.
//!
//! Field bytes: the platform as its wire name (`azure_snp_aci`, `platform_bytes`), the tenant as
//! its name, the root id as its 32 bytes, versions as u32 big-endian. Every derivation from the
//! platform root or master key uses HKDF-SHA256 with no salt; a session token's AEAD key uses the
//! token's random salt.
//! Label strings are frozen and need not match type names (`seal/v1/emk` derives the
//! platform master key, `seal/v1/tenant-key` the tenant wrapping key).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use seal_proto::PlatformId;

use crate::Key32;

pub const PLATFORM_MASTER_KEY_FROM_ROOT: &str = "seal/v1/emk";
pub const TENANT_WRAPPING_KEY: &str = "seal/v1/tenant-key";
pub const TOKEN_SEED: &str = "seal/v1/token-seed";
pub const TOKEN_PER_TOKEN: &str = "seal/v1/token-aead";
pub const INGEST_SEED: &str = "seal/v1/ingest-seed";
pub const TELEMETRY_SEED: &str = "seal/v1/audit-seed";
pub const TLS_SEED: &str = "seal/v1/tls-seed";
pub const TLS_SCALAR: &str = "seal/v1/tls-p256-scalar";
pub const TLS_CA_SCALAR: &str = "seal/v1/tls-ca-p256-scalar";
pub const TICKET_SEED: &str = "seal/v1/challenge-seed";
pub const GUARDIAN_KEY: &str = "seal/v1/guardian-key";
pub const GUARDIAN_CHALLENGE_KEY: &str = "seal/v1/guardian-challenge";

/// Builds an HKDF `info`: `label`, then each field as u32-BE length || bytes.
pub fn info(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let len = label.len() + fields.iter().map(|f| 4 + f.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(label.as_bytes());
    for f in fields {
        let n = u32::try_from(f.len()).expect("HKDF info field longer than 4 GiB");
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// The platform's wire name, as KDF fields and HPKE `info`s carry it.
pub fn platform_bytes(platform: PlatformId) -> &'static [u8] {
    match platform {
        PlatformId::AzureSnpAci => b"azure_snp_aci",
        PlatformId::AwsNitro => b"aws_nitro",
        PlatformId::GcpConfidentialSpace => b"gcp_confidential_space",
        PlatformId::Sim => b"sim",
    }
}

/// HKDF-SHA256 extract-and-expand into `out`.
pub(crate) fn expand_into(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(salt, ikm).expand(info, out).expect("HKDF-SHA256 output length is within 255 blocks");
}

/// HKDF-SHA256 with no salt, 32 bytes out.
pub(crate) fn derive32(ikm: &[u8; 32], label: &str, fields: &[&[u8]]) -> Key32 {
    let mut out = Zeroizing::new([0u8; 32]);
    expand_into(None, ikm, &info(label, fields), out.as_mut());
    Key32::from_bytes(*out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_is_label_then_length_prefixed_fields() {
        assert_eq!(info("l", &[]), b"l");
        assert_eq!(
            info("ab", &[b"x", b"", b"yz"]),
            [&b"ab"[..], &[0, 0, 0, 1], b"x", &[0, 0, 0, 0], &[0, 0, 0, 2], b"yz"].concat()
        );
        // Length prefixes keep field boundaries apart.
        assert_ne!(info("l", &[b"ab", b"c"]), info("l", &[b"a", b"bc"]));
    }

    #[test]
    fn platform_bytes_are_the_wire_names() {
        for p in [PlatformId::AzureSnpAci, PlatformId::AwsNitro, PlatformId::GcpConfidentialSpace, PlatformId::Sim] {
            let wire = serde_json::to_value(p).unwrap();
            assert_eq!(wire.as_str().unwrap().as_bytes(), platform_bytes(p));
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 5869 A.1 and A.3 (HKDF-SHA256).
    #[test]
    fn hkdf_sha256_rfc5869() {
        let mut okm = [0u8; 42];
        expand_into(Some(&unhex("000102030405060708090a0b0c")), &[0x0b; 22], &unhex("f0f1f2f3f4f5f6f7f8f9"), &mut okm);
        assert_eq!(
            okm.to_vec(),
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
        expand_into(None, &[0x0b; 22], b"", &mut okm);
        assert_eq!(
            okm.to_vec(),
            unhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        );
    }

    #[test]
    fn labels_are_distinct() {
        let labels = [
            PLATFORM_MASTER_KEY_FROM_ROOT,
            TENANT_WRAPPING_KEY,
            TOKEN_SEED,
            TOKEN_PER_TOKEN,
            INGEST_SEED,
            TELEMETRY_SEED,
            TLS_SEED,
            TLS_SCALAR,
            TLS_CA_SCALAR,
            TICKET_SEED,
            GUARDIAN_KEY,
            GUARDIAN_CHALLENGE_KEY,
        ];
        let set: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(set.len(), labels.len());
    }
}
