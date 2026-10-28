//! Canonical crypto vectors, v1. A fixed root secret goes through every derivation (platform
//! master key, guardian key, challenge key, tenant wrapping keys, service seeds and the keys built
//! from them, the TLS certificate), and a seeded deterministic generator (`common::TestRng`)
//! drives every randomized output (tickets, challenges, a session token, a sealed blob). The
//! results are in `tests/vectors/crypto-v1.json`; a change to any of them fails this test.
//!
//! A changed vector means already-sealed blobs, issued certificates or pinned keys stop
//! matching: KDF labels and field encodings never change within v1.
//!
//! Regenerate only for a deliberate change: `SEAL_WRITE_VECTORS=1 cargo test -p
//! sealzone-crypto --test vectors`, then review the diff of `crypto-v1.json`.
mod common;

use std::collections::BTreeMap;

use common::*;
use seal_crypto::blob::{BlobCipher, BlobSealer};
use seal_crypto::telemetry::{batch_aad, open_entries, seal_entries, TelemetryReaderKey};
use seal_crypto::{ServiceKeys, TenantWrappingKey};
use seal_proto::codec::canonical;
use seal_proto::release::ReleasedKeys;
use seal_proto::telemetry::{Operation, TelemetryBatch, TelemetryEntry, TelemetryEvent};
use seal_proto::ErrorCode;
use seal_proto::{PlatformId, ServiceKeyVersion, TenantKeyVersion, TrustedTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Vector {
    name: String,
    /// Hex of the value's bytes (raw keys, DER, canonical CBOR, token text).
    bytes: String,
    sha256: String,
}

struct Vectors(Vec<Vector>);

impl Vectors {
    fn raw(&mut self, name: impl Into<String>, bytes: &[u8]) {
        self.0.push(Vector {
            name: name.into(),
            bytes: hex::encode(bytes),
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    fn cbor<T: Serialize>(&mut self, name: impl Into<String>, value: &T) {
        self.raw(name, &canonical(value));
    }
}

const PLATFORMS: [PlatformId; 4] =
    [PlatformId::AzureSnpAci, PlatformId::AwsNitro, PlatformId::GcpConfidentialSpace, PlatformId::Sim];
fn platform_name(p: PlatformId) -> &'static str {
    std::str::from_utf8(seal_crypto::kdf::platform_bytes(p)).unwrap()
}

fn telemetry_entry(at: u64) -> TelemetryEntry {
    TelemetryEntry {
        at,
        tenant: tenant(),
        identity: Some(producer()),
        event: TelemetryEvent::Refused { operation: Operation::Seal, code: ErrorCode::NotAllowed },
    }
}

fn build() -> Vec<Vector> {
    let mut v = Vectors(Vec::new());
    let time = TrustedTime::exact(1_900_000_000);

    for p in PLATFORMS {
        let name = platform_name(p);
        let m = master(p);
        v.raw(format!("{name}/guardian-key/public"), &m.guardian_key().public_key().0);
        let challenge = m.challenge_key().issue(&time, &mut TestRng::new(1));
        m.challenge_key().verify(&challenge, &time).unwrap();
        v.cbor(format!("{name}/guardian-challenge"), &challenge);
        for tkv in [1, 2] {
            v.raw(
                format!("{name}/tenant-wrapping-key/v{tkv}/public"),
                &m.tenant_wrapping_key(&tenant(), &root_id(), TenantKeyVersion(tkv)).public_key().0,
            );
        }
        v.cbor(
            format!("{name}/tenant-wrap-key/v1/signed"),
            &m.tenant_wrap_key(&tenant(), &root_id(), TenantKeyVersion(1)),
        );
    }

    // Service keys: every seed, every public half, the certificate and the TLS identity, on Sim.
    let m = master(PlatformId::Sim);
    let released = m.release_service(&tenant(), &root_id(), ServiceKeyVersion(2));
    let ReleasedKeys::Service { token, ingest, telemetry, tls, ticket, certificate, .. } = &released else {
        unreachable!()
    };
    for (seed, bytes) in
        [("token", token), ("ingest", ingest), ("telemetry", telemetry), ("tls", tls), ("ticket", ticket)]
    {
        v.raw(format!("sim/service/v2/seed/{seed}"), bytes.expose());
    }
    v.cbor("sim/service/v2/certificate/signed", certificate);
    let keys = ServiceKeys::from_released(PlatformId::Sim, &released).unwrap();
    v.raw("sim/service/v2/ingest/public", &keys.ingest.public_key().0);
    v.raw("sim/service/v2/telemetry/public", &keys.telemetry.public_key().0);
    v.raw("sim/service/v2/tls/spki", &keys.tls.spki_der());
    v.raw("sim/service/v2/tls/spki-sha256", &keys.tls.spki_sha256());
    let names = ["acme.sim.seal.zone".to_string()];
    v.raw("sim/service/v2/tls/ca-certificate", &keys.tls.ca_certificate_der(&names).unwrap());
    v.raw("sim/service/v2/tls/leaf-certificate", &keys.tls.leaf_certificate_der(&names).unwrap());
    v.cbor("sim/service/v2/ticket", &keys.ticket.issue(&tenant(), &time, &mut TestRng::new(2)));

    let tenant_keys = m.release_tenant(&tenant(), &root_id(), &[TenantKeyVersion(1)]);
    let ReleasedKeys::Tenant { keys: tk, .. } = &tenant_keys else { unreachable!() };
    v.raw("sim/tenant/v1/seed", tk[0].1.expose());

    // A blob for two platforms, and a session token on it.
    let recipients = wrap_keys(&[PlatformId::AzureSnpAci, PlatformId::Sim], 1);
    let blob = BlobSealer::new(&recipients)
        .unwrap()
        .seal(b"sk-test-0123456789", policy(), producer(), 1_900_000_000, &mut TestRng::new(3))
        .unwrap();
    let wrapping = TenantWrappingKey::from_released(PlatformId::Sim, &tenant_keys).unwrap();
    assert_eq!(BlobCipher::new(&wrapping[0]).open(&blob).unwrap().secret(), b"sk-test-0123456789");
    v.cbor("blob/sealed", &blob);
    let token = keys.token.issue(&claims(blob, ServiceKeyVersion(2)), &mut TestRng::new(4));
    keys.token.redeem(token.expose()).unwrap();
    v.raw("token/session", token.expose().as_bytes());

    // A telemetry batch sealed to two readers; the first opens it.
    let readers = [TelemetryReaderKey::from_seed(&[0x71; 32]), TelemetryReaderKey::from_seed(&[0x72; 32])];
    v.raw("telemetry/reader/public", &readers[0].public_key().0);
    let entries = [telemetry_entry(1_900_000_000), telemetry_entry(1_900_000_001)];
    let (stream, sequence, first_entry) = ([0x5d; 16], 3, 40);
    v.raw("telemetry/batch/aad", &batch_aad(&tenant(), stream, sequence, first_entry, 2));
    let public: Vec<_> = readers.iter().map(|r| r.public_key()).collect();
    let mut rng = TestRng::new(5);
    let sealed = seal_entries(&tenant(), stream, sequence, first_entry, &entries, &public, &mut rng).unwrap();
    let batch = TelemetryBatch {
        tenant: tenant(),
        stream,
        sequence,
        first_entry,
        count: 2,
        from: 1_900_000_000,
        to: 1_900_000_001,
        entries: sealed,
        last: false,
    };
    assert_eq!(open_entries(&readers[0], &batch).unwrap(), entries);
    v.cbor("telemetry/batch/sealed", &batch);

    v.0
}

/// The derivations, recomputed from the `kdf` module's description with plain HKDF.
#[test]
fn derivations_follow_the_documented_layout() {
    use seal_crypto::kdf::*;
    let hkdf = |ikm: &[u8], label: &str, fields: &[&[u8]]| {
        let mut out = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(None, ikm).expand(&info(label, fields), &mut out).unwrap();
        out
    };
    let platform: &[u8] = b"aws_nitro";
    let mk = hkdf(root_secret().expose(), PLATFORM_MASTER_KEY_FROM_ROOT, &[platform]);
    let m = master(PlatformId::AwsNitro);

    let guardian = seal_crypto::sign::SigningKey::from_seed(&hkdf(&mk, GUARDIAN_KEY, &[platform]));
    assert_eq!(guardian.public_key(), m.guardian_key().public_key());

    let tenant_fields: [&[u8]; 4] = [platform, b"acme", &root_id().0, &7u32.to_be_bytes()];
    let ReleasedKeys::Tenant { keys, .. } = m.release_tenant(&tenant(), &root_id(), &[TenantKeyVersion(7)]) else {
        unreachable!()
    };
    assert_eq!(keys[0].1.expose(), hkdf(&mk, TENANT_WRAPPING_KEY, &tenant_fields));

    let ReleasedKeys::Service { token, ingest, telemetry, tls, ticket, .. } =
        m.release_service(&tenant(), &root_id(), ServiceKeyVersion(7))
    else {
        unreachable!()
    };
    for (label, seed) in [
        (TOKEN_SEED, token),
        (INGEST_SEED, ingest),
        (TELEMETRY_SEED, telemetry),
        (TLS_SEED, tls),
        (TICKET_SEED, ticket),
    ] {
        assert_eq!(seed.expose(), hkdf(&mk, label, &tenant_fields), "{label}");
    }

    // The challenge key MACs `canonical((value, expires_at))`.
    use hmac::{KeyInit, Mac};
    let challenge = m.challenge_key().issue(&TrustedTime::exact(5), &mut TestRng::new(9));
    let mut mac =
        <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&hkdf(&mk, GUARDIAN_CHALLENGE_KEY, &[platform])).unwrap();
    mac.update(&canonical(&(challenge.value, challenge.expires_at)));
    assert_eq!(<[u8; 32]>::from(mac.finalize().into_bytes()), challenge.mac);
}

#[test]
fn the_test_rng_is_fixed() {
    let mut r = TestRng::new(0);
    let mut out = [0u8; 40];
    rand::Rng::fill_bytes(&mut r, &mut out);
    let mut expected = Sha256::digest([[0u8; 32].as_slice(), &0u64.to_be_bytes()].concat()).to_vec();
    expected.extend_from_slice(&Sha256::digest([[0u8; 32].as_slice(), &1u64.to_be_bytes()].concat())[..8]);
    assert_eq!(out.to_vec(), expected);
}

#[test]
fn crypto_v1_vectors_are_unchanged() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/crypto-v1.json");
    let built = build();
    if std::env::var_os("SEAL_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
        return;
    }
    let stored: Vec<Vector> =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("tests/vectors/crypto-v1.json")).unwrap();
    let stored: BTreeMap<_, _> = stored.into_iter().map(|v| (v.name.clone(), v)).collect();
    let mut changed = Vec::new();
    for v in &built {
        match stored.get(&v.name) {
            Some(s) if s == v => {}
            Some(_) => changed.push(format!("changed: {}", v.name)),
            None => changed.push(format!("new, not in the file: {}", v.name)),
        }
    }
    for name in stored.keys() {
        if !built.iter().any(|v| &v.name == name) {
            changed.push(format!("removed: {name}"));
        }
    }
    assert!(
        changed.is_empty(),
        "crypto v1 vectors differ (see the rule at the top of this file):\n{}",
        changed.join("\n")
    );
}
