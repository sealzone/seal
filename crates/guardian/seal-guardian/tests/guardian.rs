//! `Guardian::boot` and `Guardian::handle` with sim evidence, the system clock and real keys:
//! released keys, response signatures, HPKE, challenges, and the platform pre-check.
#![cfg(feature = "sim")]

mod common;

use common::sim::*;
use common::*;
use seal_crypto::{EphemeralKey, ServiceKeys, SysRng, UnwrapErr};
use seal_guardian::client::{open_response, verify_response};
use seal_guardian::keysource::FileKeySource;
use seal_guardian::{Denial, Guardian, GuardianComponents, GuardianError, KeySource};
use seal_proto::codec::{from_canonical, labeled_digest};
use seal_proto::release::{
    KeyPurpose, KeyRequest, KeyResponse, ReleasedKeys, GUARDIAN_IDENTITY_LABEL, KEY_RESPONSE_LABEL,
    TENANT_WRAP_KEY_LABEL,
};
use seal_proto::{Evidence, PlatformId, ServiceKeyVersion, TenantKeyVersion, TrustedTime};
use seal_tee::sim::SystemClock;
use seal_tee::Clock;

struct Setup {
    world: World,
    tenant: Tenant,
    guardian: Guardian,
    _dir: TempDir,
}

async fn setup(cosign: bool) -> Setup {
    let mut world = World::new();
    let tenant = world.tenant("acme", cosign, versions(2, 3));
    let dir = TempDir::new();
    let guardian = boot(world.config(), ROOT, GUARDIAN_OLD, &dir).await;
    Setup { world, tenant, guardian, _dir: dir }
}

/// A request from an enclave measuring `ENCLAVE`, with sim evidence over its binding.
async fn enclave_request(s: &mut Setup, purpose: impl FnOnce(&Tenant) -> KeyPurpose) -> (KeyRequest, EphemeralKey) {
    let purpose = purpose(&s.tenant);
    let ephemeral = EphemeralKey::generate(&mut UnwrapErr(SysRng));
    let binding = binding(s.guardian.challenge(), ephemeral.public_key(), purpose);
    let evidence = attestor(ENCLAVE).attest(report_data(&binding)).await.unwrap();
    let release = s.world.release(enclave_manifest(ENCLAVE));
    let bundle = s.world.bundle(&s.tenant);
    (request(evidence, binding, release, Some(bundle)), ephemeral)
}

fn denial(result: Result<KeyResponse, GuardianError>) -> Denial {
    match result {
        Err(GuardianError::Denied(d)) => d,
        other => panic!("expected a denial, got {:?}", other.map(|_| "keys")),
    }
}

#[tokio::test]
async fn service_keys_round_trip() {
    let mut s = setup(false).await;
    let (req, ephemeral) = enclave_request(&mut s, service).await;
    let binding = req.binding.clone();
    let resp = s.guardian.handle(req).await.unwrap();

    // Signed by the guardian key over (binding digest, enc, ciphertext).
    let guardian = guardian_key(ROOT);
    verify_response(&guardian, &binding, &resp).unwrap();
    let message = (report_data(&binding), resp.hpke_enc.clone(), resp.ciphertext.clone());
    seal_crypto::sign::verify(&guardian, KEY_RESPONSE_LABEL, &message, &resp.signature).unwrap();

    // HPKE to the ephemeral key, AAD the binding: exactly the keys the master key derives.
    let keys = open_response(&ephemeral, &binding, &resp).unwrap();
    let expected = master(ROOT).release_service(&s.tenant.id, &s.tenant.root_id, ServiceKeyVersion(2));
    let (
        ReleasedKeys::Service { certificate, tls, service_key_version, .. },
        ReleasedKeys::Service { certificate: want, tls: want_tls, .. },
    ) = (&keys, &expected)
    else {
        panic!("service keys expected");
    };
    assert_eq!(*service_key_version, ServiceKeyVersion(2));
    assert_eq!(certificate, want);
    assert_eq!(tls.expose(), want_tls.expose());
    ServiceKeys::from_released(PlatformId::Sim, &keys).unwrap();
    let guardians = [(PlatformId::Sim, guardian)].into();
    seal_verify::verify_service_certificate(&guardians, certificate).unwrap();

    // Nobody else opens it, and it opens only for this binding.
    let other = EphemeralKey::generate(&mut UnwrapErr(SysRng));
    assert!(open_response(&other, &binding, &resp).is_err());
    let mut other_binding = binding.clone();
    other_binding.challenge.value[0] ^= 1;
    assert!(open_response(&ephemeral, &other_binding, &resp).is_err());
}

#[tokio::test]
async fn tampered_responses_fail_the_signature() {
    let mut s = setup(false).await;
    let (req, _) = enclave_request(&mut s, service).await;
    let binding = req.binding.clone();
    let resp = s.guardian.handle(req).await.unwrap();
    let guardian = guardian_key(ROOT);

    let mut tampered = resp.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(verify_response(&guardian, &binding, &tampered).is_err());
    let mut tampered = resp.clone();
    tampered.hpke_enc[0] ^= 1;
    assert!(verify_response(&guardian, &binding, &tampered).is_err());
    let mut other_binding = binding.clone();
    other_binding.ephemeral_public_key.0[0] ^= 1;
    assert!(verify_response(&guardian, &other_binding, &resp).is_err());
    assert!(verify_response(&key(99).public_key(), &binding, &resp).is_err());
}

#[tokio::test]
async fn tenant_keys_round_trip() {
    let mut s = setup(false).await;
    let (req, ephemeral) = enclave_request(&mut s, |t| tenant_keys(t, &[2, 3])).await;
    let binding = req.binding.clone();
    let resp = s.guardian.handle(req).await.unwrap();
    verify_response(&guardian_key(ROOT), &binding, &resp).unwrap();
    let released = open_response(&ephemeral, &binding, &resp).unwrap();
    let ReleasedKeys::Tenant { tenant, root_id, keys } = &released else {
        panic!("tenant keys expected");
    };
    assert_eq!((tenant, root_id), (&s.tenant.id, &s.tenant.root_id));
    let ReleasedKeys::Tenant { keys: want, .. } =
        master(ROOT).release_tenant(&s.tenant.id, &s.tenant.root_id, &[TenantKeyVersion(2), TenantKeyVersion(3)])
    else {
        unreachable!()
    };
    assert_eq!(keys, &want);
    // Each private key matches the public wrap key the guardian certifies for it.
    for key in seal_crypto::TenantWrappingKey::from_released(PlatformId::Sim, &released).unwrap() {
        let wrap = s.guardian.wrap_key(&s.tenant.id, &s.tenant.root_id, key.scope().tenant_key_version);
        seal_crypto::sign::verify(&guardian_key(ROOT), TENANT_WRAP_KEY_LABEL, &wrap.body, &wrap.signatures[0]).unwrap();
        assert_eq!(key.public_key(), wrap.body.public_key);
    }
}

#[tokio::test]
async fn cosigned_tenant_round_trip() {
    let mut s = setup(true).await;
    let (mut req, _) = enclave_request(&mut s, service).await;
    let refused = s.guardian.handle(req.clone()).await;
    assert_eq!(denial(refused), Denial::TenantCosign);
    req.tenant_cosign = Some(cosign(&s.tenant.id, ENCLAVE, ADMINS[0]));
    s.guardian.handle(req).await.unwrap();
}

#[tokio::test]
async fn forged_or_expired_challenges_are_refused() {
    let mut s = setup(false).await;
    let (req, _) = enclave_request(&mut s, service).await;

    // Same request, but a challenge whose MAC is not the guardian's.
    let mut forged = req.clone();
    forged.binding.challenge.mac[0] ^= 1;
    forged.evidence = attestor(ENCLAVE).attest(report_data(&forged.binding)).await.unwrap();
    assert_eq!(denial(s.guardian.handle(forged).await), Denial::Challenge);

    // A genuine challenge that expired.
    let mut expired = req.clone();
    expired.binding.challenge =
        master(ROOT).challenge_key().issue(&TrustedTime::exact(wall() - 61), &mut UnwrapErr(SysRng));
    expired.evidence = attestor(ENCLAVE).attest(report_data(&expired.binding)).await.unwrap();
    assert_eq!(denial(s.guardian.handle(expired).await), Denial::Challenge);

    // Another platform's challenge key.
    let mut other = req.clone();
    other.binding.challenge = seal_crypto::PlatformMasterKey::from_root_secret(
        PlatformId::AzureSnpAci,
        &seal_crypto::Key32::from_bytes(ROOT),
    )
    .challenge_key()
    .issue(&TrustedTime::exact(wall()), &mut UnwrapErr(SysRng));
    other.evidence = attestor(ENCLAVE).attest(report_data(&other.binding)).await.unwrap();
    assert_eq!(denial(s.guardian.handle(other).await), Denial::Challenge);

    // The original still works: challenges are stateless and reusable until they expire.
    s.guardian.handle(req.clone()).await.unwrap();
    s.guardian.handle(req).await.unwrap();
}

#[tokio::test]
async fn evidence_must_be_this_platform_and_verify_and_bind() {
    let mut s = setup(false).await;
    let (req, _) = enclave_request(&mut s, service).await;

    let mut nitro = req.clone();
    nitro.evidence = Evidence::AwsNitro { document: vec![1, 2, 3] };
    assert_eq!(denial(s.guardian.handle(nitro).await), Denial::WrongPlatform);

    let mut garbage = req.clone();
    garbage.evidence = Evidence::Sim { document: vec![0xa0] };
    assert!(matches!(s.guardian.handle(garbage).await, Err(GuardianError::Evidence(_))));

    // Evidence over another binding (e.g. lifted from another request).
    let mut lifted = req.clone();
    lifted.binding.ephemeral_public_key.0[0] ^= 1;
    assert_eq!(denial(s.guardian.handle(lifted).await), Denial::Binding);

    // Evidence of another measurement than the release.
    let mut other = req;
    other.evidence = attestor(GUARDIAN_NEW).attest(report_data(&other.binding)).await.unwrap();
    assert_eq!(denial(s.guardian.handle(other).await), Denial::MeasurementMismatch);
}

#[tokio::test]
async fn succession_releases_the_root() {
    let mut s = setup(false).await;
    let ephemeral = EphemeralKey::generate(&mut UnwrapErr(SysRng));
    let binding = binding(s.guardian.challenge(), ephemeral.public_key(), KeyPurpose::Succession);
    let evidence = attestor(GUARDIAN_NEW).attest(report_data(&binding)).await.unwrap();
    let release = s.world.release(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)));
    let req = request(evidence, binding.clone(), release, None);
    let resp = s.guardian.handle(req).await.unwrap();
    verify_response(&guardian_key(ROOT), &binding, &resp).unwrap();
    let ReleasedKeys::Root { platform, root } = open_response(&ephemeral, &binding, &resp).unwrap() else {
        panic!("root expected");
    };
    assert_eq!(platform, PlatformId::Sim);
    assert_eq!(root.expose(), ROOT);
}

#[tokio::test]
async fn anchors_name_the_state_in_force_under_the_guardian_key() {
    let mut s = setup(false).await;
    let now = s.world.now;
    // State 2 un-retires version 1 (widening) and waits a one-hour window state 1 sets.
    s.world.publish(&mut s.tenant, now - 7_200, |st| st.pending_window_secs = 3_600);
    s.world.publish(&mut s.tenant, now - 600, |st| st.tenant_key_versions.oldest_accepted = TenantKeyVersion(1));
    let bundle = s.world.bundle(&s.tenant);
    let anchor = s.guardian.anchor(&s.tenant.id, &s.tenant.root_id, &bundle).await.unwrap();
    assert_eq!(anchor.body.version, 2, "the pending state 3 is not in force");
    assert_eq!(anchor.body.platform, PlatformId::Sim);
    let key = guardian_key(ROOT);
    let label = seal_proto::state::TENANT_ANCHOR_LABEL;
    seal_crypto::sign::verify(&key, label, &anchor.body, &anchor.signatures[0]).unwrap();
    // Another chain's root id, or a bundle that does not verify, gets none.
    let other = seal_proto::TenantRootId([7; 32]);
    assert!(matches!(s.guardian.anchor(&s.tenant.id, &other, &bundle).await, Err(GuardianError::Denied(_))));
    let mut stale = bundle;
    stale.freshness.clear();
    assert!(matches!(s.guardian.anchor(&s.tenant.id, &s.tenant.root_id, &stale).await, Err(GuardianError::Denied(_))));
}

#[tokio::test]
async fn identity_commits_to_the_guardian_key() {
    let s = setup(false).await;
    let identity = s.guardian.identity([0x71; 32]).await.unwrap();
    assert_eq!((identity.platform, identity.runs_on), (PlatformId::Sim, PlatformId::Sim));
    assert_eq!(identity.guardian_key, guardian_key(ROOT));
    let verified = seal_attest::verify(&identity.evidence, &TrustedTime::exact(wall())).unwrap();
    assert_eq!(verified.measurement, GUARDIAN_OLD);
    assert_eq!(
        verified.report_data,
        labeled_digest(GUARDIAN_IDENTITY_LABEL, &([0x71u8; 32], PlatformId::Sim, identity.guardian_key))
    );
}

#[tokio::test]
async fn boot_checks_platform_and_key_source() {
    let world = World::new();
    let dir = TempDir::new();
    let path = dir.0.join("root");
    std::fs::write(&path, ROOT).unwrap();
    let components = |measurement| GuardianComponents {
        key_source: KeySource::File(FileKeySource::new(path.clone(), GUARDIAN_OLD)),
        attestor: attestor(measurement),
        clock: Clock::System(SystemClock::new(0)),
    };

    // The attestor must be for the platform the guardian runs on.
    let mut config = world.config();
    config.runs_on = PlatformId::AzureSnpAci;
    assert!(matches!(Guardian::boot(config, components(GUARDIAN_OLD)).await, Err(GuardianError::Tee(_))));

    // The file source releases the root only to its measurement.
    assert!(matches!(Guardian::boot(world.config(), components(GUARDIAN_NEW)).await, Err(GuardianError::Root(_))));

    // A root file of the wrong size is refused.
    std::fs::write(&path, [1u8; 31]).unwrap();
    assert!(matches!(Guardian::boot(world.config(), components(GUARDIAN_OLD)).await, Err(GuardianError::Root(_))));

    // An absent root file is created with a random root, which then stays.
    std::fs::remove_file(&path).unwrap();
    let first = Guardian::boot(world.config(), components(GUARDIAN_OLD)).await.unwrap();
    let created = std::fs::read(&path).unwrap();
    assert_eq!(created.len(), 32);
    let again = Guardian::boot(world.config(), components(GUARDIAN_OLD)).await.unwrap();
    assert_eq!(
        first.identity([0; 32]).await.unwrap().guardian_key,
        again.identity([0; 32]).await.unwrap().guardian_key
    );
}

/// The response's signed message has exactly the shape of the `guardian/key-response` wire vector.
#[test]
fn response_message_matches_the_wire_vector() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../shared/seal-proto/tests/vectors/wire-v1.json");
    let vectors: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vector = vectors.iter().find(|v| v["name"] == "guardian/key-response").unwrap();
    assert_eq!(vector["label"], KEY_RESPONSE_LABEL);
    let bytes = hex::decode(vector["bytes"].as_str().unwrap()).unwrap();
    let message: ([u8; 32], Vec<u8>, Vec<u8>) = from_canonical(&bytes).unwrap();
    assert_eq!(seal_proto::codec::canonical(&message), bytes);
    assert_eq!(hex::encode(labeled_digest(KEY_RESPONSE_LABEL, &message)), vector["labeled_digest"].as_str().unwrap());
}
