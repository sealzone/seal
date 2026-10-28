//! `KeyReleaseAuthorizer::authorize`: an accepting and a rejecting case for every check, in
//! the documented order. Facts are built directly; release evidence and tenant bundles are real.

mod common;

use common::*;
use seal_attest::VerifiedEvidence;
use seal_guardian::{Denial, GuardianConfig, KeyReleaseAuthorizer, RequestFacts};
use seal_proto::freshness::GuardianChallenge;
use seal_proto::release::{KeyPurpose, KeyRequest, ReleaseConstraints, ReleaseEvidence, Tcb};
use seal_proto::state::TenantBundle;
use seal_proto::{Evidence, Measurement, PlatformId, PublicKey, TenantKeyVersion, TenantRootId, TrustedTime};
use seal_verify::VerifyError;

fn challenge() -> GuardianChallenge {
    GuardianChallenge { value: [0x41; 32], expires_at: wall() + 60, mac: [0x42; 32] }
}

/// A request and the facts that accept it, unless a test changes one of them.
struct Case {
    config: GuardianConfig,
    req: KeyRequest,
    facts: RequestFacts,
}

impl Case {
    fn new(world: &World, purpose: KeyPurpose, release: ReleaseEvidence, bundle: Option<TenantBundle>) -> Self {
        let binding = binding(challenge(), PublicKey([0x69; 32]), purpose);
        let measurement = release.manifest.body.measurement;
        let facts = RequestFacts {
            evidence: VerifiedEvidence {
                platform: PlatformId::Sim,
                measurement,
                tcb: Tcb::default(),
                report_data: report_data(&binding),
                deployment: None,
            },
            time: TrustedTime::exact(world.now),
            challenge_ok: true,
        };
        let req = request(Evidence::Sim { document: vec![] }, binding, release, bundle);
        Self { config: world.config(), req, facts }
    }

    fn authorize(&self) -> Result<(), Denial> {
        // The bundles carry no anchors, so whose key is the guardian's own does not matter here.
        let permit =
            KeyReleaseAuthorizer::new(&self.config, PublicKey([0x47; 32])).authorize(&self.req, &self.facts)?;
        assert!(std::ptr::eq(permit.request(), &self.req), "the permit holds the exact approved request");
        Ok(())
    }

    /// Re-commits the evidence to the (changed) binding.
    fn rebind(&mut self) {
        self.facts.evidence.report_data = report_data(&self.req.binding);
    }
}

/// A service-key case for tenant `acme` (no co-signature, key versions 2..=3).
fn service_case() -> (World, Case) {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(2, 3));
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    let case = Case::new(&world, service(&tenant), release, Some(bundle));
    (world, case)
}

fn succession_case(serves: Option<PlatformId>) -> Case {
    let mut world = World::new();
    let release = world.release(guardian_manifest(GUARDIAN_NEW, serves));
    Case::new(&world, KeyPurpose::Succession, release, None)
}

#[test]
fn accepts_service_tenant_and_succession() {
    let (_, case) = service_case();
    case.authorize().unwrap();

    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(2, 3));
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    Case::new(&world, tenant_keys(&tenant, &[2, 3]), release, Some(bundle)).authorize().unwrap();

    succession_case(Some(PlatformId::Sim)).authorize().unwrap();
}

#[test]
fn protocol_version() {
    let (_, mut case) = service_case();
    case.req.protocol_version = 2;
    assert_eq!(case.authorize(), Err(Denial::ProtocolVersion));

    let (_, mut case) = service_case();
    case.req.binding.protocol_version = 2;
    case.rebind();
    assert_eq!(case.authorize(), Err(Denial::ProtocolVersion));
}

#[test]
fn challenge_invalid_or_expired() {
    let (_, mut case) = service_case();
    case.facts.challenge_ok = false;
    assert_eq!(case.authorize(), Err(Denial::Challenge));
    // Checked before the platform: a forged challenge learns nothing more.
    case.facts.evidence.platform = PlatformId::AwsNitro;
    assert_eq!(case.authorize(), Err(Denial::Challenge));
}

#[test]
fn wrong_platform() {
    let (_, mut case) = service_case();
    case.facts.evidence.platform = PlatformId::AzureSnpAci;
    assert_eq!(case.authorize(), Err(Denial::WrongPlatform));

    // A manifest for another platform, even with matching evidence.
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let release = world.release(seal_proto::release::ReleaseManifest {
        platform: PlatformId::AzureSnpAci,
        ..enclave_manifest(ENCLAVE)
    });
    let bundle = world.bundle(&tenant);
    let case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::WrongPlatform));
}

#[test]
fn platform_served_versus_platform_run_on() {
    // A guardian serving Azure, running on the simulator: enclave requests need Azure
    // evidence, succession requests the evidence of where the guardian runs.
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    let mut case = Case::new(&world, service(&tenant), release, Some(bundle));
    case.config.platform = PlatformId::AzureSnpAci;
    assert_eq!(case.authorize(), Err(Denial::WrongPlatform));

    let mut case = succession_case(Some(PlatformId::AzureSnpAci));
    case.config.platform = PlatformId::AzureSnpAci;
    case.authorize().unwrap();
    case.config.runs_on = PlatformId::GcpConfidentialSpace;
    assert_eq!(case.authorize(), Err(Denial::WrongPlatform));

    // A successor's manifest for another platform than its evidence's, the one the guardian runs on.
    let mut world = World::new();
    let release = world.release(seal_proto::release::ReleaseManifest {
        platform: PlatformId::AzureSnpAci,
        ..guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim))
    });
    let case = Case::new(&world, KeyPurpose::Succession, release, None);
    assert_eq!(case.authorize(), Err(Denial::WrongPlatform));
}

#[test]
fn binding_mismatch() {
    let (_, mut case) = service_case();
    case.facts.evidence.report_data[0] ^= 1;
    assert_eq!(case.authorize(), Err(Denial::Binding));

    // Evidence committed to another ephemeral key.
    let (_, mut case) = service_case();
    case.req.binding.ephemeral_public_key = PublicKey([0x6a; 32]);
    assert_eq!(case.authorize(), Err(Denial::Binding));
}

#[test]
fn wrong_component() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let release = world.release(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)));
    let bundle = world.bundle(&tenant);
    let case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::WrongComponent));
}

#[test]
fn succession_needs_a_guardian_serving_this_platform() {
    // Not a guardian.
    let mut world = World::new();
    let release = world.release(enclave_manifest(ENCLAVE));
    let case = Case::new(&world, KeyPurpose::Succession, release, None);
    assert_eq!(case.authorize(), Err(Denial::WrongComponent));
    // A guardian serving another platform, or none.
    assert_eq!(succession_case(Some(PlatformId::AwsNitro)).authorize(), Err(Denial::WrongComponent));
    assert_eq!(succession_case(None).authorize(), Err(Denial::WrongComponent));
}

#[test]
fn measurement_mismatch() {
    let (_, mut case) = service_case();
    case.facts.evidence.measurement = Measurement([0xe2; 48]);
    assert_eq!(case.authorize(), Err(Denial::MeasurementMismatch));
}

#[test]
fn release_short_of_time_lock() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let now = world.now;
    let release = world.release_at(enclave_manifest(ENCLAVE), now - 13 * DAY, now - 60);
    let bundle = world.bundle(&tenant);
    let case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert!(matches!(case.authorize(), Err(Denial::Release(VerifyError::TimeLock { .. }))));

    // A successor passes exactly the same rule.
    let mut world = World::new();
    let now = world.now;
    let release = world.release_at(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)), now - 13 * DAY, now - 60);
    let case = Case::new(&world, KeyPurpose::Succession, release, None);
    assert!(matches!(case.authorize(), Err(Denial::Release(VerifyError::TimeLock { .. }))));
}

#[test]
fn release_with_stale_checkpoint() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let now = world.now;
    let release = world.release_at(enclave_manifest(ENCLAVE), now - 20 * DAY, now - DAY - 3600);
    let bundle = world.bundle(&tenant);
    let case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::Release(VerifyError::StaleCheckpoint)));
}

#[test]
fn release_revoked() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    world.set_policy(ReleaseConstraints {
        revoked_measurements: [(PlatformId::Sim, [ENCLAVE].into())].into(),
        ..Default::default()
    });
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    let case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::Release(VerifyError::Revoked)));

    // Revocation applies to successors too.
    let mut world = World::new();
    world.set_policy(ReleaseConstraints {
        revoked_measurements: [(PlatformId::Sim, [GUARDIAN_NEW].into())].into(),
        ..Default::default()
    });
    let release = world.release(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)));
    let case = Case::new(&world, KeyPurpose::Succession, release, None);
    assert_eq!(case.authorize(), Err(Denial::Release(VerifyError::Revoked)));
}

#[test]
fn release_signatures_below_threshold() {
    let (_, mut case) = service_case();
    case.req.release.manifest.signatures.truncate(1);
    assert!(matches!(case.authorize(), Err(Denial::Release(VerifyError::ReleaseSignatures(_)))));
}

#[test]
fn tcb_below_floor() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let floor = Tcb([("snp".to_string(), 5)].into());
    world.set_policy(ReleaseConstraints { min_tcb: [(PlatformId::Sim, floor.clone())].into(), ..Default::default() });
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    let mut case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::Release(VerifyError::TcbTooLow)));
    case.facts.evidence.tcb = Tcb([("snp".to_string(), 4)].into());
    assert_eq!(case.authorize(), Err(Denial::Release(VerifyError::TcbTooLow)));
    case.facts.evidence.tcb = floor;
    case.authorize().unwrap();
}

#[test]
fn tenant_bundle_missing_or_stale() {
    let (_, mut case) = service_case();
    case.req.tenant = None;
    assert_eq!(case.authorize(), Err(Denial::Tenant));

    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let release = world.release(enclave_manifest(ENCLAVE));
    let now = world.now;
    let stale = world.bundle_at(&tenant, now - DAY - 60);
    let case = Case::new(&world, service(&tenant), release, Some(stale));
    assert_eq!(case.authorize(), Err(Denial::Tenant));
}

#[test]
fn tenant_bundle_for_another_tenant() {
    let mut world = World::new();
    let acme = world.tenant("acme", false, versions(1, 1));
    let other = world.tenant("other", false, versions(1, 1));
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&other);
    let case = Case::new(&world, service(&acme), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::Tenant));
}

#[test]
fn tenant_bundle_for_another_root() {
    let (_, mut case) = service_case();
    case.req.binding.purpose = KeyPurpose::Service { tenant: acme(), root_id: TenantRootId([9; 32]) };
    case.rebind();
    assert_eq!(case.authorize(), Err(Denial::Tenant));
    case.req.binding.purpose =
        KeyPurpose::Tenant { tenant: acme(), root_id: TenantRootId([9; 32]), tenant_key_versions: vec![] };
    case.rebind();
    assert_eq!(case.authorize(), Err(Denial::Tenant));
}

#[test]
fn tenant_cosign_required() {
    let mut world = World::new();
    let tenant = world.tenant("acme", true, versions(1, 1));
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    let mut case = Case::new(&world, service(&tenant), release, Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::TenantCosign));
    // Another measurement, another tenant, or a key that is not the tenant's admin.
    case.req.tenant_cosign = Some(cosign(&tenant.id, Measurement([0xe2; 48]), ADMINS[0]));
    assert_eq!(case.authorize(), Err(Denial::TenantCosign));
    case.req.tenant_cosign = Some(cosign(&seal_proto::TenantId::new("other").unwrap(), ENCLAVE, ADMINS[0]));
    assert_eq!(case.authorize(), Err(Denial::TenantCosign));
    case.req.tenant_cosign = Some(cosign(&tenant.id, ENCLAVE, 99));
    assert_eq!(case.authorize(), Err(Denial::TenantCosign));
    case.req.tenant_cosign = Some(cosign(&tenant.id, ENCLAVE, ADMINS[1]));
    case.authorize().unwrap();

    // Tenant keys need it as well.
    case.req.binding.purpose = tenant_keys(&tenant, &[1]);
    case.rebind();
    case.authorize().unwrap();
    case.req.tenant_cosign = None;
    assert_eq!(case.authorize(), Err(Denial::TenantCosign));
}

#[test]
fn a_pending_state_does_not_widen_what_is_released() {
    let mut world = World::new();
    let now = world.now;
    let mut tenant = world.tenant("acme", false, versions(2, 3));
    let release = world.release(enclave_manifest(ENCLAVE));
    // A one-hour window (lengthening applies at once), then un-retiring version 1: widening.
    world.publish(&mut tenant, now - 7_200, |s| s.pending_window_secs = 3_600);
    world.publish(&mut tenant, now - 600, |s| s.tenant_key_versions.oldest_accepted = TenantKeyVersion(1));
    let bundle = world.bundle(&tenant);
    let mut case = Case::new(&world, tenant_keys(&tenant, &[1]), release.clone(), Some(bundle));
    assert_eq!(case.authorize(), Err(Denial::TenantKeyVersionOutOfRange), "version 1 is still retired");
    case.req.binding.purpose = tenant_keys(&tenant, &[2, 3]);
    case.rebind();
    case.authorize().unwrap();

    // Once public for the window, it is in force.
    let mut world = World::new();
    let now = world.now;
    let mut tenant = world.tenant("acme", false, versions(2, 3));
    world.publish(&mut tenant, now - 7_200, |s| s.pending_window_secs = 3_600);
    world.publish(&mut tenant, now - 3_660, |s| s.tenant_key_versions.oldest_accepted = TenantKeyVersion(1));
    let bundle = world.bundle(&tenant);
    let release = world.release(enclave_manifest(ENCLAVE));
    let case = Case::new(&world, tenant_keys(&tenant, &[1]), release, Some(bundle));
    case.authorize().unwrap();
}

#[test]
fn tenant_key_versions_within_window() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(2, 3));
    let release = world.release(enclave_manifest(ENCLAVE));
    let bundle = world.bundle(&tenant);
    let mut case = Case::new(&world, tenant_keys(&tenant, &[2, 3]), release, Some(bundle));
    case.authorize().unwrap();
    for outside in [&[1][..], &[4], &[2, 4], &[1, 3]] {
        case.req.binding.purpose = tenant_keys(&tenant, outside);
        case.rebind();
        assert_eq!(case.authorize(), Err(Denial::TenantKeyVersionOutOfRange), "{outside:?}");
    }
}
