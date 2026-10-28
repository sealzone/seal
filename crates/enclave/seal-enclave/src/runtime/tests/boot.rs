//! Boot order, the attestation it serves, and each boot refusal.

use super::*;

#[tokio::test]
async fn boots_in_order_and_attests_its_certified_keys() {
    let h = Boot::new().start().await.map_err(|(e, _)| e).unwrap();
    // Release, tenant, deployment (no port), keys, certificate; no tenant key until a blob needs one.
    assert_eq!(
        h.calls.list(),
        ["releases.load", "tenants.load", "keys.service_keys", "tenants.publish_service_key_certificate"]
    );
    let signer = h.telemetry.signer.lock().unwrap().clone().expect("the telemetry port was started");
    let keys = service_keys(&h.world.root_id);
    assert_eq!(signer.key.public_key(), keys.telemetry.public_key());
    assert_eq!(signer.tenant(), &acme());
    assert!(signer.readers().is_empty());

    let attestation = h.attestation().await;
    let evidence = seal_attest::verify(&attestation.evidence, &seal_proto::TrustedTime::exact(wall())).unwrap();
    assert_eq!(evidence.measurement, MEASUREMENT);
    assert_eq!(
        evidence.report_data,
        codec::labeled_digest(seal_proto::api::ATTESTATION_BINDING_LABEL, &attestation.binding)
    );
    assert!(attestation.binding.attested_at.abs_diff(wall()) <= 2);
    let certificate =
        seal_verify::verify_service_certificate(&h.world.trust().guardians, &attestation.certificate).unwrap();
    assert_eq!(certificate.tls_spki_sha256, attestation.binding.tls_spki_sha256);
    assert_eq!(certificate.ingest_public_key, attestation.binding.ingest_public_key);
    assert_eq!(certificate.telemetry_public_keys, attestation.binding.telemetry_public_keys);
    assert_eq!((&certificate.tenant, certificate.root_id), (&acme(), h.world.root_id));
    assert_eq!(h.stores.certificates.lock().unwrap().as_slice(), std::slice::from_ref(&attestation.certificate));
    assert_eq!(attestation.binding.tls_spki_sha256, keys.tls.spki_sha256());
}

async fn refused(boot: Boot) -> (ErrorCode, Vec<&'static str>) {
    match boot.start().await {
        Ok(_) => panic!("boot succeeded"),
        Err((e, calls)) => (e.code, calls),
    }
}

#[tokio::test]
async fn refuses_a_pin_for_another_chain_or_tenant() {
    let mut boot = Boot::new();
    boot.pin.root_id = TenantRootId([9; 32]);
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::NotAllowed);
    assert_eq!(calls, ["releases.load", "tenants.load"]);

    let mut boot = Boot::new();
    boot.pin.tenant = TenantId::new("bravo").unwrap();
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::VerificationFailed);
    assert_eq!(calls, ["releases.load", "tenants.load"]);
}

#[tokio::test]
async fn refuses_unverified_release_evidence() {
    // One release signature where two are needed.
    let mut boot = Boot::new();
    boot.release = boot.world.release(MEASUREMENT, &[1]);
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::VerificationFailed);
    assert_eq!(calls, ["releases.load"]);

    // A valid release of another build.
    let mut boot = Boot::new();
    boot.release = boot.world.release(Measurement([0xe2; 48]), &[1, 2]);
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::VerificationFailed);
    assert_eq!(calls, ["releases.load"]);
}

#[tokio::test]
async fn refuses_a_stale_state() {
    let mut boot = Boot::new();
    boot.bundle = boot.world.publish_fresh_at(wall() - DAY - 60, |_| {});
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::VerificationFailed);
    assert_eq!(calls, ["releases.load", "tenants.load"]);
}

#[tokio::test]
async fn requests_no_keys_for_an_undeployed_identity() {
    let mut boot = Boot::new();
    boot.deployment = WorkloadIdentity::ConfidentialSpace { project_number: 8, service_account: "other@x.iam".into() };
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::NotAllowed);
    assert_eq!(calls, ["releases.load", "tenants.load"]);

    let mut boot = Boot::new();
    boot.bundle = boot.world.publish(|s| s.deployments.clear());
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::NotAllowed);
    assert!(!calls.contains(&"keys.service_keys"));
}

#[tokio::test]
async fn refuses_keys_for_another_scope_or_without_a_trusted_certificate() {
    let mut boot = Boot::new();
    boot.keys_root = Some(TenantRootId([3; 32]));
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::VerificationFailed);
    assert_eq!(calls, ["releases.load", "tenants.load", "keys.service_keys"]);

    // Certified by a key that is not this platform's guardian.
    let mut boot = Boot::new();
    boot.trust.guardians.insert(PlatformId::Sim, key(99).public_key());
    let (code, calls) = refused(boot).await;
    assert_eq!(code, ErrorCode::VerificationFailed);
    assert_eq!(calls, ["releases.load", "tenants.load", "keys.service_keys"]);
}
