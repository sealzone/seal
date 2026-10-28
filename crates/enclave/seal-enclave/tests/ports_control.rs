//! `ControlTenantStore` and `ControlReleaseStore` through `ControlClient` and an untrusted TLS
//! proxy against an in-memory control plane holding real signed documents.

mod ports_support;

use std::sync::Arc;

use ports_support::*;
use seal_crypto::{PlatformMasterKey, ServiceKeys};
use seal_enclave::ports::control::{ControlReleaseStore, ControlTenantStore};
use seal_enclave::{ReleaseStore, TenantStore};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::integrity::{IntegritySignal, Severity, SignalSource, SIGNAL_LABEL};
use seal_proto::session::{SessionEnd, SESSION_END_LABEL};
use seal_proto::{ErrorCode, KeyId, PlatformId, TenantId};

fn json(value: &impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

fn service_keys(tenant: &Tenant) -> ServiceKeys {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &seal_crypto::Key32::from_bytes(ROOT));
    ServiceKeys::from_released(
        PlatformId::Sim,
        &master.release_service(&tenant.id, &tenant.root_id, SERVICE_KEY_VERSION),
    )
    .unwrap()
}

#[tokio::test]
async fn loads_the_bundle_and_release_evidence() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let bundle = world.bundle(&tenant);
    let release = world.release();
    let control = Arc::new(FakeControl::default());
    control.put("/v1/tenants/acme/bundle", &bundle);
    control.put(&format!("/v1/releases/sim/{ENCLAVE}"), &release);
    let proxy = control.serve().await;

    let tenants = ControlTenantStore::new(proxy.control_client(), tenant.id.clone());
    assert_eq!(json(&tenants.load().await.unwrap()), json(&bundle));
    let releases = ControlReleaseStore::new(proxy.control_client());
    assert_eq!(releases.load(PlatformId::Sim, &ENCLAVE).await.unwrap(), release);

    // Whatever the control plane withholds or refuses is `Unavailable`.
    let other = ControlTenantStore::new(proxy.control_client(), TenantId::new("beta").unwrap());
    assert_eq!(other.load().await.unwrap_err().code, ErrorCode::Unavailable);
    let missing = releases.load(PlatformId::AzureSnpAci, &ENCLAVE).await.unwrap_err();
    assert_eq!(missing.code, ErrorCode::Unavailable);
}

#[tokio::test]
async fn release_evidence_carries_the_latest_checkpoint() {
    let mut world = World::new();
    let stale = world.release();
    let older = world.log.checkpoint();
    world.tenant("acme", false, versions(1, 1));
    let latest = world.log.checkpoint();
    assert!(latest.checkpoint.size > stale.fresh.checkpoint.size);
    let control = Arc::new(FakeControl::default());
    control.put(&format!("/v1/releases/sim/{ENCLAVE}"), &stale);
    control.put("/v1/checkpoint", &latest);
    let proxy = control.serve().await;

    // The stored fresh checkpoint is as old as the upload; the control plane's latest replaces it.
    let releases = ControlReleaseStore::new(proxy.control_client());
    let loaded = releases.load(PlatformId::Sim, &ENCLAVE).await.unwrap();
    assert_eq!(loaded.fresh, latest);
    assert_eq!((loaded.manifest, loaded.included), (stale.manifest.clone(), stale.included.clone()));

    // A checkpoint smaller than the stored one is not taken.
    let mut smaller = older.clone();
    smaller.checkpoint.size = stale.fresh.checkpoint.size - 1;
    control.put("/v1/checkpoint", &smaller);
    assert_eq!(releases.load(PlatformId::Sim, &ENCLAVE).await.unwrap(), stale);
}

#[tokio::test]
async fn publishes_what_the_enclave_signed() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let keys = service_keys(&tenant);
    let control = Arc::new(FakeControl::default());
    let proxy = control.serve().await;
    let store = ControlTenantStore::new(proxy.control_client(), tenant.id.clone());

    let signal = keys.telemetry.signer().sign_into(
        SIGNAL_LABEL,
        IntegritySignal {
            tenant: tenant.id.clone(),
            identity: WorkloadIdentity::AppKey { key_id: KeyId([3; 32]) },
            source: SignalSource::Sdk,
            code: "artifact-mismatch".into(),
            severity: Severity::High,
            observed_at: wall(),
            blob_id: None,
        },
    );
    store.publish_signal(&signal).await.unwrap();
    let end = keys.telemetry.signer().sign_into(
        SESSION_END_LABEL,
        SessionEnd {
            tenant: tenant.id.clone(),
            session_id: [5; 16],
            reason: ErrorCode::SessionEnded,
            ended_at: wall(),
        },
    );
    store.publish_session_end(&end).await.unwrap();
    store.publish_service_key_certificate(&keys.certificate).await.unwrap();

    assert_eq!(control.posts_to("/v1/tenants/acme/signals"), [json(&signal)]);
    assert_eq!(control.posts_to("/v1/tenants/acme/session-ends"), [json(&end)]);
    assert_eq!(control.posts_to("/v1/tenants/acme/service-key-certificates"), [json(&keys.certificate)]);

    // A refusal is `Unavailable` to callers too: the enclave already applied what it publishes.
    *control.post_status.lock().unwrap() = Some(403);
    assert_eq!(store.publish_session_end(&end).await.unwrap_err().code, ErrorCode::Unavailable);
}

/// Before the guardian released its keys, the enclave reads its bundle with evidence that
/// commits to exactly that request on its pinned chain.
#[cfg(feature = "sim")]
#[tokio::test]
async fn boot_reads_are_attested() {
    use seal_control::client::ControlClient;
    use seal_enclave::ports::control::EnclaveCredential;
    use seal_proto::control::{AttestedControlRequest, CONTROL_REQUEST_LABEL};

    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let bundle = world.bundle(&tenant);
    let control = Arc::new(FakeControl::default());
    control.put("/v1/tenants/acme/bundle", &bundle);
    let proxy = control.serve().await;
    let credential = Arc::new(EnclaveCredential::new(tenant.root_id, enclave_attestor()));
    let client = Arc::new(
        ControlClient::new(url::Url::parse(&format!("https://{CONTROL_HOST}/")).unwrap(), proxy.https(), None)
            .with_credential(credential),
    );
    ControlTenantStore::new(client.clone(), tenant.id.clone()).load().await.unwrap();
    // Public reads carry no credential.
    let _ = client.get_service_key_certificates(&tenant.id).await;

    let seen = control.authorizations.lock().unwrap().clone();
    assert_eq!(seen[1], ("/v1/tenants/acme/service-key-certificates".to_string(), None));
    let (path, header) = &seen[0];
    assert_eq!(path, "/v1/tenants/acme/bundle");
    let encoded = header.as_deref().unwrap().strip_prefix("SealAttested ").unwrap();
    let attested: AttestedControlRequest =
        serde_json::from_slice(&seal_proto::codec::from_b64url(encoded).unwrap()).unwrap();
    let request = &attested.request;
    assert_eq!((request.tenant.clone(), request.root_id), (tenant.id.clone(), tenant.root_id));
    assert_eq!((request.method.as_str(), request.path.as_str()), ("GET", "/v1/tenants/acme/bundle"));
    let evidence = seal_attest::verify(&attested.evidence, &seal_proto::TrustedTime::exact(wall())).unwrap();
    assert_eq!(evidence.measurement, ENCLAVE);
    assert_eq!(evidence.report_data, seal_proto::codec::labeled_digest(CONTROL_REQUEST_LABEL, request));
}
