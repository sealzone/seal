//! `GuardianKeyProvider` end to end: a sim guardian (`seal_guardian::server::serve`) behind an
//! untrusted TLS proxy, request inputs from an in-memory control plane through
//! `ControlKeyRequestSource`, sim evidence for the enclave's measurement.
#![cfg(feature = "sim")]

mod ports_support;

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::Json;
use ports_support::*;
use seal_crypto::hpke::KEY_RELEASE_INFO;
use seal_crypto::{ServiceKeyScope, SysRng, TenantWrappingKeyScope, UnwrapErr};
use seal_enclave::ports::control::ControlKeyRequestSource;
use seal_enclave::ports::guardian::GuardianKeyProvider;
use seal_enclave::KeyProvider;
use seal_proto::codec::{canonical, labeled_digest};
use seal_proto::release::{
    KeyRequest, KeyResponse, KEY_REQUEST_BINDING_LABEL, KEY_RESPONSE_LABEL, SERVICE_KEY_CERTIFICATE_LABEL,
};
use seal_proto::{ErrorCode, PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion, TrustedTime};

struct Setup {
    tenant: Tenant,
    control: Arc<FakeControl>,
    control_proxy: Proxy,
    guardian: Proxy,
    _dir: TempDir,
}

impl Setup {
    /// A guardian for the world's trust, a control plane serving the enclave's release and the
    /// tenant's bundle (and the tenant's co-signature when `cosign_releases`).
    async fn new(cosign_releases: bool) -> Self {
        let mut world = World::new();
        let tenant = world.tenant("acme", cosign_releases, versions(1, 2));
        let control = Arc::new(FakeControl::default());
        control.put(&format!("/v1/releases/sim/{ENCLAVE}"), &world.release());
        control.put("/v1/tenants/acme/bundle", &world.bundle(&tenant));
        if cosign_releases {
            control.put(&format!("/v1/tenants/acme/release-cosigns/{ENCLAVE}"), &cosign(&tenant.id));
        }
        let control_proxy = control.serve().await;
        let dir = TempDir::new();
        let guardian = serve_guardian(boot_guardian(world.guardian_config(), ROOT, &dir).await).await;
        Self { tenant, control, control_proxy, guardian, _dir: dir }
    }

    fn provider_for(&self, guardian: &Proxy, guardian_key: seal_proto::PublicKey) -> GuardianKeyProvider {
        let inputs = ControlKeyRequestSource::new(self.control_proxy.control_client(), self.tenant.id.clone());
        GuardianKeyProvider::new(guardian.guardian_client(guardian_key), enclave_attestor(), inputs)
    }

    fn provider(&self) -> GuardianKeyProvider {
        self.provider_for(&self.guardian, guardian_key(ROOT))
    }

    fn service_scope(&self, version: u32) -> ServiceKeyScope {
        ServiceKeyScope {
            platform: PlatformId::Sim,
            tenant: self.tenant.id.clone(),
            root_id: self.tenant.root_id,
            service_key_version: ServiceKeyVersion(version),
        }
    }

    fn tenant_scope(&self, version: u32) -> TenantWrappingKeyScope {
        TenantWrappingKeyScope {
            platform: PlatformId::Sim,
            tenant: self.tenant.id.clone(),
            root_id: self.tenant.root_id,
            tenant_key_version: TenantKeyVersion(version),
        }
    }
}

#[tokio::test]
async fn service_keys_come_from_the_guardian_with_the_requested_scope() {
    let setup = Setup::new(false).await;
    let scope = setup.service_scope(SERVICE_KEY_VERSION.0);
    let keys = setup.provider().service_keys(&scope).await.unwrap();
    assert_eq!(keys.scope, scope);
    let certificate = &keys.certificate;
    assert_eq!((&certificate.body.tenant, certificate.body.root_id), (&setup.tenant.id, setup.tenant.root_id));
    assert_eq!(certificate.body.tls_spki_sha256, keys.tls.spki_sha256());
    seal_crypto::sign::verify(
        &guardian_key(ROOT),
        SERVICE_KEY_CERTIFICATE_LABEL,
        &certificate.body,
        &certificate.signatures[0],
    )
    .unwrap();
    // The derivation is the guardian's: the same keys as the platform master key releases.
    let expected = master(ROOT).release_service(&setup.tenant.id, &setup.tenant.root_id, SERVICE_KEY_VERSION);
    let expected = seal_crypto::ServiceKeys::from_released(PlatformId::Sim, &expected).unwrap();
    assert_eq!(keys.ingest.public_key(), expected.ingest.public_key());
}

#[tokio::test]
async fn tenant_wrapping_keys_are_fetched_once_per_cache_period() {
    let setup = Setup::new(false).await;
    let provider = setup.provider();
    let scope = setup.tenant_scope(1);
    let key = provider.tenant_wrapping_key(&scope).await.unwrap();
    assert_eq!(key.scope(), &scope);
    let certified = master(ROOT).tenant_wrap_key(&setup.tenant.id, &setup.tenant.root_id, TenantKeyVersion(1));
    assert_eq!(key.public_key(), certified.body.public_key);

    // A challenge and a key request.
    let fetched = setup.guardian.connections();
    assert_eq!(fetched, 2);
    let again = provider.tenant_wrapping_key(&scope).await.unwrap();
    assert_eq!(again.public_key(), key.public_key());
    assert_eq!(setup.guardian.connections(), fetched, "served from the cache");

    let other = provider.tenant_wrapping_key(&setup.tenant_scope(2)).await.unwrap();
    assert_ne!(other.public_key(), key.public_key());
    assert_eq!(setup.guardian.connections(), fetched + 2);
}

#[tokio::test]
async fn keys_for_another_scope_than_requested_are_refused() {
    let setup = Setup::new(false).await;
    // The release gets version 2 keys; asking for version 3 gets keys that do not match.
    let refused = setup.provider().service_keys(&setup.service_scope(3)).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::Internal);
    assert_eq!(setup.guardian.connections(), 2, "the guardian answered");
}

#[tokio::test]
async fn guardian_refusals_reach_the_caller_as_not_allowed() {
    let setup = Setup::new(false).await;
    // Tenant key version 3 is outside the state's window 1..=2.
    let refused = setup.provider().tenant_wrapping_key(&setup.tenant_scope(3)).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::NotAllowed);
}

#[tokio::test]
async fn a_response_the_guardian_key_did_not_sign_is_refused() {
    let setup = Setup::new(false).await;
    let provider = setup.provider_for(&setup.guardian, guardian_key([0x11; 32]));
    let refused = provider.service_keys(&setup.service_scope(SERVICE_KEY_VERSION.0)).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::Unavailable);
}

#[tokio::test]
async fn keys_for_another_platform_are_never_requested() {
    let setup = Setup::new(false).await;
    let mut scope = setup.tenant_scope(1);
    scope.platform = PlatformId::AzureSnpAci;
    let refused = setup.provider().tenant_wrapping_key(&scope).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::Internal);
    assert_eq!(setup.guardian.connections(), 0);
}

#[tokio::test]
async fn tenants_requiring_cosigned_releases_get_the_cosign_sent() {
    let setup = Setup::new(true).await;
    let scope = setup.service_scope(SERVICE_KEY_VERSION.0);
    assert_eq!(setup.provider().service_keys(&scope).await.unwrap().scope, scope);

    // Without the co-signature on the control plane nothing is requested.
    setup.control.documents.lock().unwrap().retain(|path, _| !path.contains("release-cosigns"));
    let before = setup.guardian.connections();
    let refused = setup.provider().service_keys(&scope).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::Unavailable);
    assert_eq!(setup.guardian.connections(), before);
}

/// A guardian that signs correctly but releases another tenant's wrapping keys.
async fn wrong_tenant(State(other): State<TenantId>, Json(request): Json<KeyRequest>) -> Json<KeyResponse> {
    let master = master(ROOT);
    let keys = master.release_tenant(&other, &seal_proto::TenantRootId([3; 32]), &[TenantKeyVersion(1)]);
    let binding = &request.binding;
    let (hpke_enc, ciphertext) = seal_crypto::hpke::seal(
        &binding.ephemeral_public_key,
        KEY_RELEASE_INFO,
        &canonical(binding),
        &canonical(&keys),
        &mut UnwrapErr(SysRng),
    )
    .unwrap();
    let signature = master.guardian_key().sign(
        KEY_RESPONSE_LABEL,
        &(labeled_digest(KEY_REQUEST_BINDING_LABEL, binding), hpke_enc.clone(), ciphertext.clone()),
    );
    Json(KeyResponse { hpke_enc, ciphertext, signature })
}

#[tokio::test]
async fn signed_keys_of_another_tenant_are_refused() {
    let setup = Setup::new(false).await;
    let router = axum::Router::new()
        .route(
            "/v1/challenge",
            get(|| async {
                let time = TrustedTime::exact(wall());
                Json(master(ROOT).challenge_key().issue(&time, &mut UnwrapErr(SysRng)))
            }),
        )
        .route("/v1/keys", post(wrong_tenant))
        .with_state(TenantId::new("other").unwrap());
    let fake = serve_router(router).await;
    let refused = setup.provider_for(&fake, guardian_key(ROOT)).tenant_wrapping_key(&setup.tenant_scope(1)).await;
    assert_eq!(refused.unwrap_err().code, ErrorCode::Internal);
    assert_eq!(fake.connections(), 2);
}
