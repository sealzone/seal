//! The HTTP surface over local TLS: `GuardianClient` → untrusted TLS-terminating proxy →
//! plain-HTTP `server::serve`. Also clients facing a fake guardian, and guardian succession.
#![cfg(feature = "sim")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::sim::*;
use common::*;
use http_body_util::Full;
use hyper::body::Bytes;
use seal_crypto::{EphemeralKey, SysRng, UnwrapErr};
use seal_guardian::client::open_response;
use seal_guardian::keysource::PredecessorKeySource;
use seal_guardian::{Guardian, GuardianComponents, GuardianError, GuardianIdentity, KeySource};
use seal_proto::codec::{b64url, labeled_digest};
use seal_proto::freshness::GuardianChallenge;
use seal_proto::release::{
    KeyPurpose, KeyRequest, KeyResponse, ReleaseManifest, ReleasedKeys, SignedTenantWrapKey, GUARDIAN_IDENTITY_LABEL,
    KEY_RESPONSE_LABEL,
};
use seal_proto::signed::{SigAlg, Signature};
use seal_proto::{PlatformId, TenantKeyVersion, TrustedTime};
use seal_tee::sim::SystemClock;
use seal_tee::Clock;

/// An enclave request for `purpose`, using a challenge fetched through `client`.
async fn enclave_request(
    world: &mut World,
    client: &seal_guardian::client::GuardianClient,
    purpose: KeyPurpose,
) -> (KeyRequest, EphemeralKey) {
    let ephemeral = EphemeralKey::generate(&mut UnwrapErr(SysRng));
    let binding = binding(client.challenge().await.unwrap(), ephemeral.public_key(), purpose);
    let evidence = attestor(ENCLAVE).attest(report_data(&binding)).await.unwrap();
    let release = world.release(enclave_manifest(ENCLAVE));
    (request(evidence, binding, release, None), ephemeral)
}

#[tokio::test]
async fn end_to_end_over_tls() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 2));
    let dir = TempDir::new();
    let guardian = boot(world.config(), ROOT, GUARDIAN_OLD, &dir).await;
    let proxy = serve(guardian).await;
    let client = client(proxy, guardian_key(ROOT));

    // Service keys.
    let (mut req, ephemeral) = enclave_request(&mut world, &client, service(&tenant)).await;
    req.tenant = Some(world.bundle(&tenant));
    let resp = client.keys(&req).await.unwrap();
    let ReleasedKeys::Service { certificate, .. } = open_response(&ephemeral, &req.binding, &resp).unwrap() else {
        panic!("service keys expected");
    };
    assert_eq!(certificate.body.tenant, tenant.id);

    // Tenant keys.
    let (mut req, ephemeral) = enclave_request(&mut world, &client, tenant_keys(&tenant, &[1, 2])).await;
    req.tenant = Some(world.bundle(&tenant));
    let resp = client.keys(&req).await.unwrap();
    let ReleasedKeys::Tenant { keys, .. } = open_response(&ephemeral, &req.binding, &resp).unwrap() else {
        panic!("tenant keys expected");
    };
    assert_eq!(keys.len(), 2);

    // A denial reaches the client as `Refused`, nothing more.
    let (mut req, _) = enclave_request(&mut world, &client, tenant_keys(&tenant, &[3])).await;
    req.tenant = Some(world.bundle(&tenant));
    let refused = client.keys(&req).await.unwrap_err();
    assert!(matches!(refused, GuardianError::Refused));
    assert_eq!(refused.code(), seal_proto::ErrorCode::NotAllowed);
}

#[tokio::test]
async fn public_endpoints_and_errors() {
    let world = World::new();
    let dir = TempDir::new();
    let guardian = boot(world.config(), ROOT, GUARDIAN_OLD, &dir).await;
    let tenant_id = acme();
    let root_id = seal_proto::TenantRootId([0x3c; 32]);
    let expected_wrap = guardian.wrap_key(&tenant_id, &root_id, TenantKeyVersion(4));
    let proxy = serve(guardian).await;
    let https = https(proxy);
    let base = format!("https://{HOST}");

    let (status, body) = https.get(&format!("{base}/v1/wrap-keys/acme/{root_id}/4"), &[]).await.unwrap();
    assert_eq!(status, 200);
    let wrap: SignedTenantWrapKey = serde_json::from_slice(&body).unwrap();
    assert_eq!(wrap, expected_wrap);

    let (status, body) =
        https.get(&format!("{base}/v1/identity?challenge={}", b64url(&[0x71; 32])), &[]).await.unwrap();
    assert_eq!(status, 200);
    let identity: GuardianIdentity = serde_json::from_slice(&body).unwrap();
    assert_eq!(identity.guardian_key, guardian_key(ROOT));
    let verified = seal_attest::verify(&identity.evidence, &TrustedTime::exact(wall())).unwrap();
    assert_eq!(
        verified.report_data,
        labeled_digest(GUARDIAN_IDENTITY_LABEL, &([0x71u8; 32], identity.platform, identity.guardian_key))
    );

    let (status, body) = https.get(&format!("{base}/v1/challenge"), &[]).await.unwrap();
    assert_eq!(status, 200);
    let challenge: GuardianChallenge = serde_json::from_slice(&body).unwrap();
    master(ROOT).challenge_key().verify(&challenge, &TrustedTime::exact(wall())).unwrap();

    let error = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap()["error"].clone();
    let bad = [
        "/v1/identity?challenge=AAAA".to_string(),
        "/v1/identity".to_string(),
        "/v1/wrap-keys/acme/00/1".to_string(),
        format!("/v1/wrap-keys/acme/{root_id}/x"),
        format!("/v1/wrap-keys/Not%20A%20Tenant/{root_id}/1"),
    ];
    for path in bad {
        let (status, body) = https.get(&format!("{base}{path}"), &[]).await.unwrap();
        assert_eq!((status, error(&body)), (400, "bad_request".into()), "{path}");
    }
    let (status, body) = https.post(&format!("{base}/v1/keys"), &[], b"{\"not\":\"a request\"}").await.unwrap();
    assert_eq!((status, error(&body)), (400, "bad_request".into()));
    let (status, body) = https.get(&format!("{base}/v1/nothing"), &[]).await.unwrap();
    assert_eq!((status, error(&body)), (404, "not_found".into()));
    let (status, _) = https.get(&format!("{base}/v1/keys"), &[]).await.unwrap();
    assert_eq!(status, 404);
}

/// A fake guardian: answers every request with `status` and `body`, behind the TLS proxy.
async fn fake_guardian(status: u16, body: Vec<u8>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Bytes::from(body);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let body = body.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_req| {
                    let mut resp = hyper::Response::new(Full::new(body.clone()));
                    *resp.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
                    async move { Ok::<_, std::convert::Infallible>(resp) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    tls_proxy(addr).await
}

#[tokio::test]
async fn client_refuses_responses_the_guardian_did_not_sign_for_this_request() {
    let mut world = World::new();
    let ephemeral = EphemeralKey::generate(&mut UnwrapErr(SysRng));
    let challenge = master(ROOT).challenge_key().issue(&TrustedTime::exact(wall()), &mut UnwrapErr(SysRng));
    let this = binding(challenge.clone(), ephemeral.public_key(), KeyPurpose::Succession);
    let mut other = this.clone();
    other.ephemeral_public_key.0[0] ^= 1;
    let release = world.release(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)));
    let evidence = attestor(GUARDIAN_NEW).attest(report_data(&this)).await.unwrap();
    let req = request(evidence, this.clone(), release, None);

    let (hpke_enc, ciphertext) = (vec![0x82; 32], vec![0x83; 64]);
    let response = |binding: &seal_proto::release::KeyRequestBinding, signer: &seal_crypto::sign::SigningKey| {
        let signature = signer.sign(KEY_RESPONSE_LABEL, &(report_data(binding), hpke_enc.clone(), ciphertext.clone()));
        serde_json::to_vec(&KeyResponse { hpke_enc: hpke_enc.clone(), ciphertext: ciphertext.clone(), signature })
            .unwrap()
    };
    let guardian = master(ROOT).guardian_key();
    let unsigned = serde_json::to_vec(&KeyResponse {
        hpke_enc: hpke_enc.clone(),
        ciphertext: ciphertext.clone(),
        signature: Signature { signer: guardian.key_id(), alg: SigAlg::Ed25519 { sig: vec![0; 64] } },
    })
    .unwrap();

    let refused = [
        ("unsigned", unsigned),
        ("forged", response(&this, &key(99))),
        ("mis-bound", response(&other, &guardian)),
        ("malformed", b"{}".to_vec()),
    ];
    for (name, body) in refused {
        let fake = client(fake_guardian(200, body).await, guardian_key(ROOT));
        let err = fake.keys(&req).await.unwrap_err();
        assert!(matches!(err, GuardianError::Unavailable(_)), "{name}: {err:?}");
    }

    // Signed by the guardian for this request: accepted.
    let fake = client(fake_guardian(200, response(&this, &guardian)).await, guardian_key(ROOT));
    fake.keys(&req).await.unwrap();

    // Status codes: 403 is a denial, anything else is unavailable.
    let fake = client(fake_guardian(403, br#"{"error":"denied"}"#.to_vec()).await, guardian_key(ROOT));
    assert!(matches!(fake.keys(&req).await, Err(GuardianError::Refused)));
    assert!(matches!(fake.challenge().await, Err(GuardianError::Refused)));
    let fake = client(fake_guardian(503, br#"{"error":"unavailable"}"#.to_vec()).await, guardian_key(ROOT));
    assert!(matches!(fake.keys(&req).await, Err(GuardianError::Unavailable(_))));
}

/// A successor guardian (measuring `GUARDIAN_NEW`) whose first boot asks `predecessor` for the root.
fn successor(
    world: &World,
    predecessor: SocketAddr,
    predecessor_key: seal_proto::PublicKey,
    release: seal_proto::release::ReleaseEvidence,
) -> (seal_guardian::GuardianConfig, GuardianComponents) {
    let source = PredecessorKeySource::new(client(predecessor, predecessor_key), release);
    let components = GuardianComponents {
        key_source: KeySource::Predecessor(source),
        attestor: attestor(GUARDIAN_NEW),
        clock: Clock::System(SystemClock::new(0)),
    };
    (world.config(), components)
}

#[tokio::test]
async fn successor_boots_from_its_predecessor() {
    let mut world = World::new();
    let tenant = world.tenant("acme", false, versions(1, 1));
    let dir = TempDir::new();
    let predecessor = boot(world.config(), ROOT, GUARDIAN_OLD, &dir).await;
    let old_identity = predecessor.identity([1; 32]).await.unwrap();
    let old_wrap = predecessor.wrap_key(&tenant.id, &tenant.root_id, TenantKeyVersion(1));
    let proxy = serve(predecessor).await;

    let release = world.release(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)));
    let (config, components) = successor(&world, proxy, guardian_key(ROOT), release);
    let next = Guardian::boot(config, components).await.unwrap();

    // The same platform master key: the same guardian key, wrap keys and service keys.
    let new_identity = next.identity([1; 32]).await.unwrap();
    assert_eq!(new_identity.guardian_key, old_identity.guardian_key);
    assert_eq!(next.wrap_key(&tenant.id, &tenant.root_id, TenantKeyVersion(1)), old_wrap);
    let new_proxy = serve(next).await;
    let next_client = client(new_proxy, guardian_key(ROOT));
    let (mut req, ephemeral) = enclave_request(&mut world, &next_client, service(&tenant)).await;
    req.tenant = Some(world.bundle(&tenant));
    let resp = next_client.keys(&req).await.unwrap();
    let ReleasedKeys::Service { certificate, .. } = open_response(&ephemeral, &req.binding, &resp).unwrap() else {
        panic!("service keys expected");
    };
    let ReleasedKeys::Service { certificate: want, .. } =
        master(ROOT).release_service(&tenant.id, &tenant.root_id, req.release.manifest.body.service_key_version)
    else {
        unreachable!()
    };
    assert_eq!(certificate, want);
}

#[tokio::test]
async fn successor_needs_a_guardian_release_for_this_platform() {
    let mut world = World::new();
    let dir = TempDir::new();
    let proxy = serve(boot(world.config(), ROOT, GUARDIAN_OLD, &dir).await).await;

    let refused: [(&str, ReleaseManifest); 4] = [
        ("an enclave release", enclave_manifest(GUARDIAN_NEW)),
        ("serving another platform", guardian_manifest(GUARDIAN_NEW, Some(PlatformId::AwsNitro))),
        ("serving nothing", guardian_manifest(GUARDIAN_NEW, None)),
        ("for another measurement", guardian_manifest(GUARDIAN_OLD, Some(PlatformId::Sim))),
    ];
    for (name, manifest) in refused {
        let release = world.release(manifest);
        let (config, components) = successor(&world, proxy, guardian_key(ROOT), release);
        let err = Guardian::boot(config, components).await.err().unwrap_or_else(|| panic!("{name}: booted"));
        assert!(matches!(err, GuardianError::Root(_)), "{name}: {err:?}");
    }

    // Still inside the time lock.
    let now = world.now;
    let release = world.release_at(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)), now - DAY, now - 60);
    let (config, components) = successor(&world, proxy, guardian_key(ROOT), release);
    assert!(matches!(Guardian::boot(config, components).await, Err(GuardianError::Root(_))));

    // A predecessor that is not the configured guardian key.
    let release = world.release(guardian_manifest(GUARDIAN_NEW, Some(PlatformId::Sim)));
    let (config, components) = successor(&world, proxy, key(99).public_key(), release);
    assert!(matches!(Guardian::boot(config, components).await, Err(GuardianError::Root(_))));
}

#[test]
fn guardian_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<seal_guardian::client::GuardianClient>();
    assert_send_sync::<Arc<Guardian>>();
}
