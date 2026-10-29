//! The admin workflow (`seal_client::admin::Admin`) against the in-process dev log and a fake
//! control plane.
#![cfg(feature = "sim")]

mod common;

use common::{acme, now, registrar, Servers};
use seal_client::admin::{next_root, Admin};
use seal_client::ClientError;
use seal_crypto::sign::SigningKey;
use seal_proto::identity::IdentityMatcher;
use seal_proto::release::LogEntry;
use seal_proto::state::{AdminKey, TenantRoot, TENANT_ROOT_LABEL};
use seal_proto::{AppName, Measurement, PlatformId};

fn app_key(n: u8) -> IdentityMatcher {
    let key = SigningKey::from_seed(&[n; 32]).public_key();
    IdentityMatcher::AppKey { key_id: seal_crypto::sign::key_id(&key), public_key: key }
}

/// A tenant created with `admin` as its only admin key.
async fn tenant(servers: &Servers, admin: &SigningKey) -> Admin {
    let init =
        servers.admin(None).init(admin, &[registrar()], false, [PlatformId::Sim].into(), 0, &now()).await.unwrap();
    assert_eq!(init.root_id, seal_proto::state::root_id(&init.root.root.body));
    servers.admin(Some(init.root_id))
}

#[tokio::test]
async fn init_then_edits_are_verified_signed_logged_and_stored() {
    let servers = Servers::start("edits").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let admin = tenant(&servers, &key).await;

    let current = admin.fetch(&now()).await.unwrap();
    assert_eq!(current.tenant.state().version, 1);
    let checkout = AppName::new("checkout").unwrap();
    let proposal = Admin::draft(&current, &now(), |s| {
        s.apps.entry(checkout.clone()).or_default().insert(app_key(9));
        s.deployments.insert(IdentityMatcher::ConfidentialSpace {
            project_number: 1,
            service_account: "sim".into(),
            hosted: None,
        });
        Ok(())
    })
    .unwrap();
    assert_eq!(proposal.new.version, 2);
    assert_eq!(proposal.changes.len(), 3, "{:?}", proposal.changes);
    let signed = Admin::sign_state(current.tenant.root(), proposal.new, std::slice::from_ref(&key)).unwrap();
    admin.publish(&signed).await.unwrap();

    let verified = servers.verified();
    assert_eq!(verified.state().version, 2);
    assert!(verified.state().apps[&checkout].contains(&app_key(9)));
    assert!(Admin::draft(&admin.fetch(&now()).await.unwrap(), &now(), |_| Ok(())).is_err(), "nothing to change");

    let other = SigningKey::from_seed(&[2; 32]);
    let current = admin.fetch(&now()).await.unwrap();
    let proposal = Admin::draft(&current, &now(), |s| {
        s.platforms.insert(PlatformId::AzureSnpAci);
        Ok(())
    })
    .unwrap();
    assert!(Admin::sign_state(current.tenant.root(), proposal.new, &[other]).is_err(), "not an admin key");
}

/// Root version 1 as `init` builds it for `admin`.
fn root_v1(admin: &SigningKey) -> seal_proto::signed::Signed<TenantRoot> {
    let root = TenantRoot {
        tenant: acme(),
        version: 1,
        admin_keys: [AdminKey::Ed25519 { public_key: admin.public_key() }].into(),
        threshold: 1,
        cosign_releases: false,
    };
    let mut signed = seal_proto::signed::Signed { body: root, signatures: Vec::new() };
    registrar().cosign(TENANT_ROOT_LABEL, &mut signed);
    signed
}

fn roots_v1_in_log(servers: &Servers) -> usize {
    let log = servers.log.lock().unwrap();
    (0..log.size())
        .filter(|&i| matches!(log.entry(i), Some(LogEntry::TenantRoot(r)) if r.tenant == acme() && r.version == 1))
        .count()
}

#[tokio::test]
async fn init_resumes_where_a_failed_run_stopped() {
    let servers = Servers::start("resume").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let init = |servers: &Servers, time: seal_proto::TrustedTime| {
        let admin = servers.admin(None);
        async move {
            let key = SigningKey::from_seed(&[1; 32]);
            admin.init(&key, &[registrar()], false, [PlatformId::Sim].into(), 0, &time).await
        }
    };

    // A run that logged root version 1 and stopped: the next run reuses that entry.
    let root = root_v1(&key);
    servers.admin(None).log().append(&LogEntry::TenantRoot(root.body.clone())).await.unwrap();
    // ...and one that also logged state version 1 but never stored it on the control plane.
    let state = seal_proto::state::TenantState {
        tenant: acme(),
        version: 1,
        root_version: 1,
        apps: Default::default(),
        tenant_key_versions: seal_proto::state::TenantKeyVersions {
            current: seal_proto::TenantKeyVersion(1),
            oldest_accepted: seal_proto::TenantKeyVersion(1),
        },
        platforms: [PlatformId::Sim].into(),
        integrity: Default::default(),
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: now().now,
        pending_window_secs: 0,
        app_networks: Default::default(),
        freshness_secs: None,
    };
    let state = Admin::sign_state(&root.body, state, std::slice::from_ref(&key)).unwrap();
    servers.admin(None).log().append_state(&acme(), &state).await.unwrap();

    let resumed = init(&servers, now()).await.unwrap();
    assert_eq!(resumed.root_id, seal_proto::state::root_id(&root.body));
    assert_eq!(resumed.resumed.len(), 2, "{:?}", resumed.resumed);
    assert!(resumed.resumed[0].starts_with("root version 1 is already log entry 0"), "{:?}", resumed.resumed);
    assert_eq!(resumed.state.body.version, 2, "the logged state 1 is superseded");
    assert_eq!(roots_v1_in_log(&servers), 1, "root version 1 is not logged twice");
    // State 2 cannot be compared with a first state nobody can see: it is in force once it
    // has been public for the longest window.
    assert!(matches!(servers.verify_at(now()), Err(seal_verify::VerifyError::State(_))));
    let later = servers.advance(seal_proto::state::MAX_PENDING_WINDOW_SECS + 60);
    let verified = servers.verify_at(later).unwrap();
    assert_eq!((verified.root_id(), verified.state().version), (&resumed.root_id, 2));

    // Run again once complete: nothing is signed or logged, the stored state comes back.
    let size = servers.log.lock().unwrap().size();
    let again = init(&servers, later).await.unwrap();
    assert_eq!(again.root_id, resumed.root_id);
    assert_eq!(again.state, resumed.state);
    assert!(again.resumed.iter().any(|l| l.contains("already holds state version 2")), "{:?}", again.resumed);
    assert_eq!(servers.log.lock().unwrap().size(), size);

    // Another admin key makes another root: refused, since the log's first version 1 is ours.
    let other = SigningKey::from_seed(&[2; 32]);
    let err = servers.admin(None).init(&other, &[registrar()], false, [].into(), 0, &later).await.err().unwrap();
    assert!(err.to_string().contains("already holds root version 1 of acme as entry 0"), "{err}");
    assert_eq!(roots_v1_in_log(&servers), 1);
}

#[tokio::test]
async fn init_resubmits_a_proposed_state_the_log_holds() {
    let servers = Servers::start("resubmit").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let root = root_v1(&key);
    servers.admin(None).log().append(&LogEntry::TenantRoot(root.body.clone())).await.unwrap();
    // A run that proposed state 1 and stopped after the control plane logged it.
    let state = seal_proto::state::TenantState {
        tenant: acme(),
        version: 1,
        root_version: 1,
        apps: Default::default(),
        tenant_key_versions: seal_proto::state::TenantKeyVersions {
            current: seal_proto::TenantKeyVersion(1),
            oldest_accepted: seal_proto::TenantKeyVersion(1),
        },
        platforms: [PlatformId::Sim].into(),
        integrity: Default::default(),
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: now().now,
        pending_window_secs: 3_600,
        app_networks: Default::default(),
        freshness_secs: None,
    };
    let state = Admin::sign_state(&root.body, state, std::slice::from_ref(&key)).unwrap();
    servers.admin(None).log().append_state(&acme(), &state).await.unwrap();
    let id = seal_client::admin::Proposed::State(state.clone()).id();
    let proposal = seal_client::admin::Proposal {
        id: id.clone(),
        document: seal_client::admin::Proposed::State(state.clone()),
        created_at: now().now,
        updated_at: now().now,
    };
    servers.stored.lock().unwrap().proposals.insert(id, proposal);

    let admin = servers.admin(None);
    let resumed = admin.init(&key, &[registrar()], false, [PlatformId::Sim].into(), 0, &now()).await.unwrap();
    assert_eq!(resumed.state, state, "the proposed state, not a new one");
    assert!(resumed.resumed.iter().any(|l| l.contains("submitted again")), "{:?}", resumed.resumed);
    assert_eq!(servers.verified().state().version, 1);
}

#[tokio::test]
async fn a_control_plane_behind_the_log_is_caught() {
    let servers = Servers::start("stale").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let admin = tenant(&servers, &key).await;
    let current = admin.fetch(&now()).await.unwrap();
    let proposal = Admin::draft(&current, &now(), |s| {
        s.platforms.insert(PlatformId::AzureSnpAci);
        Ok(())
    })
    .unwrap();
    let signed = Admin::sign_state(current.tenant.root(), proposal.new, &[key]).unwrap();
    // Logged, but the control plane keeps serving version 1 (with its still-current statement).
    admin.log().append_state(&acme(), &signed).await.unwrap();
    let err = admin.fetch(&now()).await.err().unwrap();
    assert!(matches!(&err, ClientError::Verification(m) if m.contains("the log's latest is version 2")), "{err}");
}

#[tokio::test]
async fn the_wrong_root_chain_is_refused() {
    let servers = Servers::start("chain").await;
    let key = SigningKey::from_seed(&[1; 32]);
    tenant(&servers, &key).await;
    let err = servers.admin(Some(seal_proto::TenantRootId([9; 32]))).fetch(&now()).await.err().unwrap();
    assert!(err.to_string().contains("serves root chain"), "{err}");
}

#[tokio::test]
async fn rotating_the_root_re_signs_the_state_under_it() {
    let servers = Servers::start("rotate").await;
    let a = SigningKey::from_seed(&[1; 32]);
    let b = SigningKey::from_seed(&[2; 32]);
    let admin = tenant(&servers, &a).await;
    let current = admin.fetch(&now()).await.unwrap();
    let next =
        next_root(current.tenant.root(), [AdminKey::Ed25519 { public_key: b.public_key() }], &[], Some(2)).unwrap();
    let keys = [a, b];
    assert!(admin.rotate_root(&current, next.clone(), &keys[..1], &now()).await.is_err(), "needs b too");
    assert_eq!(servers.verified().root().version, 1, "nothing was logged");
    let (link, state) = admin.rotate_root(&current, next, &keys, &now()).await.unwrap();
    assert_eq!((link.root.body.version, state.body.version, state.body.root_version), (2, 2, 2));
    let verified = servers.verified();
    assert_eq!((verified.root().version, verified.root().threshold), (2, 2));

    // Later edits need both keys.
    let current = admin.fetch(&now()).await.unwrap();
    let proposal = Admin::draft(&current, &now(), |s| {
        s.apps.entry(seal_proto::AppName::new("billing").unwrap()).or_default().insert(app_key(3));
        Ok(())
    })
    .unwrap();
    assert!(Admin::sign_state(current.tenant.root(), proposal.new.clone(), &keys[1..]).is_err());
    let signed = Admin::sign_state(current.tenant.root(), proposal.new, &keys).unwrap();
    admin.publish(&signed).await.unwrap();
    assert_eq!(servers.verified().state().version, 3);
}

#[tokio::test]
async fn freshness_keys_need_their_statement() {
    let servers = Servers::start("freshness").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let signer = SigningKey::from_seed(&[5; 32]);
    let admin = tenant(&servers, &key).await;
    let current = admin.fetch(&now()).await.unwrap();
    let proposal = Admin::draft(&current, &now(), |s| {
        s.freshness_keys.insert(signer.public_key());
        Ok(())
    })
    .unwrap();
    let signed = Admin::sign_state(current.tenant.root(), proposal.new, &[key]).unwrap();
    admin.publish(&signed).await.unwrap();
    let err = admin.fetch(&now()).await.err().unwrap();
    assert!(err.to_string().contains("seal settings freshness sign"), "{err}");
    assert!(admin.fetch_as_freshness_signer(&SigningKey::from_seed(&[6; 32]), &now()).await.is_err());
    let current = admin.fetch_as_freshness_signer(&signer, &now()).await.unwrap();
    admin.post_freshness(&signer, current.tenant.state(), &now()).await.unwrap();
    assert_eq!(admin.fetch(&now()).await.unwrap().tenant.state().version, 2);
}

#[tokio::test]
async fn release_approval_is_admin_signed() {
    let servers = Servers::start("cosign").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let admin = tenant(&servers, &key).await;
    let current = admin.fetch(&now()).await.unwrap();
    let measurement = Measurement([7; 48]);
    let cosign = admin.approve_release(&current, measurement, &[key]).await.unwrap();
    seal_verify::TenantVerifier::verify_admin_signed(
        current.tenant.root(),
        seal_proto::release::RELEASE_COSIGN_LABEL,
        &cosign,
    )
    .unwrap();
    assert!(servers.stored.lock().unwrap().cosigns.contains_key(&measurement.to_string()));
}

#[tokio::test]
async fn verify_roots_finds_a_competing_root() {
    let servers = Servers::start("roots").await;
    let key = SigningKey::from_seed(&[1; 32]);
    let admin = tenant(&servers, &key).await;
    let scan = admin.verify_roots(&now()).await.unwrap();
    assert_eq!(scan.scanned, Some(2), "root v1 and state v1");
    assert!(scan.findings.is_empty(), "{:?}", scan.findings);

    let rogue = TenantRoot {
        tenant: acme(),
        version: 1,
        admin_keys: [AdminKey::Ed25519 { public_key: SigningKey::from_seed(&[8; 32]).public_key() }].into(),
        threshold: 1,
        cosign_releases: false,
    };
    let signed = registrar().sign_into(TENANT_ROOT_LABEL, rogue.clone());
    admin.log().append(&LogEntry::TenantRoot(signed.body)).await.unwrap();
    let scan = admin.verify_roots(&now()).await.unwrap();
    assert_eq!(scan.scanned, Some(3));
    assert_eq!(scan.findings.len(), 1, "{:?}", scan.findings);
    let rogue_id = seal_proto::state::root_id(&rogue).to_string();
    assert!(scan.findings[0].contains("competing root version 1") && scan.findings[0].contains(&rogue_id));
}

/// Two admins of a threshold-2 root sign one after another, each from their own machine.
#[tokio::test]
async fn admins_sign_a_proposal_one_after_another() {
    use seal_client::admin::{cosign, meets_threshold, Proposed, Submitted};
    use seal_proto::signed::Signed;
    use seal_proto::state::TENANT_STATE_LABEL;

    let servers = Servers::start("m-of-n").await;
    let a = SigningKey::from_seed(&[1; 32]);
    let b = SigningKey::from_seed(&[2; 32]);
    let admin = tenant(&servers, &a).await;
    let current = admin.fetch(&now()).await.unwrap();
    let next =
        next_root(current.tenant.root(), [AdminKey::Ed25519 { public_key: b.public_key() }], &[], Some(2)).unwrap();
    admin
        .rotate_root(&current, next, &[SigningKey::from_seed(&[1; 32]), SigningKey::from_seed(&[2; 32])], &now())
        .await
        .unwrap();

    let current = admin.fetch(&now()).await.unwrap();
    let root = current.tenant.root().clone();
    let draft = Admin::draft(&current, &now(), |s| {
        s.apps.entry(seal_proto::AppName::new("billing").unwrap()).or_default().insert(app_key(4));
        Ok(())
    })
    .unwrap();
    let by_a = cosign(&root, TENANT_STATE_LABEL, Signed { body: draft.new, signatures: vec![] }, &[a]);
    assert!(!meets_threshold(&root, TENANT_STATE_LABEL, &by_a));
    let proposal = admin.propose_document(&Proposed::State(by_a)).await.unwrap();

    // The second admin finds it, signs it and submits.
    let open = admin.proposals().await.unwrap();
    assert_eq!(open, vec![proposal.clone()]);
    let Proposed::State(held) = &open[0].document else { panic!("a state") };
    let by_both = cosign(&root, TENANT_STATE_LABEL, held.clone(), &[b]);
    assert!(meets_threshold(&root, TENANT_STATE_LABEL, &by_both));
    admin.propose_document(&Proposed::State(by_both.clone())).await.unwrap();
    let Submitted::State(logged) = admin.submit(&Proposed::State(by_both)).await.unwrap() else { panic!("a state") };
    assert_eq!(logged.state.body.version, 3);
    assert_eq!(servers.verified().state().version, 3);
    assert!(admin.proposals().await.unwrap().is_empty());
}
