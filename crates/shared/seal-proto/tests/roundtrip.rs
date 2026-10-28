//! Every proto type must survive canonical CBOR and JSON unchanged.

use std::collections::BTreeMap;

use seal_proto::blob::{Blob, BlobHeader, DekWrap};
use seal_proto::codec::{canonical, from_canonical, labeled_digest};
use seal_proto::identity::*;
use seal_proto::policy::*;
use seal_proto::release::*;
use seal_proto::signed::*;
use seal_proto::state::*;
use seal_proto::*;

fn both<T>(v: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let back: T = from_canonical(&canonical(v)).expect("cbor roundtrip");
    assert_eq!(&back, v, "cbor");
    let back: T = serde_json::from_str(&serde_json::to_string(v).unwrap()).expect("json roundtrip");
    assert_eq!(&back, v, "json");
}

fn app_key() -> WorkloadIdentity {
    WorkloadIdentity::AppKey { key_id: KeyId([7; 32]) }
}

fn sig() -> Signature {
    Signature { signer: KeyId([1; 32]), alg: SigAlg::Ed25519 { sig: vec![2; 64] } }
}

fn policy() -> SecretPolicy {
    SecretPolicy::new("https://api.openai.com/v1", [AppName::new("checkout").unwrap()])
        .unwrap()
        .with_expiry(1_900_000_000)
}

fn proof() -> TlogProof {
    TlogProof {
        checkpoint: SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: "log.seal.dev/v1".into(),
                size: 9,
                root_hash: [3; 32],
                policy: ReleaseConstraints {
                    min_service_key_version: BTreeMap::from([(PlatformId::AzureSnpAci, ServiceKeyVersion(1))]),
                    ..Default::default()
                },
            },
            log_signature: sig(),
            cosignatures: vec![Cosignature { timestamp: 5, signature: sig() }],
        },
        leaf_index: 4,
        audit_path: vec![[9; 32]],
    }
}

#[test]
fn tagged_enums_with_bytes_roundtrip() {
    both(&app_key());
    both(&IdentityMatcher::AppKey { key_id: KeyId([1; 32]), public_key: PublicKey([2; 32]) });
    both(&ProofPurpose::Seal { request_digest: [4; 32] });
    both(&AdminKey::WebAuthnEs256 { sec1: vec![4; 65], rp_id: "seal.dev".into() });
    both(&sig());
    both(&LogEntry::Release(ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement: Measurement([5; 48]),
        service_key_version: ServiceKeyVersion(1),
        version: "0.1.0".into(),
        source_commit: "abc".into(),
        serves: None,
    }));
    both(&proof());
}

fn blob_with(p: SecretPolicy) -> Blob {
    Blob {
        header: BlobHeader {
            version: 1,
            tenant: TenantId::new("acme").unwrap(),
            root_id: TenantRootId([6; 32]),
            tenant_key_version: TenantKeyVersion(3),
            blob_id: BlobId([0xb7, 0xf2, 0, 0, 0, 0, 0, 1]),
            producer: app_key(),
            policy_digest: labeled_digest(seal_proto::blob::POLICY_LABEL, &p),
            created_at: 1,
        },
        policy: p,
        wraps: vec![DekWrap::Hpke { platform: PlatformId::Sim, enc: vec![1; 32], wrapped_dek: vec![2; 48] }],
        nonce: [3; 12],
        ciphertext: vec![4; 40],
    }
}

#[test]
fn blob_text_roundtrip_with_app_key_producer() {
    let blob = blob_with(policy());
    let text = blob.to_string();
    assert!(text.starts_with("seal1.acme.3.b7f2000000000001."));
    assert_eq!(text.parse::<Blob>().unwrap(), blob);
}

#[test]
fn edited_policy_is_rejected() {
    let blob = blob_with(policy());
    let mut edited = blob.clone();
    edited.policy = SecretPolicy::new("https://attacker.example", [AppName::new("checkout").unwrap()]).unwrap();
    assert!(edited.to_string().parse::<Blob>().is_err());
}

#[test]
fn pins_cost_little_and_nothing_when_unset() {
    let unpinned = blob_with(policy());
    assert!(!String::from_utf8_lossy(&canonical(&unpinned.policy)).contains("pins"));
    let pinned = blob_with(policy().with_pins([SpkiPin([9; 32])]).unwrap());
    assert_eq!(pinned.to_string().parse::<Blob>().unwrap(), pinned);
    let growth = pinned.to_string().len() - unpinned.to_string().len();
    assert!(growth <= 60, "one pin added {growth} characters");
    assert!(policy().with_pins((0..=MAX_PINS as u8).map(|b| SpkiPin([b; 32]))).is_err());
}

#[test]
fn ids_are_hex_in_json() {
    assert_eq!(serde_json::to_string(&BlobId([0xab; 8])).unwrap(), "\"abababababababab\"");
}

#[test]
fn new_wire_types_roundtrip() {
    both(&seal_proto::freshness::GuardianChallenge { value: [1; 32], expires_at: 60, mac: [2; 32] });
    both(&LogEntry::TenantState(TenantStateLeaf {
        tenant: TenantId::new("acme").unwrap(),
        root_id: TenantRootId([6; 32]),
        version: 42,
        digest: [7; 32],
    }));
    both(&StateFreshness { tenant: TenantId::new("acme").unwrap(), version: 42, digest: [7; 32], signed_at: 9 });
    both(&seal_proto::telemetry::TelemetryEntries::Sealed {
        readers: vec![seal_proto::telemetry::TelemetryReaderKey {
            reader: PublicKey([3; 32]),
            enc: vec![4; 32],
            wrapped_key: vec![5; 48],
        }],
        nonce: [6; 12],
        ciphertext: vec![7; 64],
    });
    both(&KeyPurpose::Tenant {
        tenant: TenantId::new("acme").unwrap(),
        root_id: TenantRootId([6; 32]),
        tenant_key_versions: vec![TenantKeyVersion(1)],
    });
}

#[test]
fn revocations_and_min_platform_cost_nothing_when_unset() {
    let unrevoked = ReleaseConstraints::default();
    assert!(!String::from_utf8_lossy(&canonical(&unrevoked)).contains("revoked"));
    let revoked = ReleaseConstraints {
        revoked_keys: [KeyId([1; 32])].into(),
        revoked_measurements: BTreeMap::from([(PlatformId::AzureSnpAci, [Measurement([2; 48])].into())]),
        ..Default::default()
    };
    both(&revoked);

    assert!(!String::from_utf8_lossy(&canonical(&policy())).contains("min_platform"));
    let sealed_only = blob_with(policy().with_min_platform(seal_proto::session::PlatformTier::Sealed));
    assert_eq!(sealed_only.to_string().parse::<Blob>().unwrap(), sealed_only);
}

#[test]
fn a_competing_root_v1_has_another_root_id() {
    let root = |threshold| TenantRoot {
        tenant: TenantId::new("acme").unwrap(),
        version: 1,
        admin_keys: [AdminKey::Ed25519 { public_key: PublicKey([1; 32]) }].into(),
        threshold,
        cosign_releases: false,
    };
    assert_eq!(root_id(&root(1)), root_id(&root(1)));
    assert_ne!(root_id(&root(1)), root_id(&root(2)));
}

#[test]
fn multi_cloud_wire_types_roundtrip() {
    both(&TenantWrapKey {
        platform: PlatformId::AwsNitro,
        tenant: TenantId::new("acme").unwrap(),
        root_id: TenantRootId([6; 32]),
        tenant_key_version: TenantKeyVersion(2),
        public_key: PublicKey([8; 32]),
    });
    both(&WorkloadIdentity::ConfidentialSpace {
        project_number: 123_456_789,
        service_account: "seal@acme.iam.gserviceaccount.com".into(),
    });
    both(&seal_proto::api::AttestationBinding {
        attested_at: 1_900_000_000,
        service_key_version: ServiceKeyVersion(1),
        tls_spki_sha256: [1; 32],
        ingest_public_key: PublicKey([2; 32]),
        telemetry_public_keys: vec![(ServiceKeyVersion(1), PublicKey([3; 32]))],
    });
}

#[test]
fn evidence_carries_its_platform_and_pins_parse() {
    let ev = Evidence::AwsNitro { document: vec![1; 40] };
    both(&ev);
    assert_eq!(ev.platform(), PlatformId::AwsNitro);
    both(&Evidence::AzureSnpAci { report: vec![2; 1184], vcek_der: vec![3; 64], uvm_endorsement: "AA".into() });
    both(&Evidence::GcpConfidentialSpace { token: "eyJ.x.y".into() });

    let pin: TenantPin = format!("acme@{}", TenantRootId([6; 32])).parse().unwrap();
    assert_eq!(pin.tenant.as_str(), "acme");
    assert_eq!(pin.to_string().parse::<TenantPin>().unwrap(), pin);
    assert!("acme".parse::<TenantPin>().is_err());
    assert!("acme@zz".parse::<TenantPin>().is_err());
    both(&pin);
}

#[test]
fn hosted_mode_is_optional_and_never_matched_on() {
    let plain = r#"{"kind":"confidential_space","project_number":456,"service_account":"t-acme@seal.iam"}"#;
    let m: IdentityMatcher = serde_json::from_str(plain).unwrap();
    assert_eq!(m.hosted(), None);
    assert_eq!(serde_json::to_string(&m).unwrap(), plain, "unset is omitted");
    let hosted =
        r#"{"kind":"confidential_space","project_number":456,"service_account":"t-acme@seal.iam","hosted":"sessions"}"#;
    let h: IdentityMatcher = serde_json::from_str(hosted).unwrap();
    assert_eq!(h.hosted(), Some(HostedMode::Sessions));
    assert_eq!(serde_json::to_string(&h).unwrap(), hosted);
    both(&h);
    let replica =
        WorkloadIdentity::ConfidentialSpace { project_number: 456, service_account: "t-acme@seal.iam".into() };
    assert!(m.matches(&replica) && h.matches(&replica));
    // Seal's hosted replicas on ACI: the same field on the Azure kind.
    let plain = r#"{"kind":"azure","entra_tenant":"tid","object_id":"oid","audience":"api://seal-hosted"}"#;
    let m: IdentityMatcher = serde_json::from_str(plain).unwrap();
    assert_eq!((m.hosted(), serde_json::to_string(&m).unwrap().as_str()), (None, plain), "unset is omitted");
    let hosted =
        r#"{"kind":"azure","entra_tenant":"tid","object_id":"oid","audience":"api://seal-hosted","hosted":"sessions"}"#;
    let h: IdentityMatcher = serde_json::from_str(hosted).unwrap();
    assert_eq!(h.hosted(), Some(HostedMode::Sessions));
    assert_eq!(serde_json::to_string(&h).unwrap(), hosted);
    both(&h);
    let replica = WorkloadIdentity::Azure { entra_tenant: "tid".into(), object_id: "oid".into() };
    assert!(m.matches(&replica) && h.matches(&replica));
    assert_eq!(IdentityMatcher::AppKey { key_id: KeyId([1; 32]), public_key: PublicKey([2; 32]) }.hosted(), None);
}

#[test]
fn app_networks_are_omitted_until_used() {
    let mut state = TenantState {
        tenant: TenantId::new("acme").unwrap(),
        version: 2,
        root_version: 1,
        apps: [(AppName::new("checkout").unwrap(), Default::default())].into(),
        producers: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(1), oldest_accepted: TenantKeyVersion(1) },
        platforms: Default::default(),
        integrity: Default::default(),
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: 1,
        pending_window_secs: 0,
        app_networks: Default::default(),
    };
    // States that use no network rule keep their encoding (and so their digest): the key
    // is in neither the canonical CBOR nor the JSON.
    let has = |bytes: &[u8]| bytes.windows(12).any(|w| w == b"app_networks");
    assert!(!has(&canonical(&state)));
    assert!(!serde_json::to_string(&state).unwrap().contains("app_networks"));
    state.app_networks.insert(AppName::new("checkout").unwrap(), ["203.0.113.0/24".parse().unwrap()].into());
    assert!(has(&canonical(&state)));
    let text = serde_json::to_string(&state).unwrap();
    assert!(text.contains(r#""app_networks":{"checkout":["203.0.113.0/24"]}"#), "{text}");
    both(&state);
}

#[test]
fn a_pending_window_has_one_encoding() {
    let state = TenantState {
        tenant: TenantId::new("acme").unwrap(),
        version: 2,
        root_version: 1,
        apps: Default::default(),
        producers: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(1), oldest_accepted: TenantKeyVersion(1) },
        platforms: Default::default(),
        integrity: Default::default(),
        deployments: Default::default(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: 1,
        pending_window_secs: 0,
        app_networks: Default::default(),
    };
    let mut json = serde_json::to_value(&state).unwrap();
    assert!(json.get("pending_window_secs").is_none(), "no window is the omitted field");
    let max = seal_proto::state::MAX_PENDING_WINDOW_SECS;
    for (secs, decodes) in [(0, false), (1, true), (max, true), (max + 1, false)] {
        json["pending_window_secs"] = secs.into();
        assert_eq!(serde_json::from_value::<TenantState>(json.clone()).is_ok(), decodes, "{secs}");
    }
}
