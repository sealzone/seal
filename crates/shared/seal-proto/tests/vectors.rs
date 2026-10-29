//! Canonical wire vectors, wire format v1. Every type that is signed, hashed, used as AEAD
//! associated data or read by a guardian has a fixed sample here, with its exact canonical
//! bytes and digests, in `tests/vectors/wire-v1.json`. A change to any of them fails this test.
//!
//! The rule, because a frozen guardian decodes these forever: within v1 a type may only gain
//! optional fields that are omitted when unset (so existing bytes stay identical), and labels
//! never change. Anything else is a new label version (`…/v2`) next to the old one.
//!
//! Regenerate only for a deliberate format change: `SEAL_WRITE_VECTORS=1 cargo test -p
//! sealzone-proto --test vectors`, then review the diff of `wire-v1.json`.

use std::collections::{BTreeMap, BTreeSet};

use seal_proto::api::{AttestationBinding, ExtendRequest, IngestContext, SessionRequest, SignalRequest};
use seal_proto::blob::{Blob, BlobHeader, DekWrap, POLICY_LABEL};
use seal_proto::codec::{canonical, labeled_digest};
use seal_proto::freshness::{GuardianChallenge, ProofTicket};
use seal_proto::identity::*;
use seal_proto::integrity::*;
use seal_proto::policy::{HttpRules, Injection, SecretPolicy, SpkiPin};
use seal_proto::release::*;
use seal_proto::session::{ConsumerTier, PlatformTier, SessionEnd, SESSION_END_LABEL};
use seal_proto::signed::{SigAlg, Signature};
use seal_proto::state::*;
use seal_proto::telemetry::*;
use seal_proto::tunnel::{TunnelConnect, TunnelPreamble};
use seal_proto::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
struct Vector {
    name: String,
    /// Hex of `codec::canonical(value)`, or of the raw bytes for text and framing vectors.
    bytes: String,
    sha256: String,
    /// The signing or hashing label, when the type has one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    label: Option<String>,
    /// `codec::labeled_digest(label, value)`: what signatures sign.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    labeled_digest: Option<String>,
}

struct Vectors(Vec<Vector>);

impl Vectors {
    fn raw(&mut self, name: &str, bytes: &[u8]) {
        self.0.push(Vector {
            name: name.into(),
            bytes: hex::encode(bytes),
            sha256: hex::encode(Sha256::digest(bytes)),
            label: None,
            labeled_digest: None,
        });
    }
    fn cbor<T: Serialize>(&mut self, name: &str, value: &T) {
        self.raw(name, &canonical(value));
    }
    fn signed<T: Serialize>(&mut self, name: &str, label: &str, value: &T) {
        self.cbor(name, value);
        let v = self.0.last_mut().unwrap();
        v.label = Some(label.into());
        v.labeled_digest = Some(hex::encode(labeled_digest(label, value)));
    }
}

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}
fn app() -> AppName {
    AppName::new("checkout").unwrap()
}
fn app_key_id() -> WorkloadIdentity {
    WorkloadIdentity::AppKey { key_id: KeyId([0x11; 32]) }
}
fn sig() -> Signature {
    Signature { signer: KeyId([0x22; 32]), alg: SigAlg::Ed25519 { sig: vec![0x33; 64] } }
}
fn ticket() -> ProofTicket {
    ProofTicket { value: [0x44; 32], expires_at: 1_900_000_120, mac: [0x45; 32] }
}
fn context(purpose: ProofPurpose) -> ProofContext {
    ProofContext { tenant: tenant(), purpose, tls_spki_sha256: [0x46; 32], ticket: ticket() }
}
fn proof() -> IdentityProof {
    IdentityProof::AppKey { key_id: KeyId([0x11; 32]), signature: vec![0x47; 64] }
}
fn endpoint() -> EndpointReport {
    EndpointReport { artifact: Some(ArtifactHash { name: "executable".into(), sha256: [0x48; 32] }), evidence: vec![] }
}
fn policy() -> SecretPolicy {
    SecretPolicy::new("https://api.openai.com/v1", [app()])
        .unwrap()
        .with_expiry(1_950_000_000)
        .with_http(
            Injection::new("authorization", Some("Bearer {key}")).unwrap(),
            HttpRules { methods: ["POST".into()].into(), deny_path_prefixes: ["/v1/organization".into()].into() },
        )
        .unwrap()
        .with_pins([SpkiPin([0x49; 32])])
        .unwrap()
        .with_min_platform(PlatformTier::Sealed)
}
fn root_v1() -> TenantRoot {
    TenantRoot {
        tenant: tenant(),
        version: 1,
        admin_keys: [
            AdminKey::Ed25519 { public_key: PublicKey([0x50; 32]) },
            AdminKey::WebAuthnEs256 { sec1: vec![0x04; 65], rp_id: "seal.zone".into() },
        ]
        .into(),
        threshold: 1,
        cosign_releases: false,
    }
}
fn checkpoint() -> Checkpoint {
    Checkpoint {
        origin: "log.seal.zone/v1".into(),
        size: 42,
        root_hash: [0x51; 32],
        policy: ReleaseConstraints {
            min_service_key_version: BTreeMap::from([(PlatformId::AzureSnpAci, ServiceKeyVersion(1))]),
            min_tcb: BTreeMap::from([(
                PlatformId::AzureSnpAci,
                Tcb(BTreeMap::from([("snp".into(), 22), ("microcode".into(), 213), ("uvm_svn".into(), 100)])),
            )]),
            revoked_keys: [KeyId([0x52; 32])].into(),
            revoked_measurements: BTreeMap::from([(PlatformId::AwsNitro, [Measurement([0x53; 48])].into())]),
        },
    }
}

fn build() -> Vec<Vector> {
    let mut v = Vectors(Vec::new());

    // Text forms and framing.
    let pin = TenantPin { tenant: tenant(), root_id: root_id(&root_v1()) };
    v.raw("text/tenant-pin", pin.to_string().as_bytes());
    v.raw(
        "tunnel/connect",
        &seal_proto::tunnel::encode(&TunnelPreamble::Connect(TunnelConnect {
            token: Bearer::new("sealtok_example".into()),
            local_key_sha256: [0x54; 32],
        })),
    );
    v.raw(
        "tunnel/extend",
        &seal_proto::tunnel::encode(&TunnelPreamble::Extend { token: Bearer::new("sealtok_example".into()) }),
    );

    // Evidence, every platform.
    v.cbor(
        "evidence/azure-snp-aci",
        &Evidence::AzureSnpAci { report: vec![0x60; 1184], vcek_der: vec![0x61; 16], uvm_endorsement: "AAEC".into() },
    );
    v.cbor("evidence/aws-nitro", &Evidence::AwsNitro { document: vec![0x62; 32] });
    v.cbor("evidence/gcp-confidential-space", &Evidence::GcpConfidentialSpace { token: "eyJ.eyJ.sig".into() });
    v.cbor("evidence/sim", &Evidence::Sim { document: vec![0x63; 32] });

    // Bindings committed in report data.
    v.signed(
        "binding/attestation",
        seal_proto::api::ATTESTATION_BINDING_LABEL,
        &AttestationBinding {
            attested_at: 1_900_000_000,
            service_key_version: ServiceKeyVersion(1),
            tls_spki_sha256: [0x64; 32],
            ingest_public_key: PublicKey([0x65; 32]),
            telemetry_public_keys: vec![(ServiceKeyVersion(1), PublicKey([0x66; 32]))],
        },
    );
    let challenge = GuardianChallenge { value: [0x67; 32], expires_at: 1_900_000_060, mac: [0x68; 32] };
    for (name, purpose) in [
        ("binding/key-request/service", KeyPurpose::Service { tenant: tenant(), root_id: pin.root_id }),
        (
            "binding/key-request/tenant",
            KeyPurpose::Tenant {
                tenant: tenant(),
                root_id: pin.root_id,
                tenant_key_versions: vec![TenantKeyVersion(1), TenantKeyVersion(2)],
            },
        ),
        ("binding/key-request/succession", KeyPurpose::Succession),
    ] {
        v.signed(
            name,
            KEY_REQUEST_BINDING_LABEL,
            &KeyRequestBinding {
                protocol_version: GUARDIAN_PROTOCOL_VERSION,
                challenge: challenge.clone(),
                ephemeral_public_key: PublicKey([0x69; 32]),
                purpose,
            },
        );
    }
    let binding = KeyRequestBinding {
        protocol_version: GUARDIAN_PROTOCOL_VERSION,
        challenge: challenge.clone(),
        ephemeral_public_key: PublicKey([0x69; 32]),
        purpose: KeyPurpose::Service { tenant: tenant(), root_id: pin.root_id },
    };
    v.signed(
        "guardian/key-response",
        KEY_RESPONSE_LABEL,
        &(labeled_digest(KEY_REQUEST_BINDING_LABEL, &binding), vec![0x82u8; 32], vec![0x83u8; 64]),
    );
    v.cbor("freshness/guardian-challenge", &challenge);
    v.cbor("freshness/proof-ticket", &ticket());

    // Tenant documents.
    let root = root_v1();
    v.signed("state/tenant-root-v1", TENANT_ROOT_LABEL, &root);
    v.raw("state/root-id", &root_id(&root).0);
    let state = TenantState {
        tenant: tenant(),
        version: 7,
        root_version: 1,
        apps: BTreeMap::from([(
            app(),
            BTreeSet::from([
                IdentityMatcher::Azure {
                    entra_tenant: "t".into(),
                    object_id: "o".into(),
                    audience: "api://seal".into(),
                    hosted: None,
                },
                IdentityMatcher::GitHub {
                    repository: "acme/api".into(),
                    repository_id: 101,
                    repository_owner_id: 7,
                    scope: GitHubScope::Environment("prod".into()),
                },
            ]),
        )]),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(2), oldest_accepted: TenantKeyVersion(1) },
        platforms: [PlatformId::AzureSnpAci, PlatformId::AwsNitro].into(),
        integrity: IntegrityPolicy {
            artifacts: BTreeMap::from([(app(), [ArtifactHash { name: "image".into(), sha256: [0x6b; 32] }].into())]),
            sources: BTreeMap::from([("defender".into(), PublicKey([0x6c; 32]))]),
            actions: BTreeMap::from([(Severity::High, IntegrityAction::Suspend { secs: Some(3600) })]),
            cleared: [Clearance { identity: app_key_id(), before: 1_890_000_000 }].into(),
        },
        deployments: [IdentityMatcher::ConfidentialSpace {
            project_number: 123,
            service_account: "seal@acme.iam".into(),
            hosted: None,
        }]
        .into(),
        freshness_keys: [PublicKey([0x6d; 32])].into(),
        telemetry_readers: [PublicKey([0x6e; 32])].into(),
        issued_at: 1_900_000_000,
        pending_window_secs: 0,
        app_networks: Default::default(),
        freshness_secs: None,
    };
    v.signed("state/tenant-state", TENANT_STATE_LABEL, &state);
    let state_digest = labeled_digest(TENANT_STATE_LABEL, &state);
    // The tenant's consent to Seal's hosted replicas, next to its own deployment.
    let mut hosted = state.clone();
    hosted.version = 8;
    hosted.deployments.insert(IdentityMatcher::ConfidentialSpace {
        project_number: 456,
        service_account: "t-acme@seal-hosted.iam.gserviceaccount.com".into(),
        hosted: Some(HostedMode::Sessions),
    });
    v.signed("state/tenant-state-hosted", TENANT_STATE_LABEL, &hosted);
    v.cbor(
        "identity/deployment-hosted-sessions",
        &IdentityMatcher::ConfidentialSpace {
            project_number: 456,
            service_account: "t-acme@seal-hosted.iam.gserviceaccount.com".into(),
            hosted: Some(HostedMode::Sessions),
        },
    );
    // Seal's hosted replicas on ACI: the tenant's managed identity in Seal's subscription.
    let hosted_azure = IdentityMatcher::Azure {
        entra_tenant: "8c1b1f9e-5f1c-4a0e-9d6a-3c2b1a0f9e8d".into(),
        object_id: "0f9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d6c".into(),
        audience: "api://seal-hosted".into(),
        hosted: Some(HostedMode::Sessions),
    };
    let mut hosted_on_azure = state.clone();
    hosted_on_azure.version = 9;
    hosted_on_azure.deployments.insert(hosted_azure);
    v.signed("state/tenant-state-hosted-azure", TENANT_STATE_LABEL, &hosted_on_azure);
    v.cbor(
        "identity/deployment-hosted-azure-sessions",
        &IdentityMatcher::Azure {
            entra_tenant: "8c1b1f9e-5f1c-4a0e-9d6a-3c2b1a0f9e8d".into(),
            object_id: "0f9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d6c".into(),
            audience: "api://seal-hosted".into(),
            hosted: Some(HostedMode::Sessions),
        },
    );
    v.signed(
        "state/freshness",
        STATE_FRESHNESS_LABEL,
        &StateFreshness { tenant: tenant(), version: 7, digest: state_digest, signed_at: 1_900_000_100 },
    );

    // Log leaves and checkpoints.
    let manifest = ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::AzureSnpAci,
        measurement: Measurement([0x6f; 48]),
        service_key_version: ServiceKeyVersion(1),
        version: "0.1.0".into(),
        source_commit: "81af7cc".into(),
        serves: None,
    };
    v.signed("release/manifest", RELEASE_LABEL, &manifest);
    v.cbor("log/release", &LogEntry::Release(manifest.clone()));
    v.cbor("log/tenant-root", &LogEntry::TenantRoot(root.clone()));
    v.cbor(
        "log/tenant-state",
        &LogEntry::TenantState(TenantStateLeaf {
            tenant: tenant(),
            root_id: pin.root_id,
            version: 7,
            digest: state_digest,
        }),
    );
    v.signed("log/checkpoint", CHECKPOINT_LABEL, &checkpoint());

    // The pending window: a state that sets one, a state with its log proof
    // (`TenantBundle::states`) and a guardian's anchor (`TenantBundle::anchors`).
    let windowed = TenantState { version: 8, pending_window_secs: 86_400, ..state.clone() };
    v.signed("state/tenant-state-pending-window", TENANT_STATE_LABEL, &windowed);
    // A state with its own freshness window (`TenantState::freshness_secs`).
    let short_fresh = TenantState { version: 9, freshness_secs: Some(600), ..state.clone() };
    v.signed("state/tenant-state-freshness-window", TENANT_STATE_LABEL, &short_fresh);
    let signed_checkpoint = SignedCheckpoint {
        checkpoint: checkpoint(),
        log_signature: sig(),
        cosignatures: vec![Cosignature { timestamp: 1_900_000_200, signature: sig() }],
    };
    v.cbor(
        "state/logged-state",
        &LoggedState {
            state: seal_proto::signed::Signed { body: windowed.clone(), signatures: vec![sig()] },
            proof: TlogProof { checkpoint: signed_checkpoint, leaf_index: 41, audit_path: vec![[0x54; 32]] },
        },
    );
    v.signed(
        "state/tenant-anchor",
        TENANT_ANCHOR_LABEL,
        &TenantAnchor {
            platform: PlatformId::AzureSnpAci,
            tenant: tenant(),
            root_id: pin.root_id,
            version: 8,
            digest: labeled_digest(TENANT_STATE_LABEL, &windowed),
            since: 1_900_000_300,
            at: 1_900_003_600,
        },
    );
    v.signed("log/cosignature", COSIGNATURE_LABEL, &(checkpoint(), 1_900_000_200u64));
    v.signed(
        "release/manifest-guardian",
        RELEASE_LABEL,
        &ReleaseManifest {
            component: Component::Guardian,
            platform: PlatformId::AzureSnpAci,
            measurement: Measurement([0x81; 48]),
            service_key_version: ServiceKeyVersion(1),
            version: "0.2.0".into(),
            source_commit: "b4ab49a".into(),
            serves: Some(PlatformId::AwsNitro),
        },
    );
    v.signed(
        "release/cosign",
        RELEASE_COSIGN_LABEL,
        &ReleaseCosign { tenant: tenant(), measurement: manifest.measurement },
    );

    // Guardian outputs.
    v.signed(
        "guardian/service-key-certificate",
        SERVICE_KEY_CERTIFICATE_LABEL,
        &ServiceKeyCertificate {
            platform: PlatformId::AzureSnpAci,
            tenant: tenant(),
            root_id: pin.root_id,
            service_key_version: ServiceKeyVersion(1),
            tls_spki_sha256: [0x64; 32],
            ingest_public_key: PublicKey([0x65; 32]),
            telemetry_public_keys: vec![(ServiceKeyVersion(1), PublicKey([0x66; 32]))],
        },
    );
    v.signed(
        "guardian/tenant-wrap-key",
        TENANT_WRAP_KEY_LABEL,
        &TenantWrapKey {
            platform: PlatformId::AwsNitro,
            tenant: tenant(),
            root_id: pin.root_id,
            tenant_key_version: TenantKeyVersion(2),
            public_key: PublicKey([0x70; 32]),
        },
    );
    v.signed(
        "guardian/identity",
        GUARDIAN_IDENTITY_LABEL,
        &([0x71u8; 32], PlatformId::AzureSnpAci, PublicKey([0x72; 32])),
    );

    // Blob.
    let policy = policy();
    v.signed("blob/policy", POLICY_LABEL, &policy);
    let header = BlobHeader {
        version: seal_proto::blob::BLOB_VERSION,
        tenant: tenant(),
        root_id: pin.root_id,
        tenant_key_version: TenantKeyVersion(2),
        blob_id: BlobId([0xb7, 0xf2, 0, 0, 0, 0, 0, 1]),
        policy_digest: labeled_digest(POLICY_LABEL, &policy),
        created_at: 1_900_000_000,
    };
    v.cbor("blob/header", &header);
    let blob = Blob {
        header,
        policy,
        wraps: vec![
            DekWrap::Hpke { platform: PlatformId::AzureSnpAci, enc: vec![0x73; 32], wrapped_dek: vec![0x74; 48] },
            DekWrap::Hpke { platform: PlatformId::AwsNitro, enc: vec![0x75; 32], wrapped_dek: vec![0x76; 48] },
        ],
        nonce: [0x77; 12],
        ciphertext: vec![0x78; 40],
    };
    v.raw("blob/text", blob.to_string().as_bytes());

    // Request bindings: what identity proofs commit to.
    let ctx = context(ProofPurpose::Session { request_digest: [0; 32] });
    v.signed("identity/proof-context", PROOF_CONTEXT_LABEL, &ctx);
    v.cbor(
        "purpose/ingest-context",
        &IngestContext { tenant: tenant(), service_key_version: ServiceKeyVersion(1), tls_spki_sha256: [0x46; 32] },
    );
    let session_req = SessionRequest {
        blob: blob.to_string(),
        context: ctx.clone(),
        proof: proof(),
        min_tier: Some(ConsumerTier::Base),
        endpoint: Some(endpoint()),
    };
    v.cbor("purpose/session", &session_req.expected_purpose());
    let extend_req = ExtendRequest {
        token: Bearer::new("sealtok_example".into()),
        endpoint: Some(endpoint()),
        context: ctx.clone(),
        proof: proof(),
    };
    v.cbor("purpose/extend", &extend_req.expected_purpose());
    let signal_req = SignalRequest {
        code: "edr-high".into(),
        severity: Severity::High,
        context: Some(ctx),
        proof: Some(proof()),
        identity: None,
        observed_at: None,
        blob_id: None,
        signatures: Vec::new(),
    };
    v.cbor("purpose/signal", &signal_req.expected_purpose());

    // Enclave-signed records.
    v.signed(
        "session/end",
        SESSION_END_LABEL,
        &SessionEnd {
            tenant: tenant(),
            session_id: [0x7b; 16],
            reason: ErrorCode::SessionEnded,
            ended_at: 1_900_000_300,
        },
    );
    v.signed(
        "integrity/signal",
        SIGNAL_LABEL,
        &IntegritySignal {
            tenant: tenant(),
            identity: app_key_id(),
            source: SignalSource::External { source: "defender".into() },
            code: "edr-high".into(),
            severity: Severity::High,
            observed_at: 1_900_000_400,
            blob_id: None,
        },
    );
    let entries = vec![
        TelemetryEntry {
            at: 1_900_000_500,
            tenant: tenant(),
            identity: Some(app_key_id()),
            event: TelemetryEvent::Seal {
                blob_id: BlobId([1; 8]),
                destination: "https://api.openai.com:443/v1".into(),
                apps: [app()].into(),
            },
        },
        TelemetryEntry {
            at: 1_900_000_501,
            tenant: tenant(),
            identity: None,
            event: TelemetryEvent::Dropped { requests: 3, other: 0 },
        },
    ];
    for (name, entries) in [
        ("telemetry/batch-clear", TelemetryEntries::Clear { entries }),
        (
            "telemetry/batch-sealed",
            TelemetryEntries::Sealed {
                readers: vec![TelemetryReaderKey {
                    reader: PublicKey([0x6e; 32]),
                    enc: vec![0x7c; 32],
                    wrapped_key: vec![0x7d; 48],
                }],
                nonce: [0x7e; 12],
                ciphertext: vec![0x7f; 80],
            },
        ),
    ] {
        v.signed(
            name,
            TELEMETRY_BATCH_LABEL,
            &TelemetryBatch {
                tenant: tenant(),
                stream: [0x80; 16],
                sequence: 3,
                first_entry: 120,
                count: 2,
                from: 1_900_000_500,
                to: 1_900_000_501,
                entries,
                last: false,
            },
        );
    }

    // Entries with values added within v1, each under its own name so earlier vectors stay.
    v.cbor(
        "telemetry/entry-refused-reseal-required",
        &TelemetryEntry {
            at: 1_900_000_502,
            tenant: tenant(),
            identity: Some(app_key_id()),
            event: TelemetryEvent::Refused {
                operation: Operation::Session,
                code: ErrorCode::ResealRequired,
                context: None,
            },
        },
    );

    v.cbor(
        "telemetry/entry-session-from",
        &TelemetryEntry {
            at: 1_900_000_505,
            tenant: tenant(),
            identity: Some(app_key_id()),
            event: TelemetryEvent::Session {
                session_id: [0x82; 16],
                app: app(),
                blob_id: BlobId([1; 8]),
                tier: seal_proto::session::ConsumerTier::Base,
                from: Some("203.0.113.7:51234".parse().unwrap()),
            },
        },
    );

    v.cbor(
        "telemetry/entry-refused-outside-networks",
        &TelemetryEntry {
            at: 1_900_000_504,
            tenant: tenant(),
            identity: Some(app_key_id()),
            event: TelemetryEvent::Refused {
                operation: Operation::Session,
                code: ErrorCode::NotAllowed,
                context: Some(RefusalContext::OutsideNetworks {
                    app: app(),
                    from: Some("203.0.113.7".parse().unwrap()),
                }),
            },
        },
    );

    v.cbor(
        "telemetry/entry-request-sqlstate",
        &TelemetryEntry {
            at: 1_900_000_503,
            tenant: tenant(),
            identity: Some(app_key_id()),
            event: TelemetryEvent::Request {
                session_id: [0x81; 16],
                app: app(),
                blob_id: BlobId([1; 8]),
                connection_id: 9,
                completion: Completion {
                    protocol: seal_proto::policy::Protocol::Postgres,
                    action: "QUERY".into(),
                    outcome: Outcome::UpstreamError(UpstreamErrorKind::Sqlstate(Sqlstate::new(*b"42P01").unwrap())),
                    bytes_up: 30,
                    bytes_down: 120,
                },
            },
        },
    );

    // Control-plane requests: signed by an admin or telemetry key, or committed in report data.
    v.signed(
        "control/request",
        seal_proto::control::CONTROL_REQUEST_LABEL,
        &seal_proto::control::ControlRequest {
            tenant: tenant(),
            root_id: pin.root_id,
            method: "GET".into(),
            path: "/v1/tenants/acme/telemetry?since=1900000000".into(),
            body_sha256: Sha256::digest(b"").into(),
            issued_at: 1_900_000_600,
        },
    );

    // The signature envelope.
    v.cbor("signed/envelope", &seal_proto::signed::Signed { body: 1u8, signatures: vec![sig()] });

    // Framing added within v1.
    v.raw("tunnel/challenge", &seal_proto::tunnel::encode(&TunnelPreamble::Challenge { nonce: [0x55; 32] }));

    v.0
}

/// Every label is distinct, so a signature for one purpose can never verify as another.
#[test]
fn labels_are_distinct() {
    let labels = [
        seal_proto::api::ATTESTATION_BINDING_LABEL,
        POLICY_LABEL,
        PROOF_CONTEXT_LABEL,
        SIGNAL_LABEL,
        SESSION_END_LABEL,
        TENANT_ROOT_LABEL,
        TENANT_ROOT_ID_LABEL,
        TENANT_STATE_LABEL,
        STATE_FRESHNESS_LABEL,
        TELEMETRY_BATCH_LABEL,
        RELEASE_LABEL,
        AUDITOR_LABEL,
        CHECKPOINT_LABEL,
        COSIGNATURE_LABEL,
        RELEASE_COSIGN_LABEL,
        KEY_REQUEST_BINDING_LABEL,
        KEY_RESPONSE_LABEL,
        SERVICE_KEY_CERTIFICATE_LABEL,
        TENANT_WRAP_KEY_LABEL,
        GUARDIAN_IDENTITY_LABEL,
        seal_proto::control::CONTROL_REQUEST_LABEL,
        TENANT_ANCHOR_LABEL,
        "seal/session-request/v1",
        "seal/extend-request/v1",
        "seal/signal-request/v1",
    ];
    let unique: BTreeSet<_> = labels.iter().collect();
    assert_eq!(unique.len(), labels.len());
    assert!(labels.iter().all(|l| l.starts_with("seal/") && l.ends_with("/v1")));
}

#[test]
fn wire_v1_vectors_are_unchanged() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/wire-v1.json");
    let built = build();
    if std::env::var_os("SEAL_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
        return;
    }
    let stored: Vec<Vector> =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("tests/vectors/wire-v1.json")).unwrap();
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
        "wire v1 vectors differ (see the rule at the top of this file):\n{}",
        changed.join("\n")
    );
}
