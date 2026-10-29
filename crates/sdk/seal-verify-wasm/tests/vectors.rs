//! The browser API's vectors (`tests/vectors.json`): real documents, proofs, passkey
//! assertions and telemetry with what each function must return. This test checks them
//! against `api`; `js/test.mjs` checks the same file against the WebAssembly build, so both
//! builds agree.
//!
//! Regenerate only for a deliberate change: `SEAL_WRITE_VECTORS=1 cargo test -p
//! sealzone-verify-wasm --test vectors`, then review the diff.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{json, Value};

use seal_crypto::sign::SigningKey;
use seal_crypto::telemetry::TelemetryReaderKey;
use seal_proto::api::TelemetryReceipt;
use seal_proto::codec::{b64url, labeled_digest};
use seal_proto::identity::{HostedMode, IdentityMatcher};
use seal_proto::release::{
    Component, LogEntry, ReleaseEvidence, ReleaseManifest, ServiceKeyCertificate, RELEASE_LABEL,
    SERVICE_KEY_CERTIFICATE_LABEL,
};
use seal_proto::signed::Signed;
use seal_proto::state::{
    root_id, AdminKey, LoggedRoot, LoggedState, TenantBundle, TenantKeyVersions, TenantRoot, TenantState,
    TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::telemetry::{TelemetryBatch, TelemetryEntries, TelemetryEntry, TelemetryEvent, TELEMETRY_BATCH_LABEL};
use seal_proto::{KeyId, Measurement, PlatformId, PublicKey, ServiceKeyVersion, TenantId, TenantKeyVersion, UnixTime};
use seal_tlog::dev::DevLog;
use seal_verify_wasm::api;

const T: UnixTime = 1_900_000_000;
const HOUR: u64 = 3_600;

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}
fn acme() -> TenantId {
    TenantId::new("acme").unwrap()
}
fn wall() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors.json")
}

/// A dev log whose witnesses stamp exactly the times asked for.
struct Log {
    log: DevLog,
    dir: PathBuf,
}

impl Log {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-verify-wasm-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self { log: DevLog::open(&dir, [9; 32], 3, 2).unwrap(), dir }
    }
    /// Runs `f` with every witness stamping exactly `t`.
    fn at<R>(&mut self, t: UnixTime, f: impl Fn(&mut DevLog) -> R, stamp: impl Fn(&R) -> Option<UnixTime>) -> R {
        loop {
            self.log.set_clock_offset(t as i64 - wall());
            let r = f(&mut self.log);
            if stamp(&r) == Some(t) {
                return r;
            }
        }
    }
    fn logged_state(&mut self, state: &Signed<TenantState>, t: UnixTime) -> LoggedState {
        let index = self.log.append_state(state).unwrap();
        let proof = self.at(
            t,
            |l| {
                l.checkpoint();
                l.prove(index)
            },
            |p| uniform(&p.checkpoint),
        );
        LoggedState { state: state.clone(), proof }
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn uniform(cp: &seal_proto::release::SignedCheckpoint) -> Option<UnixTime> {
    let first = cp.cosignatures.first()?.timestamp;
    cp.cosignatures.iter().all(|c| c.timestamp == first).then_some(first)
}

fn deployment(n: u8) -> IdentityMatcher {
    IdentityMatcher::AppKey { key_id: KeyId([n; 32]), public_key: PublicKey([n; 32]) }
}

fn state(version: u64, deployments: &[u8]) -> TenantState {
    TenantState {
        tenant: acme(),
        version,
        root_version: 1,
        apps: Default::default(),
        tenant_key_versions: TenantKeyVersions { current: TenantKeyVersion(1), oldest_accepted: TenantKeyVersion(1) },
        platforms: [PlatformId::Sim].into(),
        integrity: Default::default(),
        deployments: deployments.iter().map(|&n| deployment(n)).collect(),
        freshness_keys: Default::default(),
        telemetry_readers: Default::default(),
        issued_at: T,
        pending_window_secs: HOUR,
        app_networks: Default::default(),
        freshness_secs: None,
    }
}

/// `state(version, &[1])` listing Seal's hosted replicas on ACI with `mode`.
fn hosted_on_azure(version: u64, mode: HostedMode) -> TenantState {
    let mut s = state(version, &[1]);
    s.deployments.insert(IdentityMatcher::Azure {
        entra_tenant: "8c1b1f9e-5f1c-4a0e-9d6a-3c2b1a0f9e8d".into(),
        object_id: "0f9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d6c".into(),
        audience: "api://seal-hosted".into(),
        hosted: Some(mode),
    });
    s
}

/// A passkey (P-256 key `n`) for `seal.zone` and its assertion over `labeled_digest(label, body)`.
fn passkey_assertion<B: serde::Serialize>(n: u8, label: &str, body: &B) -> (AdminKey, Value) {
    use p256::ecdsa::signature::Signer as _;
    use sha2::{Digest, Sha256};
    let signing = p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap();
    let sec1 = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let admin = AdminKey::WebAuthnEs256 { sec1, rp_id: "seal.zone".into() };
    let mut authenticator_data = Sha256::digest(b"seal.zone").to_vec();
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&7u32.to_be_bytes());
    let challenge = b64url(&labeled_digest(label, body));
    let client_data_json =
        format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://console.seal.zone"}}"#)
            .into_bytes();
    let signed = [&authenticator_data[..], &Sha256::digest(&client_data_json)[..]].concat();
    let sig: p256::ecdsa::DerSignature = signing.sign(&signed);
    let assertion = json!({
        "authenticator_data": b64url(&authenticator_data),
        "client_data_json": b64url(&client_data_json),
        "signature": b64url(sig.as_bytes()),
    });
    (admin, assertion)
}

fn build() -> Value {
    let mut log = Log::new();
    let trust_tlog = log.log.trust();
    let guardian = key(60);
    let trust = json!({
        "tenants": {
            "tlog": {
                "origin": trust_tlog.origin,
                "log_key": trust_tlog.log_key,
                "witness_keys": trust_tlog.witness_keys,
                "witness_quorum": trust_tlog.witness_quorum,
            },
            "registrar_keys": [key(21).public_key()],
            "registrar_threshold": 1,
        },
        "releases": {
            "tlog": {
                "origin": trust_tlog.origin,
                "log_key": trust_tlog.log_key,
                "witness_keys": trust_tlog.witness_keys,
                "witness_quorum": trust_tlog.witness_quorum,
            },
            "release_keys": [key(70).public_key(), key(71).public_key(), key(72).public_key()],
            "release_threshold": 2,
            "required_auditor": null,
            "time_lock_secs": HOUR,
        },
        "guardians": { "sim": guardian.public_key() },
    });

    // A tenant with a one-hour window: state 1, a widening state 2 (a deployment added), and a
    // state 3 that supersedes it with state 1's contents.
    let root = TenantRoot {
        tenant: acme(),
        version: 1,
        admin_keys: [AdminKey::Ed25519 { public_key: key(31).public_key() }].into(),
        threshold: 1,
        cosign_releases: false,
    };
    let mut v1 = Signed { body: root.clone(), signatures: vec![] };
    key(21).cosign(TENANT_ROOT_LABEL, &mut v1);
    let root_index = log.log.append(LogEntry::TenantRoot(root.clone())).unwrap();
    let root_proof = log.at(
        T - 10,
        |l| {
            l.checkpoint();
            l.prove(root_index)
        },
        |p| uniform(&p.checkpoint),
    );
    let chain = vec![LoggedRoot { root: v1.clone(), proof: root_proof }];
    let sign = |s: TenantState| key(31).sign_into(TENANT_STATE_LABEL, s);
    let s1 = log.logged_state(&sign(state(1, &[1])), T);
    let s2 = log.logged_state(&sign(state(2, &[1, 2])), T + 100);
    let bundle = |log: &mut Log, states: &[LoggedState], at: UnixTime| {
        let freshness = log.at(at, |l| l.freshness(&acme()).unwrap(), |f| Some(f.body.signed_at));
        let checkpoint = log.at(at, |l| l.checkpoint(), uniform);
        TenantBundle {
            root_chain: chain.clone(),
            state: states.last().unwrap().state.clone(),
            signals: vec![],
            ended_sessions: vec![],
            freshness: vec![freshness],
            wrap_keys: vec![],
            states: states.to_vec(),
            checkpoint: Some(checkpoint),
            anchors: Vec::new(),
        }
    };
    let pending = bundle(&mut log, &[s1.clone(), s2.clone()], T + 200);
    let effective = bundle(&mut log, &[s1.clone(), s2.clone()], T + 100 + HOUR);
    let s3 = log.logged_state(&sign(state(3, &[1])), T + 300);
    let cancelled = bundle(&mut log, &[s1.clone(), s2.clone(), s3.clone()], T + 100 + 2 * HOUR);
    let documents = json!({
        "roots": chain,
        "states": [s1, s2, s3],
        "checkpoint": cancelled.checkpoint,
    });
    // The guardian's anchor for the last bundle: a bundle from it on needs state 3 alone.
    let tenant_trust = seal_verify::TenantTrust {
        tlog: trust_tlog.clone(),
        registrar_keys: vec![key(21).public_key()],
        registrar_threshold: 1,
    };
    let anchor = seal_verify::TenantVerifier::new(tenant_trust, vec![])
        .anchor(PlatformId::Sim, &acme(), &cancelled, &seal_proto::TrustedTime::exact(T + 100 + 2 * HOUR))
        .unwrap();
    let mut anchored = cancelled.clone();
    anchored.states = vec![s3.clone()];
    anchored.anchors = vec![guardian.sign_into(seal_proto::state::TENANT_ANCHOR_LABEL, anchor)];
    let mut unanchored = anchored.clone();
    unanchored.anchors.clear();

    // Signing: a passkey's assertion over a proposed state.
    let proposed = state(4, &[1, 3]);
    let (passkey, assertion) = passkey_assertion(0x42, TENANT_STATE_LABEL, &proposed);
    let signature = api::webauthn_signature(
        &serde_json::to_string(&passkey).unwrap(),
        TENANT_STATE_LABEL,
        &serde_json::to_string(&proposed).unwrap(),
        &assertion.to_string(),
    )
    .unwrap();
    let signature: Value = serde_json::from_str(&signature).unwrap();
    let mut passkey_root = root.clone();
    passkey_root.admin_keys.insert(passkey.clone());
    let mut signed = key(31).sign_into(TENANT_STATE_LABEL, proposed.clone());
    signed.signatures.push(serde_json::from_value(signature.clone()).unwrap());
    signed.signatures.push(key(77).sign(TENANT_STATE_LABEL, &proposed));

    // Telemetry: a certificate for telemetry key 50, a clear stream without its last batch and
    // a sealed one that ends.
    let cert = ServiceKeyCertificate {
        platform: PlatformId::Sim,
        tenant: acme(),
        root_id: root_id(&root),
        service_key_version: ServiceKeyVersion(1),
        tls_spki_sha256: [1; 32],
        ingest_public_key: PublicKey([2; 32]),
        telemetry_public_keys: vec![(ServiceKeyVersion(1), key(50).public_key())],
    };
    let certificates = vec![guardian.sign_into(SERVICE_KEY_CERTIFICATE_LABEL, cert.clone()), {
        let mut other = cert;
        other.tenant = TenantId::new("other").unwrap();
        guardian.sign_into(SERVICE_KEY_CERTIFICATE_LABEL, other)
    }];
    let entry = |at| TelemetryEntry {
        at,
        tenant: acme(),
        identity: None,
        event: TelemetryEvent::Dropped { requests: 1, other: 0 },
    };
    let batch = |stream: u8, sequence, first_entry, count: u32, entries, last| TelemetryBatch {
        tenant: acme(),
        stream: [stream; 16],
        sequence,
        first_entry,
        count,
        from: T,
        to: T,
        entries,
        last,
    };
    let reader = TelemetryReaderKey::from_seed(&[0x33; 32]);
    let mut rng = seal_crypto::UnwrapErr(seal_crypto::SysRng);
    let sealed_entries = seal_crypto::telemetry::seal_entries(
        &acme(),
        [2; 16],
        0,
        0,
        &[entry(T), entry(T)],
        &[reader.public_key()],
        &mut rng,
    )
    .unwrap();
    let batches = vec![
        key(50).sign_into(
            TELEMETRY_BATCH_LABEL,
            batch(1, 0, 0, 1, TelemetryEntries::Clear { entries: vec![entry(T)] }, false),
        ),
        key(50).sign_into(
            TELEMETRY_BATCH_LABEL,
            batch(1, 2, 4, 1, TelemetryEntries::Clear { entries: vec![entry(T)] }, false),
        ),
        key(50).sign_into(TELEMETRY_BATCH_LABEL, batch(2, 0, 0, 2, sealed_entries, true)),
        key(51).sign_into(
            TELEMETRY_BATCH_LABEL,
            batch(3, 0, 0, 1, TelemetryEntries::Clear { entries: vec![entry(T)] }, true),
        ),
    ];
    let receipts = vec![TelemetryReceipt { stream: [1; 16], entry: 0 }, TelemetryReceipt { stream: [1; 16], entry: 2 }];

    // A release signed by two of the three release keys, logged at R and published with a
    // checkpoint from two hours later, so its one-hour time lock has passed; and the same
    // release with one signature. Last in the log, so nothing above changes.
    const R: UnixTime = T + 10 * HOUR;
    let manifest = ReleaseManifest {
        component: Component::Enclave,
        platform: PlatformId::Sim,
        measurement: Measurement([0x5e; 48]),
        service_key_version: ServiceKeyVersion(1),
        version: "1.0.0".into(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
        serves: None,
    };
    let mut signed_manifest = key(70).sign_into(RELEASE_LABEL, manifest.clone());
    key(71).cosign(RELEASE_LABEL, &mut signed_manifest);
    let release_index = log.log.append(LogEntry::Release(manifest.clone())).unwrap();
    let included = log.at(
        R,
        |l| {
            l.checkpoint();
            l.prove(release_index)
        },
        |p| uniform(&p.checkpoint),
    );
    let fresh = log.at(R + 2 * HOUR, |l| l.checkpoint(), uniform);
    let early = log.at(R + HOUR / 2, |l| l.checkpoint(), uniform);
    let evidence = ReleaseEvidence { manifest: signed_manifest.clone(), included, fresh: fresh.clone(), auditor: None };
    let under_threshold =
        ReleaseEvidence { manifest: key(70).sign_into(RELEASE_LABEL, manifest.clone()), ..evidence.clone() };

    json!({
        "trust": trust,
        "tenant": "acme",
        "tenant_cases": [
            {
                "name": "a widening state waits the window",
                "bundle": pending, "now": T + 200,
                "in_force": 1, "latest": 2,
                "pending": [{ "version": 2, "change": "widening", "effective_at": T + 100 + HOUR }],
            },
            {
                "name": "once public for the window it is in force",
                "bundle": effective, "now": T + 100 + HOUR,
                "in_force": 2, "latest": 2, "pending": [],
            },
            {
                "name": "a newer state built on the one in force cancels it",
                "bundle": cancelled, "now": T + 100 + 2 * HOUR,
                "in_force": 3, "latest": 3, "pending": [],
            },
            {
                "name": "a guardian's anchor stands for the states before it",
                "bundle": anchored, "now": T + 100 + 2 * HOUR,
                "in_force": 3, "latest": 3, "pending": [],
            },
            {
                "name": "without an anchor it trusts, /documents completes the bundle",
                "bundle": unanchored, "documents": documents, "now": T + 100 + 2 * HOUR,
                "in_force": 3, "latest": 3, "pending": [],
            },
        ],
        "documents": {
            "documents": documents,
            "public_since": [T, T + 100, T + 300],
        },
        "classify": [
            { "old": state(1, &[1]), "new": state(2, &[1, 2]), "change": "widening", "kinds": ["deployment_added"] },
            { "old": state(2, &[1, 2]), "new": state(3, &[1]), "change": "narrowing", "kinds": ["deployment_removed"] },
            { "old": state(1, &[1]), "new": hosted_on_azure(2, HostedMode::Sessions),
              "change": "widening", "kinds": ["deployment_added"] },
        ],
        "classify_roots": [
            { "old": root, "new": TenantRoot { version: 2, threshold: 1, admin_keys: passkey_root.admin_keys.clone(), ..root.clone() },
              "change": "widening", "kinds": ["admin_key_added"] },
        ],
        "signing": {
            "label": TENANT_STATE_LABEL,
            "document": proposed,
            "digest": hex(&labeled_digest(TENANT_STATE_LABEL, &proposed)),
            "admin_key": passkey,
            "admin_key_id": seal_crypto::sign::admin_key_id(&passkey).to_string(),
            "assertion": assertion,
            "signature": signature,
            "root": passkey_root,
            "signed": signed,
            "signers": [key(31).key_id().to_string(), seal_crypto::sign::admin_key_id(&passkey).to_string()],
            "root_v1": root,
            "root_id": root_id(&root).to_string(),
        },
        "releases": {
            "checkpoint": fresh,
            "witnessed_at": R + 2 * HOUR,
            "entry": LogEntry::Release(manifest.clone()),
            "evidence": evidence,
            "release_index": release_index,
            "public_since": R,
            "unlocked_at": R + HOUR,
            "now": R + 2 * HOUR + 60,
            "early_checkpoint": early,
            "signers": [key(70).key_id().to_string(), key(71).key_id().to_string()],
            "under_threshold": under_threshold,
            "other_proof": chain[0].proof,
        },
        "telemetry": {
            "root_id": root_id(&root).to_string(),
            "certificates": certificates,
            "keys": [key(50).public_key()],
            "batches": batches,
            "receipts": receipts,
            "reader_seed": hex(&[0x33; 32]),
            "reader_public_key": reader.public_key(),
            "entries": 4,
            "sealed_without_reader": 1,
            "findings": ["missing_batches", "no_last", "not_certified", "receipt_not_held"],
            "certificate_findings": ["certificate_ignored"],
        },
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn s(v: &Value) -> String {
    v.to_string()
}

fn kinds(v: &Value, key: &str) -> Vec<String> {
    let mut k: Vec<String> =
        v.as_array().unwrap().iter().map(|d| d[key]["kind"].as_str().unwrap().to_string()).collect();
    k.sort();
    k
}

#[test]
fn the_api_meets_its_vectors() {
    if std::env::var_os("SEAL_WRITE_VECTORS").is_some() {
        std::fs::write(path(), serde_json::to_string_pretty(&build()).unwrap() + "\n").unwrap();
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path()).expect("tests/vectors.json")).unwrap();
    let (trust, tenant) = (s(&v["trust"]), v["tenant"].as_str().unwrap());

    for case in v["tenant_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let documents = case.get("documents").map(s).unwrap_or_default();
        let now = case["now"].as_u64().unwrap();
        let out = api::verify_tenant(&trust, tenant, &s(&case["bundle"]), now, "[]", &documents).unwrap();
        let out: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(out["state"]["version"], case["in_force"], "{name}");
        assert_eq!(out["latest_state"]["version"], case["latest"], "{name}");
        let pending: Vec<Value> = out["pending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| json!({ "version": p["version"], "change": p["change"], "effective_at": p["effective_at"] }))
            .collect();
        assert_eq!(Value::Array(pending), case["pending"], "{name}");
    }
    let mut stale = v["tenant_cases"][0]["bundle"].clone();
    stale["states"].as_array_mut().unwrap().remove(0);
    let err = api::verify_tenant(&trust, tenant, &s(&stale), v["tenant_cases"][0]["now"].as_u64().unwrap(), "[]", "");
    assert!(err.unwrap_err().contains("cannot tell which state is in force"));

    let d = &v["documents"];
    let out: Value =
        serde_json::from_str(&api::verify_documents(&trust, tenant, &s(&d["documents"])).unwrap()).unwrap();
    let since: Vec<Value> = out["states"].as_array().unwrap().iter().map(|s| s["public_since"].clone()).collect();
    assert_eq!(Value::Array(since), d["public_since"]);

    for case in v["classify"].as_array().unwrap() {
        let change = api::classify_state(&s(&case["old"]), &s(&case["new"])).unwrap();
        assert_eq!(change, s(&case["change"]));
        let diff: Value = serde_json::from_str(&api::diff_states(&s(&case["old"]), &s(&case["new"])).unwrap()).unwrap();
        assert_eq!(json!(kinds(&diff, "item")), case["kinds"]);
    }
    for case in v["classify_roots"].as_array().unwrap() {
        assert_eq!(api::classify_root(&s(&case["old"]), &s(&case["new"])).unwrap(), s(&case["change"]));
        let diff: Value = serde_json::from_str(&api::diff_roots(&s(&case["old"]), &s(&case["new"])).unwrap()).unwrap();
        assert_eq!(json!(kinds(&diff, "item")), case["kinds"]);
    }

    let g = &v["signing"];
    let label = g["label"].as_str().unwrap();
    assert_eq!(hex(&api::labeled_digest_of(label, &s(&g["document"])).unwrap()), g["digest"].as_str().unwrap());
    assert!(api::labeled_digest_of("seal/other/v1", &s(&g["document"])).is_err());
    let signature =
        api::webauthn_signature(&s(&g["admin_key"]), label, &s(&g["document"]), &s(&g["assertion"])).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&signature).unwrap(), g["signature"]);
    let mut other = g["document"].clone();
    other["version"] = json!(5);
    assert!(api::webauthn_signature(&s(&g["admin_key"]), label, &s(&other), &s(&g["assertion"])).is_err());
    assert_eq!(api::admin_key_id_of(&s(&g["admin_key"])).unwrap(), g["admin_key_id"].as_str().unwrap());
    let signers: Value = serde_json::from_str(&api::signers(&s(&g["root"]), label, &s(&g["signed"])).unwrap()).unwrap();
    let mut want: Vec<Value> = g["signers"].as_array().unwrap().clone();
    let mut got: Vec<Value> = signers.as_array().unwrap().clone();
    want.sort_by_key(|x| x.to_string());
    got.sort_by_key(|x| x.to_string());
    assert_eq!(got, want);
    assert_eq!(api::root_id_of(&s(&g["root_v1"])).unwrap(), g["root_id"].as_str().unwrap());

    let t = &v["telemetry"];
    let certified: Value = serde_json::from_str(
        &api::certified_telemetry_keys(&trust, tenant, t["root_id"].as_str().unwrap(), &s(&t["certificates"])).unwrap(),
    )
    .unwrap();
    assert_eq!(certified["keys"], t["keys"]);
    let found: Vec<&str> =
        certified["findings"].as_array().unwrap().iter().map(|f| f["kind"].as_str().unwrap()).collect();
    assert_eq!(json!(found), t["certificate_findings"]);
    let seed = t["reader_seed"].as_str().unwrap();
    assert_eq!(api::telemetry_reader_public_key(seed).unwrap(), t["reader_public_key"].as_str().unwrap());
    let analyze = |seed: &str| -> Value {
        let out = api::analyze_telemetry(tenant, &s(&t["keys"]), &s(&t["batches"]), 0, &s(&t["receipts"]), seed);
        serde_json::from_str(&out.unwrap()).unwrap()
    };
    let opened = analyze(seed);
    assert_eq!(opened["entries"].as_array().unwrap().len() as u64, t["entries"].as_u64().unwrap(), "{opened}");
    let mut found: Vec<&str> =
        opened["findings"].as_array().unwrap().iter().map(|f| f["kind"].as_str().unwrap()).collect();
    found.sort_unstable();
    assert_eq!(json!(found), t["findings"]);
    let closed = analyze("");
    assert_eq!(closed["sealed"].as_array().unwrap().len() as u64, t["sealed_without_reader"].as_u64().unwrap());

    let r = &v["releases"];
    let parse = |out: String| -> Value { serde_json::from_str(&out).unwrap() };
    let checkpoint = parse(api::verify_checkpoint(&trust, &s(&r["checkpoint"])).unwrap());
    assert_eq!(checkpoint["public_since"], r["witnessed_at"]);
    assert_eq!(checkpoint["quorum"], json!(2));
    let cosigned: Vec<&Value> = checkpoint["witnesses"].as_array().unwrap().iter().map(|w| &w["cosigned_at"]).collect();
    assert_eq!(cosigned, vec![&r["witnessed_at"]; 3]);
    let mut tampered = r["checkpoint"].clone();
    tampered["checkpoint"]["size"] = json!(tampered["checkpoint"]["size"].as_u64().unwrap() + 1);
    assert!(api::verify_checkpoint(&trust, &s(&tampered)).unwrap_err().contains("not signed by the log key"));
    let mut one_witness = r["checkpoint"].clone();
    one_witness["cosignatures"].as_array_mut().unwrap().truncate(1);
    assert!(api::verify_checkpoint(&trust, &s(&one_witness)).unwrap_err().contains("quorum"));

    let included = &r["evidence"]["included"];
    let inclusion = parse(api::verify_inclusion(&trust, &s(&r["entry"]), &s(included)).unwrap());
    assert_eq!(inclusion["leaf_index"], r["release_index"]);
    assert_eq!(inclusion["public_since"], r["public_since"]);
    let err = api::verify_inclusion(&trust, &s(&r["entry"]), &s(&r["other_proof"])).unwrap_err();
    assert!(err.contains("inclusion proof does not match"), "{err}");

    let signers = parse(api::release_signers(&trust, &s(&r["evidence"]["manifest"])).unwrap());
    assert_eq!(signers, r["signers"]);
    let one = parse(api::release_signers(&trust, &s(&r["under_threshold"]["manifest"])).unwrap());
    assert_eq!(one.as_array().unwrap().len(), 1);

    let now = r["now"].as_u64().unwrap();
    let release = parse(api::verify_release(&trust, &s(&r["evidence"]), "", now).unwrap());
    assert_eq!(release["public_since"], r["public_since"]);
    assert_eq!(release["unlocked_at"], r["unlocked_at"]);
    assert_eq!(release["manifest"], r["entry"]["body"]);
    let err = api::verify_release(&trust, &s(&r["under_threshold"]), "", now).unwrap_err();
    assert!(err.starts_with("release signatures"), "{err}");
    let err = api::verify_release(&trust, &s(&r["evidence"]), &s(&r["early_checkpoint"]), now).unwrap_err();
    assert!(err.starts_with("time lock"), "{err}");
    let err = api::verify_release(&trust, &s(&r["evidence"]), &s(&tampered), now).unwrap_err();
    assert!(err.contains("not signed by the log key"), "{err}");
}
