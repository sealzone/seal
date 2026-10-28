//! The browser API over JSON: every argument and result is the protocol's serde JSON (as
//! `seal-proto` writes it), so the JS side passes documents through as fetched. Pure and
//! synchronous; the WebAssembly exports (`js`) and the native tests call the same functions.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use seal_crypto::sign::{admin_key_id, verify_admin};
use seal_crypto::telemetry::TelemetryReaderKey;
use seal_proto::api::TelemetryReceipt;
use seal_proto::codec::{self, labeled_digest};
use seal_proto::release::{ReleaseCosign, SignedCheckpoint, SignedServiceKeyCertificate, RELEASE_COSIGN_LABEL};
use seal_proto::signed::{SigAlg, Signature};
use seal_proto::state::{
    root_id as chain_root_id, AdminKey, LoggedRoot, LoggedState, TenantBundle, TenantRoot, TenantState,
    TENANT_ROOT_LABEL, TENANT_STATE_LABEL,
};
use seal_proto::telemetry::SignedTelemetryBatch;
use seal_proto::{PlatformId, PublicKey, TenantId, TenantRootId, TrustedTime, UnixTime};
use seal_verify::change::{self, Difference};
use seal_verify::{Pending, Public, TenantTrust, TenantVerifier};

/// Every function fails with a message, which the JS side throws as an `Error`.
pub type Result<T> = std::result::Result<T, String>;

fn parse<T: DeserializeOwned>(what: &str, json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| format!("{what}: {e}"))
}

fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| e.to_string())
}

/// The trust file as `seal --trust` takes it (`trust.json`); the browser uses
/// `tenants` and `guardians`, and ignores the rest.
#[derive(Deserialize)]
struct TrustJson {
    tenants: TenantTrustJson,
    #[serde(default)]
    guardians: BTreeMap<PlatformId, PublicKey>,
}

#[derive(Deserialize)]
struct TenantTrustJson {
    tlog: TlogTrustJson,
    registrar_keys: Vec<PublicKey>,
    registrar_threshold: usize,
}

#[derive(Deserialize)]
struct TlogTrustJson {
    origin: String,
    log_key: PublicKey,
    witness_keys: Vec<PublicKey>,
    witness_quorum: usize,
}

impl TrustJson {
    fn tenants(&self) -> TenantTrust {
        let t = &self.tenants;
        TenantTrust {
            tlog: seal_tlog::TlogTrust {
                origin: t.tlog.origin.clone(),
                log_key: t.tlog.log_key,
                witness_keys: t.tlog.witness_keys.clone(),
                witness_quorum: t.tlog.witness_quorum,
            },
            registrar_keys: t.registrar_keys.clone(),
            registrar_threshold: t.registrar_threshold,
        }
    }
}

fn tenant_id(tenant: &str) -> Result<TenantId> {
    TenantId::new(tenant).map_err(|e| format!("tenant: {e}"))
}

/// A pending state with its differences from the documents in force.
#[derive(Serialize)]
struct PendingJson {
    #[serde(flatten)]
    pending: Pending,
    differences: Vec<Difference>,
}

#[derive(Serialize)]
struct VerifiedTenantJson<'a> {
    root_id: &'a TenantRootId,
    root: &'a TenantRoot,
    state: &'a TenantState,
    in_force_since: UnixTime,
    latest_root: &'a TenantRoot,
    latest_state: &'a TenantState,
    checked_at: UnixTime,
    fresh_until: UnixTime,
    pending: Vec<PendingJson>,
    roots: &'a [Public<TenantRoot>],
    states: &'a [Public<TenantState>],
    signals: &'a [seal_proto::integrity::IntegritySignal],
    ended_sessions: &'a [seal_proto::session::SessionEnd],
}

/// `TenantVerifier::verify` of `bundle` (a `TenantBundle`) for `tenant` at `now` (Unix
/// seconds, the browser's clock: the log's witnessed time bounds it), starting from anchors of
/// the trust's guardians, signals and session ends checked against `telemetry_keys` (a JSON
/// array of hex keys, from `certified_telemetry_keys`). `documents` (`GET /documents`, or empty)
/// replaces the bundle's states with every stored one, for a bundle that starts from an anchor of
/// a guardian the trust does not name.
pub fn verify_tenant(
    trust: &str,
    tenant: &str,
    bundle: &str,
    now: UnixTime,
    telemetry_keys: &str,
    documents: &str,
) -> Result<String> {
    let trust: TrustJson = parse("trust", trust)?;
    let mut bundle: TenantBundle = parse("bundle", bundle)?;
    let keys: Vec<PublicKey> = parse("telemetry keys", telemetry_keys)?;
    if !documents.is_empty() {
        let d: DocumentsJson = parse("documents", documents)?;
        bundle.states = consecutive_to(&d.states, &bundle.state.body);
    }
    let v = TenantVerifier::new(trust.tenants(), keys)
        .with_anchor_keys(trust.guardians.values().copied().collect())
        .verify(&tenant_id(tenant)?, &bundle, &TrustedTime::exact(now))
        .map_err(|e| e.to_string())?;
    let pending = v
        .pending()
        .into_iter()
        .map(|p| {
            let differences = v.differences(p.version).unwrap_or_default();
            PendingJson { pending: p, differences }
        })
        .collect();
    json(&VerifiedTenantJson {
        root_id: v.root_id(),
        root: v.root(),
        state: v.state(),
        in_force_since: v.in_force_since(),
        latest_root: v.latest_root(),
        latest_state: v.latest_state(),
        checked_at: v.checked_at(),
        fresh_until: v.fresh_until(),
        pending,
        roots: v.roots(),
        states: v.states(),
        signals: v.signals(),
        ended_sessions: v.ended_sessions(),
    })
}

/// What `GET /v1/tenants/{t}/documents` serves.
#[derive(Deserialize)]
struct DocumentsJson {
    roots: Vec<LoggedRoot>,
    #[serde(default)]
    states: Vec<LoggedState>,
    #[serde(default)]
    checkpoint: Option<SignedCheckpoint>,
}

/// The consecutive run of `states` (by version) that ends with `latest`; empty when none does.
fn consecutive_to(states: &[LoggedState], latest: &TenantState) -> Vec<LoggedState> {
    let Some(end) = states.iter().position(|s| &s.state.body == latest) else { return Vec::new() };
    let start = states[..=end]
        .windows(2)
        .rposition(|w| w[0].state.body.version + 1 != w[1].state.body.version)
        .map_or(0, |i| i + 1);
    states[start..=end].to_vec()
}

/// `TenantVerifier::verify_documents` of `documents` (`GET /documents`: `{ roots, states, checkpoint }`):
/// signatures and log proofs, with when each document became public. No freshness, and no
/// claim about which state is in force.
pub fn verify_documents(trust: &str, tenant: &str, documents: &str) -> Result<String> {
    let trust: TrustJson = parse("trust", trust)?;
    let d: DocumentsJson = parse("documents", documents)?;
    let v = TenantVerifier::new(trust.tenants(), Vec::new())
        .verify_documents(&tenant_id(tenant)?, &d.roots, &d.states, d.checkpoint.as_ref())
        .map_err(|e| e.to_string())?;
    json(&v)
}

/// `"narrowing"` or `"widening"`: `new` compared with `old`, the state in force.
pub fn classify_state(old: &str, new: &str) -> Result<String> {
    json(&change::classify_state(&parse("old state", old)?, &parse("new state", new)?))
}

pub fn diff_states(old: &str, new: &str) -> Result<String> {
    json(&change::diff_states(&parse("old state", old)?, &parse("new state", new)?))
}

pub fn classify_root(old: &str, new: &str) -> Result<String> {
    json(&change::classify_root(&parse("old root", old)?, &parse("new root", new)?))
}

pub fn diff_roots(old: &str, new: &str) -> Result<String> {
    json(&change::diff_roots(&parse("old root", old)?, &parse("new root", new)?))
}

/// A document an admin key signs, typed by its label: canonical bytes depend on the type.
enum Document {
    State(Box<TenantState>),
    Root(TenantRoot),
    Cosign(ReleaseCosign),
}

impl Document {
    fn parse(label: &str, document: &str) -> Result<Self> {
        Ok(match label {
            TENANT_STATE_LABEL => Self::State(parse("document", document)?),
            TENANT_ROOT_LABEL => Self::Root(parse("document", document)?),
            RELEASE_COSIGN_LABEL => Self::Cosign(parse("document", document)?),
            _ => return Err(format!("{label}: not a label admin keys sign")),
        })
    }
    fn digest(&self, label: &str) -> [u8; 32] {
        match self {
            Self::State(d) => labeled_digest(label, d),
            Self::Root(d) => labeled_digest(label, d),
            Self::Cosign(d) => labeled_digest(label, d),
        }
    }
    fn signed_by(&self, key: &AdminKey, label: &str, sig: &Signature) -> bool {
        match self {
            Self::State(d) => verify_admin(key, label, d, sig).is_ok(),
            Self::Root(d) => verify_admin(key, label, d, sig).is_ok(),
            Self::Cosign(d) => verify_admin(key, label, d, sig).is_ok(),
        }
    }
}

/// `labeled_digest(label, document)`: the 32 bytes an admin key signs, which a passkey takes
/// as its WebAuthn challenge. `label` is one of `seal/tenant-state/v1`, `seal/tenant-root/v1`,
/// `seal/release-cosign/v1`.
pub fn labeled_digest_of(label: &str, document: &str) -> Result<[u8; 32]> {
    Ok(Document::parse(label, document)?.digest(label))
}

/// A WebAuthn assertion's parts, base64url.
#[derive(Deserialize)]
struct AssertionJson {
    authenticator_data: String,
    client_data_json: String,
    /// The DER ECDSA signature, as WebAuthn returns it.
    signature: String,
}

/// The protocol `Signature` (`SigAlg::WebAuthnEs256`) for a passkey's assertion over
/// `labeled_digest_of(label, document)`, checked before it is returned: challenge, type,
/// origin's RP ID, flags and signature, as every verifier checks them.
pub fn webauthn_signature(admin_key: &str, label: &str, document: &str, assertion: &str) -> Result<String> {
    let key: AdminKey = parse("admin key", admin_key)?;
    if !matches!(key, AdminKey::WebAuthnEs256 { .. }) {
        return Err("not a passkey (web_authn_es256) admin key".into());
    }
    let doc = Document::parse(label, document)?;
    let a: AssertionJson = parse("assertion", assertion)?;
    let bytes = |what: &str, s: &str| codec::from_b64url(s).map_err(|e| format!("{what}: {e}"));
    let signature = Signature {
        signer: admin_key_id(&key),
        alg: SigAlg::WebAuthnEs256 {
            authenticator_data: bytes("authenticator data", &a.authenticator_data)?,
            client_data_json: bytes("client data", &a.client_data_json)?,
            sig: bytes("signature", &a.signature)?,
        },
    };
    if !doc.signed_by(&key, label, &signature) {
        return Err("the assertion does not verify for this key and document".into());
    }
    json(&signature)
}

#[derive(Deserialize)]
struct AnySigned {
    body: serde_json::Value,
    signatures: Vec<Signature>,
}

/// The key ids (hex) of `root`'s admin keys with a valid signature on `signed` (a
/// `Signed<…>` under `label`), each once: what a proposal has so far, against `root.threshold`.
pub fn signers(root: &str, label: &str, signed: &str) -> Result<String> {
    let root: TenantRoot = parse("root", root)?;
    let signed: AnySigned = parse("signed document", signed)?;
    let doc = Document::parse(label, &signed.body.to_string())?;
    let mut out: Vec<String> = Vec::new();
    for sig in &signed.signatures {
        let Some(key) = root.admin_keys.iter().find(|k| admin_key_id(k) == sig.signer) else { continue };
        let id = sig.signer.to_string();
        if !out.contains(&id) && doc.signed_by(key, label, sig) {
            out.push(id);
        }
    }
    json(&out)
}

/// `admin_key_id`, hex: what `Signature::signer` names.
pub fn admin_key_id_of(admin_key: &str) -> Result<String> {
    Ok(admin_key_id(&parse("admin key", admin_key)?).to_string())
}

/// `state::root_id` of a root version 1, hex: the `<root id>` of `SEAL_TENANT`.
pub fn root_id_of(root_v1: &str) -> Result<String> {
    let root: TenantRoot = parse("root", root_v1)?;
    if root.version != 1 {
        return Err("a root id is the digest of root version 1".into());
    }
    Ok(chain_root_id(&root).to_string())
}

#[derive(Serialize)]
struct CertifiedJson {
    keys: Vec<PublicKey>,
    findings: Vec<seal_verify::telemetry::Finding>,
}

/// The telemetry keys (hex) of the certificates (`SignedServiceKeyCertificate`s) the trust's
/// guardians signed for `tenant` and `root_id` (hex), and findings for the others.
pub fn certified_telemetry_keys(trust: &str, tenant: &str, root_id: &str, certificates: &str) -> Result<String> {
    let trust: TrustJson = parse("trust", trust)?;
    let root_id: TenantRootId = root_id.parse().map_err(|e| format!("root id: {e}"))?;
    let certificates: Vec<SignedServiceKeyCertificate> = parse("certificates", certificates)?;
    let (keys, findings) =
        seal_verify::telemetry::certified_keys(&trust.guardians, &tenant_id(tenant)?, &root_id, &certificates);
    json(&CertifiedJson { keys, findings })
}

fn reader_key(seed: &str) -> Result<TelemetryReaderKey> {
    let bytes: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|i| seed.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect::<Option<_>>()
        .ok_or("a reader key seed is 64 hex digits")?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| "a reader key seed is 64 hex digits")?;
    Ok(TelemetryReaderKey::from_seed(&seed))
}

/// `seal_verify::telemetry::analyze`: `batches` (`SignedTelemetryBatch`es) verified with
/// `keys` (hex), entries from `since`, `receipts` (`TelemetryReceipt`s) checked, sealed batches
/// opened with the reader key whose X25519 seed is `reader_seed` (64 hex digits, or empty).
pub fn analyze_telemetry(
    tenant: &str,
    keys: &str,
    batches: &str,
    since: UnixTime,
    receipts: &str,
    reader_seed: &str,
) -> Result<String> {
    let keys: Vec<PublicKey> = parse("keys", keys)?;
    let batches: Vec<SignedTelemetryBatch> = parse("batches", batches)?;
    let receipts: Vec<TelemetryReceipt> = parse("receipts", receipts)?;
    let reader = if reader_seed.is_empty() { None } else { Some(reader_key(reader_seed)?) };
    let analysis =
        seal_verify::telemetry::analyze(&tenant_id(tenant)?, &keys, &batches, since, &receipts, reader.as_ref());
    json(&analysis)
}

/// The X25519 public key (hex) of the reader key with this seed: what `telemetry_readers`
/// lists.
pub fn telemetry_reader_public_key(reader_seed: &str) -> Result<String> {
    Ok(reader_key(reader_seed)?.public_key().to_string())
}
