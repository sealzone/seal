//! The browser API over JSON: every argument and result is the protocol's serde JSON (as
//! `seal-proto` writes it), so the JS side passes documents through as fetched. Pure and
//! synchronous; the WebAssembly exports (`js`) and the native tests call the same functions.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use seal_crypto::sign::{admin_key_id, verify_admin};
use seal_crypto::telemetry::TelemetryReaderKey;
use seal_proto::api::{AttestationResponse, IngestContext, SealPayload, SealRequest, SealResponse, TelemetryReceipt};
use seal_proto::codec::{self, labeled_digest};
use seal_proto::identity::{IdentityProof, ProofContext, ProofPurpose, PROOF_CONTEXT_LABEL};
use seal_proto::policy::{HttpRules, Injection, SecretPolicy, SpkiPin};
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

// Sealing in the browser. The page verifies the tenant's enclave (`verify_enclave`), then
// HPKE-seals the secret to the attested ingest key and signs the request with a producer's app
// key (`seal_request`), as `seal seal` does; the attestation, the ticket and the request travel
// through any relay, which sees only ciphertext. What it cannot protect against is the page
// itself: the trust and this code come from wherever the page does.

fn full_trust(trust: &str) -> Result<seal_verify::Trust> {
    seal_verify::Trust::from_json(trust.as_bytes()).map_err(|e| format!("trust: {e}"))
}

fn verified_enclave(
    trust: &str,
    tenant: &TenantId,
    root_id: &str,
    attestation: &str,
    now: UnixTime,
) -> Result<seal_verify::attestation::VerifiedAttestation> {
    let root_id: TenantRootId = root_id.parse().map_err(|e| format!("root id: {e}"))?;
    let response: AttestationResponse = parse("attestation", attestation)?;
    seal_verify::attestation::verify(&response, &full_trust(trust)?, tenant, Some(&root_id), now)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct EnclaveJson<'a> {
    platform: PlatformId,
    release: &'a str,
    measurement: &'a seal_proto::Measurement,
    attested_at: UnixTime,
    service_key_version: seal_proto::ServiceKeyVersion,
    tenant: &'a TenantId,
    root_id: &'a TenantRootId,
}

/// `seal_verify::attestation::verify` of `attestation` (`GET /v1/attestation`) for `tenant`
/// and `root_id` (hex) at `now`: which enclave a seal would go to.
pub fn verify_enclave(trust: &str, tenant: &str, root_id: &str, attestation: &str, now: UnixTime) -> Result<String> {
    let v = verified_enclave(trust, &tenant_id(tenant)?, root_id, attestation, now)?;
    json(&EnclaveJson {
        platform: v.certificate.platform,
        release: &v.release_version,
        measurement: &v.measurement,
        attested_at: v.binding.attested_at,
        service_key_version: v.binding.service_key_version,
        tenant: &v.certificate.tenant,
        root_id: &v.certificate.root_id,
    })
}

/// A producer's app key as `seal grant producer key --generate` writes it (`SEAL_APP_KEY`'s
/// `sealak_<base64url(32-byte seed)>`). Errors never repeat the key.
fn app_key(text: &str) -> Result<seal_crypto::sign::SigningKey> {
    const BAD: &str = "a producer key is sealak_ followed by 32 bytes in base64url";
    let encoded = text.trim().strip_prefix("sealak_").ok_or(BAD)?;
    let seed = zeroize::Zeroizing::new(codec::from_b64url(encoded).map_err(|_| BAD)?);
    let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| BAD)?;
    Ok(seal_crypto::sign::SigningKey::from_seed(seed))
}

/// The `IdentityMatcher` a producer key is granted as: `{"kind":"app_key","key_id","public_key"}`.
pub fn producer_identity(producer_key: &str) -> Result<String> {
    let key = app_key(producer_key)?;
    json(&seal_proto::identity::IdentityMatcher::AppKey { key_id: key.key_id(), public_key: key.public_key() })
}

/// What a seal says about the secret: `seal seal`'s options.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealOptions {
    to: String,
    apps: Vec<String>,
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    pins: Vec<String>,
    #[serde(default)]
    expires: Option<UnixTime>,
    #[serde(default)]
    sealed_only: bool,
    #[serde(default)]
    hardened_only: bool,
}

impl SealOptions {
    /// The `SecretPolicy` these options describe, as `SealBuilder` makes it.
    fn policy(&self) -> Result<SecretPolicy> {
        let e = |e: seal_proto::ProtoError| e.to_string();
        let apps = self
            .apps
            .iter()
            .map(|a| seal_proto::AppName::new(a.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(e)?;
        let mut policy = SecretPolicy::new(&self.to, apps).map_err(e)?;
        if let Some(at) = self.expires {
            policy = policy.with_expiry(at);
        }
        if self.header.is_some() || self.format.is_some() || !self.methods.is_empty() || !self.deny.is_empty() {
            let injection =
                Injection::new(self.header.as_deref().unwrap_or("authorization"), self.format.as_deref()).map_err(e)?;
            let rules = HttpRules {
                methods: self.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                deny_path_prefixes: self.deny.iter().cloned().collect(),
            };
            policy = policy.with_http(injection, rules).map_err(e)?;
        }
        if !self.pins.is_empty() {
            let pins = self
                .pins
                .iter()
                .map(|p| p.parse::<SpkiPin>())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(e)?;
            policy = policy.with_pins(pins).map_err(e)?;
        }
        if self.sealed_only {
            policy = policy.with_min_platform(seal_proto::session::PlatformTier::Sealed);
        }
        if self.hardened_only {
            policy = policy.with_min_tier(seal_proto::session::ConsumerTier::Hardened);
        }
        Ok(policy)
    }
}

#[derive(Serialize)]
struct SealRequestJson<'a> {
    /// `POST /v1/blobs`'s body.
    request: &'a SealRequest,
    /// The policy sent, which `check_sealed` holds the blob to.
    policy: &'a SecretPolicy,
}

/// `POST /v1/blobs`'s body sealing `secret` under `options` to the enclave of `attestation`
/// (verified as `verify_enclave` does), proven by `producer_key` over `ticket` (`POST
/// /v1/tickets`). The plaintext is `canonical(SealPayload)`, HPKE-sealed to the attested ingest
/// key with info `ingest_info(tenant)` and AAD `canonical(IngestContext)`; it is zeroed here.
#[allow(clippy::too_many_arguments)]
pub fn seal_request(
    trust: &str,
    tenant: &str,
    root_id: &str,
    attestation: &str,
    ticket: &str,
    producer_key: &str,
    secret: &[u8],
    options: &str,
    now: UnixTime,
) -> Result<String> {
    let tenant = tenant_id(tenant)?;
    let enclave = verified_enclave(trust, &tenant, root_id, attestation, now)?;
    let key = app_key(producer_key)?;
    let ticket: seal_proto::freshness::ProofTicket = parse("ticket", ticket)?;
    let options: SealOptions = parse("options", options)?;
    let policy = options.policy()?;
    policy.validate_secret(secret).map_err(|e| e.to_string())?;

    let binding = &enclave.binding;
    let ingest = IngestContext {
        tenant: tenant.clone(),
        service_key_version: binding.service_key_version,
        tls_spki_sha256: binding.tls_spki_sha256,
    };
    let payload = zeroize::Zeroizing::new(codec::canonical(&SealPayload {
        secret: seal_proto::SecretVec::new(secret.to_vec()),
        policy: policy.clone(),
    }));
    let (hpke_enc, sealed_payload) = seal_crypto::hpke::seal(
        &binding.ingest_public_key,
        &seal_crypto::hpke::ingest_info(&tenant),
        &codec::canonical(&ingest),
        &payload,
        &mut seal_crypto::UnwrapErr(seal_crypto::SysRng),
    )
    .map_err(|e| format!("the attested ingest key: {e}"))?;
    let mut request = SealRequest {
        service_key_version: binding.service_key_version,
        hpke_enc,
        sealed_payload,
        context: ProofContext {
            tenant: tenant.clone(),
            purpose: ProofPurpose::Seal { request_digest: [0; 32] },
            tls_spki_sha256: binding.tls_spki_sha256,
            ticket,
        },
        proof: IdentityProof::AppKey { key_id: key.key_id(), signature: Vec::new() },
    };
    request.context.purpose = request.expected_purpose();
    let signature = key.sign(PROOF_CONTEXT_LABEL, &request.context);
    let SigAlg::Ed25519 { sig } = signature.alg else {
        return Err("app keys are Ed25519".into());
    };
    request.proof = IdentityProof::AppKey { key_id: signature.signer, signature: sig };
    json(&SealRequestJson { request: &request, policy: &policy })
}

/// `POST /v1/blobs`'s response, checked as the SDK does: the blob parses, names `tenant` and
/// `root_id`, and carries exactly `policy` (from `seal_request`). Returns the response.
pub fn check_sealed(response: &str, tenant: &str, root_id: &str, policy: &str) -> Result<String> {
    let response: SealResponse = parse("seal response", response)?;
    let root_id: TenantRootId = root_id.parse().map_err(|e| format!("root id: {e}"))?;
    let policy: SecretPolicy = parse("policy", policy)?;
    let blob: seal_proto::blob::Blob =
        response.blob.parse().map_err(|e| format!("the enclave returned no valid blob: {e}"))?;
    if blob.header.tenant != tenant_id(tenant)? || blob.header.root_id != root_id || blob.policy != policy {
        return Err("the enclave returned a blob for another tenant or policy".into());
    }
    json(&response)
}
