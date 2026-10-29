//! Releases, the transparency log, and the key-guardian protocol.
//!
//! The guardian's code never changes, so everything here that it reads is
//! versioned (`GUARDIAN_PROTOCOL_VERSION`) and every rule that must be able to
//! tighten later (retire releases, require newer firmware) arrives through
//! witnessed checkpoints (`ReleaseConstraints`), not through guardian code.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::signed::{Signature, Signed};
use crate::state::{TenantBundle, TenantRoot};
use crate::{
    codec, KeyId, Measurement, PlatformId, PublicKey, SecretVec, ServiceKeyVersion, TenantId, TenantKeyVersion,
    TenantRootId,
};

pub const GUARDIAN_PROTOCOL_VERSION: u16 = 1;

/// One approved enclave build. Signed by M-of-N Seal release keys (signatures
/// travel in `ReleaseEvidence`, not in the log leaf).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub component: Component,
    pub platform: PlatformId,
    pub measurement: Measurement,
    /// Which service keys this release receives. Must be ≥ the checkpoint's minimum.
    pub service_key_version: ServiceKeyVersion,
    /// Human version, e.g. `0.1.0`.
    pub version: String,
    /// Git commit of the reproducible build.
    pub source_commit: String,
    /// Guardian releases only: the enclave platform the guardian serves (`platform` is where
    /// it runs). Omitted for enclaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serves: Option<PlatformId>,
}
pub const RELEASE_LABEL: &str = "seal/release/v1";
/// An independent auditor's signature over `labeled_digest(AUDITOR_LABEL, &manifest)`.
pub const AUDITOR_LABEL: &str = "seal/auditor/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// The Seal app enclave (`seal-enclave`). Gets keys from the guardian.
    Enclave,
    /// The key guardian. Its own measurement is pinned in its vaults' locked release policies.
    /// A guardian release passes the same rules as an enclave release (M-of-N, log, time lock)
    /// and is what a running guardian hands its root to (`KeyPurpose::Succession`).
    Guardian,
}

/// A transparency-log leaf. Leaf hash (RFC 9162): `SHA-256(0x00 || canonical(LogEntry))`.
/// Bodies only: signatures are verified separately, so adding a signature
/// later never changes a leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum LogEntry {
    Release(ReleaseManifest),
    TenantRoot(TenantRoot),
    /// Every published `TenantState`, as a digest only (grants stay private). The log appends
    /// one only when its root's admins signed it and its version is the tenant's highest, and
    /// signs `StateFreshness` for the latest one.
    TenantState(TenantStateLeaf),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantStateLeaf {
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    pub version: u64,
    /// `labeled_digest(TENANT_STATE_LABEL, state)`.
    #[serde(with = "codec::array_b64")]
    pub digest: [u8; 32],
}

/// Rules that can only tighten, carried in every checkpoint. Witnesses refuse
/// to cosign a checkpoint that loosens any of them relative to one they saw.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseConstraints {
    /// Releases with an older `service_key_version` get no keys.
    pub min_service_key_version: BTreeMap<PlatformId, ServiceKeyVersion>,
    /// Minimum platform TCB per platform, compared component by component, each family's
    /// floor only with that family's evidence (`Tcb::passes`).
    pub min_tcb: BTreeMap<PlatformId, Tcb>,
    /// Release, auditor and witness keys that no longer count (a leaked key below the
    /// threshold). Only grows. The trust compiled into the guardian never changes, so this
    /// is how one of its keys is retired.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked_keys: BTreeSet<KeyId>,
    /// Single releases that get no keys and that SDKs refuse. Only grows.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revoked_measurements: BTreeMap<PlatformId, BTreeSet<Measurement>>,
}

/// A platform's trusted computing base as named version components. A name `family.component`
/// belongs to one hardware family: evidence carries the components of its own family only, and
/// a floor's `family.*` entries apply only to evidence of that family (`Tcb::passes`).
/// - Azure SNP ACI: `<family>.bootloader`, `.tee`, `.snp` and `.microcode` (and `.fmc` on
///   Turin and later) from the report's REPORTED_TCB, with family `milan`, `genoa` or `turin`
///   (the AMD key that verified the report), plus `uvm_svn` from Microsoft's UVM endorsement
///   (production floor at least 100). Each family numbers its firmware on its own scale, so
///   a floor names each family it admits. Never compared as a packed integer: AMD reorders
///   the packed fields between CPU generations.
/// - AWS Nitro: none. The Nitro hypervisor is AWS-run and not versioned in the attestation
///   document, so `min_tcb` has no entry for it; retirement works through releases only.
/// - GCP Confidential Space: `cs_version` (the token's `swversion`) and `cs_stable` (1 when
///   `support_attributes` includes `STABLE`); TDX tokens add Intel's verdict,
///   `tdx_tcb_status` (3 `UpToDate`, 2 `SWHardeningNeeded`, 1 `ConfigurationNeeded*`, 0
///   anything else) and `tdx_tcb_evaluation_data_number`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tcb(pub BTreeMap<String, u64>);

impl Tcb {
    /// Every component `minimum` names is present here and at least as high. Compares two
    /// floors (`seal_tlog::policy_not_loosened`); evidence is checked with `passes`.
    pub fn meets(&self, minimum: &Tcb) -> bool {
        minimum.0.iter().all(|(name, min)| self.0.get(name).is_some_and(|have| have >= min))
    }

    /// Whether evidence with this TCB passes `floor`:
    /// - a component without a family (no `.`) must be present here and at least as high;
    /// - `family.component` entries apply only when this evidence is of that family, and then
    ///   each must be present and at least as high;
    /// - when `floor` names any family, this evidence must be of one of them. A family the
    ///   floor does not list, such as hardware newer than the floor, is refused.
    pub fn passes(&self, floor: &Tcb) -> bool {
        let mine: BTreeSet<&str> = self.0.keys().filter_map(|name| family(name)).collect();
        let listed: BTreeSet<&str> = floor.0.keys().filter_map(|name| family(name)).collect();
        (listed.is_empty() || !listed.is_disjoint(&mine))
            && floor.0.iter().all(|(name, min)| match family(name) {
                Some(other) if !mine.contains(other) => true,
                _ => self.0.get(name).is_some_and(|have| have >= min),
            })
    }
}

/// The family of a `family.component` name.
fn family(name: &str) -> Option<&str> {
    name.split_once('.').map(|(family, _)| family)
}

/// A log checkpoint (C2SP signed-note style, CBOR-encoded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Log identity, e.g. `log.seal.dev/v1`.
    pub origin: String,
    pub size: u64,
    #[serde(with = "codec::array_b64")]
    pub root_hash: [u8; 32],
    pub policy: ReleaseConstraints,
}
pub const CHECKPOINT_LABEL: &str = "seal/checkpoint/v1";

/// A witness's statement: "I saw this checkpoint at `timestamp`; it consistently
/// extends, and does not loosen the policy of, every checkpoint I saw before."
/// Signs `labeled_digest(COSIGNATURE_LABEL, &(checkpoint, timestamp))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    pub timestamp: crate::UnixTime,
    pub signature: Signature,
}
pub const COSIGNATURE_LABEL: &str = "seal/cosignature/v1";

/// A checkpoint with its log signature and witness cosignatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub log_signature: Signature,
    pub cosignatures: Vec<Cosignature>,
}

/// Proof that an entry is in the log, and since when it was public.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlogProof {
    pub checkpoint: SignedCheckpoint,
    pub leaf_index: u64,
    /// RFC 9162 inclusion path, leaf to root.
    pub audit_path: Vec<[u8; 32]>,
}

/// Everything needed to accept an enclave release.
///
/// - `included`: inclusion in an OLD checkpoint, proving the release has been
///   public long enough (time lock).
/// - `fresh`: a RECENT checkpoint (witness quorum within `FRESH_CHECKPOINT_SECS`),
///   whose policy decides whether the release is still allowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvidence {
    pub manifest: Signed<ReleaseManifest>,
    pub included: TlogProof,
    pub fresh: SignedCheckpoint,
    /// Optional independent auditor signature (`AUDITOR_LABEL`).
    pub auditor: Option<Signature>,
}

/// A checkpoint used for policy must have been cosigned by a witness quorum within this window.
pub const FRESH_CHECKPOINT_SECS: u64 = 86_400;

/// A tenant admin's approval of one release, for tenants with `cosign_releases`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseCosign {
    pub tenant: TenantId,
    pub measurement: Measurement,
}
pub const RELEASE_COSIGN_LABEL: &str = "seal/release-cosign/v1";

/// What the requesting enclave commits to in its own attestation report data:
/// `labeled_digest(KEY_REQUEST_BINDING_LABEL, &KeyRequestBinding)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRequestBinding {
    pub protocol_version: u16,
    /// From any guardian instance's `GET /v1/challenge`.
    pub challenge: crate::freshness::GuardianChallenge,
    /// X25519 key the guardian HPKE-seals the released keys to. Lives only in the requester's RAM.
    pub ephemeral_public_key: PublicKey,
    pub purpose: KeyPurpose,
}
pub const KEY_REQUEST_BINDING_LABEL: &str = "seal/key-request-binding/v1";

/// Every key the guardian releases belongs to one tenant: an enclave deployment serves one
/// tenant, so no key is shared across tenants. Both purposes pass the same tenant checks
/// (verified, fresh bundle; `root_id` matching its chain; the tenant's co-signature when
/// `cosign_releases`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyPurpose {
    /// The tenant's service keys of the manifest's `service_key_version`.
    Service { tenant: TenantId, root_id: TenantRootId },
    /// The tenant's wrapping keys. The guardian releases only tenant key versions within the
    /// verified tenant state's `[oldest_accepted, current]`.
    Tenant { tenant: TenantId, root_id: TenantRootId, tenant_key_versions: Vec<TenantKeyVersion> },
    /// A successor guardian takes over this guardian's root. The requester's release must be
    /// a `Component::Guardian` that serves the same platform, runs on a platform this guardian
    /// can verify, and passes the same release rules as an enclave release. The guardian
    /// answers with `ReleasedKeys::Root`; the successor stores the root in its own vaults,
    /// pinned to its own measurement. Done while this guardian can still verify the successor.
    Succession,
}

/// `POST /v1/keys` on the guardian.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRequest {
    pub protocol_version: u16,
    /// The requester's evidence; its report data is the `KeyRequestBinding` digest, and its
    /// platform must be the one the guardian serves.
    pub evidence: crate::Evidence,
    pub binding: KeyRequestBinding,
    pub release: ReleaseEvidence,
    /// The tenant the purpose names, with current freshness statements. `None` only for
    /// `KeyPurpose::Succession`.
    pub tenant: Option<TenantBundle>,
    /// Required when the tenant's latest root has `cosign_releases`.
    pub tenant_cosign: Option<Signed<ReleaseCosign>>,
}

/// The guardian's statement that it released a tenant's service keys of one version, after
/// every check it makes (release signatures, log, time lock, TCB, revocations, tenant
/// freshness and co-signature). Signed with the guardian key, which derives from the platform
/// master key and so never changes; its public half is compiled into `seal_verify::Trust`.
/// SDKs require it for the keys an enclave attests to, so an enclave that made up its own keys
/// (a release still inside its time lock, or one the tenant never co-signed) is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceKeyCertificate {
    pub platform: PlatformId,
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    pub service_key_version: ServiceKeyVersion,
    #[serde(with = "codec::array_b64")]
    pub tls_spki_sha256: [u8; 32],
    pub ingest_public_key: PublicKey,
    /// Telemetry public keys of service key versions 1..=`service_key_version` for this tenant.
    pub telemetry_public_keys: Vec<(ServiceKeyVersion, PublicKey)>,
}
pub const SERVICE_KEY_CERTIFICATE_LABEL: &str = "seal/service-key-certificate/v1";
/// One platform's public wrap key for a tenant key version, certified by that platform's
/// guardian key. Anyone may fetch it (`GET /v1/wrap-keys/...` on the guardian); the control
/// plane serves the tenant's in `TenantBundle::wrap_keys`; enclaves check it with
/// `seal_verify::Trust::guardians[platform]` before wrapping a DEK to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantWrapKey {
    pub platform: PlatformId,
    pub tenant: TenantId,
    pub root_id: TenantRootId,
    pub tenant_key_version: TenantKeyVersion,
    /// X25519.
    pub public_key: PublicKey,
}
pub const TENANT_WRAP_KEY_LABEL: &str = "seal/tenant-wrap-key/v1";
pub type SignedTenantWrapKey = Signed<TenantWrapKey>;

/// What a guardian's `GET /v1/identity` evidence commits to, with the caller's challenge and
/// the platform it serves.
pub const GUARDIAN_IDENTITY_LABEL: &str = "seal/guardian-identity/v1";
pub type SignedServiceKeyCertificate = Signed<ServiceKeyCertificate>;

/// HPKE (same suite as ingest) to `binding.ephemeral_public_key`;
/// `info = "seal/key-release/v1"`, `aad = canonical(binding)`. Plaintext: `canonical(ReleasedKeys)`.
/// HPKE base mode does not authenticate the sender, and the ephemeral public key is in the
/// request, so anyone on the path (the TLS-terminating proxy included) could seal keys of their
/// own to it. The guardian therefore signs every response with its guardian key over
/// `labeled_digest(KEY_RESPONSE_LABEL, (labeled_digest(KEY_REQUEST_BINDING_LABEL, binding),
/// hpke_enc, ciphertext))`; the requester checks it against `Trust::guardians` before opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyResponse {
    #[serde(with = "codec::bytes_b64")]
    pub hpke_enc: Vec<u8>,
    #[serde(with = "codec::bytes_b64")]
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}
pub const KEY_RESPONSE_LABEL: &str = "seal/key-response/v1";

/// Derived key material. Only ever exists inside the guardian and approved
/// enclaves. The platform master key itself never leaves the guardian.
// One value per key request, decoded once: the size of the `Service` variant costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReleasedKeys {
    /// One 32-byte seed per service key, all of one tenant and `service_key_version`.
    Service {
        tenant: TenantId,
        root_id: TenantRootId,
        service_key_version: ServiceKeyVersion,
        token: SecretVec,
        ingest: SecretVec,
        telemetry: SecretVec,
        /// Inbound TLS key (shared by the tenant's replicas of this service key version).
        tls: SecretVec,
        /// MAC key for stateless proof tickets.
        ticket: SecretVec,
        /// Telemetry PUBLIC keys of every service key version 1..=`service_key_version`, so
        /// integrity signals signed by older releases still verify after a version bump.
        telemetry_public_keys: Vec<(ServiceKeyVersion, PublicKey)>,
        /// The guardian's certificate over these keys' public halves; the enclave serves it
        /// in `AttestationResponse`.
        certificate: SignedServiceKeyCertificate,
    },
    /// This guardian's platform root, for its successor (`KeyPurpose::Succession`). Only
    /// a guardian release ever receives it.
    Root { platform: PlatformId, root: SecretVec },
    /// The X25519 private seeds of the tenant's wrap keys on the requester's platform.
    Tenant { tenant: TenantId, root_id: TenantRootId, keys: Vec<(TenantKeyVersion, SecretVec)> },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcb(parts: &[(&str, u64)]) -> Tcb {
        Tcb(parts.iter().map(|(k, v)| (k.to_string(), *v)).collect())
    }

    #[test]
    fn tcb_is_compared_component_by_component() {
        let min = tcb(&[("snp", 22), ("microcode", 213), ("uvm_svn", 100)]);
        assert!(tcb(&[("snp", 22), ("microcode", 213), ("uvm_svn", 104), ("tee", 0)]).meets(&min));
        // Higher in one component never makes up for lower in another.
        assert!(!tcb(&[("snp", 99), ("microcode", 212), ("uvm_svn", 104)]).meets(&min));
        // A component the minimum names must be present.
        assert!(!tcb(&[("snp", 22), ("microcode", 213)]).meets(&min));
        assert!(tcb(&[]).meets(&Tcb::default()));
    }

    #[test]
    fn floors_without_families_pass_as_meets() {
        let min = tcb(&[("cs_stable", 1), ("tdx_tcb_status", 3)]);
        assert!(tcb(&[("cs_stable", 1), ("tdx_tcb_status", 3), ("cs_version", 9)]).passes(&min));
        assert!(!tcb(&[("cs_stable", 1), ("tdx_tcb_status", 2)]).passes(&min));
        assert!(!tcb(&[("cs_stable", 1)]).passes(&min));
        assert!(tcb(&[]).passes(&Tcb::default()));
        assert!(tcb(&[("milan.snp", 1)]).passes(&Tcb::default()));
    }

    #[test]
    fn a_family_floor_applies_to_its_family_only() {
        let floor = tcb(&[("milan.snp", 24), ("milan.microcode", 219), ("turin.fmc", 1), ("uvm_svn", 100)]);
        let milan = |snp, microcode| tcb(&[("milan.snp", snp), ("milan.microcode", microcode), ("uvm_svn", 100)]);
        assert!(milan(24, 219).passes(&floor));
        assert!(!milan(23, 255).passes(&floor));
        assert!(!milan(24, 218).passes(&floor));
        // Turin's fmc is never asked of Milan, and Milan's numbers never of Turin.
        let turin = |fmc| tcb(&[("turin.fmc", fmc), ("turin.snp", 4), ("turin.microcode", 81), ("uvm_svn", 100)]);
        assert!(turin(1).passes(&floor));
        assert!(!turin(0).passes(&floor));
        // A component without a family applies to every family.
        assert!(!tcb(&[("milan.snp", 24), ("milan.microcode", 219), ("uvm_svn", 99)]).passes(&floor));
        // A family-only floor component the evidence lacks is still required.
        assert!(!tcb(&[("milan.snp", 24), ("uvm_svn", 100)]).passes(&floor));
    }

    #[test]
    fn a_family_the_floor_does_not_list_is_refused() {
        let floor = tcb(&[("milan.snp", 24), ("uvm_svn", 100)]);
        assert!(!tcb(&[("genoa.snp", 99), ("uvm_svn", 100)]).passes(&floor));
        // Evidence without any family fails a floor that lists families.
        assert!(!tcb(&[("snp", 99), ("uvm_svn", 100)]).passes(&floor));
        // A floor without families admits every family.
        assert!(tcb(&[("genoa.snp", 1), ("uvm_svn", 100)]).passes(&tcb(&[("uvm_svn", 100)])));
    }
}
