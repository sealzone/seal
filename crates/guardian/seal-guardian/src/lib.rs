//! The key guardian.
//!
//! Its measurement is pinned in an immutable KMS release policy, so this code
//! can never change: keep it small. It answers `KeyRequest`s by checking
//! `authorize` and HPKE-sealing derived keys to the requester's ephemeral key.
//! It never returns the platform master key. Every rule that may need to tighten later arrives
//! via witnessed checkpoints (`ReleaseConstraints`), which `seal-verify` enforces.
//!
//! Rules (`GuardianConfig`) are compiled in. Sim builds may load them from a
//! file; production builds have no such code path.
//!
//! A guardian serves one enclave platform (whose evidence it accepts, and whose platform
//! master key it holds) and runs on one platform (its attestor and `KeySource`); the two
//! may differ. Seal runs one
//! guardian per enclave platform, on ACI with its root behind Key Vault
//! (`KeySource::KeyVault`): only Azure Key Vault offers a release policy nobody can change,
//! not even the account's owner. Self-hosted guardians run where the customer chooses, with
//! that cloud's key source; on Cloud KMS (`KeySource::GcpKms`), or AWS KMS once Nitro ships,
//! that means trusting that cloud's account administrators. Each
//! (served platform, platform it runs on) pair is its own build, measurement and freeze, so a platform's guardian
//! freezes when that platform ships.
//!
//! Succession: a frozen guardian is replaced by handing its root to a successor guardian
//! release that passes the same rules as an enclave release (`KeyPurpose::Succession`). Do it
//! while this guardian can still verify the successor, e.g. as soon as a platform announces a
//! format change it would not understand. Afterwards Seal deletes the old vault copies and
//! stops the old instances. If that window is missed, the fallback is a new root and every
//! customer reseals: an outage, never a leak.

#![forbid(unsafe_code)]

use std::sync::Mutex;
use std::time::Instant;

use seal_crypto::hpke::KEY_RELEASE_INFO;
use seal_crypto::sign::SigningKey;
use seal_crypto::{ChallengeKey, Key32, PlatformMasterKey, SecretBytes, SysRng, UnwrapErr};
use seal_proto::codec::{canonical, labeled_digest};
use seal_proto::release::{
    KeyPurpose, KeyRequest, KeyResponse, ReleasedKeys, GUARDIAN_IDENTITY_LABEL, KEY_REQUEST_BINDING_LABEL,
    KEY_RESPONSE_LABEL,
};
use seal_proto::{Evidence, PlatformId, PublicKey, SecretVec, TrustedTime};
use serde::{Deserialize, Serialize};

pub mod authorize;
pub mod client;
pub mod keysource;
pub mod server;

pub use authorize::{Denial, KeyReleaseAuthorizer, KeyReleasePermit};
pub use keysource::KeySource;

/// The guardian's fixed rules.
#[derive(Clone, Debug)]
pub struct GuardianConfig {
    /// The one enclave platform this guardian serves; its platform master key and every key it
    /// derives belong to it, and requests must carry that platform's evidence.
    pub platform: PlatformId,
    /// The TEE the guardian itself runs in, attests with and unseals its root from.
    pub runs_on: PlatformId,
    /// Release approval (M-of-N keys, log, time lock of 14 days in production, optional
    /// auditor) and tenant root chains (for `KeyPurpose::Tenant`).
    pub trust: seal_verify::Trust,
}

#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("denied: {0}")]
    Denied(#[from] Denial),
    #[error("tee: {0}")]
    Tee(#[from] seal_tee::TeeError),
    #[error("evidence: {0}")]
    Evidence(#[from] seal_attest::AttestError),
    /// The key source refused to release the root or could not be reached.
    #[error("root unavailable: {0}")]
    Root(String),
    /// `client` only: the guardian denied the request. Its reason stays in the guardian's log.
    #[error("denied by the guardian")]
    Refused,
    /// `client` only: the guardian could not be reached or answered with something else.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

impl GuardianError {
    /// The public code (`Denied`, `Refused` → `NotAllowed`; the requester learns nothing more).
    pub fn code(&self) -> seal_proto::ErrorCode {
        match self {
            GuardianError::Denied(_) | GuardianError::Refused => seal_proto::ErrorCode::NotAllowed,
            GuardianError::Tee(e) => e.code(),
            GuardianError::Evidence(e) => e.code(),
            GuardianError::Root(_) | GuardianError::Unavailable(_) => seal_proto::ErrorCode::Unavailable,
        }
    }
}

/// The guardian's environment, injected at boot like the enclave's `Components`.
pub struct GuardianComponents {
    /// Unseals the platform root where the guardian runs.
    pub key_source: KeySource,
    /// The guardian's own attestor (`seal_tee::Attestor::detect`), whose platform is
    /// `GuardianConfig::runs_on`.
    pub attestor: seal_tee::Attestor,
    pub clock: seal_tee::Clock,
}

/// A running guardian: config + platform root and master key + clock. It keeps no request
/// state, so several instances can serve one platform.
pub struct Guardian {
    config: GuardianConfig,
    /// Kept only for `KeyPurpose::Succession`.
    root: Key32,
    master: PlatformMasterKey,
    guardian_key: SigningKey,
    challenge_key: ChallengeKey,
    attestor: seal_tee::Attestor,
    clock: seal_tee::Clock,
    /// The last trusted time read and the monotonic instant it was read at, so the sync
    /// `challenge` can stamp expiries without a clock round trip.
    anchor: Mutex<(TrustedTime, Instant)>,
}

impl Guardian {
    /// Boot: `KeySource::root_secret` (attesting as the guardian) → `PlatformMasterKey` for `config.platform`.
    /// Fails unless `attestor.platform() == config.runs_on`, and unless the clock answers.
    pub async fn boot(config: GuardianConfig, components: GuardianComponents) -> Result<Self, GuardianError> {
        let GuardianComponents { key_source, attestor, clock } = components;
        if attestor.platform() != config.runs_on {
            return Err(seal_tee::TeeError::Unavailable(format!(
                "the attestor is for {:?}, the guardian runs on {:?}",
                attestor.platform(),
                config.runs_on
            ))
            .into());
        }
        let time = clock.now().await?;
        let root = key_source.root_secret(&attestor).await?;
        let master = PlatformMasterKey::from_root_secret(config.platform, &root);
        let guardian_key = master.guardian_key();
        let challenge_key = master.challenge_key();
        tracing::info!(
            platform = ?config.platform,
            runs_on = ?config.runs_on,
            guardian_key = %guardian_key.public_key(),
            "guardian booted"
        );
        Ok(Self {
            config,
            root,
            master,
            guardian_key,
            challenge_key,
            attestor,
            clock,
            anchor: Mutex::new((time, Instant::now())),
        })
    }

    /// Reads the trusted clock and re-anchors `challenge`'s time.
    async fn now(&self) -> Result<TrustedTime, GuardianError> {
        let time = self.clock.now().await?;
        *self.anchor.lock().unwrap_or_else(|e| e.into_inner()) = (time, Instant::now());
        Ok(time)
    }

    /// A stateless challenge (`ChallengeKey::issue`, valid `GUARDIAN_CHALLENGE_TTL_SECS`). The
    /// guardian keeps no table, so any instance verifies it and nobody can exhaust it. Its
    /// expiry counts from the last trusted time read (at boot or by `handle`) plus the
    /// monotonic time since; `handle` checks it against a fresh read.
    pub fn challenge(&self) -> seal_proto::freshness::GuardianChallenge {
        let (anchor, at) = *self.anchor.lock().unwrap_or_else(|e| e.into_inner());
        let time = TrustedTime { now: anchor.now.saturating_add(at.elapsed().as_secs()), radius: anchor.radius };
        self.challenge_key.issue(&time, &mut UnwrapErr(SysRng))
    }

    /// Refuses evidence of any platform but `config.platform`, or `config.runs_on` for
    /// `Succession` (`Denial::WrongPlatform`), then gathers `RequestFacts`
    /// (`seal_attest::verify`, read clock, verify the challenge's MAC and expiry), calls
    /// `authorize`, then seals
    /// `PlatformMasterKey::release_service(tenant, root_id, manifest.service_key_version)`
    /// (which includes the `ServiceKeyCertificate`),
    /// `PlatformMasterKey::release_tenant(tenant, root_id, tenant_key_versions)`, or for
    /// `Succession` the root itself (`ReleasedKeys::Root`), and signs the response with the
    /// guardian key (`KEY_RESPONSE_LABEL`).
    ///
    /// The sealed plaintext is `canonical(ReleasedKeys)`. A denial is logged here with its
    /// reason; the error the caller gets says only that it was denied.
    pub async fn handle(&self, req: KeyRequest) -> Result<KeyResponse, GuardianError> {
        let result = self.decide_and_seal(&req).await;
        if let Err(e) = &result {
            let manifest = &req.release.manifest.body;
            tracing::warn!(
                purpose = purpose_name(&req.binding.purpose),
                evidence_platform = ?req.evidence.platform(),
                component = ?manifest.component,
                measurement = %manifest.measurement,
                version = %manifest.version,
                reason = %e,
                "key request refused"
            );
        }
        result
    }

    async fn decide_and_seal(&self, req: &KeyRequest) -> Result<KeyResponse, GuardianError> {
        let platform = match req.binding.purpose {
            KeyPurpose::Succession => self.config.runs_on,
            _ => self.config.platform,
        };
        if req.evidence.platform() != platform {
            return Err(Denial::WrongPlatform.into());
        }
        let time = self.now().await?;
        let evidence = seal_attest::verify(&req.evidence, &time)?;
        let challenge_ok = self.challenge_key.verify(&req.binding.challenge, &time).is_ok();
        let facts = RequestFacts { evidence, time, challenge_ok };
        let permit = KeyReleaseAuthorizer::new(&self.config, self.guardian_key.public_key()).authorize(req, &facts)?;
        let req = permit.request();

        let keys = match &req.binding.purpose {
            KeyPurpose::Service { tenant, root_id } => {
                self.master.release_service(tenant, root_id, req.release.manifest.body.service_key_version)
            }
            KeyPurpose::Tenant { tenant, root_id, tenant_key_versions } => {
                self.master.release_tenant(tenant, root_id, tenant_key_versions)
            }
            KeyPurpose::Succession => {
                ReleasedKeys::Root { platform: self.config.platform, root: SecretVec::new(self.root.expose().to_vec()) }
            }
        };
        let plaintext = SecretBytes::new(canonical(&keys));
        let binding = &req.binding;
        let (hpke_enc, ciphertext) = seal_crypto::hpke::seal(
            &binding.ephemeral_public_key,
            KEY_RELEASE_INFO,
            &canonical(binding),
            plaintext.expose(),
            &mut UnwrapErr(SysRng),
        )
        // A low-order ephemeral key: the binding names no key anything can be sealed to.
        .map_err(|_| Denial::Binding)?;
        let signature = self.guardian_key.sign(
            KEY_RESPONSE_LABEL,
            &(labeled_digest(KEY_REQUEST_BINDING_LABEL, binding), hpke_enc.clone(), ciphertext.clone()),
        );
        tracing::info!(
            purpose = purpose_name(&binding.purpose),
            measurement = %req.release.manifest.body.measurement,
            "keys released"
        );
        Ok(KeyResponse { hpke_enc, ciphertext, signature })
    }

    /// A `TenantAnchor` for `bundle` (`TenantVerifier::anchor` at the trusted time, this
    /// guardian's earlier anchors counting), signed with the guardian key. Public: it states
    /// which state was in force, which anyone with the bundle can work out; it only saves later
    /// verifiers the older states. Refused (`Denial::Tenant`, logged) when the bundle does not
    /// verify for `tenant` and `root_id`.
    pub async fn anchor(
        &self,
        tenant: &seal_proto::TenantId,
        root_id: &seal_proto::TenantRootId,
        bundle: &seal_proto::state::TenantBundle,
    ) -> Result<seal_proto::state::SignedTenantAnchor, GuardianError> {
        let time = self.now().await?;
        let anchor = seal_verify::TenantVerifier::new(self.config.trust.tenants.clone(), Vec::new())
            .with_anchor_keys(vec![self.guardian_key.public_key()])
            .anchor(self.config.platform, tenant, bundle, &time)
            .map_err(|e| {
                tracing::warn!(%tenant, reason = %e, "anchor refused");
                GuardianError::Denied(Denial::Tenant)
            })?;
        if &anchor.root_id != root_id {
            return Err(Denial::Tenant.into());
        }
        Ok(self.guardian_key.sign_into(seal_proto::state::TENANT_ANCHOR_LABEL, anchor))
    }

    /// The certified public wrap key of `(tenant, root_id, tenant_key_version)` on the served
    /// platform (`PlatformMasterKey::tenant_wrap_key`). Public, no checks: a public key reveals
    /// nothing, and only this platform's enclaves get the private half.
    pub fn wrap_key(
        &self,
        tenant: &seal_proto::TenantId,
        root_id: &seal_proto::TenantRootId,
        tenant_key_version: seal_proto::TenantKeyVersion,
    ) -> seal_proto::release::SignedTenantWrapKey {
        self.master.tenant_wrap_key(tenant, root_id, tenant_key_version)
    }

    /// The guardian's own evidence for `GET /v1/identity`, committing to
    /// `labeled_digest(GUARDIAN_IDENTITY_LABEL, (challenge, config.platform, guardian_key))`.
    pub async fn identity(&self, challenge: [u8; 32]) -> Result<GuardianIdentity, GuardianError> {
        let guardian_key = self.guardian_key.public_key();
        let report_data = labeled_digest(GUARDIAN_IDENTITY_LABEL, &(challenge, self.config.platform, guardian_key));
        let evidence = self.attestor.attest(report_data).await?;
        Ok(GuardianIdentity { platform: self.config.platform, runs_on: self.config.runs_on, guardian_key, evidence })
    }
}

/// `GET /v1/identity`: the platform a guardian serves, where it runs, its guardian key and its
/// evidence (see `Guardian::identity`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianIdentity {
    pub platform: PlatformId,
    pub runs_on: PlatformId,
    pub guardian_key: PublicKey,
    pub evidence: Evidence,
}

fn purpose_name(purpose: &KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Service { .. } => "service",
        KeyPurpose::Tenant { .. } => "tenant",
        KeyPurpose::Succession => "succession",
    }
}

/// Facts `authorize` needs that come from IO, gathered by `Guardian::handle`.
#[derive(Clone, Debug)]
pub struct RequestFacts {
    /// Evidence that passed `seal_attest::verify` (requests failing it never reach `authorize`).
    pub evidence: seal_attest::VerifiedEvidence,
    pub time: seal_proto::TrustedTime,
    /// The binding's challenge carries a valid MAC from this platform's challenge key and
    /// has not expired.
    pub challenge_ok: bool,
}
