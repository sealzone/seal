//! Shared fixtures for the integration tests.
#![allow(dead_code)]

use std::convert::Infallible;

use seal_crypto::{Key32, PlatformMasterKey};
use seal_proto::identity::{AuthenticationScope, ProofAssurance, WorkloadIdentity};
use seal_proto::policy::SecretPolicy;
use seal_proto::release::TenantWrapKey;
use seal_proto::session::{ConsumerTier, SessionClaims};
use seal_proto::{AppName, KeyId, PlatformId, ServiceKeyVersion, TenantId, TenantKeyVersion, TenantRootId};
use sha2::{Digest, Sha256};

/// Deterministic test generator: block i = SHA-256(seed || i as u64 BE). Fixed here, so the
/// frozen vectors do not depend on any `rand` generator's algorithm.
pub struct TestRng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl TestRng {
    pub fn new(seed: u8) -> Self {
        Self { seed: [seed; 32], counter: 0, buf: [0; 32], pos: 32 }
    }
}

impl rand::TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for d in dst {
            if self.pos == 32 {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.counter.to_be_bytes());
                self.buf = h.finalize().into();
                self.counter += 1;
                self.pos = 0;
            }
            *d = self.buf[self.pos];
            self.pos += 1;
        }
        Ok(())
    }
}
impl rand::TryCryptoRng for TestRng {}

pub fn sys_rng() -> impl rand::CryptoRng {
    seal_crypto::UnwrapErr(seal_crypto::SysRng)
}

pub fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}
pub fn root_id() -> TenantRootId {
    TenantRootId([0x52; 32])
}
pub fn app() -> AppName {
    AppName::new("checkout").unwrap()
}
pub fn workload() -> WorkloadIdentity {
    WorkloadIdentity::AppKey { key_id: KeyId([0x11; 32]) }
}
pub fn policy() -> SecretPolicy {
    SecretPolicy::new("https://api.openai.com/v1", [app()]).unwrap()
}
pub fn root_secret() -> Key32 {
    Key32::from_bytes(core::array::from_fn(|i| i as u8))
}
pub fn master(platform: PlatformId) -> PlatformMasterKey {
    PlatformMasterKey::from_root_secret(platform, &root_secret())
}
/// The certified wrap keys of `platforms` for the fixture tenant at `version` (bodies only:
/// callers verify the guardian signatures before sealing).
pub fn wrap_keys(platforms: &[PlatformId], version: u32) -> Vec<TenantWrapKey> {
    platforms
        .iter()
        .map(|p| master(*p).tenant_wrap_key(&tenant(), &root_id(), TenantKeyVersion(version)).body)
        .collect()
}

pub fn claims(blob: seal_proto::blob::Blob, service_key_version: ServiceKeyVersion) -> SessionClaims {
    SessionClaims {
        tenant: tenant(),
        app: app(),
        session_id: [0x5e; 16],
        caller: workload(),
        authentication: AuthenticationScope {
            matched_grants: vec![],
            expires_at: None,
            assurance: ProofAssurance::BearerOverAttestedChannel,
        },
        blob,
        service_key_version,
        tier: ConsumerTier::Base,
        platform: PlatformId::Sim,
        issued_at: 1_900_000_000,
        expires_at: 1_900_000_600,
        min_tier: None,
    }
}
