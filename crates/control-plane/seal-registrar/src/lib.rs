//! Seal's tenant registrar: signs root version 1 of a new tenant, appends it to the
//! transparency log, and stores it on the control plane. It never signs any later version and
//! never signs two roots for one tenant. Its HTTP API is in `server`; only the console calls it.
//!
//! The registrar is the one party that issues a root version 1, so it keeps its own durable
//! ledger of every root it signed and decides there whether a tenant id is free. A root is
//! recorded before it is logged; a retry after a crash re-sends the identical signed root
//! (Ed25519 is deterministic), so the registrar can never log a competing root for a tenant.
#![forbid(unsafe_code)]

pub mod http;
pub mod ledger;
pub mod server;

use async_trait::async_trait;
use seal_crypto::sign::{admin_key_id, SigningKey};
use seal_proto::release::{LogEntry, TlogProof};
use seal_proto::signed::Signed;
use seal_proto::state::{root_id, AdminKey, LoggedRoot, TenantRoot, TENANT_ROOT_LABEL};
use seal_proto::{PublicKey, TenantId};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use ledger::Ledger;

/// What `POST /v1/roots` answers: the new chain's root id, the admin key's id (both lowercase
/// hex) and the root's index in the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    pub root_id: String,
    pub key_id: String,
    pub log_index: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrarError {
    /// Not creating this tenant; the reason is safe to show the user.
    #[error("{0}")]
    Refused(String),
    /// The log, the control plane or the ledger failed; worth retrying.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UpstreamError(pub String);

/// The transparency log and the control plane, as the registrar uses them.
#[async_trait]
pub trait Upstreams: Send + Sync {
    /// Appends an entry; its index.
    async fn log_append(&self, entry: &LogEntry) -> Result<u64, UpstreamError>;
    /// The inclusion proof of `index` against the latest checkpoint.
    async fn log_proof(&self, index: u64) -> Result<TlogProof, UpstreamError>;
    /// Stores root version 1 (idempotent for the identical root).
    async fn put_root(&self, tenant: &TenantId, root: &LoggedRoot) -> Result<(), UpstreamError>;
}

/// What makes a root acceptable beyond its shape.
#[derive(Clone, Debug)]
pub struct Policy {
    /// The WebAuthn RP ID passkey admin keys must be scoped to (`seal.zone`).
    pub passkey_rp_id: String,
}

pub struct Registrar {
    key: SigningKey,
    policy: Policy,
    upstreams: Box<dyn Upstreams>,
    /// Serializes registrations: the ledger decides who gets an id.
    ledger: Mutex<Ledger>,
}

impl Registrar {
    pub fn new(key: SigningKey, policy: Policy, upstreams: Box<dyn Upstreams>, ledger: Ledger) -> Self {
        Self { key, policy, upstreams, ledger: Mutex::new(ledger) }
    }

    /// The key that signs every root version 1; the control plane and every verifier trust it
    /// (`seal_verify::Trust`'s registrar keys).
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    fn check_key(&self, key: &AdminKey) -> Result<(), RegistrarError> {
        match key {
            AdminKey::Ed25519 { .. } => Ok(()),
            AdminKey::WebAuthnEs256 { sec1, rp_id } => {
                if sec1.len() != 65 || sec1[0] != 4 {
                    return Err(RegistrarError::Refused("a passkey is an uncompressed P-256 point (65 bytes)".into()));
                }
                if *rp_id != self.policy.passkey_rp_id {
                    return Err(RegistrarError::Refused(format!(
                        "passkeys must be scoped to {}",
                        self.policy.passkey_rp_id
                    )));
                }
                Ok(())
            }
        }
    }

    /// Creates `tenant` with `admin_key` as its only admin: root version 1, threshold 1.
    /// Retrying with the same key returns the same answer; a different key for a taken id is
    /// refused.
    pub async fn create_root(&self, tenant: &str, admin_key: AdminKey) -> Result<Registered, RegistrarError> {
        let tenant = TenantId::new(tenant).map_err(|e| RegistrarError::Refused(e.to_string()))?;
        self.check_key(&admin_key)?;
        let root = TenantRoot {
            tenant: tenant.clone(),
            version: 1,
            admin_keys: [admin_key.clone()].into(),
            threshold: 1,
            cosign_releases: false,
        };
        let mut ledger = self.ledger.lock().await;
        let signed: Signed<TenantRoot> = match ledger.get(&tenant) {
            Some(rec) if rec.root.body == root => rec.root.clone(),
            Some(_) => return Err(RegistrarError::Refused("that tenant id is taken".into())),
            None => {
                let signed = self.key.sign_into(TENANT_ROOT_LABEL, root.clone());
                ledger
                    .record(&tenant, &signed, None)
                    .map_err(|e| RegistrarError::Unavailable(format!("ledger: {e}")))?;
                signed
            }
        };
        let log_index = match ledger.get(&tenant).and_then(|r| r.log_index) {
            Some(i) => i,
            None => {
                let unavailable = |e: UpstreamError| RegistrarError::Unavailable(format!("log: {e}"));
                let i = self.upstreams.log_append(&LogEntry::TenantRoot(root.clone())).await.map_err(unavailable)?;
                ledger
                    .record(&tenant, &signed, Some(i))
                    .map_err(|e| RegistrarError::Unavailable(format!("ledger: {e}")))?;
                i
            }
        };
        let proof =
            self.upstreams.log_proof(log_index).await.map_err(|e| RegistrarError::Unavailable(format!("log: {e}")))?;
        self.upstreams
            .put_root(&tenant, &LoggedRoot { root: signed, proof })
            .await
            .map_err(|e| RegistrarError::Unavailable(format!("control plane: {e}")))?;
        Ok(Registered { root_id: root_id(&root).to_string(), key_id: admin_key_id(&admin_key).to_string(), log_index })
    }
}

#[cfg(test)]
mod tests;
