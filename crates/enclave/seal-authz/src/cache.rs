use std::sync::RwLock;

use seal_proto::TenantId;
use seal_verify::VerifiedTenant;

use crate::AuthzError;

/// The newest verified state of the enclave's one tenant (its cloud's tenant pin).
/// Thread-safe; never goes back.
pub struct StateCache {
    tenant: TenantId,
    current: RwLock<Option<VerifiedTenant>>,
    /// Counts changes (`subscribe`).
    changes: tokio::sync::watch::Sender<u64>,
}

/// What a change is: anything a decision or a live-session recheck reads.
fn fingerprint(t: &VerifiedTenant) -> (u64, u64, seal_proto::UnixTime, usize, usize) {
    (t.root().version, t.state().version, t.fresh_until(), t.signals().len(), t.ended_sessions().len())
}

impl StateCache {
    pub fn new(tenant: TenantId) -> Self {
        Self { tenant, current: RwLock::new(None), changes: tokio::sync::watch::Sender::new(0) }
    }
    /// `None` until the first verified load.
    pub fn get(&self) -> Option<VerifiedTenant> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    /// `VerifiedTenant::merge` into the cached value (or insert). `Stale` if older; denied
    /// (`NotAllowed`) if it is another tenant's, or another root chain of the same name.
    pub fn update(&self, tenant: VerifiedTenant) -> Result<(), AuthzError> {
        if tenant.state().tenant != self.tenant || tenant.root().tenant != self.tenant {
            return Err(AuthzError::not_allowed("state of another tenant"));
        }
        let mut current = self.current.write().unwrap_or_else(|e| e.into_inner());
        let changed = match current.as_mut() {
            None => {
                *current = Some(tenant);
                true
            }
            Some(cached) => {
                if cached.root_id() != tenant.root_id() {
                    return Err(AuthzError::not_allowed("state of another root chain"));
                }
                let before = fingerprint(cached);
                cached.merge(tenant).map_err(|_| AuthzError::Stale)?;
                fingerprint(cached) != before
            }
        };
        drop(current);
        if changed {
            self.changes.send_modify(|n| *n = n.wrapping_add(1));
        }
        Ok(())
    }
    /// A receiver that sees every change from now on, including those made between two waits
    /// on it; the runtime rechecks every live session on each.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::testing::{acme, base_state, other_tenant, Fixture, T};
    use seal_proto::identity::WorkloadIdentity;
    use seal_proto::integrity::{IntegritySignal, Severity, SignalSource};
    use seal_proto::{ErrorCode, KeyId};

    async fn fires(cache: &StateCache, update: impl FnOnce() -> Result<(), AuthzError>) -> bool {
        let mut rx = cache.subscribe();
        update().unwrap();
        tokio::time::timeout(Duration::from_millis(200), rx.changed()).await.is_ok()
    }

    #[tokio::test]
    async fn keeps_the_newest_state_of_its_one_tenant() {
        let mut fx = Fixture::new(31);
        let v1 = fx.verified(base_state(1), &[], &[]);
        let v2 = fx.verified(base_state(2), &[], &[]);
        let cache = StateCache::new(acme());
        assert!(cache.get().is_none());

        assert!(fires(&cache, || cache.update(v1.clone())).await);
        assert_eq!(cache.get().unwrap().state().version, 1);
        assert!(fires(&cache, || cache.update(v2.clone())).await);
        assert_eq!(cache.get().unwrap().state().version, 2);

        // Older: refused, nothing changes.
        assert!(matches!(cache.update(v1), Err(AuthzError::Stale)));
        assert_eq!(cache.get().unwrap().state().version, 2);
        // The same again: accepted, but no change to recheck sessions for.
        assert!(!fires(&cache, || cache.update(v2.clone())).await);

        // New signals for the same state are a change.
        let signal = IntegritySignal {
            tenant: acme(),
            identity: WorkloadIdentity::AppKey { key_id: KeyId([1; 32]) },
            source: SignalSource::Sdk,
            code: "edr-high".into(),
            severity: Severity::High,
            observed_at: T,
            blob_id: None,
        };
        // A third state carries the signal (the log takes each version once).
        let v3 = fx.verified(base_state(3), &[signal], &[]);
        assert!(fires(&cache, || cache.update(v3)).await);
        assert_eq!(cache.get().unwrap().signals().len(), 1);
    }

    #[tokio::test]
    async fn a_subscription_sees_changes_made_between_waits() {
        let mut fx = Fixture::new(31);
        let cache = StateCache::new(acme());
        let mut rx = cache.subscribe();
        cache.update(fx.verified(base_state(1), &[], &[])).unwrap();
        // Nobody was waiting when the change happened; the receiver still sees it.
        tokio::time::timeout(Duration::from_millis(200), rx.changed()).await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(1), rx.changed()).await.is_err());
    }

    #[tokio::test]
    async fn refuses_other_tenants_and_chains() {
        let cache = StateCache::new(acme());
        cache.update(Fixture::new(31).verified(base_state(1), &[], &[])).unwrap();
        // Another root chain under the same name.
        let competing = Fixture::new(32).verified(base_state(5), &[], &[]);
        assert_eq!(cache.update(competing).unwrap_err().code(), ErrorCode::NotAllowed);
        assert_eq!(cache.get().unwrap().state().version, 1);
        // A cache pinned to another tenant.
        let bravo = StateCache::new(other_tenant());
        assert_eq!(
            bravo.update(Fixture::new(31).verified(base_state(1), &[], &[])).unwrap_err().code(),
            ErrorCode::NotAllowed
        );
        assert!(bravo.get().is_none());
    }
}
