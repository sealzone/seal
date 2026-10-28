//! What the tenant's `deployments` entries let this replica serve, and the idle exit of
//! Seal-hosted replicas.
//!
//! Both come from the newest verified state only: the entries matching the replica's own
//! deployment identity (attested, or proved at boot). An entry with a `HostedMode` is Seal's
//! hosted identity; nothing else a replica reads marks it as hosted, so neither Seal nor the
//! host can make a customer's replica idle out.

use std::sync::Mutex;
use std::time::Duration;

use seal_proto::identity::WorkloadIdentity;
use seal_proto::state::TenantState;
use seal_proto::ErrorCode;
use tokio::time::Instant;

use super::{fail, lock};
use crate::ServiceError;

/// What a replica serves under one state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Serving {
    /// Seal's hosted replica: it exits when idle.
    pub hosted: bool,
}

/// The entries of `state.deployments` matching `identity`, combined: `None` when none does,
/// hosted if any entry is.
pub(crate) fn serving(state: &TenantState, identity: &WorkloadIdentity) -> Option<Serving> {
    let mut matching = state.deployments.iter().filter(|m| m.matches(identity)).peekable();
    matching.peek()?;
    Some(Serving { hosted: matching.any(|m| m.hosted().is_some()) })
}

/// When the replica last did something for an authenticated caller, what it is doing now, and
/// whether it is draining. Only authenticated work counts: anyone can reach the API, and
/// unauthenticated requests must not keep a hosted replica (and its VM) running.
pub(crate) struct Activity {
    inner: Mutex<State>,
}

struct State {
    last: Instant,
    in_flight: usize,
    draining: bool,
}

impl Default for Activity {
    fn default() -> Self {
        Self { inner: Mutex::new(State { last: Instant::now(), in_flight: 0, draining: false }) }
    }
}

impl Activity {
    /// Authenticated work starts; it counts until the returned guard drops. `Unavailable` once
    /// the replica drains, so nothing starts that could outlive it.
    pub(crate) fn begin(&self) -> Result<Busy<'_>, ServiceError> {
        let mut state = lock(&self.inner);
        if state.draining {
            return Err(fail(ErrorCode::Unavailable, "the replica is stopping"));
        }
        state.in_flight += 1;
        Ok(Busy(self))
    }

    /// `Unavailable` once the replica drains.
    pub(crate) fn check(&self) -> Result<(), ServiceError> {
        match lock(&self.inner).draining {
            true => Err(fail(ErrorCode::Unavailable, "the replica is stopping")),
            false => Ok(()),
        }
    }

    /// Something authenticated just ended (a data-plane connection).
    pub(crate) fn touch(&self) {
        lock(&self.inner).last = Instant::now();
    }

    /// Starts draining if nothing authenticated is running and nothing ran for `idle`; returns
    /// whether it did. The caller has checked that no session connection is live: a connection
    /// resolving its session counts as running work until it is live.
    pub(crate) fn drain_if_idle(&self, idle: Duration) -> bool {
        let mut state = lock(&self.inner);
        if state.in_flight == 0 && state.last.elapsed() >= idle {
            state.draining = true;
        }
        state.draining
    }
}

/// Authenticated work in progress (`Activity::begin`).
pub(crate) struct Busy<'a>(&'a Activity);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        let mut state = lock(&self.0.inner);
        state.in_flight -= 1;
        state.last = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use seal_proto::identity::{HostedMode, IdentityMatcher};

    use super::*;

    fn space(n: u64, hosted: Option<HostedMode>) -> IdentityMatcher {
        IdentityMatcher::ConfidentialSpace { project_number: n, service_account: "r@p.iam".into(), hosted }
    }

    fn state(deployments: &[IdentityMatcher]) -> TenantState {
        TenantState {
            tenant: seal_proto::TenantId::new("acme").unwrap(),
            version: 1,
            root_version: 1,
            apps: Default::default(),
            producers: Default::default(),
            tenant_key_versions: seal_proto::state::TenantKeyVersions {
                current: seal_proto::TenantKeyVersion(1),
                oldest_accepted: seal_proto::TenantKeyVersion(1),
            },
            platforms: Default::default(),
            integrity: Default::default(),
            deployments: deployments.iter().cloned().collect(),
            freshness_keys: Default::default(),
            telemetry_readers: Default::default(),
            issued_at: 0,
            pending_window_secs: 0,
            app_networks: Default::default(),
        }
    }

    #[test]
    fn the_matching_entries_decide() {
        let me = WorkloadIdentity::ConfidentialSpace { project_number: 1, service_account: "r@p.iam".into() };
        let (own, hosted) = (Serving { hosted: false }, Serving { hosted: true });
        assert_eq!(serving(&state(&[space(1, None)]), &me), Some(own));
        assert_eq!(serving(&state(&[space(1, Some(HostedMode::Sessions))]), &me), Some(hosted));
        // Listed more than once: hosted if any entry is.
        assert_eq!(serving(&state(&[space(1, None), space(1, Some(HostedMode::Sessions))]), &me), Some(hosted));
        // Other deployments' modes are not this replica's.
        assert_eq!(serving(&state(&[space(1, None), space(2, Some(HostedMode::Sessions))]), &me), Some(own));
        assert_eq!(serving(&state(&[space(2, None)]), &me), None);
        assert_eq!(serving(&state(&[]), &me), None);
    }

    /// Seal's hosted replicas on ACI: the tenant's entry for their managed identity decides the same way.
    #[test]
    fn an_azure_entry_decides_alike() {
        let azure = |oid: &str, hosted| IdentityMatcher::Azure {
            entra_tenant: "tid".into(),
            object_id: oid.into(),
            audience: "api://seal-hosted".into(),
            hosted,
        };
        let me = WorkloadIdentity::Azure { entra_tenant: "tid".into(), object_id: "oid".into() };
        assert_eq!(serving(&state(&[azure("oid", Some(HostedMode::Sessions))]), &me), Some(Serving { hosted: true }));
        assert_eq!(serving(&state(&[azure("oid", None)]), &me), Some(Serving { hosted: false }));
        assert_eq!(serving(&state(&[azure("other", Some(HostedMode::Sessions))]), &me), None);
    }

    #[test]
    fn drains_only_when_nothing_ran_for_the_period() {
        let activity = Activity::default();
        let busy = activity.begin().unwrap();
        assert!(!activity.drain_if_idle(Duration::ZERO), "work in progress");
        drop(busy);
        assert!(!activity.drain_if_idle(Duration::from_secs(60)), "work just ended");
        activity.check().unwrap();
        assert!(activity.drain_if_idle(Duration::ZERO));
        assert_eq!(activity.begin().err().unwrap().code, ErrorCode::Unavailable);
        assert_eq!(activity.check().unwrap_err().code, ErrorCode::Unavailable);
    }
}
