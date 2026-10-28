//! Which tenant state is in force: the pending window, as a pure function of the logged
//! documents and the log's witnessed time.
//!
//! The document in force is a pair: a state and the root that signed it. From the pair in
//! force the tenant moves to a newer state as soon as one is admissible (the oldest of several
//! admissible at once, so states apply in log order), and from there on judges the rest again:
//!
//! - **at once** (from its `public_since`) if the state does not widen the one in force and,
//!   when it comes with a newer root, that root does not widen the root in force and carries
//!   the threshold of the root in force too;
//! - otherwise **once public for the window** of the state in force: its `public_since` (and
//!   that of every newer root up to its own) plus `TenantState::pending_window` of the state in
//!   force, by the log's witnessed time (`lock_time`, as for the release time lock).
//!
//! It never moves back, so a newer state that applies supersedes every older pending one: that
//! is how a pending change is cancelled. A state signed under an older root than the one in
//! force never applies.
//!
//! Every time is a `public_since` from an inclusion proof: the document was public by then.
//! Whoever serves a proof can only make a document look later (a proof against a later
//! checkpoint), never earlier: an untrusted control plane can delay a cancel or a narrowing,
//! as it can by withholding them, but cannot make a widening count as public before it was.
//!
//! Verifiers without memory (the guardian, an enclave at boot) start from an **anchor**, a
//! state known to have been in force: a guardian's `TenantAnchor` (the caller checks it); the
//! tenant's first state (version 1), which applies at once; a state whose successor became
//! public `MAX_PENDING_WINDOW_SECS` or more after it and its roots did, since by then it was
//! admissible from whatever was in force; or the latest state once that long has passed. Every
//! state after the anchor must be in the bundle.

use seal_proto::signed::Signed;
use seal_proto::state::{TenantRoot, TenantState, MAX_PENDING_WINDOW_SECS, TENANT_ROOT_LABEL};
use seal_proto::UnixTime;
use serde::Serialize;

use crate::change::{classify_root, classify_state, Change};

/// A logged document and the witnessed time it was public by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Public<T> {
    pub signed: Signed<T>,
    /// The `public_since` of its inclusion checkpoint. 0 for a first state the bundle carried
    /// no proof for.
    pub public_since: UnixTime,
}

impl<T> Public<T> {
    pub fn body(&self) -> &T {
        &self.signed.body
    }
}

/// Root `version` of the chain (`roots[0]` is version 1).
fn root(roots: &[Public<TenantRoot>], version: u64) -> Option<&Public<TenantRoot>> {
    roots.get(usize::try_from(version.checked_sub(1)?).ok()?)
}

/// The latest `public_since` of the roots after `from` up to and including `to`.
fn roots_public(roots: &[Public<TenantRoot>], from: u64, to: u64) -> UnixTime {
    (from.saturating_add(1)..=to).filter_map(|v| root(roots, v)).map(|r| r.public_since).max().unwrap_or(0)
}

/// When `states[k]` becomes admissible from `states[f]` in force, or `None` if it never can.
/// The window is that of `states[f]`.
pub(crate) fn admissible_at(
    roots: &[Public<TenantRoot>],
    states: &[Public<TenantState>],
    f: usize,
    k: usize,
) -> Option<UnixTime> {
    let (current, next) = (states[f].body(), states[k].body());
    if next.root_version < current.root_version {
        return None;
    }
    let mut narrowing = classify_state(current, next) == Change::Narrowing;
    let mut public = states[k].public_since;
    if next.root_version > current.root_version {
        let (in_force, newer) = (root(roots, current.root_version)?, root(roots, next.root_version)?);
        narrowing = narrowing
            && classify_root(in_force.body(), newer.body()) == Change::Narrowing
            && crate::TenantVerifier::verify_admin_signed(in_force.body(), TENANT_ROOT_LABEL, &newer.signed).is_ok();
        public = public.max(roots_public(roots, current.root_version, next.root_version));
    }
    Some(if narrowing { public } else { public.saturating_add(current.pending_window_secs) })
}

/// From `states[f]`, in force since `since`, to the state in force at `now`: repeatedly the state
/// admissible at the earliest time any is, the oldest of several (log order: one that became
/// public in the same second as an older one is judged against it). A newer state still applies
/// over older pending ones, since it is judged again from each state the tenant moves to. Returns
/// its index and since when.
pub(crate) fn advance(
    roots: &[Public<TenantRoot>],
    states: &[Public<TenantState>],
    mut f: usize,
    mut since: UnixTime,
    now: UnixTime,
) -> (usize, UnixTime) {
    loop {
        let times: Vec<(usize, UnixTime)> = (f + 1..states.len())
            .filter_map(|k| admissible_at(roots, states, f, k).map(|t| (k, t.max(since))))
            .collect();
        let Some(at) = times.iter().map(|&(_, t)| t).min().filter(|&t| t <= now) else {
            return (f, since);
        };
        f = times.iter().filter(|&&(_, t)| t == at).map(|&(k, _)| k).min().expect("one is admissible at `at`");
        since = at;
    }
}

/// The newest state known from the documents alone to have been in force, and since when at
/// the latest; `None` when the states do not reach back to one. `states` are consecutive
/// versions, oldest first.
pub(crate) fn anchor(
    roots: &[Public<TenantRoot>],
    states: &[Public<TenantState>],
    now: UnixTime,
) -> Option<(usize, UnixTime)> {
    let settled = |k: usize| {
        let s = &states[k];
        s.public_since.max(roots_public(roots, 1, s.body().root_version)).saturating_add(MAX_PENDING_WINDOW_SECS)
    };
    (0..states.len()).rev().find_map(|k| {
        let by = settled(k);
        let next = states.get(k + 1).map(|n| n.public_since);
        if states[k].body().version == 1 {
            // In force from the start, and never later than any state after it: a later proof
            // must not make the states after it look as if they came before it.
            let earliest = states[k..].iter().map(|s| s.public_since).min().unwrap_or(0);
            Some((k, earliest))
        } else if next.map_or(by <= now, |next| by <= next) {
            Some((k, by))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::state::{AdminKey, TenantKeyVersions};
    use seal_proto::{PlatformId, PublicKey, TenantId, TenantKeyVersion};

    fn public<T>(body: T, public_since: UnixTime) -> Public<T> {
        Public { signed: Signed { body, signatures: vec![] }, public_since }
    }

    fn state(version: u64, window: u64, platforms: &[PlatformId]) -> TenantState {
        TenantState {
            tenant: TenantId::new("acme").unwrap(),
            version,
            root_version: 1,
            apps: Default::default(),
            tenant_key_versions: TenantKeyVersions {
                current: TenantKeyVersion(1),
                oldest_accepted: TenantKeyVersion(1),
            },
            platforms: platforms.iter().copied().collect(),
            integrity: Default::default(),
            deployments: Default::default(),
            freshness_keys: Default::default(),
            telemetry_readers: Default::default(),
            issued_at: 0,
            pending_window_secs: window,
            app_networks: Default::default(),
        }
    }

    fn roots() -> Vec<Public<TenantRoot>> {
        let root = TenantRoot {
            tenant: TenantId::new("acme").unwrap(),
            version: 1,
            admin_keys: [AdminKey::Ed25519 { public_key: PublicKey([1; 32]) }].into(),
            threshold: 1,
            cosign_releases: false,
        };
        vec![public(root, 0)]
    }

    #[test]
    fn a_late_proof_of_the_first_state_does_not_skip_a_window() {
        let sim = [PlatformId::Sim];
        // State 1 (window 0) shown with a late proof; state 2 lengthens the window to 2 h
        // (narrowing) at 100; state 3 adds a platform (widening) at 200.
        let states = vec![
            public(state(1, 0, &sim), 1_000),
            public(state(2, 7_200, &sim), 100),
            public(state(3, 7_200, &[PlatformId::Sim, PlatformId::AwsNitro]), 200),
        ];
        let (anchor, since) = anchor(&roots(), &states, 1_000).unwrap();
        assert_eq!((anchor, since), (0, 100), "in force no later than the states after it");
        // State 2 applied at 100; state 3 waits state 2's window, not state 1's.
        assert_eq!(advance(&roots(), &states, anchor, since, 1_000), (1, 100));
        assert_eq!(advance(&roots(), &states, anchor, since, 7_400), (2, 7_400));
    }

    #[test]
    fn states_public_in_the_same_second_apply_in_log_order() {
        let sim = [PlatformId::Sim];
        let both = [PlatformId::Sim, PlatformId::AwsNitro];
        // Under a window of 0, state 2 lengthens it to 35 s and state 3 widens: both public at
        // 100. State 3 is judged against state 2, which applied first, so it waits.
        let states =
            vec![public(state(1, 0, &sim), 0), public(state(2, 35, &sim), 100), public(state(3, 35, &both), 100)];
        assert_eq!(advance(&roots(), &states, 0, 0, 120), (1, 100));
        assert_eq!(advance(&roots(), &states, 0, 0, 135), (2, 135));
    }

    #[test]
    fn identical_states_public_together_end_at_the_newest() {
        let sim = [PlatformId::Sim];
        let both = [PlatformId::Sim, PlatformId::AwsNitro];
        // Two widening states public at the same time under a window of 0: the newer applies.
        let states = vec![public(state(1, 0, &sim), 0), public(state(2, 0, &both), 50), public(state(3, 0, &both), 50)];
        assert_eq!(advance(&roots(), &states, 0, 0, 60), (2, 50));
    }
}
