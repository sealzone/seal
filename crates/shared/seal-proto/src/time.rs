//! Time as an interval. Checks take a `TrustedTime`; timestamps written into documents
//! take a plain `UnixTime` (`TrustedTime::now`).

use crate::UnixTime;

/// The true time lies in `[now - radius, now + radius]`. Checks take the pessimistic end:
/// "not before" checks (time locks) use `earliest()`; "not after" checks (expiry, ticket and
/// checkpoint freshness) use `latest()`. So clock uncertainty never helps an attacker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedTime {
    pub now: UnixTime,
    /// Uncertainty in seconds.
    pub radius: u64,
}

impl TrustedTime {
    /// A point in time with no stated uncertainty, for callers without a trusted clock
    /// (SDK clients, tests).
    pub fn exact(now: UnixTime) -> Self {
        Self { now, radius: 0 }
    }
    pub fn earliest(&self) -> UnixTime {
        self.now.saturating_sub(self.radius)
    }
    pub fn latest(&self) -> UnixTime {
        self.now.saturating_add(self.radius)
    }
}
