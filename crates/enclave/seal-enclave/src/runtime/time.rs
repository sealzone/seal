//! Trusted time between clock reads. Every operation reads the cloud's `Clock`; what runs
//! synchronously (adapter reports, session expiry timers, live-session rechecks) uses the
//! latest reading advanced by the monotonic clock, with the radius widened so the estimate
//! never claims more than it knows.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use seal_proto::{TrustedTime, UnixTime};

use super::lock;

/// Extra radius per second since the last reading, as a divisor: 1 s per 1000 s of drift.
const DRIFT_DIVISOR: u64 = 1000;

pub(crate) struct TimeBase {
    /// The latest trusted reading and the instant it was taken.
    anchor: Mutex<(Instant, TrustedTime)>,
}

impl TimeBase {
    pub(crate) fn new(time: TrustedTime) -> Self {
        Self { anchor: Mutex::new((Instant::now(), time)) }
    }

    /// A fresh reading from the clock becomes the anchor.
    pub(crate) fn record(&self, time: TrustedTime) {
        *lock(&self.anchor) = (Instant::now(), time);
    }

    /// The anchor plus the whole seconds elapsed since. The radius grows by one second (the
    /// truncated fraction) plus the allowed drift, so `earliest()` and `latest()` stay bounds.
    pub(crate) fn estimate(&self) -> TrustedTime {
        let (at, time) = *lock(&self.anchor);
        let elapsed = at.elapsed().as_secs();
        TrustedTime {
            now: time.now.saturating_add(elapsed),
            radius: time.radius.saturating_add(1).saturating_add(elapsed / DRIFT_DIVISOR),
        }
    }

    /// The instant by which `estimate().latest()` reaches `unix`: now if it already has, and at
    /// most `MAX_WAIT` ahead (callers check again when it comes).
    pub(crate) fn instant_at(&self, unix: UnixTime) -> Instant {
        let latest = self.estimate().latest();
        Instant::now() + Duration::from_secs(unix.saturating_sub(latest)).min(MAX_WAIT)
    }
}

/// The furthest `instant_at` looks ahead.
const MAX_WAIT: Duration = Duration::from_secs(3600);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_estimate_brackets_the_true_time() {
        let base = TimeBase::new(TrustedTime { now: 1_000, radius: 2 });
        let t = base.estimate();
        assert_eq!(t.now, 1_000);
        assert!(t.earliest() <= 998 && t.latest() >= 1_002);
        base.record(TrustedTime::exact(5_000));
        assert_eq!(base.estimate().now, 5_000);
        // Already reached: now; far ahead: capped.
        assert!(base.instant_at(4_000) <= Instant::now());
        assert!(base.instant_at(u64::MAX) <= Instant::now() + MAX_WAIT);
    }
}
