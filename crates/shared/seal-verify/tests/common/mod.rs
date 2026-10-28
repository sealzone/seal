//! Fixtures: real keys and a `DevLog` whose witness and freshness times are pinned exactly.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use seal_crypto::sign::SigningKey;
use seal_proto::release::{SignedCheckpoint, TlogProof};
use seal_proto::state::SignedStateFreshness;
use seal_proto::{TenantId, UnixTime};
use seal_tlog::dev::DevLog;

/// Base time of every fixture.
pub const T: UnixTime = 1_900_000_000;

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&[n; 32])
}

pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("seal-verify-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A dev log with 3 witnesses and a quorum of 2, deleted on drop.
pub struct Log {
    pub log: DevLog,
    _dir: TempDir,
}

impl Log {
    pub fn new(seed: u8) -> Self {
        let dir = TempDir::new();
        Self { log: DevLog::open(&dir.0, [seed; 32], 3, 2).unwrap(), _dir: dir }
    }

    fn wall() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    /// Runs `f` with the log clock at exactly `t`, retrying across a wall-clock second boundary.
    fn at<R>(&mut self, t: UnixTime, f: impl Fn(&mut DevLog) -> R, time_of: impl Fn(&R) -> UnixTime) -> R {
        loop {
            self.log.set_clock_offset(t as i64 - Self::wall());
            let r = f(&mut self.log);
            if time_of(&r) == t {
                return r;
            }
        }
    }

    /// A new checkpoint every witness stamped at `t`.
    pub fn checkpoint_at(&mut self, t: UnixTime) -> SignedCheckpoint {
        self.at(
            t,
            |log| log.checkpoint(),
            |cp| {
                assert!(!cp.cosignatures.is_empty());
                let first = cp.cosignatures[0].timestamp;
                if cp.cosignatures.iter().all(|c| c.timestamp == first) {
                    first
                } else {
                    0
                }
            },
        )
    }

    /// An inclusion proof against a new checkpoint stamped at `t`.
    pub fn proof_at(&mut self, index: u64, t: UnixTime) -> TlogProof {
        self.checkpoint_at(t);
        self.log.prove(index)
    }

    pub fn freshness_at(&mut self, tenant: &TenantId, t: UnixTime) -> SignedStateFreshness {
        self.at(t, |log| log.freshness(tenant).expect("a logged state"), |f| f.body.signed_at)
    }
}
