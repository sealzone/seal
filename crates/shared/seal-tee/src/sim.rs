//! Simulator (feature `sim`, never in production): evidence signed by the dev root of
//! `seal_attest::sim::DEV_ROOT_SEED`, with whatever measurement the test chooses.
//!
//! `Attestor::detect` picks the simulator only in a `sim` build with `SEAL_SIM=1` set, and
//! then measures the running binary (SHA-384 of its file, as `Measurement` defines for sim).

use seal_attest::sim::Document;
use seal_proto::release::Tcb;
use seal_proto::{Evidence, Measurement, TrustedTime};
use sha2::{Digest, Sha384};

use crate::TeeError;

/// Signs `Evidence::Sim` documents for `measurement`.
pub struct SimAttestor {
    measurement: Measurement,
}

impl SimAttestor {
    pub fn new(measurement: Measurement) -> Self {
        Self { measurement }
    }

    /// Measures the running binary: SHA-384 of its file.
    pub(crate) fn of_running_binary() -> Result<Self, TeeError> {
        let binary = std::fs::read(std::env::current_exe()?)?;
        let digest = Sha384::digest(&binary);
        Ok(Self::new(Measurement(std::array::from_fn(|i| digest[i]))))
    }

    pub(crate) fn measurement(&self) -> Measurement {
        self.measurement
    }

    /// Exactly what `seal_attest::verify` accepts in a `sim` build, with an empty TCB.
    pub(crate) fn attest(&self, report_data: [u8; 32]) -> Evidence {
        let document = Document { measurement: self.measurement, report_data, tcb: Tcb::default() };
        Evidence::Sim { document: seal_attest::sim::sign(&document) }
    }
}

/// System clock plus a fixed offset (tests use the offset to cross time locks).
pub struct SystemClock {
    offset_secs: i64,
}

impl SystemClock {
    pub fn new(offset_secs: i64) -> Self {
        Self { offset_secs }
    }

    /// The host's time shifted by the offset, with radius 0.
    pub(crate) fn now(&self) -> Result<TrustedTime, TeeError> {
        let system = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TeeError::Unavailable("system clock before the Unix epoch".into()))?
            .as_secs();
        let now = system
            .checked_add_signed(self.offset_secs)
            .ok_or_else(|| TeeError::Unavailable("clock offset out of range".into()))?;
        Ok(TrustedTime::exact(now))
    }
}
