//! AWS Nitro Enclaves: designed, not built. Both types are uninhabited: `new` refuses with
//! `TeeError::Unavailable`, so an image started on a Nitro host fails at `Attestor::detect`
//! with that error instead of panicking, and no code path can hold a Nitro attestor or clock.
//! Verifying Nitro evidence (`seal_attest::nitro`) is built.

use std::convert::Infallible;

use seal_proto::{Evidence, Measurement, TrustedTime};

use crate::TeeError;

fn not_built() -> TeeError {
    TeeError::Unavailable("AWS Nitro Enclaves are not supported by this build".into())
}

/// Attestation documents from `/dev/nsm` with `user_data` = the report data.
pub struct NitroAttestor(Infallible);

impl NitroAttestor {
    pub fn new() -> Result<Self, TeeError> {
        Err(not_built())
    }
    pub fn measurement(&self) -> Measurement {
        match self.0 {}
    }
    pub async fn attest(&self, _report_data: [u8; 32]) -> Result<Evidence, TeeError> {
        match self.0 {}
    }
}

/// Trusted time from the Nitro hypervisor: the `timestamp` (UTC milliseconds) of a fresh NSM
/// attestation document, requested with a random nonce and checked with `seal_attest::verify`,
/// so the parent instance can neither set nor replay it. It adds no trust beyond what Nitro
/// already requires (AWS). Between documents, time advances by the enclave's monotonic clock;
/// a new document is taken at least every 60 s, and a radius of 1 s covers the hypervisor
/// clock's accuracy until it is measured.
pub struct NitroClock(Infallible);

impl NitroClock {
    pub fn new() -> Result<Self, TeeError> {
        Err(not_built())
    }
    pub async fn now(&self) -> Result<TrustedTime, TeeError> {
        match self.0 {}
    }
}
