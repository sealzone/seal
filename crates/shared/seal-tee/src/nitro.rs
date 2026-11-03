//! AWS Nitro Enclaves: attestation documents and trusted time from the Nitro Secure Module.
//!
//! The NSM is a virtual device the Nitro hypervisor serves at `/dev/nsm`, not the parent
//! instance: the parent cannot see, answer or replay a request. One request is one CBOR map in
//! and one CBOR map out, through the NSM driver's one ioctl (`nsm`).
//!
//! - `NitroAttestor` asks for a document with `user_data` = the 32 report-data bytes, which is
//!   what `seal_attest::nitro` verifies. Its measurement is read once at construction from a
//!   document with all-zero `user_data` (`seal_attest::nitro::peek`), and every later document
//!   must state the same PCRs and the `user_data` asked for. A debug enclave (PCR0..2 all zero)
//!   attests as on the other clouds: its measurement is no release's, and every verifier
//!   refuses its evidence (`AttestError::DebugMode`). Its clock is refused (`NitroClock`).
//! - `NitroClock` (below) reads the hypervisor's signed timestamp.

use std::sync::Arc;
use std::time::Duration;

use seal_attest::AttestError;
use seal_proto::{Evidence, Measurement, TrustedTime};
use tokio::time::Instant;

use crate::TeeError;

pub(crate) mod nsm;
#[cfg(test)]
mod tests;

use nsm::Nsm;

fn unavailable(msg: impl std::fmt::Display) -> TeeError {
    TeeError::Unavailable(format!("nitro: {msg}"))
}

/// How long one NSM request may take before the caller fails closed. The NSM answers in
/// milliseconds; a request that does not return leaves its blocking thread behind.
pub const NSM_TIMEOUT: Duration = Duration::from_secs(10);

/// One attestation document from `nsm` with these optional fields, on tokio's blocking pool,
/// within `NSM_TIMEOUT`.
async fn document(
    nsm: &Arc<dyn Nsm>,
    timeout: Duration,
    user_data: Option<[u8; 32]>,
    nonce: Option<[u8; 32]>,
) -> Result<Vec<u8>, TeeError> {
    let nsm = nsm.clone();
    let request = tokio::task::spawn_blocking(move || nsm::attestation(&*nsm, user_data.as_ref(), nonce.as_ref()));
    tokio::time::timeout(timeout, request)
        .await
        .map_err(|_| unavailable(format!("the NSM did not answer within {timeout:?}")))?
        .map_err(|e| unavailable(format!("NSM request: {e}")))?
}

/// Attestation documents from `/dev/nsm` with `user_data` = the report data.
pub struct NitroAttestor {
    nsm: Arc<dyn Nsm>,
    measurement: Measurement,
    /// `NSM_TIMEOUT`; shorter in tests.
    pub(crate) timeout: Duration,
}

impl NitroAttestor {
    /// From `/dev/nsm`; requests one document to learn PCR0..2, blocking (callers in async
    /// code run it on the blocking pool: `seal_cloud::Cloud::detect`). `Unavailable` when the
    /// device does not answer with a usable document.
    pub fn new() -> Result<Self, TeeError> {
        Self::with(Arc::new(nsm::NsmDevice::open()?))
    }

    pub(crate) fn with(nsm: Arc<dyn Nsm>) -> Result<Self, TeeError> {
        let document = nsm::attestation(&*nsm, Some(&[0; 32]), None)?;
        let measurement = measurement_of(&document)?;
        Ok(Self { nsm, measurement, timeout: NSM_TIMEOUT })
    }

    pub fn measurement(&self) -> Measurement {
        self.measurement
    }

    /// A document committing to `report_data`.
    pub async fn attest(&self, report_data: [u8; 32]) -> Result<Evidence, TeeError> {
        let document = document(&self.nsm, self.timeout, Some(report_data), None).await?;
        if measurement_of(&document)? != self.measurement {
            return Err(unavailable("the document states other PCRs"));
        }
        let stated = seal_attest::nitro::peek(&document).map_err(unavailable)?;
        if stated.user_data.as_deref() != Some(report_data.as_slice()) {
            return Err(unavailable("the document does not carry the report data"));
        }
        Ok(Evidence::AwsNitro { document })
    }
}

/// The measurement a document from our own NSM states (unverified: it only selects the
/// release evidence to load, and the verifier checks it again).
fn measurement_of(document: &[u8]) -> Result<Measurement, TeeError> {
    let stated = seal_attest::nitro::peek(document).map_err(unavailable)?;
    let pcr = |i: u8| stated.pcrs.get(&i).ok_or_else(|| unavailable(format!("the document has no PCR{i}")));
    Ok(seal_attest::nitro::measurement(pcr(0)?, pcr(1)?, pcr(2)?))
}

/// A new document is taken at least this often; between documents time advances by the
/// enclave's monotonic clock.
pub const REFRESH: Duration = Duration::from_secs(60);

/// Added to each side of a reading: the hypervisor clock's accuracy, until it is measured.
pub const RADIUS: Duration = Duration::from_secs(1);

/// Checks a clock document and returns its `timestamp` in milliseconds:
/// `seal_attest::nitro::verify_timestamp` in production.
pub(crate) type CheckDocument = fn(&[u8], &[u8]) -> Result<u64, AttestError>;

/// Trusted time from the Nitro hypervisor: the `timestamp` (UTC milliseconds) of a fresh NSM
/// attestation document, requested with a random nonce and checked with
/// `seal_attest::nitro::verify_timestamp` (the AWS chain at the document's own time, not a
/// debug enclave, our nonce), so the parent instance can neither set nor replay it. It adds no
/// trust beyond what Nitro already requires (AWS). Between documents, time advances by the
/// enclave's monotonic clock (the hypervisor's, which the parent does not control); a new
/// document is taken at least every `REFRESH` (60 s), and a radius of `RADIUS` (1 s) covers the
/// hypervisor clock's accuracy until it is measured.
///
/// A reading taken at monotonic instant `received`, after a request sent at `sent`, says the
/// true time at `received` lies in `[timestamp, timestamp + (received - sent)]`: the hypervisor
/// stamped the document while the request was in flight. Carried to a later instant by the
/// monotonic clock and widened by `RADIUS` on each side, then rounded outwards to whole
/// seconds, that interval is the `TrustedTime`.
pub struct NitroClock {
    nsm: Arc<dyn Nsm>,
    check: CheckDocument,
    /// `NSM_TIMEOUT`; shorter in tests.
    pub(crate) timeout: Duration,
    last: tokio::sync::Mutex<Option<Reading>>,
}

/// One checked clock document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reading {
    /// The document's `timestamp`, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// From sending the request to holding the document.
    pub in_flight: Duration,
    /// When we held the document.
    pub received: Instant,
}

impl NitroClock {
    /// Over `/dev/nsm`. Nothing is requested until the first `now`.
    pub fn new() -> Result<Self, TeeError> {
        Ok(Self::with(Arc::new(nsm::NsmDevice::open()?), seal_attest::nitro::verify_timestamp))
    }

    pub(crate) fn with(nsm: Arc<dyn Nsm>, check: CheckDocument) -> Self {
        Self { nsm, check, timeout: NSM_TIMEOUT, last: tokio::sync::Mutex::new(None) }
    }

    /// The time now: from the last document if it is younger than `REFRESH`, else from a new
    /// one. `Unavailable` when the NSM fails, does not answer within `NSM_TIMEOUT`, or its
    /// document does not check out; callers fail closed, as with Roughtime.
    pub async fn now(&self) -> Result<TrustedTime, TeeError> {
        let mut last = self.last.lock().await;
        let reading = match *last {
            Some(reading) if reading.received.elapsed() < REFRESH => reading,
            _ => {
                let reading = self.read().await?;
                *last = Some(reading);
                reading
            }
        };
        Ok(reading.time_at(Instant::now()))
    }

    async fn read(&self) -> Result<Reading, TeeError> {
        let nonce = random_nonce(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng));
        let sent = Instant::now();
        let document = document(&self.nsm, self.timeout, None, Some(nonce)).await?;
        let received = Instant::now();
        let timestamp_ms = (self.check)(&document, &nonce).map_err(|e| unavailable(format!("clock document: {e}")))?;
        Ok(Reading { timestamp_ms, in_flight: received - sent, received })
    }
}

fn random_nonce(rng: &mut impl rand::CryptoRng) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    nonce
}

impl Reading {
    /// The interval this reading gives at monotonic instant `at` (type docs).
    pub(crate) fn time_at(&self, at: Instant) -> TrustedTime {
        let carried = at.saturating_duration_since(self.received);
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let base = self.timestamp_ms.saturating_add(ms(carried));
        let earliest = base.saturating_sub(ms(RADIUS)) / 1000;
        let latest = base.saturating_add(ms(self.in_flight)).saturating_add(ms(RADIUS)).div_ceil(1000);
        let now = earliest + (latest - earliest) / 2;
        TrustedTime { now, radius: latest - now }
    }
}
