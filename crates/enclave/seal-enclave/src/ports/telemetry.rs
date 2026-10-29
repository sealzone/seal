//! `Telemetry` over the control plane (`POST /v1/tenants/{tenant}/telemetry`).
//!
//! **Stream and numbering.** Each `ControlTelemetry` is one stream: a random 16-byte `stream`
//! id chosen at construction (once per replica boot). `append` numbers entries from 0 in
//! call order and returns that number as the `TelemetryReceipt` at once; it never waits for
//! the network. Batches are numbered by `sequence` from 0.
//!
//! **Hand-off at boot.** The telemetry key exists only once boot has the service keys:
//! `SealService::boot` posts the service key certificate (the control plane accepts batches
//! only under a certified key) and then calls `Telemetry::start` with a `TelemetrySigner`, which
//! spawns the flusher. Entries appended before that are numbered and buffered (subject to the
//! drop policy) but not shipped. Each batch is signed with `TelemetrySigner::sign` and sealed to
//! `TelemetrySigner::readers`, read as each batch is built, so reader changes in a reloaded
//! state apply to the next batch. `start` also hands the signer to the replica's
//! `EnclaveCredential` (`with_credential`), so its control-plane reads are signed from then on.
//!
//! **Batches.** The flusher ships every `TELEMETRY_FLUSH_SECS`, and early once
//! `MAX_BATCH_ENTRIES` entries wait. A batch holds one contiguous run of entry numbers (at most
//! `MAX_BATCH_ENTRIES`): entries dropped from the middle of the buffer split runs, so the gaps
//! in a stream's entry numbers are exactly the dropped entries. Each batch is signed with the
//! telemetry key (`TELEMETRY_BATCH_LABEL`), its entries sealed to the readers when the tenant
//! names any (`seal_crypto::telemetry::seal_entries`), in clear otherwise.
//!
//! **Retries.** One batch is in flight at a time. A batch that fails to post stays signed and
//! is posted again unchanged (same stream and sequence, so a post that did land is accepted
//! again as a duplicate) on the next flush, after a full flush interval; newer entries wait
//! behind it in the buffer.
//!
//! **Drop policy.** At most `TELEMETRY_BUFFER_ENTRIES` entries are held unsent, the in-flight
//! batch included. A full buffer drops its oldest `Request` entry, or, with none left, its
//! oldest entry of any kind, to make room. Drops are counted and recorded in a `Dropped`
//! entry, appended when the next batch is cut, so the buffer may briefly hold that one entry
//! more. Dropping a `Dropped` entry folds its counts into the next one, so across a stream
//! the gaps in entry numbers add up to the counts of its `Dropped` entries.
//!
//! **Shutdown.** `shutdown` stops the flusher and ships everything left, marking the final
//! batch `last` (an empty one when nothing is left), retrying a few times. Entries appended
//! afterwards get receipts but are never shipped.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use seal_control::client::ControlClient;
use seal_crypto::telemetry::seal_entries;
use seal_proto::api::TelemetryReceipt;
use seal_proto::telemetry::{SignedTelemetryBatch, TelemetryBatch, TelemetryEntries, TelemetryEntry, TelemetryEvent};
use seal_proto::{ErrorCode, PublicKey, TenantId, UnixTime};

use super::control::EnclaveCredential;
use crate::{
    fail, host_now, lock, random, rng, ServiceError, Telemetry, TelemetrySigner, TELEMETRY_BUFFER_ENTRIES,
    TELEMETRY_FLUSH_SECS,
};

/// Entries per batch at most.
const MAX_BATCH_ENTRIES: usize = 1_000;

/// Attempts `shutdown` makes to ship what is left, `SHUTDOWN_RETRY` apart.
const SHUTDOWN_ATTEMPTS: u32 = 3;
const SHUTDOWN_RETRY: Duration = Duration::from_secs(1);

/// Where signed batches go. `ControlSink` in production.
#[async_trait]
trait BatchSink: Send + Sync {
    async fn post(&self, batch: &SignedTelemetryBatch) -> Result<(), String>;
}

/// What batches are signed with and sealed to: `TelemetrySigner` in production.
trait BatchSigner: Send + Sync {
    fn sign(&self, batch: TelemetryBatch) -> SignedTelemetryBatch;
    fn readers(&self) -> BTreeSet<PublicKey>;
}

impl BatchSigner for TelemetrySigner {
    fn sign(&self, batch: TelemetryBatch) -> SignedTelemetryBatch {
        TelemetrySigner::sign(self, batch)
    }
    fn readers(&self) -> BTreeSet<PublicKey> {
        TelemetrySigner::readers(self)
    }
}

struct ControlSink {
    client: Arc<ControlClient>,
}

#[async_trait]
impl BatchSink for ControlSink {
    async fn post(&self, batch: &SignedTelemetryBatch) -> Result<(), String> {
        self.client.post_telemetry(&batch.body.tenant, batch).await.map_err(|e| e.to_string())
    }
}

#[derive(Clone, Copy)]
struct Limits {
    flush: Duration,
    capacity: usize,
    max_batch: usize,
}

const LIMITS: Limits = Limits {
    flush: Duration::from_secs(TELEMETRY_FLUSH_SECS),
    capacity: TELEMETRY_BUFFER_ENTRIES,
    max_batch: MAX_BATCH_ENTRIES,
};

/// The control-plane `Telemetry` port (module docs). Cheap to share behind an `Arc`.
pub struct ControlTelemetry {
    inner: Arc<Inner>,
    credential: Option<Arc<EnclaveCredential>>,
}

struct Inner {
    tenant: TenantId,
    stream: [u8; 16],
    sink: Arc<dyn BatchSink>,
    limits: Limits,
    buffer: Mutex<Buffer>,
    /// Held while a batch is cut and posted, so batches leave in sequence order.
    shipper: tokio::sync::Mutex<Shipper>,
    /// Woken when `max_batch` entries wait.
    wake: tokio::sync::Notify,
    flusher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Whether the flusher was started and whether it has ended (`Flusher`).
    flusher_state: tokio::sync::watch::Sender<Flusher>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flusher {
    NotStarted,
    Running,
    Ended,
}

/// Marks the flusher ended when its future is dropped: it returned, panicked or was aborted.
struct FlusherGuard(Arc<Inner>);
impl Drop for FlusherGuard {
    fn drop(&mut self) {
        self.0.flusher_state.send_replace(Flusher::Ended);
    }
}

struct Buffer {
    next_entry: u64,
    /// Unsent entries not yet in a batch, by number.
    entries: VecDeque<(u64, TelemetryEntry)>,
    /// `Request` entries in `entries`.
    requests: usize,
    /// Entries in the shipper's pending batch.
    in_flight: usize,
    /// Drops not yet recorded in a `Dropped` entry: (`Request` entries, others).
    dropped: (u64, u64),
    /// The latest entry time seen, for `Dropped` entries and an empty final batch.
    latest_at: UnixTime,
    signer: Option<Arc<dyn BatchSigner>>,
}

struct Shipper {
    next_sequence: u64,
    /// Signed and not yet accepted by the control plane; posted again unchanged.
    pending: Option<SignedTelemetryBatch>,
    /// The `last` batch was accepted.
    finished: bool,
}

/// One run of entries taken from the buffer for a batch, with what is needed to build it.
struct Cut {
    first_entry: u64,
    entries: Vec<TelemetryEntry>,
    last: bool,
    latest_at: UnixTime,
    signer: Arc<dyn BatchSigner>,
}

fn is_request(entry: &TelemetryEntry) -> bool {
    matches!(entry.event, TelemetryEvent::Request { .. })
}

impl Buffer {
    fn push(&mut self, number: u64, entry: TelemetryEntry) {
        self.requests += usize::from(is_request(&entry));
        self.entries.push_back((number, entry));
    }

    /// Drops one entry by the policy; false when there is nothing to drop.
    fn drop_one(&mut self) -> bool {
        if self.requests > 0 {
            if let Some(i) = self.entries.iter().position(|(_, e)| is_request(e)) {
                self.entries.remove(i);
                self.requests -= 1;
                self.dropped.0 += 1;
                return true;
            }
        }
        match self.entries.pop_front() {
            Some((_, TelemetryEntry { event: TelemetryEvent::Dropped { requests, other }, .. })) => {
                self.dropped.0 += requests;
                self.dropped.1 += other + 1;
                true
            }
            Some(_) => {
                self.dropped.1 += 1;
                true
            }
            None => false,
        }
    }

    /// Numbers and buffers `entry`, dropping by the policy when full.
    fn append(&mut self, entry: TelemetryEntry, capacity: usize) -> u64 {
        let number = self.next_entry;
        self.next_entry += 1;
        self.latest_at = self.latest_at.max(entry.at);
        if self.entries.len() + self.in_flight >= capacity && !self.drop_one() {
            // Everything held is in flight: this entry is the one dropped.
            if is_request(&entry) {
                self.dropped.0 += 1;
            } else {
                self.dropped.1 += 1;
            }
            return number;
        }
        self.push(number, entry);
        number
    }

    /// The next batch's run, or `None` when there is nothing to ship (an empty run for the
    /// final batch) or no signing key yet. Records pending drops in a `Dropped` entry first.
    fn cut(&mut self, tenant: &TenantId, max_batch: usize, last: bool) -> Option<Cut> {
        let signer = self.signer.clone()?;
        let (requests, other) = std::mem::take(&mut self.dropped);
        if requests + other > 0 {
            let number = self.next_entry;
            self.next_entry += 1;
            let entry = TelemetryEntry {
                at: self.latest_at,
                tenant: tenant.clone(),
                identity: None,
                event: TelemetryEvent::Dropped { requests, other },
            };
            self.push(number, entry);
        }
        if self.entries.is_empty() && !last {
            return None;
        }
        let first_entry = self.entries.front().map_or(self.next_entry, |(n, _)| *n);
        let run = self
            .entries
            .iter()
            .enumerate()
            .take(max_batch)
            .take_while(|(i, (n, _))| *n == first_entry + *i as u64)
            .count();
        let entries: Vec<TelemetryEntry> = self.entries.drain(..run).map(|(_, e)| e).collect();
        self.requests -= entries.iter().filter(|e| is_request(e)).count();
        self.in_flight = entries.len();
        Some(Cut { first_entry, entries, last: last && self.entries.is_empty(), latest_at: self.latest_at, signer })
    }
}

impl ControlTelemetry {
    /// A new stream for `tenant`, posting through `client`. Ships nothing until `start`.
    pub fn new(client: Arc<ControlClient>, tenant: TenantId) -> Self {
        Self::with_sink(tenant, Arc::new(ControlSink { client }), LIMITS)
    }

    fn with_sink(tenant: TenantId, sink: Arc<dyn BatchSink>, limits: Limits) -> Self {
        let stream = random();
        let buffer = Buffer {
            next_entry: 0,
            entries: VecDeque::new(),
            requests: 0,
            in_flight: 0,
            dropped: (0, 0),
            latest_at: 0,
            signer: None,
        };
        let shipper = Shipper { next_sequence: 0, pending: None, finished: false };
        Self {
            credential: None,
            inner: Arc::new(Inner {
                tenant,
                stream,
                sink,
                limits,
                buffer: Mutex::new(buffer),
                shipper: tokio::sync::Mutex::new(shipper),
                wake: tokio::sync::Notify::new(),
                flusher: Mutex::new(None),
                flusher_state: tokio::sync::watch::Sender::new(Flusher::NotStarted),
            }),
        }
    }

    /// `start` hands the telemetry signer to `credential`.
    pub fn with_credential(mut self, credential: Arc<EnclaveCredential>) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Installs `signer` and starts the periodic flusher (once; a later call only replaces the
    /// signer). Must run inside a tokio runtime.
    fn begin(&self, signer: Arc<dyn BatchSigner>) {
        self.install(signer);
        let mut flusher = lock(&self.inner.flusher);
        if flusher.is_none() {
            self.inner.flusher_state.send_replace(Flusher::Running);
            *flusher = Some(tokio::spawn(flush_periodically(self.inner.clone())));
        }
    }

    /// Resolves once the flusher, started, has ended: it runs until `shutdown`, so before
    /// that this means it panicked and nothing more is shipped. Never resolves before `start`.
    pub async fn flusher_ended(&self) {
        let mut state = self.inner.flusher_state.subscribe();
        let _ = state.wait_for(|s| *s == Flusher::Ended).await;
    }

    /// `begin` without the flusher.
    fn install(&self, signer: Arc<dyn BatchSigner>) {
        self.inner.lock().signer = Some(signer);
    }

    /// Stops the flusher and ships what is left as the stream's final batches, the last one
    /// marked `last`. `Unavailable` when that did not succeed within `SHUTDOWN_ATTEMPTS`; the
    /// stream then ends without a `last` batch, which readers report.
    pub async fn shutdown(&self) -> Result<(), ServiceError> {
        let flusher = lock(&self.inner.flusher).take();
        if let Some(flusher) = flusher {
            flusher.abort();
            let _ = flusher.await;
        }
        if self.inner.lock().signer.is_none() {
            return Err(fail(ErrorCode::Unavailable, "telemetry never started: nothing was shipped"));
        }
        let mut last_error = String::new();
        for attempt in 0..SHUTDOWN_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(SHUTDOWN_RETRY).await;
            }
            match self.inner.ship(true).await {
                Ok(()) => return Ok(()),
                Err(e) => last_error = e,
            }
        }
        tracing::error!(error = %last_error, "telemetry: final batch not shipped");
        Err(fail(ErrorCode::Unavailable, format!("telemetry: final batch not shipped: {last_error}")))
    }
}

impl Telemetry for ControlTelemetry {
    /// Installs `signer` and spawns the flusher (module docs).
    fn start(&self, signer: TelemetrySigner) {
        if signer.tenant() != &self.inner.tenant {
            tracing::error!(tenant = %signer.tenant(), "telemetry signer for another tenant than the stream's");
        }
        if let Some(credential) = &self.credential {
            credential.sign_with(signer.clone());
        }
        self.begin(Arc::new(signer));
    }

    fn append(&self, entry: TelemetryEntry) -> TelemetryReceipt {
        let limits = self.inner.limits;
        let (number, waiting) = {
            let mut buffer = self.inner.lock();
            let number = buffer.append(entry, limits.capacity);
            (number, buffer.entries.len())
        };
        if waiting >= limits.max_batch {
            self.inner.wake.notify_one();
        }
        TelemetryReceipt { stream: self.inner.stream, entry: number }
    }
}

impl Drop for ControlTelemetry {
    fn drop(&mut self) {
        if let Some(flusher) = lock(&self.inner.flusher).take() {
            flusher.abort();
        }
    }
}

async fn flush_periodically(inner: Arc<Inner>) {
    let _ended = FlusherGuard(inner.clone());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(inner.limits.flush) => {}
            _ = inner.wake.notified() => {}
        }
        if let Err(e) = inner.ship(false).await {
            tracing::warn!(error = %e, "telemetry: batch not shipped, retrying");
            // Back off a full interval, however full the buffer is.
            tokio::time::sleep(inner.limits.flush).await;
        }
    }
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Buffer> {
        lock(&self.buffer)
    }

    /// Posts the pending batch, then cuts and posts batches until the buffer is empty (and, for
    /// `last`, the final batch went out). Stops at the first failed post.
    async fn ship(&self, last: bool) -> Result<(), String> {
        let mut shipper = self.shipper.lock().await;
        if shipper.finished {
            return Ok(());
        }
        loop {
            if shipper.pending.is_none() {
                let Some(cut) = self.lock().cut(&self.tenant, self.limits.max_batch, last) else {
                    return Ok(());
                };
                let sequence = shipper.next_sequence;
                match build(&self.tenant, self.stream, sequence, cut) {
                    Ok(batch) => {
                        shipper.next_sequence += 1;
                        shipper.pending = Some(batch);
                    }
                    Err((e, entries)) => {
                        tracing::error!(error = %e, "telemetry: cannot build a batch, its entries are dropped");
                        let mut buffer = self.lock();
                        buffer.in_flight = 0;
                        for entry in &entries {
                            if is_request(entry) {
                                buffer.dropped.0 += 1;
                            } else {
                                buffer.dropped.1 += 1;
                            }
                        }
                        continue;
                    }
                }
            }
            let Some(batch) = shipper.pending.as_ref() else { continue };
            self.sink.post(batch).await?;
            let was_last = batch.body.last;
            shipper.pending = None;
            self.lock().in_flight = 0;
            if was_last {
                shipper.finished = true;
                return Ok(());
            }
        }
    }
}

/// The signed batch for `cut`; on failure its entries come back so they can be counted.
fn build(
    tenant: &TenantId,
    stream: [u8; 16],
    sequence: u64,
    cut: Cut,
) -> Result<SignedTelemetryBatch, (String, Vec<TelemetryEntry>)> {
    let Cut { first_entry, entries, last, latest_at, signer } = cut;
    // Read now, outside the buffer lock: the newest verified state's readers.
    let readers: Vec<PublicKey> = signer.readers().into_iter().collect();
    let count = entries.len() as u32;
    let (from, to) = match (entries.iter().map(|e| e.at).min(), entries.iter().map(|e| e.at).max()) {
        (Some(from), Some(to)) => (from, to),
        _ => {
            // An empty final batch: the stream's latest time, or the host's for a stream without entries.
            let at = if latest_at > 0 { latest_at } else { host_now() };
            (at, at)
        }
    };
    let entries = if readers.is_empty() {
        TelemetryEntries::Clear { entries }
    } else {
        match seal_entries(tenant, stream, sequence, first_entry, &entries, &readers, &mut rng()) {
            Ok(sealed) => sealed,
            Err(e) => return Err((e.to_string(), entries)),
        }
    };
    let batch =
        TelemetryBatch { tenant: tenant.clone(), stream, sequence, first_entry, count, from, to, entries, last };
    Ok(signer.sign(batch))
}

#[cfg(test)]
mod tests;
