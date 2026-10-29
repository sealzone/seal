use std::sync::atomic::{AtomicUsize, Ordering};

use seal_crypto::telemetry::{open_entries, TelemetryReaderKey};
use seal_crypto::{Key32, PlatformMasterKey, ServiceKeys, TelemetryKey};
use seal_proto::identity::WorkloadIdentity;
use seal_proto::policy::Protocol;
use seal_proto::telemetry::{Completion, Operation, Outcome, TELEMETRY_BATCH_LABEL};
use seal_proto::{AppName, BlobId, KeyId, PlatformId, ServiceKeyVersion, TenantRootId};

use super::*;

/// Records every post; fails the first `fail` of them; when `hold` is set, every post waits for
/// a permit of it.
#[derive(Default)]
struct FakeSink {
    posted: Mutex<Vec<SignedTelemetryBatch>>,
    attempts: Mutex<Vec<SignedTelemetryBatch>>,
    fail: AtomicUsize,
    hold: Option<Arc<tokio::sync::Semaphore>>,
}

#[async_trait]
impl BatchSink for FakeSink {
    async fn post(&self, batch: &SignedTelemetryBatch) -> Result<(), String> {
        self.attempts.lock().unwrap().push(batch.clone());
        if let Some(hold) = &self.hold {
            let _permit = hold.acquire().await.unwrap();
        }
        if self.fail.load(Ordering::SeqCst) > 0 {
            self.fail.fetch_sub(1, Ordering::SeqCst);
            return Err("control plane unreachable".into());
        }
        self.posted.lock().unwrap().push(batch.clone());
        Ok(())
    }
}

impl FakeSink {
    fn posted(&self) -> Vec<TelemetryBatch> {
        self.posted.lock().unwrap().iter().map(|b| b.body.clone()).collect()
    }
}

impl ControlTelemetry {
    fn stream(&self) -> [u8; 16] {
        self.inner.stream
    }

    /// Ships everything buffered now: `Unavailable` if a post failed (the batch is kept for the
    /// next flush). Does nothing before `start`.
    async fn flush(&self) -> Result<(), ServiceError> {
        self.inner.ship(false).await.map_err(|e| crate::fail(ErrorCode::Unavailable, format!("telemetry: {e}")))
    }
}

fn tenant() -> TenantId {
    TenantId::new("acme").unwrap()
}

fn telemetry_key() -> TelemetryKey {
    let master = PlatformMasterKey::from_root_secret(PlatformId::Sim, &Key32::from_bytes([5; 32]));
    let released = master.release_service(&tenant(), &TenantRootId([1; 32]), ServiceKeyVersion(1));
    ServiceKeys::from_released(PlatformId::Sim, &released).unwrap().telemetry
}

/// Signs with `telemetry_key()`; `readers` stand for the newest verified state's.
struct FakeSigner {
    key: TelemetryKey,
    readers: Mutex<BTreeSet<PublicKey>>,
}

impl BatchSigner for FakeSigner {
    fn sign(&self, batch: TelemetryBatch) -> SignedTelemetryBatch {
        self.key.signer().sign_into(TELEMETRY_BATCH_LABEL, batch)
    }
    fn readers(&self) -> BTreeSet<PublicKey> {
        self.readers.lock().unwrap().clone()
    }
}

fn signer(readers: impl IntoIterator<Item = PublicKey>) -> Arc<FakeSigner> {
    Arc::new(FakeSigner { key: telemetry_key(), readers: Mutex::new(readers.into_iter().collect()) })
}

fn limits(capacity: usize, max_batch: usize) -> Limits {
    Limits { flush: Duration::from_secs(TELEMETRY_FLUSH_SECS), capacity, max_batch }
}

fn telemetry(sink: &Arc<FakeSink>, limits: Limits) -> ControlTelemetry {
    ControlTelemetry::with_sink(tenant(), sink.clone(), limits)
}

fn identity() -> WorkloadIdentity {
    WorkloadIdentity::AppKey { key_id: KeyId([3; 32]) }
}

fn seal_entry(at: UnixTime) -> TelemetryEntry {
    TelemetryEntry {
        at,
        tenant: tenant(),
        identity: Some(identity()),
        event: TelemetryEvent::Refused { operation: Operation::Seal, code: ErrorCode::NotAllowed, context: None },
    }
}

fn request_entry(at: UnixTime) -> TelemetryEntry {
    TelemetryEntry {
        at,
        tenant: tenant(),
        identity: Some(identity()),
        event: TelemetryEvent::Request {
            session_id: [9; 16],
            app: AppName::new("checkout").unwrap(),
            blob_id: BlobId([4; 8]),
            connection_id: 1,
            completion: Completion {
                protocol: Protocol::Http,
                action: "GET /v1/models".into(),
                outcome: Outcome::Allowed,
                bytes_up: 10,
                bytes_down: 20,
            },
        },
    }
}

fn clear(batch: &TelemetryBatch) -> &[TelemetryEntry] {
    match &batch.entries {
        TelemetryEntries::Clear { entries } => entries,
        TelemetryEntries::Sealed { .. } => panic!("entries in clear expected"),
    }
}

fn dropped(entry: &TelemetryEntry) -> (u64, u64) {
    match entry.event {
        TelemetryEvent::Dropped { requests, other } => (requests, other),
        _ => panic!("a Dropped entry expected, got {entry:?}"),
    }
}

#[tokio::test]
async fn entries_are_numbered_across_the_stream_and_batched_in_order() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, LIMITS);
    let key = telemetry_key();
    let receipts: Vec<_> = (0..3).map(|i| t.append(seal_entry(100 + i))).collect();
    assert_eq!(receipts.iter().map(|r| r.entry).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(receipts.iter().all(|r| r.stream == t.stream()));

    t.install(signer([]));
    t.flush().await.unwrap();
    t.append(seal_entry(110));
    t.append(seal_entry(105));
    t.flush().await.unwrap();

    let posted = sink.posted.lock().unwrap().clone();
    assert_eq!(posted.len(), 2);
    let (a, b) = (&posted[0].body, &posted[1].body);
    assert_eq!(
        (a.stream, a.sequence, a.first_entry, a.count, a.from, a.to, a.last),
        (t.stream(), 0, 0, 3, 100, 102, false)
    );
    assert_eq!((b.sequence, b.first_entry, b.count, b.from, b.to), (1, 3, 2, 105, 110));
    assert_eq!(clear(a)[2], seal_entry(102));
    for batch in &posted {
        assert_eq!(batch.body.tenant, tenant());
        seal_crypto::sign::verify(&key.public_key(), TELEMETRY_BATCH_LABEL, &batch.body, &batch.signatures[0]).unwrap();
    }
}

#[tokio::test]
async fn nothing_ships_before_start() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, LIMITS);
    t.append(seal_entry(1));
    t.flush().await.unwrap();
    assert!(sink.attempts.lock().unwrap().is_empty());
    t.install(signer([]));
    t.flush().await.unwrap();
    assert_eq!(sink.posted()[0].count, 1);
}

#[tokio::test]
async fn a_full_buffer_drops_old_requests_first_and_records_it() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, limits(5, 100));
    // 0 seal, 1 request, 2 request, 3 seal, 4 request: full.
    t.append(seal_entry(10));
    t.append(request_entry(11));
    t.append(request_entry(12));
    t.append(seal_entry(13));
    t.append(request_entry(14));
    // Each further entry drops the oldest request (1, 2, 4), then the oldest entry (0).
    for at in 15..19 {
        t.append(seal_entry(at));
    }
    t.install(signer([]));
    t.flush().await.unwrap();

    let posted = sink.posted();
    assert_eq!(posted.len(), 2, "the gap after entry 3 splits the batches");
    assert_eq!((posted[0].first_entry, posted[0].count), (3, 1));
    assert_eq!(clear(&posted[0])[0], seal_entry(13));
    assert_eq!((posted[1].first_entry, posted[1].count), (5, 5));
    let entries = clear(&posted[1]);
    assert_eq!(entries[..4], [seal_entry(15), seal_entry(16), seal_entry(17), seal_entry(18)]);
    assert_eq!(dropped(&entries[4]), (3, 1));
    assert_eq!(entries[4].at, 18);
    assert!(entries[4].identity.is_none());
}

#[tokio::test]
async fn gaps_in_entry_numbers_add_up_to_the_dropped_counts() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, limits(4, 100));
    t.install(signer([]));
    for round in 0..5u64 {
        for i in 0..7 {
            let at = round * 100 + i;
            t.append(if i % 3 == 0 { seal_entry(at) } else { request_entry(at) });
        }
        // Every other round the control plane is down: the batch is retried with more drops.
        if round % 2 == 1 {
            sink.fail.store(1, Ordering::SeqCst);
        }
        let _ = t.flush().await;
    }
    t.shutdown().await.unwrap();

    let posted = sink.posted();
    let shipped: u64 = posted.iter().map(|b| u64::from(b.count)).sum();
    let numbers = posted.last().map(|b| b.first_entry + u64::from(b.count)).unwrap();
    let recorded: u64 = posted
        .iter()
        .flat_map(|b| clear(b).iter())
        .filter_map(|e| match e.event {
            TelemetryEvent::Dropped { requests, other } => Some(requests + other),
            _ => None,
        })
        .sum();
    assert_eq!(numbers - shipped, recorded);
    assert!(recorded > 0);
    assert_eq!(posted.iter().map(|b| b.sequence).collect::<Vec<_>>(), (0..posted.len() as u64).collect::<Vec<_>>());
    assert!(posted.last().unwrap().last);
}

#[tokio::test]
async fn a_dropped_dropped_entry_folds_into_the_next() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, limits(2, 1));
    t.install(signer([]));
    sink.fail.store(usize::MAX, Ordering::SeqCst);
    t.append(seal_entry(1)); // 0, in flight below and never accepted
    t.append(seal_entry(2)); // 1
    let _ = t.flush().await; // batch [0] pending; buffer [1]
    t.append(seal_entry(3)); // full: drops 1 → (0, 1); buffer [2]
    let _ = t.flush().await; // retries [0]; nothing new is cut
    assert_eq!(t.inner.lock().dropped, (0, 1));
    sink.fail.store(1, Ordering::SeqCst);
    let _ = t.flush().await; // [0] still failing; nothing new is cut
    sink.fail.store(0, Ordering::SeqCst);
    t.flush().await.unwrap(); // [0], then Dropped{0,1} is entry 3 appended after 2: [2], [3]
    let posted = sink.posted();
    assert_eq!(posted.iter().map(|b| (b.first_entry, b.count)).collect::<Vec<_>>(), [(0, 1), (2, 1), (3, 1)]);
    assert_eq!(dropped(&clear(&posted[2])[0]), (0, 1));

    // Now a Dropped entry itself is dropped: its counts move to the next one.
    let mut buffer = t.inner.lock();
    buffer.dropped = (0, 0);
    buffer.push(
        10,
        TelemetryEntry {
            at: 5,
            tenant: tenant(),
            identity: None,
            event: TelemetryEvent::Dropped { requests: 4, other: 2 },
        },
    );
    assert!(buffer.drop_one());
    assert_eq!(buffer.dropped, (4, 3));
}

#[tokio::test]
async fn a_failed_batch_is_posted_again_unchanged() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, LIMITS);
    t.install(signer([TelemetryReaderKey::generate(&mut rng()).public_key()]));
    t.append(seal_entry(1));
    sink.fail.store(1, Ordering::SeqCst);
    assert_eq!(t.flush().await.unwrap_err().code, ErrorCode::Unavailable);
    t.append(seal_entry(2));
    t.flush().await.unwrap();

    let attempts = sink.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0], attempts[1], "same signed bytes, sealed entries included");
    assert_eq!((attempts[2].body.sequence, attempts[2].body.first_entry), (1, 1));
}

#[tokio::test]
async fn appends_never_wait_for_the_control_plane() {
    let hold = Arc::new(tokio::sync::Semaphore::new(0));
    let sink = Arc::new(FakeSink { hold: Some(hold.clone()), ..Default::default() });
    let t = Arc::new(telemetry(&sink, limits(3, 100)));
    t.install(signer([]));
    t.append(seal_entry(1));
    let flushing = tokio::spawn({
        let t = t.clone();
        async move { t.flush().await }
    });
    while sink.attempts.lock().unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
    // The post hangs; appends go on, and the full buffer drops instead of waiting.
    let receipts: Vec<_> = (2..10).map(|at| t.append(request_entry(at)).entry).collect();
    assert_eq!(receipts, (1..9).collect::<Vec<_>>());
    let held = {
        let buffer = t.inner.lock();
        buffer.entries.len() + buffer.in_flight
    };
    assert_eq!(held, 3);
    hold.add_permits(1);
    flushing.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_marks_the_final_batch_last() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, limits(100, 2));
    t.install(signer([]));
    for at in 1..=3 {
        t.append(seal_entry(at));
    }
    t.shutdown().await.unwrap();
    let posted = sink.posted();
    assert_eq!(
        posted.iter().map(|b| (b.first_entry, b.count, b.last)).collect::<Vec<_>>(),
        [(0, 2, false), (2, 1, true)]
    );

    // Shut down with nothing left: an empty final batch after the last entry.
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, LIMITS);
    t.install(signer([]));
    t.append(seal_entry(7));
    t.flush().await.unwrap();
    t.shutdown().await.unwrap();
    let posted = sink.posted();
    let end = &posted[1];
    assert_eq!((end.sequence, end.first_entry, end.count, end.from, end.to, end.last), (1, 1, 0, 7, 7, true));
    assert!(clear(end).is_empty());
    // Nothing ships after the last batch.
    t.append(seal_entry(8));
    t.flush().await.unwrap();
    assert_eq!(sink.posted().len(), 2);
}

#[tokio::test]
async fn shutdown_before_start_fails() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, LIMITS);
    t.append(seal_entry(7));
    assert_eq!(t.shutdown().await.unwrap_err().code, ErrorCode::Unavailable);
    assert!(sink.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn entries_are_sealed_to_every_reader() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, LIMITS);
    let readers: Vec<TelemetryReaderKey> = (0..2).map(|_| TelemetryReaderKey::generate(&mut rng())).collect();
    let fake = signer(readers.iter().map(|r| r.public_key()));
    t.install(fake.clone());
    t.append(seal_entry(1));
    t.append(request_entry(2));
    t.flush().await.unwrap();

    let batch = &sink.posted()[0];
    let TelemetryEntries::Sealed { readers: keys, .. } = &batch.entries else {
        panic!("sealed entries expected");
    };
    assert_eq!(keys.len(), 2);
    for reader in &readers {
        assert_eq!(open_entries(reader, batch).unwrap(), [seal_entry(1), request_entry(2)]);
    }
    let stranger = TelemetryReaderKey::generate(&mut rng());
    assert!(open_entries(&stranger, batch).is_err());

    // Readers removed by a state reload: the next batch is in clear.
    *fake.readers.lock().unwrap() = BTreeSet::new();
    t.append(seal_entry(3));
    t.flush().await.unwrap();
    assert_eq!(clear(&sink.posted()[1]), [seal_entry(3)]);
}

#[tokio::test(start_paused = true)]
async fn the_flusher_ships_every_interval_and_early_when_a_batch_is_full() {
    let sink = Arc::new(FakeSink::default());
    let t = telemetry(&sink, limits(100, 3));
    t.begin(signer([]));
    t.append(seal_entry(1));
    tokio::time::sleep(Duration::from_secs(TELEMETRY_FLUSH_SECS - 1)).await;
    assert!(sink.posted().is_empty());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(sink.posted().len(), 1);

    // A full batch wakes the flusher at once.
    for at in 2..5 {
        t.append(seal_entry(at));
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(sink.posted().len(), 2);
    assert_eq!(sink.posted()[1].count, 3);

    // A failure backs off a full interval before the retry.
    sink.fail.store(1, Ordering::SeqCst);
    t.append(seal_entry(5));
    tokio::time::sleep(Duration::from_secs(TELEMETRY_FLUSH_SECS + 1)).await;
    assert_eq!(sink.attempts.lock().unwrap().len(), 3);
    tokio::time::sleep(Duration::from_secs(2 * TELEMETRY_FLUSH_SECS)).await;
    assert_eq!(sink.posted().len(), 3);
}

/// Records the bodies posted to `/v1/tenants/acme/telemetry` and answers `status`.
#[derive(Default)]
struct FakeControl {
    posted: Mutex<Vec<SignedTelemetryBatch>>,
    status: Mutex<Option<u16>>,
}

async fn post_telemetry(
    axum::extract::State(control): axum::extract::State<Arc<FakeControl>>,
    axum::Json(batch): axum::Json<SignedTelemetryBatch>,
) -> axum::http::StatusCode {
    control.posted.lock().unwrap().push(batch);
    let status = control.status.lock().unwrap().unwrap_or(204);
    axum::http::StatusCode::from_u16(status).unwrap()
}

#[tokio::test]
async fn batches_reach_the_control_plane_through_its_client() {
    let control = Arc::new(FakeControl::default());
    let router = axum::Router::new()
        .route("/v1/tenants/acme/telemetry", axum::routing::post(post_telemetry))
        .with_state(control.clone());
    let https = crate::api::tests::serve_tls(router).await;
    let url = url::Url::parse(&format!("https://{}/", crate::api::tests::HOST)).unwrap();
    let t = ControlTelemetry::new(Arc::new(ControlClient::new(url, Arc::new(https), None)), tenant());
    t.install(signer([]));

    t.append(seal_entry(100));
    // The control plane is down: the batch waits, appends do not.
    *control.status.lock().unwrap() = Some(503);
    assert_eq!(t.flush().await.unwrap_err().code, ErrorCode::Unavailable);
    assert_eq!(t.append(seal_entry(101)).entry, 1);
    *control.status.lock().unwrap() = None;
    t.flush().await.unwrap();
    t.shutdown().await.unwrap();

    let posted = control.posted.lock().unwrap().clone();
    assert_eq!(posted.len(), 4, "the failed post, its retry, the next batch and the final one");
    assert_eq!(posted[0], posted[1]);
    let summary: Vec<_> =
        posted[1..].iter().map(|b| (b.body.sequence, b.body.first_entry, b.body.count, b.body.last)).collect();
    assert_eq!(summary, [(0, 0, 1, false), (1, 1, 1, false), (2, 2, 0, true)]);
    for batch in &posted {
        assert_eq!((&batch.body.tenant, batch.body.stream), (&tenant(), t.stream()));
        let key = telemetry_key().public_key();
        seal_crypto::sign::verify(&key, TELEMETRY_BATCH_LABEL, &batch.body, &batch.signatures[0]).unwrap();
    }
}
