//! File-backed storage. Every file is JSON, replaced atomically (written to a temporary file in
//! the same directory, synced, renamed over the old one, directory synced), so a crash leaves
//! either the old or the new document, never a torn one.
//!
//! ```text
//! <data_dir>/tenants/<tenant>/roots.json                  [LoggedRoot], versions 1..=N
//!                            /state.json                  SignedTenantState
//!                            /freshness.json              {log, tenant: [..]} for the state
//!                            /signals.json                [SignedSignal]
//!                            /session-ends.json           [SignedSessionEnd]
//!                            /service-key-certificates.json [SignedServiceKeyCertificate]
//!                            /wrap-keys.json              [SignedTenantWrapKey] (fetched, cached)
//!                            /anchors.json                [SignedTenantAnchor], the newest per guardian (fetched)
//!                            /states/<version>.json       LoggedState, every state stored with its proof
//!                            /proposals/<id>.json         Proposal (unsigned or partly signed)
//!                            /release-cosigns/<measurement>.json
//!                            /telemetry/<stream>-<sequence>.json
//! <data_dir>/releases/<platform>/<measurement>.json
//! <data_dir>/release-templates/<platform>/<measurement>.json
//! ```
//!
//! A tenant's small documents are loaded once and kept in memory (`TenantDocs`), behind one
//! async lock per tenant that serializes its writes. Release evidence, co-signatures, logged
//! states, proposals and telemetry are read from disk when asked for. Telemetry pages find their
//! batches through `TelemetryIndex`, each batch's stream, sequence, `to` and size, built from the
//! files on a tenant's first telemetry read and kept up to date by its writes.

use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::io::{self, Read as _, Write as _};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use seal_control::client::Proposal;

use seal_proto::integrity::SignedSignal;
use seal_proto::release::{ReleaseCosign, ReleaseEvidence, SignedServiceKeyCertificate, SignedTenantWrapKey};
use seal_proto::session::SignedSessionEnd;
use seal_proto::signed::Signed;
use seal_proto::state::{LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantAnchor, SignedTenantState};
use seal_proto::telemetry::SignedTelemetryBatch;
use seal_proto::{Measurement, PlatformId, TenantId, UnixTime};

/// The freshness statements kept for the latest state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Freshness {
    /// The log's newest statement for the latest state.
    pub log: Option<SignedStateFreshness>,
    /// Tenant-run statements for the latest state, newest last.
    pub tenant: Vec<SignedStateFreshness>,
}

/// One tenant's small documents, as stored.
#[derive(Clone, Debug, Default)]
pub struct TenantDocs {
    pub roots: Vec<LoggedRoot>,
    pub state: Option<SignedTenantState>,
    pub freshness: Freshness,
    pub signals: Vec<SignedSignal>,
    pub session_ends: Vec<SignedSessionEnd>,
    pub certificates: Vec<SignedServiceKeyCertificate>,
    pub wrap_keys: Vec<SignedTenantWrapKey>,
    pub anchors: Vec<SignedTenantAnchor>,
}

/// One tenant: its documents and where they live. Held through `Store::tenant`'s lock.
pub struct TenantEntry {
    dir: PathBuf,
    pub docs: TenantDocs,
    /// Built on the first telemetry read.
    telemetry: Option<TelemetryIndex>,
}

const ROOTS: &str = "roots.json";
const STATE: &str = "state.json";
const FRESHNESS: &str = "freshness.json";
const SIGNALS: &str = "signals.json";
const SESSION_ENDS: &str = "session-ends.json";
const CERTIFICATES: &str = "service-key-certificates.json";
const WRAP_KEYS: &str = "wrap-keys.json";
const ANCHORS: &str = "anchors.json";

impl TenantEntry {
    fn load(dir: PathBuf) -> io::Result<Self> {
        let docs = TenantDocs {
            roots: read_json(&dir.join(ROOTS))?.unwrap_or_default(),
            state: read_json(&dir.join(STATE))?,
            freshness: read_json(&dir.join(FRESHNESS))?.unwrap_or_default(),
            signals: read_json(&dir.join(SIGNALS))?.unwrap_or_default(),
            session_ends: read_json(&dir.join(SESSION_ENDS))?.unwrap_or_default(),
            certificates: read_json(&dir.join(CERTIFICATES))?.unwrap_or_default(),
            wrap_keys: read_json(&dir.join(WRAP_KEYS))?.unwrap_or_default(),
            anchors: read_json(&dir.join(ANCHORS))?.unwrap_or_default(),
        };
        Ok(Self { dir, docs, telemetry: None })
    }

    // Each setter writes its file first and updates memory only once the write succeeded.
    pub fn set_roots(&mut self, roots: Vec<LoggedRoot>) -> io::Result<()> {
        write_json(&self.dir.join(ROOTS), &roots)?;
        self.docs.roots = roots;
        Ok(())
    }
    pub fn set_state(&mut self, state: SignedTenantState) -> io::Result<()> {
        write_json(&self.dir.join(STATE), &state)?;
        self.docs.state = Some(state);
        Ok(())
    }
    pub fn set_freshness(&mut self, freshness: Freshness) -> io::Result<()> {
        write_json(&self.dir.join(FRESHNESS), &freshness)?;
        self.docs.freshness = freshness;
        Ok(())
    }
    pub fn set_signals(&mut self, signals: Vec<SignedSignal>) -> io::Result<()> {
        write_json(&self.dir.join(SIGNALS), &signals)?;
        self.docs.signals = signals;
        Ok(())
    }
    pub fn set_session_ends(&mut self, ends: Vec<SignedSessionEnd>) -> io::Result<()> {
        write_json(&self.dir.join(SESSION_ENDS), &ends)?;
        self.docs.session_ends = ends;
        Ok(())
    }
    pub fn set_certificates(&mut self, certificates: Vec<SignedServiceKeyCertificate>) -> io::Result<()> {
        write_json(&self.dir.join(CERTIFICATES), &certificates)?;
        self.docs.certificates = certificates;
        Ok(())
    }
    pub fn set_wrap_keys(&mut self, keys: Vec<SignedTenantWrapKey>) -> io::Result<()> {
        write_json(&self.dir.join(WRAP_KEYS), &keys)?;
        self.docs.wrap_keys = keys;
        Ok(())
    }
    pub fn set_anchors(&mut self, anchors: Vec<SignedTenantAnchor>) -> io::Result<()> {
        write_json(&self.dir.join(ANCHORS), &anchors)?;
        self.docs.anchors = anchors;
        Ok(())
    }

    fn cosign_path(&self, measurement: &Measurement) -> PathBuf {
        self.dir.join("release-cosigns").join(format!("{measurement}.json"))
    }
    pub fn release_cosign(&self, measurement: &Measurement) -> io::Result<Option<Signed<ReleaseCosign>>> {
        read_json(&self.cosign_path(measurement))
    }
    pub fn put_release_cosign(&self, measurement: &Measurement, cosign: &Signed<ReleaseCosign>) -> io::Result<()> {
        write_json(&self.cosign_path(measurement), cosign)
    }

    fn state_path(&self, version: u64) -> PathBuf {
        self.dir.join("states").join(format!("{version:020}.json"))
    }
    pub fn logged_state(&self, version: u64) -> io::Result<Option<LoggedState>> {
        read_json(&self.state_path(version))
    }
    pub fn put_logged_state(&self, state: &LoggedState) -> io::Result<()> {
        write_json(&self.state_path(state.state.body.version), state)
    }
    /// Logged states of a version above `after` (all without it), by version.
    pub fn logged_states(&self, after: Option<u64>) -> io::Result<Vec<LoggedState>> {
        let mut states: Vec<LoggedState> = read_all(&self.dir.join("states"))?
            .into_iter()
            .filter(|s: &LoggedState| after.is_none_or(|v| s.state.body.version > v))
            .collect();
        states.sort_by_key(|s| s.state.body.version);
        Ok(states)
    }

    /// `id` must be a proposal id (64 hex digits), which makes it a safe file name.
    fn proposal_path(&self, id: &str) -> PathBuf {
        debug_assert!(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()));
        self.dir.join("proposals").join(format!("{id}.json"))
    }
    pub fn proposal(&self, id: &str) -> io::Result<Option<Proposal>> {
        read_json(&self.proposal_path(id))
    }
    pub fn put_proposal(&self, proposal: &Proposal) -> io::Result<()> {
        write_json(&self.proposal_path(&proposal.id), proposal)
    }
    /// Whether there was one.
    pub fn delete_proposal(&self, id: &str) -> io::Result<bool> {
        match std::fs::remove_file(self.proposal_path(id)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// Every stored proposal, in no particular order.
    pub fn proposals(&self) -> io::Result<Vec<Proposal>> {
        read_all(&self.dir.join("proposals"))
    }

    fn telemetry_dir(&self) -> PathBuf {
        self.dir.join("telemetry")
    }
    fn telemetry_path(&self, stream: &[u8; 16], sequence: u64) -> PathBuf {
        self.telemetry_dir().join(format!("{}-{sequence:020}.json", hex(stream)))
    }
    pub fn telemetry_batch(&self, stream: &[u8; 16], sequence: u64) -> io::Result<Option<SignedTelemetryBatch>> {
        read_json(&self.telemetry_path(stream, sequence))
    }
    /// Writes the batch, then indexes it: both happen under the tenant's lock, so a reader sees
    /// a batch in the index only once its file is complete.
    pub fn put_telemetry_batch(&mut self, batch: &SignedTelemetryBatch) -> io::Result<()> {
        let bytes =
            serde_json::to_vec(batch).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        write_atomic(&self.telemetry_path(&batch.body.stream, batch.body.sequence), &bytes)?;
        if let Some(index) = &mut self.telemetry {
            let b = &batch.body;
            index.insert(b.stream, IndexedBatch { sequence: b.sequence, to: b.to, size: bytes.len() as u64 });
        }
        Ok(())
    }
    /// The files of one telemetry page, in order, and what matches the query in all.
    pub fn telemetry_page(
        &mut self,
        since: UnixTime,
        order: TelemetryOrder,
        limit: usize,
    ) -> io::Result<TelemetryPage> {
        if self.telemetry.is_none() {
            self.telemetry = Some(TelemetryIndex::build(&self.telemetry_dir())?);
        }
        let index = self.telemetry.as_ref().expect("built above");
        let (keys, remaining_batches, remaining_bytes) = index.page(since, order, limit);
        let files = keys.into_iter().map(|(stream, sequence)| self.telemetry_path(&stream, sequence)).collect();
        Ok(TelemetryPage { files, remaining_batches, remaining_bytes })
    }
    #[cfg(test)]
    pub fn telemetry_index(&self) -> Option<&TelemetryIndex> {
        self.telemetry.as_ref()
    }
}

/// A stored batch, read from a `TelemetryPage`'s file. Files are never replaced once written,
/// so reading them needs no lock.
pub fn read_telemetry_batch(path: &Path) -> io::Result<Option<SignedTelemetryBatch>> {
    read_json(path)
}

/// How a telemetry page is ordered, and the last batch of the previous page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelemetryOrder {
    /// By `(stream, sequence)`, after this one.
    Stream { after: Option<([u8; 16], u64)> },
    /// By `(to, stream, sequence)`, after this one.
    Time { after: Option<(UnixTime, [u8; 16], u64)> },
}

/// One page's batch files, and the batches (and their bytes as stored) the query matches after
/// the cursor, this page's included.
pub struct TelemetryPage {
    pub files: Vec<PathBuf>,
    pub remaining_batches: u64,
    pub remaining_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndexedBatch {
    sequence: u64,
    to: UnixTime,
    /// The file's length: the batch's JSON.
    size: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct IndexedStream {
    /// By sequence.
    batches: Vec<IndexedBatch>,
    min_to: UnixTime,
    max_to: UnixTime,
    bytes: u64,
}

/// A tenant's telemetry batches, by stream and then sequence, without their contents: about
/// 24 bytes a batch. Streams carry their earliest and latest `to` and their total size, so a
/// query skips or counts whole streams that lie entirely before or after `since`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TelemetryIndex {
    streams: BTreeMap<[u8; 16], IndexedStream>,
}

impl TelemetryIndex {
    /// Reads the head of each `<stream hex>-<sequence>.json` in `dir` for its `to`, on up to
    /// `BUILD_THREADS` threads.
    fn build(dir: &Path) -> io::Result<Self> {
        const BUILD_THREADS: usize = 8;
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e),
        };
        let mut files = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            if let Some(key) = name.to_str().and_then(parse_batch_name) {
                files.push(key);
            }
        }
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(BUILD_THREADS);
        let chunk = files.len().div_ceil(threads).max(1);
        let read = |keys: &[([u8; 16], u64)]| -> io::Result<Vec<([u8; 16], IndexedBatch)>> {
            let mut out = Vec::with_capacity(keys.len());
            for &(stream, sequence) in keys {
                let path = dir.join(format!("{}-{sequence:020}.json", hex(&stream)));
                if let Some((to, size)) = read_batch_head(&path)? {
                    out.push((stream, IndexedBatch { sequence, to, size }));
                }
            }
            Ok(out)
        };
        let parts: Vec<io::Result<Vec<_>>> = std::thread::scope(|scope| {
            let handles: Vec<_> = files.chunks(chunk).map(|keys| scope.spawn(move || read(keys))).collect();
            handles.into_iter().map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p))).collect()
        });
        let mut index = Self::default();
        for part in parts {
            for (stream, batch) in part? {
                index.insert(stream, batch);
            }
        }
        Ok(index)
    }

    fn insert(&mut self, stream: [u8; 16], batch: IndexedBatch) {
        let s = self
            .streams
            .entry(stream)
            .or_insert_with(|| IndexedStream { min_to: UnixTime::MAX, ..IndexedStream::default() });
        // Batches mostly arrive in order: the search ends at the back.
        let at = s.batches.partition_point(|b| b.sequence < batch.sequence);
        match s.batches.get_mut(at) {
            Some(b) if b.sequence == batch.sequence => {
                s.bytes = s.bytes - b.size + batch.size;
                *b = batch;
            }
            _ => {
                s.batches.insert(at, batch);
                s.bytes += batch.size;
            }
        }
        s.min_to = s.min_to.min(batch.to);
        s.max_to = s.max_to.max(batch.to);
    }

    /// The first `limit` batches with `to >= since` after the cursor, in order, and the count
    /// and size of every such batch.
    fn page(&self, since: UnixTime, order: TelemetryOrder, limit: usize) -> (Vec<([u8; 16], u64)>, u64, u64) {
        match order {
            TelemetryOrder::Stream { after } => self.stream_page(since, after, limit),
            TelemetryOrder::Time { after } => self.time_page(since, after, limit),
        }
    }

    fn stream_page(
        &self,
        since: UnixTime,
        after: Option<([u8; 16], u64)>,
        limit: usize,
    ) -> (Vec<([u8; 16], u64)>, u64, u64) {
        let (mut keys, mut count, mut bytes) = (Vec::new(), 0, 0);
        let start = after.map_or(Bound::Unbounded, |(stream, _)| Bound::Included(stream));
        for (stream, s) in self.streams.range((start, Bound::Unbounded)) {
            if s.max_to < since {
                continue;
            }
            let from = match after {
                Some((a, sequence)) if a == *stream => s.batches.partition_point(|b| b.sequence <= sequence),
                _ => 0,
            };
            if from == 0 && s.min_to >= since && keys.len() >= limit {
                count += s.batches.len() as u64;
                bytes += s.bytes;
                continue;
            }
            for b in s.batches[from..].iter().filter(|b| b.to >= since) {
                count += 1;
                bytes += b.size;
                if keys.len() < limit {
                    keys.push((*stream, b.sequence));
                }
            }
        }
        (keys, count, bytes)
    }

    fn time_page(
        &self,
        since: UnixTime,
        after: Option<(UnixTime, [u8; 16], u64)>,
        limit: usize,
    ) -> (Vec<([u8; 16], u64)>, u64, u64) {
        // The `limit` smallest keys so far, the largest on top.
        let mut page: BinaryHeap<(UnixTime, [u8; 16], u64)> = BinaryHeap::with_capacity(limit + 1);
        let (mut count, mut bytes) = (0, 0);
        let floor = after.map_or(since, |(to, _, _)| to.max(since));
        for (stream, s) in &self.streams {
            if s.max_to < floor {
                continue;
            }
            // Every batch matches and none can enter a full page: count the stream whole.
            let all_after = s.min_to >= since && after.is_none_or(|(to, _, _)| s.min_to > to);
            if all_after && page.len() >= limit && page.peek().is_some_and(|top| top.0 < s.min_to) {
                count += s.batches.len() as u64;
                bytes += s.bytes;
                continue;
            }
            for b in &s.batches {
                let key = (b.to, *stream, b.sequence);
                if b.to < since || after.is_some_and(|a| key <= a) {
                    continue;
                }
                count += 1;
                bytes += b.size;
                if page.len() < limit {
                    page.push(key);
                } else if page.peek().is_some_and(|top| key < *top) {
                    page.pop();
                    page.push(key);
                }
            }
        }
        let keys = page.into_sorted_vec().into_iter().map(|(_, stream, sequence)| (stream, sequence)).collect();
        (keys, count, bytes)
    }
}

/// `<32 hex digits>-<20 digits>.json`, as `telemetry_path` names files.
fn parse_batch_name(name: &str) -> Option<([u8; 16], u64)> {
    let (stem, ext) = name.split_once('.')?;
    let (stream, sequence) = stem.split_once('-')?;
    if ext != "json" || stream.len() != 32 || sequence.len() != 20 || !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(stream.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some((bytes, sequence.parse().ok()?))
}

/// Of a stored batch, only what the index needs.
#[derive(Deserialize)]
struct BatchHead {
    body: BatchHeadBody,
}
#[derive(Deserialize)]
struct BatchHeadBody {
    to: UnixTime,
}

/// A stored batch's `to` and file size (none when the file is gone). A batch's JSON names
/// `to` before its entries, so the first bytes usually do: up to `,"entries":`, closed, they
/// parse alone. Otherwise the whole file is parsed.
fn read_batch_head(path: &Path) -> io::Result<Option<(UnixTime, u64)>> {
    const HEAD: usize = 512;
    const ENTRIES: &[u8] = b",\"entries\":";
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let size = file.metadata()?.len();
    let mut bytes = Vec::with_capacity(HEAD);
    (&mut file).take(HEAD as u64).read_to_end(&mut bytes)?;
    if let Some(at) = bytes.windows(ENTRIES.len()).position(|w| w == ENTRIES) {
        let head = [&bytes[..at], b"}}"].concat();
        if let Ok(head) = serde_json::from_slice::<BatchHead>(&head) {
            return Ok(Some((head.body.to, size)));
        }
    }
    file.read_to_end(&mut bytes)?;
    let head: BatchHead = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?;
    Ok(Some((head.body.to, size)))
}

/// Every `*.json` document in `dir` (none when it does not exist), in no particular order.
fn read_all<T: DeserializeOwned>(dir: &Path) -> io::Result<Vec<T>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            if let Some(doc) = read_json(&path)? {
                out.push(doc);
            }
        }
    }
    Ok(out)
}

pub struct Store {
    dir: PathBuf,
    tenants: Mutex<HashMap<TenantId, Arc<tokio::sync::Mutex<TenantEntry>>>>,
}

impl Store {
    /// Creates `dir` if needed.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir.join("tenants"))?;
        std::fs::create_dir_all(dir.join("releases"))?;
        Ok(Self { dir: dir.to_path_buf(), tenants: Mutex::new(HashMap::new()) })
    }

    /// The tenant's entry, loaded from disk on first use. Lock it to read or write; writers
    /// hold the lock until their files are written. A tenant with nothing stored gets an empty
    /// entry that is not kept, so requests naming made-up tenants hold no memory; only
    /// `create_tenant` writes to one.
    pub fn tenant(&self, tenant: &TenantId) -> io::Result<Arc<tokio::sync::Mutex<TenantEntry>>> {
        self.entry(tenant, false)
    }

    /// The tenant's entry, kept from now on even while nothing is stored: for writing its
    /// first document, serialized with any other writer.
    pub fn create_tenant(&self, tenant: &TenantId) -> io::Result<Arc<tokio::sync::Mutex<TenantEntry>>> {
        self.entry(tenant, true)
    }

    fn entry(&self, tenant: &TenantId, create: bool) -> io::Result<Arc<tokio::sync::Mutex<TenantEntry>>> {
        let mut tenants = self.tenants.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = tenants.get(tenant) {
            return Ok(entry.clone());
        }
        // Tenant names are `[a-z0-9-]`, so they are safe directory names.
        let dir = self.dir.join("tenants").join(tenant.as_str());
        let keep = create || dir.try_exists()?;
        let entry = Arc::new(tokio::sync::Mutex::new(TenantEntry::load(dir)?));
        if keep {
            tenants.insert(tenant.clone(), entry.clone());
        }
        Ok(entry)
    }

    fn platform_dir(&self, kind: &str, platform: PlatformId) -> PathBuf {
        let platform = match serde_json::to_value(platform) {
            Ok(serde_json::Value::String(name)) => name,
            _ => unreachable!("a PlatformId serializes as a string"),
        };
        self.dir.join(kind).join(platform)
    }
    fn release_path(&self, platform: PlatformId, measurement: &Measurement) -> PathBuf {
        self.platform_dir("releases", platform).join(format!("{measurement}.json"))
    }
    pub fn release(&self, platform: PlatformId, measurement: &Measurement) -> io::Result<Option<ReleaseEvidence>> {
        read_json(&self.release_path(platform, measurement))
    }
    pub fn put_release(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
        evidence: &ReleaseEvidence,
    ) -> io::Result<()> {
        write_json(&self.release_path(platform, measurement), evidence)
    }
    /// Every release evidence stored for `platform`.
    pub fn releases(&self, platform: PlatformId) -> io::Result<Vec<ReleaseEvidence>> {
        let dir = self.platform_dir("releases", platform);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for entry in entries {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            out.extend(read_json(&path)?);
        }
        Ok(out)
    }
    fn release_template_path(&self, platform: PlatformId, measurement: &Measurement) -> PathBuf {
        self.platform_dir("release-templates", platform).join(format!("{measurement}.json"))
    }
    pub fn release_template(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
    ) -> io::Result<Option<serde_json::Value>> {
        read_json(&self.release_template_path(platform, measurement))
    }
    pub fn put_release_template(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
        template: &serde_json::Value,
    ) -> io::Result<()> {
        write_json(&self.release_template_path(platform, measurement), template)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Distinguishes temporary files of concurrent writers.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.{}.{}.tmp", std::process::id(), TMP_COUNTER.fetch_add(1, Ordering::Relaxed)));
    let result = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_replace_whole_files_and_leave_no_temporaries() {
        let dir = std::env::temp_dir().join(format!("seal-control-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("a").join("doc.json");
        write_json(&path, &vec![1, 2, 3]).unwrap();
        write_json(&path, &vec![4]).unwrap();
        assert_eq!(read_json::<Vec<u8>>(&path).unwrap(), Some(vec![4]));
        let names: Vec<_> = std::fs::read_dir(dir.join("a")).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("doc.json")]);
        assert_eq!(read_json::<Vec<u8>>(&dir.join("missing.json")).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_telemetry_index_rebuilt_from_disk_equals_the_live_one() {
        use seal_proto::telemetry::{TelemetryBatch, TelemetryEntries};
        let dir = std::env::temp_dir().join(format!("seal-control-store-telemetry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let acme = TenantId::new("acme").unwrap();
        let batch = |stream: u8, sequence: u64, to: UnixTime| Signed {
            body: TelemetryBatch {
                tenant: acme.clone(),
                stream: [stream; 16],
                sequence,
                first_entry: sequence,
                count: 0,
                from: to.saturating_sub(stream.into()),
                to,
                entries: TelemetryEntries::Sealed { readers: Vec::new(), nonce: [0; 12], ciphertext: vec![stream; 40] },
                last: sequence == 4,
            },
            signatures: Vec::new(),
        };
        let store = Store::open(&dir).unwrap();
        let entry = store.create_tenant(&acme).unwrap();
        let mut e = entry.lock().await;
        e.put_telemetry_batch(&batch(1, 0, 10)).unwrap();
        e.put_telemetry_batch(&batch(2, 3, 5)).unwrap();
        assert!(e.telemetry_index().is_none(), "built on the first read");
        let page = e.telemetry_page(0, TelemetryOrder::Stream { after: None }, 10).unwrap();
        assert_eq!((page.files.len(), page.remaining_batches), (2, 2));
        // Written after the build, out of order, and one stream going back in time.
        for (stream, sequence, to) in [(2, 1, 7), (3, 4, 30), (2, 0, 9), (1, 2, 8), (1, 1, 20), (3, 0, 1)] {
            e.put_telemetry_batch(&batch(stream, sequence, to)).unwrap();
        }
        // A file not named like a batch, and a writer's leftover temporary, are not batches.
        std::fs::write(e.telemetry_dir().join("notes.json"), b"{}").unwrap();
        std::fs::write(e.telemetry_dir().join(".x.json.1.2.tmp"), b"{").unwrap();
        let reopened = Store::open(&dir).unwrap();
        let fresh = reopened.tenant(&acme).unwrap();
        let mut f = fresh.lock().await;
        f.telemetry_page(0, TelemetryOrder::Stream { after: None }, 1).unwrap();
        assert_eq!(f.telemetry_index(), e.telemetry_index());
        let by_time = f.telemetry_page(6, TelemetryOrder::Time { after: Some((8, [1; 16], 2)) }, 3).unwrap();
        let names: Vec<_> =
            by_time.files.iter().map(|p| p.file_name().unwrap().to_str().unwrap()[30..].to_string()).collect();
        let expected = ["02-00000000000000000000.json", "01-00000000000000000000.json", "01-00000000000000000001.json"];
        assert_eq!(names, expected[..3], "(9, 2, 0), (10, 1, 0), (20, 1, 1); (30, 3, 4) is past the limit");
        assert_eq!(by_time.remaining_batches, 4);
        drop((e, f));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_stored_or_created_tenants_are_kept_in_memory() {
        let dir = std::env::temp_dir().join(format!("seal-control-store-tenants-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let cached = || store.tenants.lock().unwrap().len();
        for n in 0..100 {
            store.tenant(&TenantId::new(format!("ghost-{n}")).unwrap()).unwrap();
        }
        assert_eq!(cached(), 0, "made-up tenants hold no memory");
        assert!(!dir.join("tenants").join("ghost-0").exists(), "nor disk");

        let acme = TenantId::new("acme").unwrap();
        let created = store.create_tenant(&acme).unwrap();
        assert!(Arc::ptr_eq(&created, &store.tenant(&acme).unwrap()), "one lock for its writers");
        assert_eq!(cached(), 1);

        let stored = TenantId::new("stored").unwrap();
        store.tenant(&stored).unwrap().try_lock().unwrap().set_roots(Vec::new()).unwrap();
        let reopened = Store::open(&dir).unwrap();
        reopened.tenant(&stored).unwrap();
        assert_eq!(reopened.tenants.lock().unwrap().len(), 1, "a tenant on disk is kept once loaded");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
