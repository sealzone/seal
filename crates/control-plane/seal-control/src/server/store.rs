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
//! states, proposals and telemetry are read from disk when asked for.

use std::collections::HashMap;
use std::io::{self, Write as _};
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
use seal_proto::{Measurement, PlatformId, TenantId};

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
        Ok(Self { dir, docs })
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
    pub fn put_telemetry_batch(&self, batch: &SignedTelemetryBatch) -> io::Result<()> {
        write_json(&self.telemetry_path(&batch.body.stream, batch.body.sequence), batch)
    }
    /// Every stored batch, in no particular order.
    pub fn telemetry(&self) -> io::Result<Vec<SignedTelemetryBatch>> {
        read_all(&self.telemetry_dir())
    }
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
