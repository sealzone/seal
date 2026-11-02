//! Control's documents in Postgres (`migrations/0003_documents.sql`), on the one pool control
//! keeps (`telemetry_db`). Every document is stored as the JSON it is served as, and each write
//! is one statement, so a crash leaves either the old or the new document, never a torn one.
//!
//! ```text
//! tenant_documents       (tenant, kind)        roots, state, freshness, signals, session-ends,
//!                                              service-key-certificates, wrap-keys, anchors
//! tenant_states          (tenant, version)     LoggedState, every state stored with its proof
//! tenant_proposals       (tenant, id)          Proposal (unsigned or partly signed)
//! tenant_release_cosigns (tenant, measurement) Signed<ReleaseCosign>
//! releases               (platform, measurement) ReleaseEvidence
//! release_templates      (platform, measurement) the console's release template
//! ```
//!
//! A tenant's small documents are loaded once and kept in memory (`TenantDocs`), behind one
//! async lock per tenant that serializes its writes, so one control process serves a database
//! (another would not see this one's writes until it restarts). Logged states, proposals,
//! co-signatures and releases are read from the database when asked for.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use sqlx::Row;

use seal_control::client::Proposal;

use seal_proto::integrity::SignedSignal;
use seal_proto::release::{ReleaseCosign, ReleaseEvidence, SignedServiceKeyCertificate, SignedTenantWrapKey};
use seal_proto::session::SignedSessionEnd;
use seal_proto::signed::Signed;
use seal_proto::state::{LoggedRoot, LoggedState, SignedStateFreshness, SignedTenantAnchor, SignedTenantState};
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
    pool: PgPool,
    tenant: TenantId,
    pub docs: TenantDocs,
}

const ROOTS: &str = "roots";
const STATE: &str = "state";
const FRESHNESS: &str = "freshness";
const SIGNALS: &str = "signals";
const SESSION_ENDS: &str = "session-ends";
const CERTIFICATES: &str = "service-key-certificates";
const WRAP_KEYS: &str = "wrap-keys";
const ANCHORS: &str = "anchors";

fn db(e: sqlx::Error) -> io::Error {
    io::Error::other(format!("database: {e}"))
}

fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

fn decode<T: DeserializeOwned>(what: &str, body: &[u8]) -> io::Result<T> {
    serde_json::from_slice(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {e}")))
}

/// Decodes the `body` column of every row.
fn decode_all<T: DeserializeOwned>(what: &str, rows: &[sqlx::postgres::PgRow]) -> io::Result<Vec<T>> {
    rows.iter().map(|r| decode(what, r.get("body"))).collect()
}

impl TenantEntry {
    /// The tenant's documents, and whether anything at all is stored for it.
    async fn load(pool: PgPool, tenant: &TenantId) -> io::Result<(Self, bool)> {
        let rows = sqlx::query("select kind, body from tenant_documents where tenant = $1")
            .bind(tenant.as_str())
            .fetch_all(&pool)
            .await
            .map_err(db)?;
        let mut docs = TenantDocs::default();
        for row in &rows {
            let kind: &str = row.get("kind");
            let body: &[u8] = row.get("body");
            let what = format!("{tenant} {kind}");
            match kind {
                ROOTS => docs.roots = decode(&what, body)?,
                STATE => docs.state = Some(decode(&what, body)?),
                FRESHNESS => docs.freshness = decode(&what, body)?,
                SIGNALS => docs.signals = decode(&what, body)?,
                SESSION_ENDS => docs.session_ends = decode(&what, body)?,
                CERTIFICATES => docs.certificates = decode(&what, body)?,
                WRAP_KEYS => docs.wrap_keys = decode(&what, body)?,
                ANCHORS => docs.anchors = decode(&what, body)?,
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{what}: unknown document"))),
            }
        }
        let stored = !rows.is_empty() || {
            let (any,): (bool,) = sqlx::query_as(
                "select exists (select 1 from tenant_states where tenant = $1)
                     or exists (select 1 from tenant_proposals where tenant = $1)
                     or exists (select 1 from tenant_release_cosigns where tenant = $1)",
            )
            .bind(tenant.as_str())
            .fetch_one(&pool)
            .await
            .map_err(db)?;
            any
        };
        Ok((Self { pool, tenant: tenant.clone(), docs }, stored))
    }

    async fn put_doc<T: Serialize>(&self, kind: &str, value: &T) -> io::Result<()> {
        sqlx::query(
            "insert into tenant_documents (tenant, kind, body) values ($1, $2, $3)
               on conflict (tenant, kind) do update set body = excluded.body",
        )
        .bind(self.tenant.as_str())
        .bind(kind)
        .bind(encode(value)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    // Each setter stores its document first and updates memory only once the write succeeded.
    pub async fn set_roots(&mut self, roots: Vec<LoggedRoot>) -> io::Result<()> {
        self.put_doc(ROOTS, &roots).await?;
        self.docs.roots = roots;
        Ok(())
    }
    pub async fn set_state(&mut self, state: SignedTenantState) -> io::Result<()> {
        self.put_doc(STATE, &state).await?;
        self.docs.state = Some(state);
        Ok(())
    }
    pub async fn set_freshness(&mut self, freshness: Freshness) -> io::Result<()> {
        self.put_doc(FRESHNESS, &freshness).await?;
        self.docs.freshness = freshness;
        Ok(())
    }
    pub async fn set_signals(&mut self, signals: Vec<SignedSignal>) -> io::Result<()> {
        self.put_doc(SIGNALS, &signals).await?;
        self.docs.signals = signals;
        Ok(())
    }
    pub async fn set_session_ends(&mut self, ends: Vec<SignedSessionEnd>) -> io::Result<()> {
        self.put_doc(SESSION_ENDS, &ends).await?;
        self.docs.session_ends = ends;
        Ok(())
    }
    pub async fn set_certificates(&mut self, certificates: Vec<SignedServiceKeyCertificate>) -> io::Result<()> {
        self.put_doc(CERTIFICATES, &certificates).await?;
        self.docs.certificates = certificates;
        Ok(())
    }
    pub async fn set_wrap_keys(&mut self, keys: Vec<SignedTenantWrapKey>) -> io::Result<()> {
        self.put_doc(WRAP_KEYS, &keys).await?;
        self.docs.wrap_keys = keys;
        Ok(())
    }
    pub async fn set_anchors(&mut self, anchors: Vec<SignedTenantAnchor>) -> io::Result<()> {
        self.put_doc(ANCHORS, &anchors).await?;
        self.docs.anchors = anchors;
        Ok(())
    }

    pub async fn release_cosign(&self, measurement: &Measurement) -> io::Result<Option<Signed<ReleaseCosign>>> {
        let row = sqlx::query("select body from tenant_release_cosigns where tenant = $1 and measurement = $2")
            .bind(self.tenant.as_str())
            .bind(measurement.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| decode("release co-signature", r.get("body"))).transpose()
    }
    pub async fn put_release_cosign(
        &self,
        measurement: &Measurement,
        cosign: &Signed<ReleaseCosign>,
    ) -> io::Result<()> {
        sqlx::query(
            "insert into tenant_release_cosigns (tenant, measurement, body) values ($1, $2, $3)
               on conflict (tenant, measurement) do update set body = excluded.body",
        )
        .bind(self.tenant.as_str())
        .bind(measurement.to_string())
        .bind(encode(cosign)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    pub async fn logged_state(&self, version: u64) -> io::Result<Option<LoggedState>> {
        let row = sqlx::query("select body from tenant_states where tenant = $1 and version = $2")
            .bind(self.tenant.as_str())
            .bind(version as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| decode("logged state", r.get("body"))).transpose()
    }
    pub async fn put_logged_state(&self, state: &LoggedState) -> io::Result<()> {
        sqlx::query(
            "insert into tenant_states (tenant, version, body) values ($1, $2, $3)
               on conflict (tenant, version) do update set body = excluded.body",
        )
        .bind(self.tenant.as_str())
        .bind(state.state.body.version as i64)
        .bind(encode(state)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }
    /// Logged states of a version above `after` (all without it), by version.
    pub async fn logged_states(&self, after: Option<u64>) -> io::Result<Vec<LoggedState>> {
        // Versions are below 2^63 (`put_logged_state` stores them as bigint), so -1 is "none".
        let after = after.map_or(-1, |v| i64::try_from(v).unwrap_or(i64::MAX));
        let rows = sqlx::query("select body from tenant_states where tenant = $1 and version > $2 order by version")
            .bind(self.tenant.as_str())
            .bind(after)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        decode_all("logged state", &rows)
    }

    pub async fn proposal(&self, id: &str) -> io::Result<Option<Proposal>> {
        let row = sqlx::query("select body from tenant_proposals where tenant = $1 and id = $2")
            .bind(self.tenant.as_str())
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| decode("proposal", r.get("body"))).transpose()
    }
    pub async fn put_proposal(&self, proposal: &Proposal) -> io::Result<()> {
        sqlx::query(
            "insert into tenant_proposals (tenant, id, body) values ($1, $2, $3)
               on conflict (tenant, id) do update set body = excluded.body",
        )
        .bind(self.tenant.as_str())
        .bind(&proposal.id)
        .bind(encode(proposal)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }
    /// Whether there was one.
    pub async fn delete_proposal(&self, id: &str) -> io::Result<bool> {
        let done = sqlx::query("delete from tenant_proposals where tenant = $1 and id = $2")
            .bind(self.tenant.as_str())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(done.rows_affected() > 0)
    }
    /// Every stored proposal, in no particular order.
    pub async fn proposals(&self) -> io::Result<Vec<Proposal>> {
        let rows = sqlx::query("select body from tenant_proposals where tenant = $1")
            .bind(self.tenant.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        decode_all("proposal", &rows)
    }
}

pub struct Store {
    pool: PgPool,
    tenants: Mutex<HashMap<TenantId, Arc<tokio::sync::Mutex<TenantEntry>>>>,
}

/// A platform as stored: its serde name.
fn platform_name(platform: PlatformId) -> String {
    match serde_json::to_value(platform) {
        Ok(serde_json::Value::String(name)) => name,
        _ => unreachable!("a PlatformId serializes as a string"),
    }
}

impl Store {
    /// On the pool whose migrations have run (`TelemetryDb::connect`).
    pub fn new(pool: PgPool) -> Self {
        Self { pool, tenants: Mutex::new(HashMap::new()) }
    }

    /// The tenant's entry, loaded on first use. Lock it to read or write; writers hold the lock
    /// until their documents are written. A tenant with nothing stored gets an empty entry that
    /// is not kept, so requests naming made-up tenants hold no memory; only `create_tenant`
    /// writes to one.
    pub async fn tenant(&self, tenant: &TenantId) -> io::Result<Arc<tokio::sync::Mutex<TenantEntry>>> {
        self.entry(tenant, false).await
    }

    /// The tenant's entry, kept from now on even while nothing is stored: for writing its
    /// first document, serialized with any other writer.
    pub async fn create_tenant(&self, tenant: &TenantId) -> io::Result<Arc<tokio::sync::Mutex<TenantEntry>>> {
        self.entry(tenant, true).await
    }

    fn cached(&self, tenant: &TenantId) -> Option<Arc<tokio::sync::Mutex<TenantEntry>>> {
        self.tenants.lock().unwrap_or_else(|p| p.into_inner()).get(tenant).cloned()
    }

    async fn entry(&self, tenant: &TenantId, create: bool) -> io::Result<Arc<tokio::sync::Mutex<TenantEntry>>> {
        if let Some(entry) = self.cached(tenant) {
            return Ok(entry);
        }
        let (loaded, stored) = TenantEntry::load(self.pool.clone(), tenant).await?;
        let entry = Arc::new(tokio::sync::Mutex::new(loaded));
        if !(create || stored) {
            return Ok(entry);
        }
        // Another request may have loaded it meanwhile: the first one kept is the only one
        // written through, so later loads give way to it.
        let mut tenants = self.tenants.lock().unwrap_or_else(|p| p.into_inner());
        Ok(tenants.entry(tenant.clone()).or_insert(entry).clone())
    }

    pub async fn release(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
    ) -> io::Result<Option<ReleaseEvidence>> {
        let row = sqlx::query("select body from releases where platform = $1 and measurement = $2")
            .bind(platform_name(platform))
            .bind(measurement.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| decode("release evidence", r.get("body"))).transpose()
    }
    pub async fn put_release(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
        evidence: &ReleaseEvidence,
    ) -> io::Result<()> {
        sqlx::query(
            "insert into releases (platform, measurement, body) values ($1, $2, $3)
               on conflict (platform, measurement) do update set body = excluded.body",
        )
        .bind(platform_name(platform))
        .bind(measurement.to_string())
        .bind(encode(evidence)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }
    /// Every release evidence stored for `platform`.
    pub async fn releases(&self, platform: PlatformId) -> io::Result<Vec<ReleaseEvidence>> {
        let rows = sqlx::query("select body from releases where platform = $1")
            .bind(platform_name(platform))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        decode_all("release evidence", &rows)
    }
    pub async fn release_template(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
    ) -> io::Result<Option<serde_json::Value>> {
        let row = sqlx::query("select body from release_templates where platform = $1 and measurement = $2")
            .bind(platform_name(platform))
            .bind(measurement.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| decode("release template", r.get("body"))).transpose()
    }
    pub async fn put_release_template(
        &self,
        platform: PlatformId,
        measurement: &Measurement,
        template: &serde_json::Value,
    ) -> io::Result<()> {
        sqlx::query(
            "insert into release_templates (platform, measurement, body) values ($1, $2, $3)
               on conflict (platform, measurement) do update set body = excluded.body",
        )
        .bind(platform_name(platform))
        .bind(measurement.to_string())
        .bind(encode(template)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::telemetry_db::test_support;
    use super::*;

    #[tokio::test]
    async fn only_stored_or_created_tenants_are_kept_in_memory() {
        let pool = test_support::db(None).await.pool();
        let store = Store::new(pool.clone());
        let cached = || store.tenants.lock().unwrap().len();
        for n in 0..100 {
            store.tenant(&TenantId::new(format!("ghost-{n}")).unwrap()).await.unwrap();
        }
        assert_eq!(cached(), 0, "made-up tenants hold no memory");
        let (rows,): (i64,) = sqlx::query_as("select count(*) from tenant_documents").fetch_one(&pool).await.unwrap();
        assert_eq!(rows, 0, "nor rows");

        let acme = TenantId::new("acme").unwrap();
        let created = store.create_tenant(&acme).await.unwrap();
        assert!(Arc::ptr_eq(&created, &store.tenant(&acme).await.unwrap()), "one lock for its writers");
        assert_eq!(cached(), 1);

        let stored = TenantId::new("stored").unwrap();
        store.tenant(&stored).await.unwrap().try_lock().unwrap().set_roots(Vec::new()).await.unwrap();
        let reopened = Store::new(pool.clone());
        reopened.tenant(&stored).await.unwrap();
        assert_eq!(reopened.tenants.lock().unwrap().len(), 1, "a stored tenant is kept once loaded");

        // A tenant whose only document is a proposal is stored too.
        let proposing = TenantId::new("proposing").unwrap();
        sqlx::query("insert into tenant_proposals (tenant, id, body) values ($1, 'x', '{}')")
            .bind(proposing.as_str())
            .execute(&pool)
            .await
            .unwrap();
        reopened.tenant(&proposing).await.unwrap();
        assert_eq!(reopened.tenants.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn documents_round_trip_and_replace() {
        let pool = test_support::db(None).await.pool();
        let store = Store::new(pool.clone());
        let acme = TenantId::new("acme").unwrap();
        let entry = store.create_tenant(&acme).await.unwrap();
        let mut e = entry.lock().await;
        e.set_freshness(Freshness::default()).await.unwrap();
        e.set_signals(Vec::new()).await.unwrap();
        e.set_signals(Vec::new()).await.unwrap();
        assert!(e.logged_states(None).await.unwrap().is_empty());
        assert_eq!(e.proposal(&"0".repeat(64)).await.unwrap().map(|p| p.id), None);
        assert!(!e.delete_proposal(&"0".repeat(64)).await.unwrap());
        drop(e);
        let (kinds,): (i64,) = sqlx::query_as("select count(*) from tenant_documents where tenant = 'acme'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(kinds, 2, "one row per document, replaced in place");

        let template = serde_json::json!({ "a": [1, 2, 3] });
        let m: Measurement = "00".repeat(48).parse().unwrap();
        store.put_release_template(PlatformId::Sim, &m, &template).await.unwrap();
        assert_eq!(store.release_template(PlatformId::Sim, &m).await.unwrap(), Some(template));
        assert!(store.releases(PlatformId::Sim).await.unwrap().is_empty());
    }
}
