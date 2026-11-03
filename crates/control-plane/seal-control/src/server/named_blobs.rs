//! Named blobs in Postgres (`migrations/0002_named_secrets.sql`, the table renamed by
//! `0004_named_blobs.sql`), on control's pool. Each row is one version as served. The routes
//! check versions before `put`; this module only keeps the numbering, the per-tenant limit and
//! the versions kept.

use seal_proto::named::{NamedBlobVersion, MAX_NAMED_BLOBS, NAMED_BLOB_VERSIONS_KEPT};
use seal_proto::{BlobName, TenantId, TenantRootId, UnixTime};
use sqlx::postgres::PgPool;
use sqlx::Row;

use super::telemetry_db::Error;

/// Why a checked version was not stored.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The version is not the one after the newest stored.
    NotNext { next: u64 },
    /// The tenant already has `MAX_NAMED_BLOBS` names.
    TooMany,
    /// A deletion of a name that has none, or is deleted already.
    NothingToDelete,
}

pub struct NamedBlobs {
    pool: PgPool,
}

fn decode(body: &[u8]) -> Result<NamedBlobVersion, Error> {
    Ok(serde_json::from_slice(body)?)
}

impl NamedBlobs {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The newest version of `name`, a deletion included.
    pub async fn latest(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        name: &BlobName,
    ) -> Result<Option<NamedBlobVersion>, Error> {
        let row = sqlx::query(
            "select body from named_blobs where tenant = $1 and root_id = $2 and name = $3
               order by version desc limit 1",
        )
        .bind(tenant.as_str())
        .bind(root_id.to_string())
        .bind(name.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| decode(r.get("body"))).transpose()
    }

    /// The versions of `name` kept, newest first.
    pub async fn versions(
        &self,
        tenant: &TenantId,
        root_id: &TenantRootId,
        name: &BlobName,
    ) -> Result<Vec<NamedBlobVersion>, Error> {
        let rows = sqlx::query(
            "select body from named_blobs where tenant = $1 and root_id = $2 and name = $3
               order by version desc",
        )
        .bind(tenant.as_str())
        .bind(root_id.to_string())
        .bind(name.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| decode(r.get("body"))).collect()
    }

    /// The newest version of every name not deleted, by name.
    pub async fn list(&self, tenant: &TenantId, root_id: &TenantRootId) -> Result<Vec<NamedBlobVersion>, Error> {
        let rows = sqlx::query(
            "select body from (
               select distinct on (name) name, deleted, body from named_blobs
                where tenant = $1 and root_id = $2 order by name, version desc
             ) newest where not deleted order by name",
        )
        .bind(tenant.as_str())
        .bind(root_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| decode(r.get("body"))).collect()
    }

    /// Stores `version`, checked by the caller, if it is the name's next; then drops versions
    /// older than the `NAMED_BLOB_VERSIONS_KEPT` newest. Concurrent puts of one tenant are
    /// serialized, so the count and the numbering hold.
    pub async fn put(&self, version: &NamedBlobVersion, now: UnixTime) -> Result<Result<(), Refused>, Error> {
        let entry = &version.entry.body;
        let (tenant, root_id, name) = (entry.tenant.as_str(), entry.root_id.to_string(), entry.name.as_str());
        let mut tx = self.pool.begin().await?;
        sqlx::query("select pg_advisory_xact_lock(hashtext('named_blobs ' || $1))")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let newest: Option<(i64, bool)> = sqlx::query_as(
            "select version, deleted from named_blobs where tenant = $1 and root_id = $2 and name = $3
               order by version desc limit 1",
        )
        .bind(tenant)
        .bind(&root_id)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
        let next = newest.map_or(1, |(v, _)| v as u64 + 1);
        if entry.version != next {
            return Ok(Err(Refused::NotNext { next }));
        }
        let live = newest.is_some_and(|(_, deleted)| !deleted);
        if entry.blob.is_none() && !live {
            return Ok(Err(Refused::NothingToDelete));
        }
        if entry.blob.is_some() && !live {
            let (names,): (i64,) = sqlx::query_as(
                "select count(*) from (
                   select distinct on (name) deleted from named_blobs
                    where tenant = $1 and root_id = $2 order by name, version desc
                 ) newest where not deleted",
            )
            .bind(tenant)
            .bind(&root_id)
            .fetch_one(&mut *tx)
            .await?;
            if names as usize >= MAX_NAMED_BLOBS {
                return Ok(Err(Refused::TooMany));
            }
        }
        let body = serde_json::to_vec(version)?;
        sqlx::query(
            "insert into named_blobs (tenant, root_id, name, version, deleted, stored_at, body)
               values ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant)
        .bind(&root_id)
        .bind(name)
        .bind(entry.version as i64)
        .bind(entry.blob.is_none())
        .bind(now as i64)
        .bind(body)
        .execute(&mut *tx)
        .await?;
        sqlx::query("delete from named_blobs where tenant = $1 and root_id = $2 and name = $3 and version <= $4")
            .bind(tenant)
            .bind(&root_id)
            .bind(name)
            .bind(entry.version as i64 - NAMED_BLOB_VERSIONS_KEPT as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Ok(()))
    }
}
