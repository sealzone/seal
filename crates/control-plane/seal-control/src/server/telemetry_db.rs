//! Telemetry in Postgres, when `SEAL_CONTROL_DATABASE_URL` is set: batches in a table partitioned
//! by arrival week, and the counts the console shows, added in the transaction that stores each
//! batch. Without a database, telemetry stays in files (`store`), for local runs, and the count
//! routes answer 404.
//!
//! Counts come from batches the server checked were signed by a certified telemetry key, but
//! readers are told they are unverified: only the batches themselves can be verified.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::PgConnection;

use seal_proto::telemetry::{Outcome, SignedTelemetryBatch, TelemetryEntries, TelemetryEntry, TelemetryEvent};
use seal_proto::UnixTime;

use super::store::TelemetryOrder;

const WEEK: i64 = 7 * 86_400;
const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
/// A skipped sequence is reported this long after the batch beyond it arrived: batches can
/// arrive out of order.
const HOLE_GRACE_SECS: i64 = 300;
/// How long a stream without its `last` batch is silent, with a newer stream after it, before
/// it counts as stopped.
const STOP_AFTER_SECS: i64 = 900;
/// Gaps are reported for this long, so a reader's first look at an old tenant finds few.
const GAPS_WITHIN_SECS: i64 = DAY;
/// How long a stream's row outlives its last batch, and a day's active blobs the day.
const STREAM_SECS: i64 = 7 * DAY;
const ACTIVE_BLOB_SECS: i64 = 62 * DAY;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("a value is out of range: {0}")]
    Range(&'static str),
    #[error("database token: {0}")]
    Token(String),
    #[error("a stored batch does not parse: {0}")]
    Stored(#[from] serde_json::Error),
}

/// What became of a posted batch.
#[derive(Debug, PartialEq, Eq)]
pub enum Put {
    Stored,
    /// The same batch was already stored.
    Same,
    /// Another batch has this stream and sequence.
    Conflict,
}

/// One page's batches as stored, in order, and what the query matches after the cursor, this
/// page's included.
pub struct Page {
    pub bodies: Vec<Vec<u8>>,
    pub remaining_batches: u64,
    pub remaining_bytes: u64,
}

#[derive(Debug, Serialize, sqlx::FromRow, PartialEq, Eq)]
pub struct UsageDay {
    pub day: String,
    pub requests: i64,
    pub sessions: i64,
    pub entries: i64,
    pub sealed_entries: i64,
    pub active_secrets: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow, PartialEq, Eq)]
pub struct MetricPoint {
    pub hour: String,
    pub key: String,
    pub count: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    Event,
    App,
    /// What requests carried each way and how many failed, as keys `up`, `down` and `failed`.
    Requests,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "gap", rename_all = "snake_case")]
pub enum Gap {
    /// Batches `from..=to` of the stream never arrived.
    Missing { stream: String, from: i64, to: i64, count: i64 },
    /// The stream stopped without its `last` batch: its replica did not shut down, and its
    /// unsent entries are lost. `seen` is the end of its newest batch.
    Stopped { stream: String, sequence: i64, seen: i64 },
}

pub struct TelemetryDb {
    pool: PgPool,
    retention_secs: Option<i64>,
    /// Weekly partitions known to exist.
    partitions: Mutex<BTreeSet<i64>>,
}

fn int(value: u64, what: &'static str) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::Range(what))
}

/// An Entra token for Azure Database for PostgreSQL, from the instance metadata service.
async fn entra_token() -> Result<String, String> {
    const URL: &str = "http://169.254.169.254/metadata/identity/oauth2/token\
                       ?api-version=2018-02-01&resource=https%3A%2F%2Fossrdbms-aad.database.windows.net";
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<axum::body::Bytes>>();
    let request = hyper::Request::get(URL).header("metadata", "true").body(Empty::new()).map_err(|e| e.to_string())?;
    let exchange = async {
        let response = client.request(request).await.map_err(|e| e.to_string())?;
        let status = response.status();
        let body = response.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
        if !status.is_success() {
            return Err(format!("the metadata service answered {status}"));
        }
        let token: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        token["access_token"].as_str().map(String::from).ok_or_else(|| "no access_token".to_string())
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), exchange)
        .await
        .map_err(|_| "the metadata service did not answer".to_string())?
}

/// A cursor's number as stored; none is above `i64::MAX`, so one beyond it finds nothing after.
fn clamp(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `event` as the protocol names its kind, and its app when it has one.
fn kind_and_app(event: &TelemetryEvent) -> (&'static str, &str) {
    match event {
        TelemetryEvent::Seal { .. } => ("seal", ""),
        TelemetryEvent::Session { app, .. } => ("session", app.as_str()),
        TelemetryEvent::Extend { .. } => ("extend", ""),
        TelemetryEvent::End { .. } => ("end", ""),
        TelemetryEvent::Refused { .. } => ("refused", ""),
        TelemetryEvent::Request { app, .. } => ("request", app.as_str()),
        TelemetryEvent::Integrity { .. } => ("integrity", ""),
        TelemetryEvent::Dropped { .. } => ("dropped", ""),
    }
}

#[derive(Default)]
struct Counts {
    /// (hour, app, event) → count, bytes up, bytes down, failed
    rollups: BTreeMap<(i64, String, &'static str), [i64; 4]>,
    /// day → requests, sessions, entries, sealed entries
    days: BTreeMap<i64, [i64; 4]>,
    blobs: BTreeSet<(i64, Vec<u8>)>,
}

impl Counts {
    fn of(entries: &TelemetryEntries, count: u32, from: i64) -> Result<Self, Error> {
        let mut c = Counts::default();
        match entries {
            TelemetryEntries::Clear { entries } => {
                for entry in entries {
                    c.add(entry)?;
                }
            }
            TelemetryEntries::Sealed { .. } => {
                let d = c.days.entry(from - from.rem_euclid(DAY)).or_default();
                d[2] += i64::from(count);
                d[3] += i64::from(count);
            }
        }
        Ok(c)
    }

    fn add(&mut self, entry: &TelemetryEntry) -> Result<(), Error> {
        let at = int(entry.at, "an entry's time")?;
        let day = at - at.rem_euclid(DAY);
        let (kind, app) = kind_and_app(&entry.event);
        let r = self.rollups.entry((at - at.rem_euclid(HOUR), app.to_string(), kind)).or_default();
        r[0] += 1;
        let d = self.days.entry(day).or_default();
        d[2] += 1;
        match &entry.event {
            TelemetryEvent::Session { blob_id, .. } => {
                d[1] += 1;
                self.blobs.insert((day, blob_id.0.to_vec()));
            }
            TelemetryEvent::Request { blob_id, completion, .. } => {
                d[0] += 1;
                r[1] = r[1].saturating_add(i64::try_from(completion.bytes_up).unwrap_or(i64::MAX));
                r[2] = r[2].saturating_add(i64::try_from(completion.bytes_down).unwrap_or(i64::MAX));
                r[3] += i64::from(completion.outcome != Outcome::Allowed);
                self.blobs.insert((day, blob_id.0.to_vec()));
            }
            _ => {}
        }
        Ok(())
    }

    async fn save(&self, tx: &mut PgConnection, tenant: &str) -> Result<(), sqlx::Error> {
        if !self.rollups.is_empty() {
            let column = |i: usize| self.rollups.values().map(|r| r[i]).collect::<Vec<_>>();
            sqlx::query(
                "insert into telemetry_rollups (tenant, hour, app, event, count, bytes_up, bytes_down, failed)
                 select $1, * from unnest($2::bigint[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], $7::bigint[], $8::bigint[])
                 on conflict (tenant, hour, app, event) do update
                    set count = telemetry_rollups.count + excluded.count,
                        bytes_up = telemetry_rollups.bytes_up + excluded.bytes_up,
                        bytes_down = telemetry_rollups.bytes_down + excluded.bytes_down,
                        failed = telemetry_rollups.failed + excluded.failed",
            )
            .bind(tenant)
            .bind(self.rollups.keys().map(|k| k.0).collect::<Vec<_>>())
            .bind(self.rollups.keys().map(|k| k.1.clone()).collect::<Vec<_>>())
            .bind(self.rollups.keys().map(|k| k.2.to_string()).collect::<Vec<_>>())
            .bind(column(0))
            .bind(column(1))
            .bind(column(2))
            .bind(column(3))
            .execute(&mut *tx)
            .await?;
        }
        if !self.blobs.is_empty() {
            sqlx::query(
                "insert into telemetry_active_blobs (tenant, day, blob_id)
                 select $1, * from unnest($2::bigint[], $3::bytea[]) on conflict do nothing",
            )
            .bind(tenant)
            .bind(self.blobs.iter().map(|b| b.0).collect::<Vec<_>>())
            .bind(self.blobs.iter().map(|b| b.1.clone()).collect::<Vec<_>>())
            .execute(&mut *tx)
            .await?;
        }
        if !self.days.is_empty() {
            let column = |i: usize| self.days.values().map(|d| d[i]).collect::<Vec<_>>();
            sqlx::query(
                "insert into telemetry_days (tenant, day, requests, sessions, entries, sealed_entries, active_secrets)
                 select $1, u.day, u.requests, u.sessions, u.entries, u.sealed,
                        (select count(*) from telemetry_active_blobs b where b.tenant = $1 and b.day = u.day)
                   from unnest($2::bigint[], $3::bigint[], $4::bigint[], $5::bigint[], $6::bigint[])
                        as u(day, requests, sessions, entries, sealed)
                 on conflict (tenant, day) do update
                    set requests = telemetry_days.requests + excluded.requests,
                        sessions = telemetry_days.sessions + excluded.sessions,
                        entries = telemetry_days.entries + excluded.entries,
                        sealed_entries = telemetry_days.sealed_entries + excluded.sealed_entries,
                        active_secrets = excluded.active_secrets",
            )
            .bind(tenant)
            .bind(self.days.keys().copied().collect::<Vec<_>>())
            .bind(column(0))
            .bind(column(1))
            .bind(column(2))
            .bind(column(3))
            .execute(&mut *tx)
            .await?;
        }
        Ok(())
    }
}

impl TelemetryDb {
    /// Connects and applies the migrations (`migrations/`). With `entra`, the password is an
    /// Entra token for the VM's managed identity, renewed for later connections: a token is only
    /// checked when a connection signs in.
    pub async fn connect(url: &str, retention_days: Option<u32>, entra: bool) -> Result<Self, Error> {
        // On a server shared with the console: enough for a page and the writers it serves.
        let pool = PgPoolOptions::new().max_connections(10);
        let options: PgConnectOptions = url.parse()?;
        if !entra {
            return Self::with_pool(pool.connect_with(options).await?, retention_days).await;
        }
        let token = entra_token().await.map_err(Error::Token)?;
        let db = pool.connect_with(options.clone().password(&token)).await?;
        let renew = db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                match entra_token().await {
                    Ok(token) => renew.set_connect_options(options.clone().password(&token)),
                    Err(e) => tracing::warn!(error = %e, "telemetry database token"),
                }
            }
        });
        Self::with_pool(db, retention_days).await
    }

    pub async fn with_pool(pool: PgPool, retention_days: Option<u32>) -> Result<Self, Error> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool, retention_secs: retention_days.map(|d| i64::from(d) * DAY), partitions: Mutex::default() })
    }

    /// Creates the week's partition if it is not known to exist. Instances racing are
    /// serialized by the lock, since `if not exists` alone can still fail under a race.
    async fn ensure_partition(&self, week: i64) -> Result<(), Error> {
        if self.partitions.lock().unwrap_or_else(|p| p.into_inner()).contains(&week) {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("select pg_advisory_xact_lock(hashtext('telemetry_batches partitions'))").execute(&mut *tx).await?;
        // `week` is a number computed here, so it is safe in the statement.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "create table if not exists telemetry_batches_w{week} partition of telemetry_batches
               for values from ({week}) to ({})",
            week + 1
        )))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.partitions.lock().unwrap_or_else(|p| p.into_inner()).insert(week);
        Ok(())
    }

    /// Stores a batch the caller has checked and counts it, in one transaction. Retrying a batch
    /// counts it once.
    pub async fn put(&self, batch: &SignedTelemetryBatch, received_at: UnixTime) -> Result<Put, Error> {
        let b = &batch.body;
        let tenant = b.tenant.as_str();
        let sequence = int(b.sequence, "a sequence")?;
        let (from, to) = (int(b.from, "from")?, int(b.to, "to")?);
        let received_at = int(received_at, "the clock")?;
        let week = received_at / WEEK;
        let counts = Counts::of(&b.entries, b.count, from)?;
        let body = serde_json::to_vec(batch)?;
        let size = i32::try_from(body.len()).map_err(|_| Error::Range("a batch's size"))?;
        self.ensure_partition(week).await?;

        let mut tx = self.pool.begin().await?;
        // Across weeks: the primary key only covers one, and a retry can land in the next.
        let lookup = "select body from telemetry_batches where tenant = $1 and stream = $2 and sequence = $3 limit 1";
        let stored = |bytes: Vec<u8>| -> Result<Put, Error> {
            let same = serde_json::from_slice::<SignedTelemetryBatch>(&bytes)? == *batch;
            Ok(if same { Put::Same } else { Put::Conflict })
        };
        let found: Option<Vec<u8>> =
            sqlx::query_scalar(lookup).bind(tenant).bind(&b.stream[..]).bind(sequence).fetch_optional(&mut *tx).await?;
        if let Some(bytes) = found {
            return stored(bytes);
        }
        let inserted = sqlx::query(
            "insert into telemetry_batches (tenant, stream, sequence, week, received_at, batch_to, size, body)
             values ($1, $2, $3, $4, $5, $6, $7, $8) on conflict do nothing",
        )
        .bind(tenant)
        .bind(&b.stream[..])
        .bind(sequence)
        .bind(i32::try_from(week).map_err(|_| Error::Range("the clock"))?)
        .bind(received_at)
        .bind(to)
        .bind(size)
        .bind(&body)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted == 0 {
            // Another request stored it first, and this one waited for it to commit.
            let bytes: Vec<u8> =
                sqlx::query_scalar(lookup).bind(tenant).bind(&b.stream[..]).bind(sequence).fetch_one(&mut *tx).await?;
            return stored(bytes);
        }
        sqlx::query(
            "insert into telemetry_streams
                (tenant, stream, min_sequence, max_sequence, batches, oldest_from, newest_to, last, received_at)
             values ($1, $2, $3, $3, 1, $4, $5, $6, $7)
             on conflict (tenant, stream) do update
                set min_sequence = least(telemetry_streams.min_sequence, $3),
                    max_sequence = greatest(telemetry_streams.max_sequence, $3),
                    batches = telemetry_streams.batches + 1,
                    oldest_from = least(telemetry_streams.oldest_from, $4),
                    newest_to = greatest(telemetry_streams.newest_to, $5),
                    last = telemetry_streams.last or $6,
                    received_at = greatest(telemetry_streams.received_at, $7)",
        )
        .bind(tenant)
        .bind(&b.stream[..])
        .bind(sequence)
        .bind(from)
        .bind(to)
        .bind(b.last)
        .bind(received_at)
        .execute(&mut *tx)
        .await?;
        counts.save(&mut tx, tenant).await?;
        tx.commit().await?;
        Ok(Put::Stored)
    }

    /// The first `limit` batches with `to >= since` after the cursor, stopping before their JSON
    /// passes `max_bytes` (after at least one). Sizes come from the index and the window runs
    /// before any body is read, so a page reads only its own bodies.
    pub async fn page(
        &self,
        tenant: &str,
        since: UnixTime,
        order: TelemetryOrder,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Page, Error> {
        let since = int(since, "since")?;
        // With no cursor, values below any batch's, so each order has one statement.
        let (filter, by, to, stream, sequence) = match order {
            TelemetryOrder::Stream { after } => {
                let (stream, sequence) = after.map_or((Vec::new(), -1), |(s, q)| (s.to_vec(), clamp(q)));
                ("(stream, sequence) > ($5::bytea, $6::bigint)", "stream, sequence", None, stream, sequence)
            }
            TelemetryOrder::Time { after } => {
                let (to, stream, sequence) =
                    after.map_or((-1, Vec::new(), -1), |(t, s, q)| (clamp(t), s.to_vec(), clamp(q)));
                (
                    "(batch_to, stream, sequence) > ($7::bigint, $5::bytea, $6::bigint)",
                    "batch_to, stream, sequence",
                    Some(to),
                    stream,
                    sequence,
                )
            }
        };
        let matching = format!("tenant = $1 and batch_to >= $2 and {filter}");
        let sql = format!(
            "with totals as (select count(*) as batches, coalesce(sum(size), 0)::bigint as bytes
                               from telemetry_batches where {matching}),
                  page as (select stream, sequence, week, sum(size + 1) over w as running, row_number() over w as n
                             from telemetry_batches where {matching}
                           window w as (order by {by}) order by {by} limit $3)
             select t.body, totals.batches, totals.bytes from page p cross join totals
               join telemetry_batches t
                 on t.tenant = $1 and t.stream = p.stream and t.sequence = p.sequence and t.week = p.week
              where p.running <= $4 or p.n = 1
              order by p.n"
        );
        let query = sqlx::query_as::<_, (Vec<u8>, i64, i64)>(sqlx::AssertSqlSafe(sql))
            .bind(tenant)
            .bind(since)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .bind(i64::try_from(max_bytes).unwrap_or(i64::MAX))
            .bind(stream)
            .bind(sequence);
        let query = match to {
            Some(to) => query.bind(to),
            None => query,
        };
        let rows = query.fetch_all(&self.pool).await?;
        let (remaining_batches, remaining_bytes) = rows.first().map_or((0, 0), |r| (r.1 as u64, r.2 as u64));
        Ok(Page { bodies: rows.into_iter().map(|r| r.0).collect(), remaining_batches, remaining_bytes })
    }

    /// The tenant's days from `from` to `to` (Unix seconds, either end's day included).
    pub async fn usage(&self, tenant: &str, from: UnixTime, to: UnixTime) -> Result<Vec<UsageDay>, Error> {
        let (from, to) = (int(from, "from")?, int(to, "to")?);
        Ok(sqlx::query_as(
            "select to_char(to_timestamp(day) at time zone 'utc', 'YYYY-MM-DD') as day,
                    requests, sessions, entries, sealed_entries, active_secrets
               from telemetry_days where tenant = $1 and day between $2 and $3 order by telemetry_days.day",
        )
        .bind(tenant)
        .bind(from - from.rem_euclid(DAY))
        .bind(to)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The tenant's hourly counts in `from..to` (Unix seconds).
    pub async fn metrics(
        &self,
        tenant: &str,
        from: UnixTime,
        to: UnixTime,
        by: GroupBy,
    ) -> Result<Vec<MetricPoint>, Error> {
        let (from, to) = (int(from, "from")?, int(to, "to")?);
        let sql = match by {
            GroupBy::Event => {
                "select to_char(to_timestamp(r.hour) at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as hour,
                        r.event as key, sum(r.count)::bigint as count
                   from telemetry_rollups r where r.tenant = $1 and r.hour >= $2 and r.hour < $3
                  group by r.hour, r.event order by r.hour, r.event"
            }
            GroupBy::App => {
                "select to_char(to_timestamp(r.hour) at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as hour,
                        r.app as key, sum(r.count)::bigint as count
                   from telemetry_rollups r where r.tenant = $1 and r.hour >= $2 and r.hour < $3
                  group by r.hour, r.app order by r.hour, r.app"
            }
            GroupBy::Requests => {
                "select to_char(to_timestamp(r.hour) at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as hour,
                        v.key, sum(v.n)::bigint as count
                   from telemetry_rollups r,
                        lateral (values ('up', r.bytes_up), ('down', r.bytes_down), ('failed', r.failed)) as v(key, n)
                  where r.tenant = $1 and r.hour >= $2 and r.hour < $3 and r.event = 'request'
                  group by r.hour, v.key order by r.hour, v.key"
            }
        };
        Ok(sqlx::query_as(sql).bind(tenant).bind(from).bind(to).fetch_all(&self.pool).await?)
    }

    /// The tenant's telemetry gaps that are due at `now`. Silence alone is not one, since
    /// replicas send nothing while idle, and neither is a stream first seen part-way through.
    pub async fn gaps(&self, tenant: &str, now: UnixTime) -> Result<Vec<Gap>, Error> {
        let now = int(now, "the clock")?;
        let holes: Vec<(Vec<u8>, i64, i64)> = sqlx::query_as(
            "select stream, previous + 1, sequence - 1 from (
                 select stream, sequence, received_at,
                        lag(sequence) over (partition by stream order by sequence) as previous
                   from telemetry_batches
                  where tenant = $1 and stream in (
                        select stream from telemetry_streams
                         where tenant = $1 and batches <> max_sequence - min_sequence + 1 and received_at > $3)
             ) b
             where sequence > previous + 1 and received_at <= $2 and received_at > $3
             order by stream, sequence",
        )
        .bind(tenant)
        .bind(now - HOLE_GRACE_SECS)
        .bind(now - GAPS_WITHIN_SECS)
        .fetch_all(&self.pool)
        .await?;
        let stopped: Vec<(Vec<u8>, i64, i64)> = sqlx::query_as(
            "select s.stream, s.max_sequence, s.newest_to from telemetry_streams s
              where s.tenant = $1 and not s.last and s.newest_to < $2 and s.newest_to > $3
                and exists (select 1 from telemetry_streams n
                             where n.tenant = s.tenant and n.stream <> s.stream and n.oldest_from > s.newest_to)
              order by s.stream",
        )
        .bind(tenant)
        .bind(now - STOP_AFTER_SECS)
        .bind(now - GAPS_WITHIN_SECS)
        .fetch_all(&self.pool)
        .await?;
        let missing = holes.into_iter().map(|(stream, from, to)| Gap::Missing {
            stream: hex(&stream),
            from,
            to,
            count: to - from + 1,
        });
        let stopped =
            stopped.into_iter().map(|(stream, sequence, seen)| Gap::Stopped { stream: hex(&stream), sequence, seen });
        Ok(missing.chain(stopped).collect())
    }

    /// Makes the coming weeks' partitions, and applies retention: whole weeks of batches past it
    /// are dropped, and their hourly counts deleted. Daily counts stay, for billing.
    pub async fn maintain(&self, now: UnixTime) -> Result<(), Error> {
        let now = int(now, "the clock")?;
        for week in now / WEEK..=now / WEEK + 1 {
            self.ensure_partition(week).await?;
        }
        sqlx::query("delete from telemetry_streams where received_at < $1")
            .bind(now - STREAM_SECS)
            .execute(&self.pool)
            .await?;
        sqlx::query("delete from telemetry_active_blobs where day < $1")
            .bind(now - ACTIVE_BLOB_SECS)
            .execute(&self.pool)
            .await?;
        let Some(retention) = self.retention_secs else { return Ok(()) };
        let names: Vec<String> = sqlx::query_scalar(
            "select c.relname::text from pg_inherits i
               join pg_class c on c.oid = i.inhrelid join pg_class p on p.oid = i.inhparent
              where p.relname = 'telemetry_batches'",
        )
        .fetch_all(&self.pool)
        .await?;
        for name in names {
            let Some(week) = name.strip_prefix("telemetry_batches_w").and_then(|w| w.parse::<i64>().ok()) else {
                continue;
            };
            if (week + 1) * WEEK <= now - retention {
                // Parsed back to a number above, so it is safe in the statement.
                sqlx::query(sqlx::AssertSqlSafe(format!("drop table if exists telemetry_batches_w{week}")))
                    .execute(&self.pool)
                    .await?;
                self.partitions.lock().unwrap_or_else(|p| p.into_inner()).remove(&week);
            }
        }
        sqlx::query("delete from telemetry_rollups where hour < $1").bind(now - retention).execute(&self.pool).await?;
        Ok(())
    }

    /// Reads every batch file under `data_dir` into the database, once, by the time each file was
    /// written: moving a deployment from files to Postgres. Safe to run again. Returns how many
    /// batches were new, and how many files could not be read.
    pub async fn import_files(&self, data_dir: &std::path::Path) -> Result<(u64, u64), Error> {
        let (mut new, mut failed) = (0, 0);
        let Ok(tenants) = std::fs::read_dir(data_dir.join("tenants")) else { return Ok((0, 0)) };
        for tenant in tenants.flatten() {
            let Ok(files) = std::fs::read_dir(tenant.path().join("telemetry")) else { continue };
            for file in files.flatten() {
                let path = file.path();
                if path.extension().is_none_or(|e| e != "json") || file.file_name().as_encoded_bytes().starts_with(b".")
                {
                    continue;
                }
                let read = || -> Option<(SignedTelemetryBatch, u64)> {
                    let at =
                        file.metadata().ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
                    Some((serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?, at))
                };
                let Some((batch, at)) = read() else {
                    tracing::warn!(path = %path.display(), "cannot read a telemetry batch");
                    failed += 1;
                    continue;
                };
                new += u64::from(self.put(&batch, at).await? == Put::Stored);
            }
        }
        Ok((new, failed))
    }
}

/// For this crate's tests.
#[cfg(test)]
pub mod test_support {
    use sqlx::Connection;

    use super::*;

    pub fn unique() -> [u8; 8] {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let mut id = [0; 8];
        id[..4].copy_from_slice(&std::process::id().to_be_bytes());
        id[4..].copy_from_slice(&N.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        id
    }

    /// A fresh database, or `None` (the test passes) without `SEAL_CONTROL_TEST_DATABASE_URL`.
    pub async fn db(retention_days: Option<u32>) -> Option<TelemetryDb> {
        let url = std::env::var("SEAL_CONTROL_TEST_DATABASE_URL").ok()?;
        let name = format!("control_test_{}", hex(&unique()));
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("create database {name}"))).execute(&mut admin).await.unwrap();
        let mut own: url::Url = url.parse().unwrap();
        own.set_path(&format!("/{name}"));
        Some(TelemetryDb::connect(own.as_str(), retention_days, false).await.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::signed::Signed;
    use seal_proto::telemetry::{Completion, TelemetryBatch};
    use seal_proto::{AppName, BlobId, TenantId};

    const NOW: UnixTime = 1_900_000_000;

    use super::test_support::{db, unique};

    fn acme() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    fn app(name: &str) -> AppName {
        AppName::new(name).unwrap()
    }

    fn request(at: UnixTime, app_name: &str, blob: u8, outcome: Outcome) -> TelemetryEntry {
        TelemetryEntry {
            at,
            tenant: acme(),
            identity: None,
            event: TelemetryEvent::Request {
                session_id: [1; 16],
                app: app(app_name),
                blob_id: BlobId([blob; 8]),
                connection_id: 1,
                completion: Completion {
                    protocol: seal_proto::policy::Protocol::Http,
                    action: "GET".into(),
                    outcome,
                    bytes_up: 5,
                    bytes_down: 7,
                },
            },
        }
    }

    fn batch(
        stream: u8,
        sequence: u64,
        at: UnixTime,
        entries: Vec<TelemetryEntry>,
        last: bool,
    ) -> SignedTelemetryBatch {
        Signed {
            body: TelemetryBatch {
                tenant: acme(),
                stream: [stream; 16],
                sequence,
                first_entry: sequence,
                count: entries.len() as u32,
                from: at,
                to: at,
                entries: TelemetryEntries::Clear { entries },
                last,
            },
            signatures: Vec::new(),
        }
    }

    fn sealed(stream: u8, sequence: u64, at: UnixTime, count: u32) -> SignedTelemetryBatch {
        let mut b = batch(stream, sequence, at, Vec::new(), false);
        b.body.count = count;
        b.body.entries = TelemetryEntries::Sealed { readers: Vec::new(), nonce: [0; 12], ciphertext: vec![1; 8] };
        b
    }

    #[test]
    fn counts_clear_and_sealed_batches() {
        let hour = 7_200;
        let entries = vec![
            request(hour, "web", 1, Outcome::Allowed),
            request(hour + 100, "web", 1, Outcome::Aborted),
            request(hour + 3_700, "api", 2, Outcome::Allowed),
        ];
        let c = Counts::of(&TelemetryEntries::Clear { entries }, 3, hour as i64).unwrap();
        assert_eq!(c.rollups[&(7_200, "web".to_string(), "request")], [2, 10, 14, 1]);
        assert_eq!(c.rollups[&(10_800, "api".to_string(), "request")], [1, 5, 7, 0]);
        assert_eq!(c.days[&0], [3, 0, 3, 0]);
        assert_eq!(c.blobs.len(), 2);
        let s = sealed(1, 0, 90_000, 9);
        let c = Counts::of(&s.body.entries, 9, 90_000).unwrap();
        assert_eq!(c.days[&86_400], [0, 0, 9, 9], "sealed batches: counts from metadata only");
        assert!(c.rollups.is_empty() && c.blobs.is_empty());
    }

    #[tokio::test]
    async fn a_batch_is_stored_and_counted_once() {
        let Some(db) = db(None).await else { return };
        let b = batch(1, 0, NOW, vec![request(NOW, "web", 1, Outcome::Allowed)], false);
        assert_eq!(db.put(&b, NOW).await.unwrap(), Put::Stored);
        assert_eq!(db.put(&b, NOW).await.unwrap(), Put::Same);
        assert_eq!(db.put(&b, NOW + WEEK as u64).await.unwrap(), Put::Same, "a retry a week later");
        let other = batch(1, 0, NOW + 1, Vec::new(), false);
        assert_eq!(db.put(&other, NOW + WEEK as u64).await.unwrap(), Put::Conflict, "across weeks too");
        let u = db.usage("acme", NOW - 86_400, NOW).await.unwrap();
        assert_eq!((u.len(), u[0].requests, u[0].entries, u[0].active_secrets), (1, 1, 1, 1));
    }

    #[tokio::test]
    async fn concurrent_posts_of_one_batch_count_it_once() {
        let Some(db) = db(None).await else { return };
        let db = std::sync::Arc::new(db);
        let b = batch(1, 0, NOW, vec![request(NOW, "web", 1, Outcome::Allowed)], false);
        let mut posts = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (db, b) = (db.clone(), b.clone());
            posts.spawn(async move { db.put(&b, NOW).await.unwrap() });
        }
        let mut stored = 0;
        while let Some(put) = posts.join_next().await {
            stored += u32::from(put.unwrap() == Put::Stored);
        }
        assert_eq!(stored, 1);
        assert_eq!(db.usage("acme", NOW - 86_400, NOW).await.unwrap()[0].requests, 1);
    }

    #[tokio::test]
    async fn pages_follow_both_orders_and_their_byte_limit() {
        let Some(db) = db(None).await else { return };
        // Stream 2 ends before stream 1, and the batches land in different weeks.
        for (i, (stream, sequence, at)) in [(1, 0, 100), (1, 1, 400), (2, 0, 200), (2, 1, 300)].into_iter().enumerate()
        {
            let received = NOW + i as u64 * WEEK as u64;
            db.put(&batch(stream, sequence, NOW + at, Vec::new(), false), received).await.unwrap();
        }
        let keys = |page: &Page| -> Vec<(u8, u64)> {
            page.bodies
                .iter()
                .map(|b| {
                    let b: SignedTelemetryBatch = serde_json::from_slice(b).unwrap();
                    (b.body.stream[0], b.body.sequence)
                })
                .collect()
        };
        let by_stream = |after| TelemetryOrder::Stream { after };
        let p = db.page("acme", 0, by_stream(None), 3, 1 << 20).await.unwrap();
        assert_eq!(keys(&p), [(1, 0), (1, 1), (2, 0)]);
        assert_eq!(p.remaining_batches, 4);
        let p = db.page("acme", 0, by_stream(Some(([2; 16], 0))), 3, 1 << 20).await.unwrap();
        assert_eq!((keys(&p), p.remaining_batches), (vec![(2, 1)], 1));
        let by_time = |after| TelemetryOrder::Time { after };
        let p = db.page("acme", NOW + 150, by_time(None), 10, 1 << 20).await.unwrap();
        assert_eq!(keys(&p), [(2, 0), (2, 1), (1, 1)], "since drops the first");
        let p = db.page("acme", 0, by_time(Some((NOW + 200, [2; 16], 0))), 10, 1 << 20).await.unwrap();
        assert_eq!(keys(&p), [(2, 1), (1, 1)]);
        let p = db.page("acme", 0, by_stream(None), 10, 1).await.unwrap();
        assert_eq!(keys(&p), [(1, 0)], "at least one, whatever the byte limit");
        assert_eq!(db.page("other", 0, by_stream(None), 10, 1 << 20).await.unwrap().bodies.len(), 0);
    }

    #[tokio::test]
    async fn metrics_group_as_asked() {
        let Some(db) = db(None).await else { return };
        let hour = NOW - NOW % 3_600;
        let entries = vec![request(hour, "web", 1, Outcome::Allowed), request(hour + 1, "api", 1, Outcome::Aborted)];
        db.put(&batch(1, 0, hour + 1, entries, false), NOW).await.unwrap();
        let events = db.metrics("acme", hour, hour + 3_600, GroupBy::Event).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!((events[0].key.as_str(), events[0].count), ("request", 2));
        assert!(events[0].hour.ends_with(":00:00Z") && events[0].hour.contains('T'), "{}", events[0].hour);
        let apps = db.metrics("acme", hour, hour + 3_600, GroupBy::App).await.unwrap();
        assert_eq!(apps.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(), ["api", "web"]);
        let requests = db.metrics("acme", hour, hour + 3_600, GroupBy::Requests).await.unwrap();
        let of = |k: &str| requests.iter().find(|p| p.key == k).unwrap().count;
        assert_eq!((of("up"), of("down"), of("failed")), (10, 14, 1));
        assert!(
            db.metrics("acme", hour + 3_600, hour + 7_200, GroupBy::Event).await.unwrap().is_empty(),
            "to is exclusive"
        );
    }

    #[tokio::test]
    async fn holes_wait_their_grace_and_stopped_streams_need_a_newer_one() {
        let Some(db) = db(None).await else { return };
        let t = NOW - 1_000;
        db.put(&batch(1, 3, t, Vec::new(), false), t).await.unwrap();
        db.put(&batch(1, 7, t, Vec::new(), false), t).await.unwrap();
        // Silent, but nothing newer: not a gap yet. The hole is due.
        assert_eq!(
            db.gaps("acme", NOW).await.unwrap(),
            [Gap::Missing { stream: hex(&[1; 16]), from: 4, to: 6, count: 3 }],
            "first seen at 3: the sequences before it are not missing"
        );
        assert!(db.gaps("acme", t + 10).await.unwrap().is_empty(), "within the grace");
        // The hole fills.
        for sequence in 4..=6 {
            db.put(&batch(1, sequence, t, Vec::new(), false), t).await.unwrap();
        }
        assert!(db.gaps("acme", NOW).await.unwrap().is_empty());
        // A newer stream began after stream 1's end.
        db.put(&batch(2, 0, t + 1, Vec::new(), false), t + 1).await.unwrap();
        assert_eq!(
            db.gaps("acme", t + 901).await.unwrap(),
            [Gap::Stopped { stream: hex(&[1; 16]), sequence: 7, seen: t as i64 }]
        );
        // Its last batch clears it.
        db.put(&batch(1, 8, t, Vec::new(), true), t).await.unwrap();
        assert!(db.gaps("acme", t + 901).await.unwrap().is_empty());
        assert!(db.gaps("acme", t + 2 * 86_400).await.unwrap().is_empty(), "long past");
    }

    #[tokio::test]
    async fn retention_drops_whole_weeks_and_keeps_daily_counts() {
        let Some(db) = db(Some(30)).await else { return };
        let old = NOW - 60 * 86_400;
        db.put(&batch(1, 0, old, vec![request(old, "web", 1, Outcome::Allowed)], false), old).await.unwrap();
        db.put(&batch(2, 0, NOW, vec![request(NOW, "web", 1, Outcome::Allowed)], false), NOW).await.unwrap();
        db.maintain(NOW).await.unwrap();
        let p = db.page("acme", 0, TelemetryOrder::Stream { after: None }, 10, 1 << 20).await.unwrap();
        assert_eq!(p.bodies.len(), 1, "the old week is gone");
        assert!(db.metrics("acme", old - 3_600, old + 3_600, GroupBy::Event).await.unwrap().is_empty());
        assert_eq!(db.usage("acme", old - 86_400, NOW).await.unwrap().len(), 2, "days stay");
        // A later batch in the current week still lands.
        db.put(&batch(2, 1, NOW, Vec::new(), false), NOW).await.unwrap();
    }

    #[tokio::test]
    async fn files_import_once() {
        let Some(db) = db(None).await else { return };
        let dir = std::env::temp_dir().join(format!("seal-control-import-{}", hex(&unique())));
        let telemetry = dir.join("tenants").join("acme").join("telemetry");
        std::fs::create_dir_all(&telemetry).unwrap();
        let b = batch(1, 0, NOW, vec![request(NOW, "web", 1, Outcome::Allowed)], false);
        std::fs::write(telemetry.join("a.json"), serde_json::to_vec(&b).unwrap()).unwrap();
        std::fs::write(telemetry.join("bad.json"), b"{").unwrap();
        std::fs::write(telemetry.join(".a.json.1.2.tmp"), b"{").unwrap();
        assert_eq!(db.import_files(&dir).await.unwrap(), (1, 1));
        assert_eq!(db.import_files(&dir).await.unwrap(), (0, 1), "again changes nothing");
        assert_eq!(db.usage("acme", NOW - 86_400, NOW).await.unwrap()[0].requests, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// `SEAL_CONTROL_TEST_DATABASE_URL=… cargo test -p sealzone-control --release -- --ignored telemetry_db_ingest_benchmark --nocapture`
#[cfg(test)]
#[tokio::test]
#[ignore = "benchmark"]
async fn telemetry_db_ingest_benchmark() {
    use seal_proto::signed::Signed;
    use seal_proto::telemetry::{Completion, TelemetryBatch};
    use seal_proto::{AppName, BlobId, TenantId};
    let Some(db) = test_support::db(None).await else { return };
    let db = std::sync::Arc::new(db);
    const NOW: u64 = 1_900_000_000;
    let (writers, each, entries) = (16u8, 500u64, 100u64);
    let started = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for w in 0..writers {
        let db = db.clone();
        tasks.spawn(async move {
            let tenant = TenantId::new(format!("t{}", w % 4)).unwrap();
            for q in 0..each {
                let at = NOW + q * 5;
                let list: Vec<TelemetryEntry> = (0..entries)
                    .map(|i| TelemetryEntry {
                        at,
                        tenant: tenant.clone(),
                        identity: None,
                        event: TelemetryEvent::Request {
                            session_id: [w; 16],
                            app: AppName::new("web").unwrap(),
                            blob_id: BlobId([(i % 8) as u8; 8]),
                            connection_id: i,
                            completion: Completion {
                                protocol: seal_proto::policy::Protocol::Http,
                                action: "GET /".into(),
                                outcome: Outcome::Allowed,
                                bytes_up: 100,
                                bytes_down: 1000,
                            },
                        },
                    })
                    .collect();
                let body = TelemetryBatch {
                    tenant: tenant.clone(),
                    stream: [w; 16],
                    sequence: q,
                    first_entry: q * entries,
                    count: entries as u32,
                    from: at,
                    to: at,
                    entries: TelemetryEntries::Clear { entries: list },
                    last: false,
                };
                assert_eq!(db.put(&Signed { body, signatures: Vec::new() }, at).await.unwrap(), Put::Stored);
            }
        });
    }
    while let Some(done) = tasks.join_next().await {
        done.unwrap();
    }
    let total = u64::from(writers) * each;
    let secs = started.elapsed().as_secs_f64();
    println!(
        "{total} batches of {entries} entries from {writers} writers over 4 tenants: {:.0} batches/s",
        total as f64 / secs
    );
}
