-- Telemetry in Postgres (server/telemetry_db.rs). Batches are signed documents, stored as they
-- are served; everything else is counted from them at ingest, unverified.

-- Partitioned by the week a batch arrived (the server's clock, so a batch's own times cannot
-- pin it past retention). `body` is the SignedTelemetryBatch's JSON, `size` its length.
create table telemetry_batches (
  tenant      text not null,
  stream      bytea not null,
  sequence    bigint not null,
  week        integer not null,
  received_at bigint not null,
  batch_to    bigint not null,
  size        integer not null,
  body        bytea not null,
  primary key (tenant, stream, sequence, week)
) partition by range (week);
create index telemetry_batches_by_time on telemetry_batches (tenant, batch_to, stream, sequence) include (size);

-- Each stream as far as it has arrived. `batches` differing from the span of its sequence
-- numbers is what makes a stream worth searching for holes.
create table telemetry_streams (
  tenant       text not null,
  stream       bytea not null,
  min_sequence bigint not null,
  max_sequence bigint not null,
  batches      bigint not null,
  oldest_from  bigint not null,
  newest_to    bigint not null,
  last         boolean not null,
  received_at  bigint not null,
  primary key (tenant, stream)
);

-- Clear batches' entries by hour, app and event; what requests carried and how many failed.
create table telemetry_rollups (
  tenant     text not null,
  hour       bigint not null,
  app        text not null,
  event      text not null,
  count      bigint not null,
  bytes_up   bigint not null,
  bytes_down bigint not null,
  failed     bigint not null,
  primary key (tenant, hour, app, event)
);

-- Kept for billing, past telemetry's retention. Sealed batches count only as entries.
create table telemetry_days (
  tenant         text not null,
  day            bigint not null,
  requests       bigint not null,
  sessions       bigint not null,
  entries        bigint not null,
  sealed_entries bigint not null,
  active_secrets bigint not null,
  primary key (tenant, day)
);

-- Blobs used in a session or request that day; `telemetry_days.active_secrets` counts them.
create table telemetry_active_blobs (
  tenant  text not null,
  day     bigint not null,
  blob_id bytea not null,
  primary key (tenant, day, blob_id)
);
