-- Everything else control keeps (server/store.rs), which lived in files under `data_dir` until
-- now. Every `body` is a document's JSON as it is served. All of it is signed elsewhere or public:
-- enclaves and SDKs check each document against the log and the root chain, so these tables hold
-- nothing that needs secrecy and nothing a reader has to trust.

-- A tenant's small documents, one row each, all loaded on the tenant's first use: `kind` is
-- roots, state, freshness, signals, session-ends, service-key-certificates, wrap-keys or anchors.
create table tenant_documents (
  tenant text not null,
  kind   text not null,
  body   bytea not null,
  primary key (tenant, kind)
);

-- Every state the tenant has had, with its log proof (LoggedState).
create table tenant_states (
  tenant  text not null,
  version bigint not null,
  body    bytea not null,
  primary key (tenant, version)
);

-- Changes waiting for signatures (Proposal), by their id (64 hex digits).
create table tenant_proposals (
  tenant text not null,
  id     text not null,
  body   bytea not null,
  primary key (tenant, id)
);

-- A tenant's co-signatures of a release (Signed<ReleaseCosign>), by measurement.
create table tenant_release_cosigns (
  tenant      text not null,
  measurement text not null,
  body        bytea not null,
  primary key (tenant, measurement)
);

-- Release evidence (ReleaseEvidence) and the console's release templates (JSON as given), by
-- platform (its serde name) and measurement.
create table releases (
  platform    text not null,
  measurement text not null,
  body        bytea not null,
  primary key (platform, measurement)
);
create table release_templates (
  platform    text not null,
  measurement text not null,
  body        bytea not null,
  primary key (platform, measurement)
);
