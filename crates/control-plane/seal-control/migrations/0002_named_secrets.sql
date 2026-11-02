-- Named secrets (server/named_secrets.rs): each version a tenant's admins published, as it is
-- served (`body`, the NamedSecretVersion's JSON: the signed entry and the blob's text). The
-- route checks every version before it is stored; the database holds nothing that needs secrecy.
create table named_secrets (
  tenant    text not null,
  root_id   text not null,
  name      text not null,
  version   bigint not null,
  deleted   boolean not null,
  stored_at bigint not null,
  body      bytea not null,
  primary key (tenant, root_id, name, version)
);
