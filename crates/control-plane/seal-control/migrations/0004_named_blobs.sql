-- Named secrets are called named blobs: what a name points to is a sealed blob, and nothing
-- secret is stored. The table and its key follow the name (server/named_blobs.rs).
alter table named_secrets rename to named_blobs;
alter index named_secrets_pkey rename to named_blobs_pkey;
