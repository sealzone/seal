//! ClickHouse native protocol over TLS: specified here, not built yet. Nothing implements
//! `seal_adapter::Adapter` for it, so the enclave registers no ClickHouse adapter and refuses
//! tunnels to `clickhouse://` destinations with `Unavailable` (`no adapter for ClickHouse`).
//! What the adapter will do:
//!
//! Handshake: the Seal credential comes from the client Hello's password field only. Upstream
//! Hello = the client's name and version, revision `min(client, REVISION_CAP)`, then the
//! destination's database (or ""), user and the secret; the client's own user and database
//! are never forwarded. An upstream login failure is answered with Seal's own Exception,
//! never the upstream's text. The server Hello is decoded and re-encoded for the client with
//! revision `min(server, REVISION_CAP)` and chunking `notchunked`; the addendum's quota key is
//! replaced. Logins without a password (interserver secret, SSH key) are refused for lack of
//! a credential; JWT logins are refused.
//!
//! Requests: every client packet is decoded, so each query is observed (`Session::observe`)
//! before it is forwarded. Refused, answered with an Exception while the connection stays
//! open: query kinds other than initial, an interserver hash, external roles, the JWT,
//! internal-query and current-roles fields, stages other than Complete, non-default
//! `dialect`s (they change what the query text means), compression, and packet types other
//! than Query, Data, Cancel, Ping and KeepAlive. Insert blocks carry no length prefix, so the
//! adapter decodes each column type to find a block's end; blocks with types it cannot
//! decode (AggregateFunction, JSON, Dynamic, Variant, Object) and custom serializations are
//! refused. Server replies are relayed as bytes through the scrubber.
//!
//! Compression is refused because the scrubber cannot see a secret inside LZ4 or ZSTD frames;
//! the SDK's tunnel DSNs are uncompressed by default.
//!
//! When the destination names a database, queries are sent with it as the default; other
//! databases stay reachable by qualified name unless the upstream user's grants forbid them.

/// Highest protocol revision the adapter speaks (what clickhouse-go sends). Raised only with
/// the CI matrix of ClickHouse LTS servers and clients; field layouts change between
/// revisions (insert-block strings changed at 54492).
pub const REVISION_CAP: u64 = 54460;
