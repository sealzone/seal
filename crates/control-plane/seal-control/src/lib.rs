//! Seal's control plane: an untrusted store of signed documents.
//!
//! HTTP API (JSON). Untrusted by design: it cannot forge anything verifiers accept, and it
//! cannot roll a tenant back for longer than `STATE_FRESHNESS_SECS`, because verifiers need
//! a current `StateFreshness` from the log for exactly the state they get. Withholding a newer
//! state makes the tenant unavailable after that window, never quietly stale. It still
//! rejects obvious junk (shape, non-increasing versions, states the log has not recorded, roots
//! that do not extend the chain). Documents an enclave or an external source signs are accepted
//! from anyone when they verify, because enclaves hold no credentials: enclave-signed ones
//! against a telemetry public key of a guardian-certified `ServiceKeyCertificate` the tenant's
//! enclaves posted, external signals against the latest state's `integrity.sources`.
//!
//! Who may read and write a tenant's documents (`seal_proto::control` names the credentials;
//! admins are admitted wherever members are):
//!
//! | What | Anyone | Console token `read` | Console token `submit` | Admin-signed | Enclave (telemetry key) | Enclave at boot (attested) | Freshness signer | Write token |
//! |------|---|---|---|---|---|---|---|---|
//! | Bundle (grants)                       |   | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |   |
//! | Documents, proposals, telemetry       |   | ✓ | ✓ | ✓ |   |   |   |   |
//! | Put, sign, withdraw, submit proposals |   |   | ✓ | ✓ |   |   |   |   |
//! | Put roots, states, release co-signatures (each still needs its own admin signatures) | | | ✓ | ✓ | | | | ✓ |
//! | Service key certificates, release co-signatures, releases and their templates, the checkpoint | ✓ | | | | | | | |
//! | Post signals, session ends, telemetry, certificates, freshness statements (verified by their own signatures) | ✓ | | | | | | | |
//! | Put releases and their templates      |   |   |   |   |   |   |   | ✓ |
//!
//! A freshness signer is a key the latest state names in `freshness_keys`; it reads the
//! state it signs for. Public is what sealing and booting need and an attacker learns nothing
//! secret from:
//! public keys under guardian certificates, releases, co-signatures of public releases, the
//! log's checkpoint. Producers read nothing here (they seal through an enclave, whose bundle
//! holds the wrap keys). An enclave reads its bundle at boot, before the guardian released the
//! keys it would sign with, by attesting to the request instead.
//!
//! | Method | Path                                               | Body / Response                     |
//! |--------|----------------------------------------------------|-------------------------------------|
//! | GET    | /v1/tenants/{tenant}/bundle                        | → `TenantBundle`                    |
//! | GET    | /v1/tenants/{tenant}/documents?since_version=V     | → `Documents`: the whole root chain, the logged states of a version above V (all without V) oldest first, each with the proof fetched when it was logged, and the log's latest checkpoint |
//! | PUT    | /v1/tenants/{tenant}/root                          | `LoggedRoot` (appends to the chain) |
//! | PUT    | /v1/tenants/{tenant}/state                         | `LoggedState`, or a `SignedTenantState` the control plane logs (version must increase) |
//! | GET    | /v1/tenants/{tenant}/proposals                     | → `[Proposal]`, the open ones, oldest first |
//! | PUT    | /v1/tenants/{tenant}/proposals/{id}                | `Signed<TenantState>` or `Signed<TenantRoot>` whose digest is `id`, with any signatures → `Proposal`; signatures from repeated PUTs are merged |
//! | DELETE | /v1/tenants/{tenant}/proposals/{id}                | → 204                               |
//! | POST   | /v1/tenants/{tenant}/proposals/{id}/submit         | → `Submitted`: the document logged and stored as the next root or state, once it has the latest root's threshold of signatures |
//! | POST   | /v1/tenants/{tenant}/freshness                     | `SignedStateFreshness` from a tenant-run signer (one of the latest state's `freshness_keys`) |
//! | POST   | /v1/tenants/{tenant}/signals                       | `SignedSignal` (append, dedup; telemetry key or source key) |
//! | POST   | /v1/tenants/{tenant}/session-ends                  | `SignedSessionEnd` (append, dedup; telemetry key) |
//! | GET    | /v1/tenants/{tenant}/service-key-certificates      | → `[SignedServiceKeyCertificate]`, every one posted |
//! | POST   | /v1/tenants/{tenant}/service-key-certificates      | `SignedServiceKeyCertificate` (append, dedup; enclaves post theirs at boot; the platform's guardian key) |
//! | GET    | /v1/tenants/{tenant}/telemetry?since=T&after=C&limit=N | → one page of `[SignedTelemetryBatch]` with entries at or after `T`, by stream and sequence, after cursor `C` (`<stream hex>-<sequence>` of the previous page's last batch); at most `N` (≤ 1000) batches and about 768 KiB. Ask again until a page is empty |
//! | POST   | /v1/tenants/{tenant}/telemetry                     | `SignedTelemetryBatch` (append; gaps in `stream`/`sequence` are visible; telemetry key) |
//! | GET    | /v1/tenants/{tenant}/release-cosigns/{measurement} | → `Signed<ReleaseCosign>`           |
//! | PUT    | /v1/tenants/{tenant}/release-cosigns/{measurement} | `Signed<ReleaseCosign>`             |
//! | GET    | /v1/releases/{platform}                            | → `[ReleaseEvidence]`, every one stored for the platform, in log order |
//! | GET    | /v1/releases/{platform}/{measurement}              | → `ReleaseEvidence`                 |
//! | PUT    | /v1/releases/{platform}/{measurement}              | `ReleaseEvidence`                   |
//! | GET    | /v1/releases/{platform}/{measurement}/template     | → the release's deployment template (JSON; Azure: the ARM template with its `ccePolicy`) |
//! | PUT    | /v1/releases/{platform}/{measurement}/template     | the template (a JSON object; the release's evidence stored first) |
//! | GET    | /v1/checkpoint                                     | → latest fresh `SignedCheckpoint` (proxied from the log) |
//!
//! Proposals hold documents waiting for admin signatures, so admins sign one after another
//! (M-of-N); the control plane logs a document only when it is submitted. A proposal is
//! dropped once submitted, withdrawn, or overtaken (a root no longer above the chain, a state
//! no longer above the current one). Every signature a PUT brings must verify for an admin key
//! of the root the document needs: the latest one, or for a state signed for the next root,
//! a proposed next root.
//!
//! A release template is opaque here: `seal deploy` checks that its measurement is the
//! verified release's before using it.
//!
//! The bundle omits signals and session ends that are no longer live under the tenant's
//! latest state (`IntegrityPolicy::is_live`, `SessionEnd::is_live`). Its `freshness` holds
//! the log's newest statement for the latest state (refetched from the log at least hourly)
//! and the newest tenant-run statement, if any. Its `wrap_keys` are fetched from the guardian
//! of each of the tenant's `platforms` (`GET /v1/wrap-keys/...`) for every accepted tenant
//! key version; they are certified, so the control plane cannot substitute its own. Its
//! `anchors` are the newest `TenantAnchor` of each of those guardians (`POST /v1/anchors/...`,
//! asked again once an hour old), its `states` the stored states with their proofs from where
//! every verifier finds an anchor (`seal_verify::anchor_index`), and its `checkpoint` the log's
//! latest: bundles carry about a day of states however often the tenant changes.
//!
//! Browsers reach it from the console's origin only (CORS, preflight included). Successful
//! writes answer 204 (proposal writes answer the proposal or what it became); refusals
//! answer `{"error": "..."}` with 400 (malformed or junk), 401 (no credential, or one that
//! does not verify), 403 (a credential this request does not admit, or a signature that does
//! not verify against the keys above), 404, 409 (conflicts with what is stored or logged:
//! version not increasing, root not extending the chain, state the log has not recorded) or
//! 503 (the log is unreachable).

#![forbid(unsafe_code)]

pub mod client;
