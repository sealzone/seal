# Seal contract

This is the single description of Seal's public interface: roles, SDK surface, runtime
ports, per-crate ownership, request binding, vocabulary and known limits. Crate boundaries,
dependency rules and topology live in [ARCHITECTURE.md](ARCHITECTURE.md). If this file and
a crate's public signatures disagree, the code wins and this file is corrected.

**Status:** pre-release; interfaces may still change. What is built, and what is only
specified, is listed in [ARCHITECTURE.md](ARCHITECTURE.md#scope).

**Wire format v1 is frozen.** Every type that is signed, hashed, used as associated data or
read by a guardian has canonical bytes and digests in
`crates/shared/seal-proto/tests/vectors/wire-v1.json`, and a test fails if any changes.
Within v1 a type may only gain optional fields that are omitted when unset, so existing bytes
stay identical, and labels never change; anything else is a new label version (`…/v2`) next
to the old one. A frozen guardian decodes these bytes for its whole life, and checks signatures
over what it re-encodes, so it refuses a document carrying a field it was built without: every
field a tenant may set must be in the guardian before it freezes.

## Vocabulary

| Term | Meaning |
| --- | --- |
| seal | Encrypt a secret with its policy into a portable blob (`Client::seal`, `/v1/blobs`) |
| open | Decrypt a blob: literally open the seal. Only the enclave does it (`BlobCipher::open`) |
| session | Use a blob through the enclave without receiving its plaintext (`Client::session`, `/v1/sessions`) |
| extend | Replace a session's token with a fresh identity proof (`Session::extend`, `/v1/sessions/extend`, `TunnelPreamble::Extend`) |
| end | Stop a session before its token expires, on every replica (`Session::close`, `/v1/sessions/end`, `Verdict::End`; recorded as a `SessionEnd`) |
| signal | An input saying an endpoint may be compromised: a workload about itself (`signal`, `/v1/signals`), a detector or an external source |
| integrity | The tenant's policy acting on signals; the App Integrity add-on extends it (`seal_proto::integrity`, `seal-integrity`) |
| telemetry | The signed record of what the enclave did; only the enclave writes it (`seal_proto::telemetry`, `seal telemetry`) |
| `PlatformMasterKey` | Per-platform root key; exists only inside that platform's guardian |
| `TenantRootId` | Which tenant beyond its name: the digest of its root v1. Every tenant key derives from it, blob headers carry it, deployments pin it (`SEAL_TENANT=<tenant>@<root id>`) |
| `TenantWrappingKey`, `TenantWrappingKeyScope` | The private X25519 wrap key for one (platform, tenant, root id, tenant key version); only that platform's enclaves get it |
| `TenantWrapKey` | Its public half, certified by that platform's guardian; any enclave HPKE-wraps a blob's DEK to it, so blobs work on every platform the tenant enables |
| `TenantKeyVersion`, `TenantKeyVersions { current, oldest_accepted }` | Version of a tenant wrapping key; the tenant's accepted window |
| `ServiceKeyVersion`, `ServiceKeyScope` | Version of one tenant's service key set (token, ingest, telemetry, TLS, ticket); no service key is shared across tenants |
| `ServiceKeyCertificate` | The guardian's signed statement that it released a tenant's service keys; SDKs require it |
| `StateFreshness` | "This `TenantState` is the tenant's latest as of T", signed by the log (and a tenant-run signer if named); a state without a current one is not used |
| pending window | How long a state or root that widens access waits in public before it takes effect (`TenantState::pending_window_secs`, at most `MAX_PENDING_WINDOW_SECS`, 24 h; omitted when 0, and a written 0 or a longer window does not decode, so each window has one signed encoding); narrowing changes apply at once (`seal_verify::change`) |
| network rule | The networks an app may start, extend and connect sessions from (`TenantState::app_networks`, CIDR in one canonical spelling, `seal_proto::net::Cidr`), checked by the enclave against the connection's source address at session start, extend and every data connection; an app with no rule may connect from anywhere, one with an empty rule from nowhere, an unknown source is in no network. Adding an app's first network narrows, adding another widens, removing one narrows, removing the rule widens (`seal_verify::change`). It guards a credential used from elsewhere, not against the host, which controls the network, and only where replicas see clients' own addresses: Azure Container Instances with a public IP translates every caller to a private address, so on Seal-hosted replicas there a rule cannot tell callers apart. Omitted from states that use none. Set with `seal grant network APP CIDR…` |
| state in force | The state, and the root that signed it, that verifiers apply (`VerifiedTenant::state`, `root`); a newer state that widens it is pending until its window passes (`latest_state`, `pending`) |
| `TenantAnchor` | A guardian's signed statement that a state was in force at a time (`POST /v1/anchors`); verifiers start from it, so a bundle carries only about a day of states |
| proposal | A root or state on the control plane collecting admin signatures one at a time; once it has the latest root's threshold it is submitted: logged and stored |
| deployment identity | Who runs an enclave replica: an ACI group's managed identity, a Nitro parent's instance role, or a Confidential Space VM's project and service account; it must be in `TenantState::deployments` before the enclave requests keys. Seal's hosted entry (an Azure or Confidential Space identity) also carries a `HostedMode` |
| `HostedMode` | Marks the tenant's signed deployment entry for Seal's hosted replicas: `HostedMode::Sessions`, they seal and serve sessions like the tenant's own replicas, and exit when idle |
| front door | What `<tenant>.enclave.seal.zone` resolves to: a Seal-run TCP front that reads only the TLS SNI, starts the tenant's stopped hosted replica on a connection, holds the connection until the replica serves and then splices it through; TLS stays end to end, pinned to the attested key. The SDK knows nothing of it: it retries unreachable endpoints for `UNREACHABLE_WAIT_SECS` |
| periodic attestation | The enclave attests every `ATTESTATION_REFRESH_SECS` (30 s) and serves that to every client, who accepts it within `ATTESTATION_MAX_AGE_SECS` (120 s) |
| `ProofTicket`, `TicketKey` | Stateless, MAC'd challenge an identity proof binds to, and the key that issues it |
| `ConsumerTier`, `PlatformTier` | One assurance floor per attacker: `ConsumerTier` (Base < Hardened) is how much the *endpoint* proved — Base is identity, grants and the artifact rule; Hardened adds verified integrity evidence at every start and extend. `PlatformTier` is how well the *enclave* is protected |
| `SpkiPin` | SHA-256 of an upstream key the sealed policy requires in the upstream's certificate chain |
| `TrustedTime` | The current time as an interval (`now ± radius`); every check takes one |
| `ErrorCode::Expired` | Blob past `expires_at`, or its tenant key version retired |
| `ErrorCode::SessionEnded` | The session was ended early; start a new one |
| `ErrorCode::ResealRequired` | The blob has no DEK wrap for the enclave's platform: it was sealed before the tenant enabled that platform; seal it again |
| `Verified*` | What a verifier returns: `VerifiedEvidence`, `VerifiedRelease`, `VerifiedCheckpoint`, `VerifiedTenant`, `VerifiedEnclave` |
| `*Permit` | What a decision returns; the enclave acts only by consuming one |

New blobs use `current`. Advancing `current` alone does not reject older blobs: retirement
means advancing `oldest_accepted` and applying that state, and it does not erase keys already
released. KDF label strings (`seal_crypto::kdf`) are frozen and need not match type names.

## Roles

| Role | Authority | Does not imply |
| --- | --- | --- |
| Producer | Supply plaintext, seal for named apps | Permission to start a session |
| Consumer | Start sessions on blobs for an app matched by its identity and listed in the blob policy | Permission to seal |
| Admin | Sign tenant roots/state and manage producer/app grants | Runtime producer or consumer authority |

- An admin can change grants, but updated grants confer runtime permissions only once
  verified and applied. Storage write credentials alone cannot authorize unsigned changes.
- A workload may hold both producer and consumer roles only through independent grants.
- Roles are grants checked by the enclave, not SDK types: one `seal::Client` exposes every
  operation, and calls the workload is not granted fail with `NotAllowed`.

## SDK surface (`sealzone` on crates.io and PyPI, used as `seal`)

One client does everything a workload may do. Whether it may seal (producer grant) or start
sessions (app grant) is decided by the enclave on every call, from the tenant's signed
grants; the SDK has no role types.

```rust
let seal = seal::Client::from_env().await?;            // or Client::builder()…connect()
let blob = seal.seal(secret, "https://api.openai.com/v1", ["checkout"])
    .header("x-api-key")                               // format, pin, expires, methods, deny, sealed_only, hardened_only
    .await?;
let s = seal.session(&blob).http().await?;             // min_tier, reload_with, on_reseal, endpoint_reporter
let (url, key) = (s.url(), s.key());                   // .database() → db.dsn(); s.info()
s.close().await?;
seal.signal("edr-alert", Severity::High).await?;
```

```python
blob = seal.seal(secret, to="https://api.openai.com/v1", apps=["checkout"], header="x-api-key")
with seal.session(blob) as s:                          # HttpSession or DatabaseSession, per the blob
    client = OpenAI(base_url=s.url, api_key=s.key)
```

- **Shape**: required arguments are positional (Rust) or required keywords (Python);
  options chain before `.await` (Rust) or are keywords (Python). Both languages use the same
  names. Bad arguments surface as `ClientError::Invalid` (`BadRequest`).
- **`Client::from_env`** reads `SEAL_ENDPOINT` (the tenant's enclave replicas,
  comma-separated) and `SEAL_TENANT` (`<tenant>` or `<tenant>@<root id>`) and uses the first
  identity `detect_identity` finds; `Client::builder()` sets any of them explicitly.
  Identity hints: `SEAL_APP_KEY`; `SEAL_AZURE_AUDIENCE` (Azure managed identity, with
  `AZURE_CLIENT_ID`); GitHub's `ACTIONS_ID_TOKEN_REQUEST_*`; `SEAL_KUBERNETES_TOKEN_FILE`
  (default `/var/run/secrets/seal.zone/token`); the GCP metadata server; the AWS credential
  chain (`aws` feature).
  Replicas share keys and template-fixed ports, so a session works on any of them and the
  SDK fails over to the next one without a load balancer. Producers outside the tenant's
  network (CI runners, laptops) use Seal's hosted replica for the tenant
  (`<tenant>.enclave.seal.zone`), which also serves sessions; blobs sealed there open in the
  tenant's own replicas, and the other way round. A tenant that wants its apps only on its own
  replicas gives them only those endpoints, or disables Seal's.
- **Unreachable replicas**: when a pass over the endpoints reaches none of them (no TCP
  connection and TLS handshake within the 10 s connect timeout, or, when verifying, no
  attestation served), at connect, when re-verifying past `ATTESTATION_MAX_AGE_SECS`, or on any
  API call, the SDK repeats the pass
  with backoff (2 s, doubling to 15 s) until a replica answers or `UNREACHABLE_WAIT_SECS`
  (120 s) pass; then it fails with `Unavailable`. Every client does this, whatever its
  endpoints: it rides out a replica restarting, and a Seal-hosted replica that Seal's front
  door is starting on the connection. An API request is retried only when no connection was
  made, so none is sent twice. Whatever answers is verified as on any call: a failed verification, a key other
  than the attested one or an error code from the enclave is the result at once, never
  retried. A tunnel holds an app connection the same way while no replica is reachable, until
  the app closes it or the tunnel stops.
- **Release trust**: what the client verifies enclaves against, a `seal::Trust`
  (`seal_verify::Trust`; its JSON is `trust.json`'s, as in `deploy/example/trust.json`).
  Default: the trust compiled into the SDK build: `crates/sdk/seal-client/release-trust.json`,
  Seal's production trust (committed and published with the `sealzone` crate, so every SDK and
  every build from crates.io carries the same anchors), or the file `SEAL_RELEASE_TRUST` names
  at build time instead; a build without either fails
  to connect with `VerificationFailed` until given one. `ClientBuilder::trust` takes another,
  usually `seal::Trust::from_json` of a published `trust.json` (`BadRequest` on unknown fields
  or a threshold or quorum of 0 or above its keys). It is code or build input, never the
  environment: only sim builds read `SEAL_TRUST`.
- **Verification**: the client checks the enclave's periodic attestation (`GET
  /v1/attestation`: evidence from Azure, Nitro or Confidential Space, release, binding with
  `attested_at` within `ATTESTATION_MAX_AGE_SECS` of its clock), and accepts the enclave only with the guardian's
  `ServiceKeyCertificate` for exactly the keys it attests to
  (`seal_verify::verify_service_certificate` with `Trust::guardians`). The certificate exists
  only for keys the guardian released, so the guardian's time lock, revocations and the
  tenant's co-signature protect SDK traffic too: an enclave that made up its own keys is
  refused. A root id (from `SEAL_TENANT=<tenant>@<root id>` or `ClientBuilder::root_id`) also
  refuses enclaves serving another chain for the tenant's name.
- **`seal(secret, to, apps)`** builds the `SecretPolicy` (every policy check applies) and
  HPKE-seals secret and policy to the attested ingest key; it returns the `seal1.…` text.
- **`session(blob)`** ends with `.http()` → `HttpSession` (`url()`, `key()`),
  `.database()` → `DatabaseSession` (`dsn()`, `protocol()`: Postgres, Redis or ClickHouse),
  or `.await` → `Session::{Http, Database}` for code that handles any blob. These are the
  frozen `s.url`, `s.key`, `s.dsn`. The kind comes from the blob's clear-text policy, so
  asking for the wrong one fails with `Invalid` before anything is sent. Every session has
  `info()`, `extend` (the tunnel extends by itself; this extends now) and `close`, which ends it on the server and
  waits for cleanup; drop starts the same in the background. Session options:
  `reload_with` re-reads the blob on `Expired` (e.g. after a rotation); `endpoint_reporter`
  defaults to `integrity::ExecutableHash` and receives the request's `evidence_challenge()`
  (the digest of the request with the report stripped — computable before the report
  exists, where `expected_purpose()` would be circular). `integrity::HostAgentReporter`
  (App Integrity add-on) asks the seal host agent over the local `host-agent/v1` socket and
  puts the agent's artifact and signed, challenge-bound evidence into the report, falling
  back to `ExecutableHash` whenever the agent is absent, so hosts without the add-on keep
  passing the artifact check. `ResealRequired` says which attested platform the
  blob was not sealed for ("this blob was sealed before Azure (ACI) was enabled; reseal it").
- **Everything a caller touches is re-exported** from `seal` (`Severity`, `ConsumerTier`,
  `SessionInfo`, `ErrorCode`, `Trust`, …); no one needs `seal_proto` directly.
- `IdentityProvider` proves workload identity; `detect_identity` picks one.
- `admin` (`Admin`, `ControlClient`, re-exported from `seal_control::client`, and `LogClient`)
  is a separate surface for the CLI. Everything it fetches is verified before it is shown or
  re-signed. Its control-plane requests carry a console control token or are signed with an
  admin key (`SigningKeyCredential`; a freshness key for `seal settings freshness sign`); the
  write token only publishes releases and stores a development registrar's root version 1.
  Changes go through proposals: `Admin::draft` builds the next state on the state in force
  (the latest version + 1, under the latest root) and classifies each difference;
  `propose_document`, `cosign`, `meets_threshold`, `submit` (which checks the logged
  document's inclusion) and `withdraw` collect M-of-N signatures across machines and
  browsers. `seal::built_in_trust()` is the trust `SEAL_RELEASE_TRUST` named at build time.
- **The `seal` CLI** (`sealzone-cli`) keeps no admin key and no credential in `$SEAL_HOME`:
  `config.json` names the tenant, its root id, its console workspace and the URLs of the
  console, the control plane and the log (Seal's by default). The trust is the one built in,
  or `--trust FILE` (also `SEAL_TRUST`: the CLI's own option, unlike the SDK's).
  - `seal login` signs in to the console with a device code approved in the browser (`POST
    /api/v1/cli/device`, then `POST /api/v1/cli/token` every `interval` seconds:
    `authorization_pending`, `slow_down` adds 5 s, `access_denied` and `expired_token` stop).
    The `sealcli_…` bearer token goes to the OS keychain (service `seal`, account
    `console:<origin>`); a host without one (servers, containers, SSH) keeps it in
    `$SEAL_HOME/logins/<console host>`, readable only by its owner, and `seal login` says so
    before it asks for a code. `SEAL_CONSOLE_TOKEN` overrides both; `seal logout` revokes it.
    `seal use TENANT` takes the root id and workspace from `GET /api/v1/tenants/{t}`, and
    verifies the root chain against the trust and the state against the log before saving.
  - Each change (`seal grant|revoke app|producer|enclave|network …`, `seal settings …`, `seal
    deploy azure`'s grant) is drafted on the verified state in force and shown as its classified
    differences. By default it is then proposed with a `submit` control token (`POST
    /api/v1/tenants/{t}/control-token`, five minutes, renewed as needed), its console page
    (`/tenant/change?w=&t=&id=`) opened for the admins' passkeys, and followed: the CLI
    submits it once it has the root's threshold and reports it logged (Ctrl-C leaves it
    pending; `--no-wait` exits at once). `--key-file F` (repeat for M-of-N) signs here and
    publishes when the keys meet the threshold, else proposes with their signatures. Changes
    to the admin keys or the threshold (`seal settings admins add|rm|threshold`) propose the
    next root and the state re-signed under it, submitted together. Read commands need only
    the login (or a `--key-file` key) and take `--json`.
  - `seal changes` lists open proposals and logged states not yet in force; `seal changes
    show|sign|submit|cancel ID` act on one (an id prefix will do); `sign` with `--key-file`
    submits a state that reaches the threshold. `seal changes --watch [--once] [--interval D]
    [--json]` follows pending roots and states, verified locally (with the log's own
    freshness statement, so a control plane hiding a newer state fails it); `--once` exits 0
    when nothing is pending and 3 when something is. `seal status --log` also scans the log for
    roots of the tenant outside its chain and for stale freshness statements.
  - `seal key create [--out F]` writes an Ed25519 key file (the user keeps it; `seal settings
    admins add KEY` or the console's Admins page makes it an admin); `seal key public F`
    prints its public key. Every key the CLI generates (`seal key create`, `seal grant
    app|producer … key --generate`, `seal settings telemetry-readers add --generate`) is
    written only where asked, never replaces a file, never goes to a terminal, and is shown by
    its public key; grants list app keys by public key.
  - `seal dev init --tenant T --key-file F --registrar-key R` (development registrars; hidden
    from the help) creates root version 1 and state version 1 [`--pending-window D`], and
    resumes a failed run given the same admin key, registrar keys and options (the root is
    deterministic): it reuses a logged root v1 that is its own, returns a tenant whose state
    the control plane already holds, and supersedes a state the log recorded but the control
    plane never got (`Initialized::resumed`).
  - Exit status: 0 done, 1 an error (with the next step to take), 2 a usage error, 3 `seal
    changes --watch --once` found something pending, 130 stopped following a proposal.
- `seal-py` (PyPI `sealzone`, `import seal`) binds the same client. `seal.Client(endpoints=,
  tenant=, root_id=, identity=, trust=)` connects (unset arguments from the environment, as
  `from_env`; `trust` is a `trust.json` path, or its JSON as bytes, else the wheel's own); `await seal.AsyncClient.connect(...)` is the asyncio form; module-level
  `seal.seal`, `seal.session` and `seal.signal` use `seal.default_client()`. `seal(secret, *,
  to, apps, header, format, pin, expires, methods, deny, sealed_only, hardened_only, with_receipt)` returns
  the blob, or `(blob, receipt)`. `session(blob, *, kind, min_tier, reload_with,
  on_reseal, endpoint_reporter)` returns an `HttpSession` (`url`, `key`) or a
  `DatabaseSession` (`dsn`, `protocol`), with `info`, `receipts()`,
  `extend()`/`aextend()` and `close()`/`aclose()`; leaving `with` / `async with` closes it,
  and closes once more if that close failed. Errors are `seal.SealError` subclasses named
  after `ErrorCode` (`seal.BadRequest` is also a `ValueError`), with `code` and `retryable`.
  Identities:
  `seal.AppKeyIdentity`, `AzureManagedIdentity`, `KubernetesIdentity`, `GcpIdentity`,
  `GitHubActionsIdentity`, `AwsIdentity` (`aws` feature). Enum values are their wire names
  (`severity="high"`, `min_tier="hardened"`). Where Python differs: callbacks run on a worker thread and may be coroutine functions. One tokio runtime
  per process runs every call; blocking calls release the GIL and stay interruptible. A forked
  child (gunicorn, Celery prefork) gets its own runtime and default client, and clients and
  sessions made in the parent raise `RuntimeError` there; a child's copy of a parent's
  session is never ended by the child.

### Sessions

The proxy runs in the enclave: the protocol adapters parse traffic, inject the secret and
enforce the policy. Next to the app runs only the SDK's tunnel, a loopback byte forwarder
that never sees the secret. Apps reach the data plane through it alone: `url`, `key` and
`dsn` name the tunnel on `127.0.0.1`, the key is a local key worthless elsewhere, and the
session token never leaves the SDK.

- **Start** (`POST /v1/sessions`): identity proof, blob, options and endpoint report → a
  token valid `SESSION_TOKEN_SECS` (10 min) for a new random `session_id`.
- **Extend** (`POST /v1/sessions/extend`): the granted tier is recomputed from the
  fresh endpoint report, so a hardened floor holds for the session's whole life. The SDK
  re-proves its identity every
  `SESSION_EXTEND_SECS` (5 min). The enclave requires the same caller, rechecks grants,
  suspension, expiry and the endpoint report, and issues a new token for the same
  `session_id`. So identity is re-verified at least every 5 minutes. A workload disabled at
  its identity provider loses access within one extend for app keys, SigV4 (replayed to STS
  each time), GitHub and Kubernetes (tokens refused when older than
  `MAX_OIDC_TOKEN_AGE_SECS`, 10 min); Azure and GCP serve cached tokens, so theirs keep
  working until they expire (Azure managed identity: up to 24 h).
- **Extend live connections**: the tunnel extends at half the token's remaining life, then
  sends `TunnelPreamble::Extend` with the new token to every replica holding one of its
  connections; the replica moves their expiry. Connections that are not extended close at
  expiry. A `SessionExpired` extend restarts the session on the same blob, `Expired` restarts
  through `reload_with`, and `SessionEnded` or `IntegrityFailed` stop the tunnel for good.
- **Wire**: `POST /v1/blobs` carries `canonical(SealPayload)` HPKE-sealed to the attested ingest
  key (info `ingest_info(tenant)`, AAD `canonical(IngestContext)`); the SDK refuses a returned
  blob that does not name its tenant, the attested root and exactly the policy it sent. A
  destination whose protocol the image has no adapter for (ClickHouse, until it is built) is
  `BadRequest`. A replica has one port, its endpoint's: the API, and tunnel connections, which offer TLS ALPN
  `seal_proto::tunnel::ALPN` (`seal-tunnel/1`) instead of `http/1.1`, are pinned to the
  attested key and start with the tunnel preamble; the session's blob says the protocol that
  follows. Names play no part (the certificate carries one fixed name): a replica is reached
  at whatever address `SEAL_ENDPOINT` lists; the release templates use port 8443. A replica that
  serves no sessions (draining, or not listed in the state in force) drops a tunnel on its
  ClientHello, before the handshake.
- **Tunnel connections**: each goes to the replica that last answered; when it does not, the
  others are tried at once and the first to answer is used from then on. After a connection
  takes it, the tunnel opens one spare, handshaken and kept at most 20 s (under the
  enclave's 30 s wait for a preamble), so connections that come in bursts skip TCP and TLS;
  the preamble goes out with the app's first bytes.
- **End** (`POST /v1/sessions/end`, authorized by the token alone): the replica signs a
  `SessionEnd`, closes its connections of the session at once and publishes it; the others
  refuse the session's tokens and close its connections within `STATE_RELOAD_SECS`. The
  SDK ends a session in `close(&self)`: the first call stops extending and closes the tunnel
  whatever the answer; on an error (the replica ended the session but could not publish its
  `SessionEnd`) calling it again resends the end, which the replica republishes; after one
  succeeds it does nothing. A closed session is never extended or restarted, and dropping one
  not closed successfully sends one more end in the background. The enclave ends one itself when a detector's finding maps
  to `Verdict::End`. The tunnel never restarts an ended session.
- **Every connection and request** is checked against the session (expiry, grants,
  suspension) and passes `Session::observe`. Live connections are rechecked on every tenant
  state change.

### How access ends

Seal does not store blobs, so it has no per-blob kill switch. Access ends through:

| Mechanism | Scope | Who |
| --- | --- | --- |
| `expires_at` in the sealed policy | One blob, every copy of it | Producer, at seal time |
| Removing an identity from an app's grants, or a producer from `producers` | Every session that identity starts, or on blobs that producer sealed | Admin (signed tenant state) |
| Removing a deployment from `deployments` | Everything the replicas with that identity serve, but attestation and session ends | Admin (signed tenant state) |
| Raising `oldest_accepted` | Every blob below that tenant key version | Admin (signed tenant state) |
| Revoking the credential at the upstream | The secret itself | Whoever owns the upstream account |
| Ending the session (`SessionEnd`) | One session: its tokens and every connection | The client (`close`), or the enclave on an integrity finding |
| Integrity suspension | Everything one identity does | Tenant integrity policy, on signals (below) |

Live sessions are rechecked whenever the tenant's verified state changes
(`Session::ended`), so a grant removal or a published `SessionEnd` also ends connections
already established, once a replica has loaded the new state. The admin mechanisms narrow
access, so they apply as soon as they are logged, whatever the pending window. Rotating means sealing the new value (`seal secret`); revoking the old
credential at the upstream is the producer's job.

The admin mechanisms hold against replay: a state is used only with a current
`StateFreshness` for exactly it, so nobody (a control plane, a host restarting replicas, a
holder of a revoked credential running their own enclave) can bring back an older state
for more than `STATE_FRESHNESS_SECS` (24 h). See "Binding and freshness".

## Telemetry and integrity

**Signals in, telemetry out.** Three words cover everything here:

- **Signal**: an input saying a workload's endpoint may be compromised. The SDK, host
  agents, in-enclave detectors and external systems (EDR) send signals; none of them write
  telemetry.
- **Integrity**: the tenant's policy acting on signals (log, refuse, end the session,
  suspend the identity). The App Integrity add-on plugs detectors and evidence checks in.
- **Telemetry**: the signed record of what the enclave did, including what it did about each
  signal. Only the enclave writes it, so a compromised endpoint can send signals but never
  write history. Metrics (specified, not built) are telemetry aggregated.

```
 SDK / host agent ─ endpoint report, self-signal ─┐
 EDR / external ─── signal (control plane) ───────┤ signals
 adapter ─ Observation (before forwarding) ───────┤──► integrity: detectors, policy
                                                  │      └─► Verdict (forward / refuse / end)
 adapter ─ Completion (after) ─┐                  │
 runtime ─ seal, session, extend, end, refusal ───┴──► telemetry: one entry per event,
                                                         signed batches → control plane
```

| Crate | Telemetry | Integrity |
| --- | --- | --- |
| `seal-proto` | `telemetry`: `Completion`, `TelemetryEntry`, `TelemetryEvent`, `TelemetryBatch`, `TelemetryReceipt` | `integrity`: `EndpointReport`, `IntegritySignal`, `IntegrityPolicy`, `Severity` |
| `seal-enclave` | the `Telemetry` port | applies `IntegrityPolicy` |
| `seal-integrity` | | in-enclave plug-ins: `Observation`, `Verdict`, `Finding`, `Detector` (`observe`, `complete`), `EvidenceCheck` |
| `seal-client` | `admin::ControlClient::get_telemetry` | `integrity`: `EndpointReporter`, `ExecutableHash`; `signal` |

Adapters stay upstream-only. They report each request to their session twice:
`Session::observe(Observation)` before forwarding, obeying the returned `Verdict`, and
`Session::complete(Completion)` after it ends. They never judge integrity or write
telemetry, and never see the identity behind the session. The runtime attributes both
reports, runs the detectors, applies the policy and writes telemetry.

### Telemetry

- **Entries** (`TelemetryEntry`): time from the enclave's trusted clock (`seal_tee::Clock`), tenant, the acting
  identity, and a `TelemetryEvent`: `Seal`, `Session`, `Extend`, `End`, `Refused`, `Request`
  (one data-plane request with its `Completion`), `Integrity` (signal applied and the action
  taken) or `Dropped`. Entries are numbered across their stream.
- **Never contains** the secret, a credential, payload bodies or upstream-supplied text. An
  upstream error is recorded as its kind only: an HTTP status, or a Postgres `ErrorResponse`'s
  SQLSTATE (`UpstreamErrorKind::Sqlstate`, five digits or upper-case letters; `XX000` when
  malformed). A Postgres cancel request is a `Completion` with action `CANCEL`.
- **Shipping**: the `Telemetry` port batches entries into `TelemetryBatch`es signed with the
  enclave's telemetry key, posted to the control plane (`POST /v1/tenants/{tenant}/telemetry`). Each
  replica boot starts a random `stream` and numbers its batches, so the untrusted control
  plane can drop batches only visibly, and can never forge or edit them.
- **Encryption**: when `TenantState::telemetry_readers` names X25519 keys, entries are sealed to
  them (`TelemetryEntries::Sealed`) and Seal sees only batch metadata (stream, sequence,
  entry numbers, time range). Empty = entries in clear, still signed.
- **Receipts**: `SealResponse` and `SessionResponse` carry a `TelemetryReceipt` (stream, entry).
  A client that keeps them can prove an entry was withheld, even a whole stream the control
  plane never showed. The SDK hands them out (`SealBuilder::with_receipt()` →
  `(blob, receipt)`, `Session::receipts()` for the start and every restart) and appends them as
  JSON lines (`seal::receipts::append`, `seal secret --receipt-file F`), the format
  `seal telemetry --receipts F` reads.
- **Loss**: a replica flushes at least every `TELEMETRY_FLUSH_SECS` (5 s) and holds at most
  `TELEMETRY_BUFFER_ENTRIES` (10 000) unsent entries. When full it drops data-plane
  `Request` entries first and records every drop in a `Dropped` entry; requests are never
  blocked. A graceful shutdown marks its final batch `last`, so a stream without one may
  have lost its unsent tail (at most one buffer). Batches cover contiguous runs of entry
  numbers, so dropped entries show as gaps between batches that add up to the stream's
  `Dropped` counts.
- **Reading**: `GET /v1/tenants/{tenant}/telemetry?since=T&after=C&limit=N`
  (`ControlClient::get_telemetry`, `seal telemetry`), by console members and admins only. A
  page holds batches with entries at or after `T`, ordered by `(stream, sequence)`, strictly
  after the cursor `C` (`<stream hex>-<sequence>` of the previous page's last batch), at most
  `N` (default and maximum 1 000) and stops before 768 KiB of JSON (at least one batch); a
  short page is not the end, an empty one is. Readers verify batches with the telemetry public
  keys an enclave attests to (`AttestationBinding::telemetry_public_keys`, certified by the
  guardian; `seal_verify::telemetry::certified_keys`), decrypt sealed ones with a reader key,
  and report sequence gaps, streams without a `last` batch and receipts with no entry
  (`seal_verify::telemetry::analyze`, shared by the CLI and the browser).

### Integrity

Signals that a workload's endpoint may be compromised, and the tenant's rules for acting on
them. Seal treats signals as opaque: it acts only on **which
identity** and **how severe**. What a source detected, and how, stays with the source; the
signal carries a short `code` that is shown to admins and in telemetry, and never interpreted.
Integrating an EDR or a detector means producing `(identity, severity, code)`.

| Source | How it reaches Seal | Signed by |
| --- | --- | --- |
| SDK, at session start and extend | `EndpointReport` in `SessionRequest` / `ExtendRequest`, bound into the proof | enclave telemetry key (on mismatch: `AuthzError::ArtifactMismatch` carries the `artifact-mismatch` signal, severity `High`, for the caller) |
| SDK or host agent, about itself | `POST /v1/signals` (`Client::signal`); names only the caller | enclave telemetry key |
| In-enclave detector (SQL injection, unusual API calls) | adapters pass each request to `Session::observe`; `seal_integrity::Detector`s judge it | enclave telemetry key |
| The seal host agent (findings about its enrolled endpoints) | `POST /v1/signals` on a replica with a pre-signed signal (`SealService::signal`; the same endpoint takes the SDK's self-signal — the payload's shape picks the verifier); no workload proof — the signature is the authority | the agent's key, registered in `IntegrityPolicy::sources`: the receiving replica verifies it, applies the policy at once and publishes it |
| External system (EDR) | `POST /v1/tenants/{t}/signals` on the control plane (`ControlClient::post_signal`) | the source's key, registered in `IntegrityPolicy::sources` |

- **Policy** (`TenantState.integrity`, admin-signed): allowed artifacts per app, trusted
  external sources, the action per severity (`LogOnly`, `Deny`, `Suspend { secs }`; empty =
  log only), and clearances that lift a suspension.
- **Evaluation**: every replica evaluates the same policy over the same verified signals
  (`TenantBundle.signals`, invalid ones dropped), so replicas agree without coordinating.
  A host agent's finding rides the same rule through the replica that received it: verified
  against the registered source key, applied immediately (the identity's sessions on that
  replica end without waiting for `STATE_RELOAD_SECS`), then published for the others.
  The replica that creates a signal applies it at once; if the signal suspends, it also
  publishes it (`TenantStore::publish_signal`) and the others apply it within
  `STATE_RELOAD_SECS`. Every signal, published or not, is in telemetry.
- **Retention**: a signal is live while it suspends someone (`IntegrityPolicy::is_live`:
  `Suspend` action, not cleared, duration not run out). The control plane may drop signals
  that are no longer live under the latest policy.
- **Sources**: verification uses the latest state's `sources`, so removing a source (for
  example after its key leaks) voids all its signals and lifts their suspensions on the next
  reload; no per-identity clearing is needed.
- **Evidence**: `EndpointReport.evidence` is opaque. Each provider gets a
  `seal_integrity::EvidenceCheck` compiled into the image (`Components::evidence_checks`);
  evidence from a provider without one is ignored. A check receives the whole report, the
  evidence item, the public key the tenant registered for its provider in
  `IntegrityPolicy::sources` (one enrollment per source; `None` = not enrolled, ignore),
  and the `evidence_challenge()` of the request being authorized — so a check that
  verifies signatures holds self-asserted fields to signed ones and refuses evidence
  replayed from another request. None ship in the open build; the host-agent check is the
  add-on's.
- **Detector findings** take the action for their severity: `LogOnly` forwards the request,
  `Deny` refuses it (`Verdict::Refuse`), `Suspend` ends the session (`Verdict::End`, a
  published `SessionEnd`) and suspends the identity.
- **Suspension** stops the identity's session starts, extends and seals and ends its live sessions
  (`ErrorCode::IntegrityFailed`). Blobs it sealed keep working for other identities. It lifts
  when its duration ends or an admin clears the identity.
- **The artifact check is enforced**: an app listed in `artifacts` starts and extends sessions
  only with a matching `EndpointReport`. The report is self-asserted, so it catches drift and
  tampering, not an attacker who controls the endpoint. No detectors ship in this repository,
  evidence in `EndpointReport.evidence` is evaluated only by compiled-in evidence checks (none
  here), and in-enclave observation content never leaves the enclave.

## SecretPolicy

`SecretPolicy` is the one policy type shared by the SDK, encrypted upload, blob and
adapters. Its fields are private; constructors and JSON/CBOR decoding enforce the same
invariants (normalized destination and injection, at least one app, HTTP options only for
HTTPS destinations). HTTP is the first implementation; database destinations already fit
the contract. HTTP v1 paths reject encoded or ambiguous forms using `HttpPath`, shared by
policy validation and adapters.

**The policy cannot be changed without breaking the blob.** It travels in clear text next to
the header, so anyone can read where a blob may be used, but the header holds
`labeled_digest(POLICY_LABEL, policy)` and the header is the associated data of both AEAD
layers (the DEK wrap and the secret). Editing the policy breaks the digest check; editing the
digest too breaks decryption; making a new blob needs the tenant wrapping key, which only
attested enclaves hold. The policy reaches the enclave inside the HPKE-sealed upload, and
session requests carry no destination, so neither the network nor a consumer can redirect
a secret. The enclave uses only the policy of the `OpenedBlob`.

**The secret goes only to the sealed destination.** The adapter connects with
`UpstreamConnector::connect(policy.destination(), policy.pins())`, which uses the
destination's host for SNI and certificate verification. The HTTP adapter accepts
origin-form requests only, sets `Host` to the destination, relays redirects instead of
following them, and refuses `CONNECT` and `Upgrade`. Database adapters authenticate as the
destination's user and database, replacing what the client sent: Postgres drops startup
`options`, refuses replication and `FunctionCall`, and gives the client a `BackendKeyData` of
its own (random per connection, never the upstream's), so a `CancelRequest` naming it, on a
new connection to the same replica while the connection lives, passes `Session::observe`
(action `CANCEL`) and goes upstream with the upstream's key over a new verified TLS connection,
and any other pair is closed without a reply; Redis refuses re-`AUTH`
and `HELLO … AUTH`, commands outside the destination's db (`SELECT` of another db, `SWAPDB`,
`MOVE`, `COPY … DB`, `FLUSHALL`, `MIGRATE`), commands that break one reply per command
(`RESET`, `CLIENT REPLY OFF|SKIP`, `MONITOR`, `SYNC`, `PSYNC`, `REPLCONF`) and administration
(`ACL`, `CONFIG`, `MODULE`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, `SLAVEOF`, `FAILOVER`,
`CLIENT KILL|PAUSE|UNPAUSE`); the ClickHouse adapter (specified, a stub here) sets the
destination's database as the default.
Postgres authenticates upstream with SCRAM-SHA-256 only (SCRAM-SHA-256-PLUS bound to the TLS
connection when offered) and never sends the secret any other way.

**Secrets are at least `MIN_SECRET_BYTES` (16) long** (`SecretPolicy::validate_secret`, in
the SDK and the enclave at seal time). Adapters mask every echo of the secret, so a consumer
who can make the upstream return chosen text learns whether that text contains it; 16 bytes put
a random secret out of reach of that search.

**A session can do whatever the credential can.** That includes minting a credential the
consumer then holds (`ALTER ROLE … PASSWORD`, Redis `ACL SETUSER`, an API's key-creation
endpoint). Adapter command filters are best effort against dynamic SQL and scripts; the
control is least privilege at the upstream, plus `HttpRules` (`--deny` for key-management
paths) for HTTP.

**Tier floor** (`SecretPolicy::min_tier`, `--hardened-only`, `SealBuilder::hardened_only`):
only hardened sessions may use the blob. The enclave recomputes the achieved tier from the
fresh endpoint report at every start and extend, so the blob stops working within one
extend of the endpoint's attestation going silent; the replica records an `agent-silent`
signal when that is why a hardened start or extend was refused. Hardened is unreachable
in an image without compiled-in evidence checks for an enrolled source — hardened blobs
fail closed there rather than trust unverified bytes.

**Platforms** (`SecretPolicy::min_platform`, `--sealed-only`): the enclave wraps the DEK only
for the tenant's platforms at or above it, so a weaker platform the tenant enables later
cannot open the blob. Unset = every platform the tenant enables; omitted from the blob.

**Pins** (`SecretPolicy::pins`, `--pin sha256/<base64>`, at most `MAX_PINS` = 4) narrow the
baked roots for one blob: the upstream's chain must verify against the baked roots, and a
pinned key must be on a path that verifies (the leaf's key, or an intermediate or baked root
the leaf chains to; pin a CA key to survive leaf renewals; a pinned certificate merely sent
along does not count), otherwise `NetError::PinMismatch`. This stops a misissued certificate for the destination
host. Unpinned blobs carry no pin field at all; the first pin adds about 54 characters to
the blob text, each further one about 45.

Upstreams are TLS-only. `Destination` cannot represent a plaintext upstream: `http://`,
`redis://` and plain Postgres are refused at parse time, and a Postgres server that
answers `N` to `SSLRequest` is refused (`NetError::NoTls`), never downgraded. Upstream
certificates are verified against `seal_net::baked_roots()` only: the Mozilla set plus
the AWS RDS global bundle (`crates/shared/seal-net/certs/`). Azure Database and Azure Cache roots
are already in the Mozilla set. Any other CA needs a custom image.

## Enclave runtime (`seal-enclave`)

| Owner | Port | Implementations |
| --- | --- | --- |
| `seal-enclave` | `KeyProvider` | `ports::guardian::GuardianKeyProvider` (the sim guardian in sim builds) |
| `seal-enclave` | `TenantStore` | `ports::control::ControlTenantStore` over `seal_control::client` |
| `seal-enclave` | `ReleaseStore` | `ports::control::ControlReleaseStore` |
| `seal-cloud` | `Cloud` | Azure ACI, GCP Confidential Space and `Sim` (`Cloud::detect`): attestor, clock, dialer, tenant pin, deployment proof; AWS Nitro is a stub |
| `seal-client` | `IdentityProvider` | App key, Azure managed identity, GCP, GitHub Actions, Kubernetes, AWS (`aws` feature) |
| `seal-adapter` | `Adapter` | HTTP, Postgres, Redis; ClickHouse is a stub |
| `seal-net` | `Dialer` | TCP; vsock to the Nitro parent's egress proxy (a stub) |
| `seal-net` | `UpstreamConnector` | Verified TLS over the `Dialer` |
| `seal-enclave` | `Telemetry` | `ports::telemetry::ControlTelemetry` (batched, signed, posted to the control plane) |

- `KeyProvider::{service_keys, tenant_wrapping_key}` returns keys for exactly the requested
  `ServiceKeyScope` or `TenantWrappingKeyScope`, always the deployment's tenant and root;
  boot and key-cache code check this before use. Service keys come with the guardian's
  `ServiceKeyCertificate`, which the enclave serves in `AttestationResponse`. The platform
  master key never crosses this port.
- `Components::cloud` is the cloud the replica runs on (`seal_cloud::Cloud`, an enum with one
  variant per cloud plus sim). It is the only enclave input that differs between clouds: the
  rest of the runtime reads the same everywhere. `Cloud::deployment` returns a
  `DeploymentProof`: the ACI group's managed-identity token, a SigV4 request the Nitro parent
  presigned with its instance role, or the project and service account from the enclave's
  own Confidential Space attestation. Boot verifies it (`seal_authz::DeploymentVerifier`) against `TenantState::deployments` before
  requesting any key, so a genuine enclave someone deploys for a tenant that never authorized
  it holds none of that tenant's keys.
- **What a replica serves** comes from the entries of the state in force that match its own
  deployment identity, checked on every operation (`runtime/hosted.rs`):
  - none (the tenant removed it): everything but `attestation` and `end` fails with
    `NotAllowed`, data-plane connections are closed and live sessions end, within
    `STATE_RELOAD_SECS`;
  - an entry with a `HostedMode`: Seal's hosted replica, which serves as the tenant's own do
    and exits when idle; an identity listed more than once is hosted if any entry is.
  Only the tenant's admins sign entries and a widening one waits out the pending window, so
  neither Seal nor the host can make a replica the tenant did not list serve, or a customer's
  replica idle out.
- **Hosted replicas exit when idle.** A replica whose matching entry has a `HostedMode` stops
  once it has had no live session connection, and no `seal`, session, extend, end or signal by
  an authenticated caller, for `HOSTED_IDLE_SECS` (900); tickets, attestations and requests
  that fail authentication do not count, since anyone can send them. `SealService::idle_exit`
  resolves then and marks the replica draining under the lock that counts work in progress:
  later operations fail with `Unavailable` after authenticating and data-plane connections are
  closed. The binary stops accepting, lets open API requests finish, ships the `last` telemetry
  batch and exits 0. Customer replicas never exit.
- `TenantStore` serves the deployment's one tenant. `load` returns the complete
  `TenantBundle` (root chain, signed state, the states since an anchor with their proofs, a
  checkpoint, guardian anchors, integrity signals, ended sessions), because verification needs
  all of it; `publish_signal` and `publish_session_end` append what this enclave signed and
  already applied. `ReleaseStore::load` returns release evidence for the attestor's own
  measurement. Store contents are untrusted until verified, and storage is never
  authorization. The control-plane ports read with `ports::control::EnclaveCredential`:
  attested requests until `Telemetry::start`, then requests signed with the telemetry key.
- `Components::tenants` and `Components::releases` are independent; one backend may
  implement both. Providers are trusted injected components; `seal_guardian::client` and
  `seal_control::client` adapt to these ports without depending on the enclave crate.
- The sim environment runs the same ports against a dev log, a sim guardian and the control
  plane, with development signatures, never an unsigned protocol. Simulator acceptance stays
  behind the `sim` feature.
- `Components::detectors` and `Components::evidence_checks` are the in-enclave integrity
  plug-ins (`seal_integrity::{Detector, EvidenceCheck}`, none ship here); runtime sessions
  run detectors on every `Session::observe` and `Session::complete`.
- Compiled-in timing: `STATE_RELOAD_SECS` (30), `TENANT_KEY_CACHE_SECS` (900),
  `TELEMETRY_FLUSH_SECS` (5), `TELEMETRY_BUFFER_ENTRIES` (10 000), `HOSTED_IDLE_SECS` (900;
  sim builds take `hosted_idle_secs` in `SEAL_ENCLAVE_CONFIG`). Compile-time checks keep
  `SESSION_END_RETAIN_SECS` (900) ≥ `SESSION_TOKEN_SECS` + `STATE_RELOAD_SECS`, so a
  `SessionEnd` outlives every token a not-yet-reloaded replica can still issue, and
  `HOSTED_IDLE_SECS` ≥ `SESSION_TOKEN_SECS`, so no token an idle replica issued outlives it.
- `Cloud::tenant_pin` (a `TenantPin`, `<tenant>@<root id>`, delivered as each cloud allows)
  pins a deployment to one tenant and its root chain. Every other tenant or chain is refused with
  `NotAllowed` (seal, sessions, extends, ends, signals, session tokens), tickets are issued
  only for it, and keys are requested only for it. `StateCache` and `TenantStore`
  hold this one tenant. The deployer sets it and it is not attested; it can only narrow
  what the enclave serves.
- **Fail closed**: once the cached state's `fresh_until` passes without a fresh bundle,
  every operation and connection fails with `Unavailable`; every `TenantAuthorizer` decision
  also refuses a stale snapshot itself (`AuthzError::Stale`).
- `SealService::boot(config, components)` verifies release evidence against
  `ServiceConfig::trust`, then the tenant bundle (chain matching `root_id`, fresh state, the
  state in force worked out from its own platform's guardian anchors), then the deployment
  identity, and only then requests keys and checks their scopes and
  certificate, which it posts to the control plane. It exposes one method per
  enclave API operation (`attestation`, `ticket`, `seal`, `session` and `extend`, which take
  the request's peer address for the apps' network rules, `end`, `signal`, which also takes
  external findings), `idle_exit(idle)`, `admits_tunnel()` (asked on a
  tunnel's ClientHello) and `serve_tunnel(stream, peer)`, which takes a tunnel after its TLS
  handshake and owns the preamble's validation before invoking an adapter; `api::serve` runs
  both on the one port. Every operation
  that needs a decision acts only by consuming its permit (`SealPermit`, `SessionPermit`,
  `ExtendPermit`, `SignalPermit`); `end` needs only a valid token.
- Every operation and port fails with `ServiceError { code, detail }`; only `code` reaches
  a caller.
- `attestation()` keeps answering while the tenant state is stale (everything else fails
  closed) and fails only once the latest periodic attestation is `ATTESTATION_MAX_AGE_SECS`
  old. `ReleaseStore::load` runs at boot and on every periodic attestation, and the control
  plane ports replace the stored evidence's `fresh` checkpoint with the control plane's latest
  (`GET /v1/checkpoint`) when it covers at least as many entries, so the served evidence stays
  within `FRESH_CHECKPOINT_SECS`; every verifier still checks it. The API and tunnels share one TLS configuration
  (`SealService::tls_config`: the `[leaf, CA]` chain, ALPN `http/1.1` and the tunnel's).
- What a replica signs itself (a self-signal, an `artifact-mismatch`, a detector or evidence
  finding, a `SessionEnd`) is applied by verifying the latest bundle again with the item added
  and merging it into `StateCache`. Ending a session twice republishes the first `SessionEnd`.
  Detector findings that suspend also end the session; evidence-check findings other than
  `LogOnly` refuse the session start or extend with `IntegrityFailed`.
- Between clock reads, expiry checks use the last trusted reading advanced by the monotonic
  clock, its radius widened by 1 s plus 1 s per 1000 s, so a live connection may end up to about
  a second early.

## Per-crate ownership

| Crate | Public contract |
| --- | --- |
| `seal-proto` | Wire types. `Evidence` (one variant per platform; the platform is the tag); `TenantPin`; `SecretPolicy` with validated decoding, pins and `min_platform`; `blob`: HPKE DEK wraps per platform; `freshness`: periodic attestation timing, `GuardianChallenge`, `ProofTicket`; `time::TrustedTime`; `signed::Signed<T>`; `session`: tiers, claims (carrying the sealed blob), timing, `SessionEnd`; `state`: roots, `root_id`, state (with `pending_window_secs`), `LoggedRoot`, `LoggedState`, `TenantAnchor`, `StateFreshness`, `TenantBundle`; `identity`: matchers, `HostedMode`; `control`: `ControlRequest`, `AttestedControlRequest` (control-plane credentials); `release`: manifests, constraints with revocations, key requests, `ServiceKeyCertificate`, `TenantWrapKey`; `expected_purpose()` binds complete request bodies; `AuthenticationScope` persisted in session claims; `integrity`: endpoint reports, signals and policy; `telemetry`: entries, batches (clear or sealed) and receipts. |
| `seal-crypto` | `BlobSealer` builds headers, ids, nonces and one HPKE wrap per certified wrap key; `BlobCipher` opens with one platform's private wrap key and returns an authenticated `OpenedBlob`; `TenantWrappingKey` and `ServiceKeys` are bound to their full scopes; `PlatformMasterKey` derives per-tenant keys, the guardian key and the `ChallengeKey`; `TokenKey` issues and redeems tokens; `SigningKey` signs and cosigns; `TicketKey` and `ChallengeKey` issue and verify tickets and guardian challenges; `jws` verifies RS256/ES256 ID tokens under an algorithm the caller fixes. |
| `seal-tlog` | `LogVerifier` owns checkpoint and inclusion verification; `VerifiedCheckpoint` fields are private; `policy_not_loosened` is the witness rule over `ReleaseConstraints` (revocations only grow); the `dev` log logs tenant states and signs `StateFreshness`. |
| `seal-verify` | `Trust { releases, tenants, guardians }`, used by the guardian, the enclave, the SDK and the browser; `ReleaseVerifier` → `VerifiedRelease` (revocations applied), `TenantVerifier` → `VerifiedTenant` (root id, the root and state in force and since when, the latest root and state, every logged document with its `public_since`, `pending()`, `differences(version)`, freshness, verified signals and ended sessions; `merge` never moves back); both results are read-only; `TenantVerifier::{with_anchor_keys, anchor, verify_documents}`, `anchor_index`; `change` (`classify_state`, `classify_root`, `diff_states`, `diff_roots`); `telemetry` (`certified_keys`, `analyze`); `verify_service_certificate`; `attestation::verify` (an enclave's `AttestationResponse`: evidence, binding, release, guardian certificate, tenant and root; the SDK adds the presented TLS key, the browser seals to the ingest key). |
| `seal-attest` | `verify(&Evidence, time)` → `VerifiedEvidence` (with an attested deployment identity where the platform has one), `AttestError`; per-platform `measurement` helpers; `sim::{Document, sign}` so the sim attestor produces exactly what `sim::verify` accepts. Pure; the SDK's only TEE dependency. |
| `seal-tee` | `Attestor` (`detect`, `measurement`, `attest` → `Evidence`) and `Clock` (Roughtime; the Nitro hypervisor timestamp; sim), enums over the platforms; `TeeError`. Enclave and guardian only. |
| `seal-net` | `Dialer`, `TcpDialer`, `UpstreamConnector`, `baked_roots`, `HttpsClient`. |
| `seal-cloud` | `Cloud` (one variant per cloud: attestor, clock, dialer, `tenant_pin`, `deployment`; `detect` refuses AWS Nitro, which is designed but not built), `CloudError`. |
| `seal-authz` | `RequestAuthenticator` (context + identity proof together) → `AuthenticatedRequest`; `TenantAuthorizer` → `SealPermit`, `SessionPermit`, `ExtendPermit`, `SignalPermit`; `DeploymentVerifier`; `StateCache` (the one tenant). |
| `seal-guardian` | `Guardian::boot(config, GuardianComponents)` for one served platform, running on one platform; `KeySource` (Key Vault, Cloud KMS, predecessor, sim file), each returning the root itself; `KeyReleaseAuthorizer` → `KeyReleasePermit` holding the exact approved request; stateless `GuardianChallenge`s; `ServiceKeyCertificate`s; certified wrap keys (`GET /v1/wrap-keys/...`); `POST /v1/anchors/{tenant}/{root_id}` (`Guardian::anchor`: a `TenantBundle` in, a `SignedTenantAnchor` out); `GET /v1/identity` publishes the guardian key; `server::serve` (plain HTTP behind an untrusted TLS proxy; every refusal is 403 `denied`); `client::GuardianClient` for the enclave, which refuses any response the guardian key did not sign for its exact binding, and `client::open_response`. |
| `seal-adapter` | Upstream protocols only. Read-only `Session` trait (the private runtime session decides when it ends and attributes `observe` and `complete`); `SessionResolver`, `Adapter`; `HttpPolicy`, `Scrubber`; `testing` doubles. |
| `seal-integrity` | App Integrity plug-ins in the enclave: `Observation`, `Verdict`, `Finding`, `Detector`, `EvidenceCheck` (report + evidence bytes + the tenant's registered provider key + the request's evidence challenge in, `Finding` out). |
| `seal-enclave` | Ports (including `Telemetry`), `Components`, `ServiceConfig`, `SealService` (above), `HOSTED_IDLE_SECS`. |
| `seal-client` | `Client`, `ClientBuilder`, `built_in_trust`, `SealBuilder`, `SessionBuilder`, `HttpSession`, `DatabaseSession`, `Session`, `UNREACHABLE_WAIT_SECS`, `integrity::EndpointReporter`, `admin` (above). |
| `seal-control` | Untrusted document store (bin) and `client::ControlClient`, one method per endpoint named after its HTTP verb, for the enclave, admin tools and `seal deploy`, carrying one `client::Credential` (an admin key: `SigningKeyCredential`; the enclave's own lives in `seal-enclave`). Read rules and proposals below; enclave-signed documents verify against the telemetry keys of guardian-certified `ServiceKeyCertificate`s, which enclaves post at boot. |
| `seal-cli`, `seal-py`, `seal-node`, `seal-ffi` (+ Go `seal-go`), `seal-verify-wasm` | `seal` binary, Python, Node (npm `@sealzone/sdk`) and Go (`seal.zone/go`, through the C ABI `seal-ffi`) bindings over `seal-client`, the browser verifier (npm `@sealzone/verify`: `seal-verify` over JSON; `@sealzone/verify/seal`, a module of its own, seals in the browser: it verifies the enclave's attestation, HPKE-seals to its ingest key and proves a producer app key, so a relay carries only ciphertext, while the page sees the secret); no shared types of their own. |

### Control plane (`seal-control`)

Who may read and write a tenant's documents (the crate docs hold the full route table):

| What | Who |
| --- | --- |
| Bundle | Console members (control token, `read` or `submit`), admins, the tenant's enclaves (telemetry key; attested at boot), freshness signers |
| Documents (`/documents`), proposals, telemetry | Console members, admins |
| Put, sign, withdraw, submit proposals | Console members with `submit`, admins |
| Put roots, states, release co-signatures (each still carries its own admin signatures) | Console members with `submit`, admins, the write token |
| Service key certificates, releases, release listings and templates, release co-signatures, the checkpoint | Anyone |
| Post signals, session ends, telemetry, certificates, freshness statements (each verified by its own signature) | Anyone |
| Put releases and release templates | The write token |

- **Credentials** (`Authorization`): `Bearer sealct_…`, a console control token (format and
  checks in `seal_control::server::token`), served only for its tenant and root
  chain; `SealSigned <base64url(JSON Signed<ControlRequest>)>`, signed by an admin key of the
  latest root, else a telemetry key of a certified `ServiceKeyCertificate` posted for the
  chain, else a freshness key of the latest state; `SealAttested <base64url(JSON
  AttestedControlRequest)>`, for the bundle only: evidence that verifies, commits to the
  request as report data, and comes from an enclave release stored on the control plane that
  passes `ReleaseVerifier` under its configured release trust, with a TCB meeting the release
  policy; `Bearer <write token>`. Missing or invalid is 401; valid but not admitted here, or
  for another tenant or chain, is 403. A tenant without a stored chain answers 401 to signed
  and attested requests.
- **Producers read nothing** here: they seal through an enclave, whose bundle holds the wrap
  keys. Public is only what sealing and booting need and reveals nothing secret.
- **Proposals** (`/proposals/{id}`, `Proposal { id, kind, document, created_at, updated_at }`)
  hold an unsigned or partly signed root or state; the id is the lowercase hex of the digest
  admins sign (`labeled_digest(TENANT_STATE_LABEL | TENANT_ROOT_LABEL, body)`). A PUT merges
  the signatures it brings, each of which must verify for an admin key of the root the
  document needs (the latest, or a proposed next root for a state signed under it); a document
  that cannot follow the stored chain and state is 409, a threshold that does not fit its keys
  400. At most `MAX_PROPOSALS` (32) per tenant and `MAX_PROPOSAL_SIGNATURES` (64) each.
  Submit needs the latest root's threshold; the control plane then logs the document itself,
  checks its inclusion proof, stores it and answers it with the proof (`LoggedRoot` or
  `LoggedState`). A retried submit finds a document the log already holds among its last
  `LOG_LOOKBACK_ENTRIES` (1 024). Proposals overtaken by the chain or state are dropped. PUT
  `/state` takes a `LoggedState`, or a bare signed state the control plane logs the same way.
- **Documents** (`GET /documents?since_version=N`): every root, the logged states above `N`
  oldest first, each with the proof fetched right after it was logged, and the log's latest
  checkpoint: the history the pending window is judged from.
- **Bundles** carry the states since an anchor (`seal_verify::anchor_index`: the newest
  anchor every configured guardian's verifiers can start from; all states while a guardian has
  none), the latest checkpoint, and the newest anchor of each of the tenant's platforms'
  guardians, asked again once `ANCHOR_REFRESH_SECS` (1 h) old.
- **Browsers** reach it only from `console.origin` (CORS, preflight answered 204, no
  credentials mode: tokens travel in `Authorization`).
- **Releases**: `GET /v1/releases/{platform}` lists the stored evidence in log order;
  `/v1/releases/{platform}/{measurement}/template` serves a release's deployment template
  (Azure: the ARM template with its `ccePolicy`, published by `seal-release publish
  --template`), opaque here and checked by measurement in `seal deploy`.
- **Operation**: the control plane appends to the log (`POST /v1/entries`, `POST
  /v1/tenants/{t}/states`) and reads proofs and entries (`GET /v1/proof/{i}`,
  `/v1/entries/{i}`); `releases` in its configuration is the release trust attested reads
  pass (without it every enclave fails to boot); `tls` files are reread every
  `TLS_RELOAD_SECS` (60) and swapped in when a renewed pair loads.

## Ownership and order

- `BlobCipher` owns encryption metadata and is bound to tenant, platform and tenant key
  version through its key.
- `TokenKey` owns token encryption and decryption; authenticated claims still need
  authorization.
- `RequestAuthenticator` owns context and identity verification together.
- `TenantAuthorizer` owns decisions against a verified tenant snapshot. Its `SessionPermit`
  retains the exact authenticated request and decrypted blob; session issuance takes the
  permit and never a second blob or secret. An `ExtendPermit` retains the live session's
  claims and the fresh proof's scope.
- `LogVerifier`, `ReleaseVerifier` and `TenantVerifier` own trust configuration and
  verification.
- `KeyReleaseAuthorizer` returns the exact approved key request in a permit.
- Each session (`HttpSession`, `DatabaseSession`) owns one protocol connection and its tunnel.

Every crate error has `code() -> ErrorCode`, the only part a caller sees.

Low-level hash and encoding primitives remain module functions. No general-purpose Policy
or Nonce trait is introduced.

## Binding and freshness

- Encryption nonces are generated inside crypto operations.
- **Periodic attestation** (`GET /v1/attestation`): the binding carries `attested_at`, the
  enclave's trusted time, instead of a client challenge. A replayed recent attestation gains
  nothing, because the TLS handshake still needs the attested key; an old one is refused after
  `ATTESTATION_MAX_AGE_SECS`. One hardware report or Confidential Space token per 30 s serves
  every client.
- `GuardianChallenge` is stateless and MAC'd with the platform's challenge key, so any
  guardian instance verifies it and nobody can exhaust it. Reuse within its 60 s is harmless:
  a replayed `KeyRequest` only gets keys sealed again to the original requester's ephemeral key.
- `ProofTicket` (`POST /v1/tickets`, for the enclave's tenant) is MAC-authenticated and
  reusable until expiry, not a one-time-execution guarantee.
- Uploads encrypt with `IngestContext` as AAD before computing the request purpose.
  `expected_purpose()` commits the seal request's service key version, encapsulation and
  ciphertext, the full session blob and options, or the extended token and endpoint report. The outer `ProofContext` binds tenant,
  server TLS key and ticket. OIDC cannot sign this commitment; its bearer/channel
  assurance is recorded as `ProofAssurance::BearerOverAttestedChannel`.
- Caller authorization intersects the exact originally authenticated matchers with current
  app grants, checks the identity and honors authentication expiry, which preserves Azure
  audience constraints. Producer removal is principal-based: changing its audience is not
  a retroactive check of historical producer authentication, and its original JWT expiry
  does not expire blobs.
- **Control-plane requests** (`seal_proto::control`): a signed or attested request names
  exactly one request, `ControlRequest { tenant, root_id, method, path (with its query, as
  sent), body_sha256, issued_at }` under `CONTROL_REQUEST_LABEL`, accepted within
  `CONTROL_REQUEST_MAX_AGE_SECS` (300 s) of the control plane's clock either way; an attested
  one's report data is its labeled digest. It travels only over TLS, so a captured one is
  useless for another request, tenant or chain, or after its window. The enclave's
  `issued_at` is the host's clock: a host that moves it only gets reads refused.
- **State freshness.** Each `TenantState` is logged (a digest leaf, accepted only with valid
  admin signatures and a higher version), by the admin tool or by the control plane when a
  proposal is submitted, and stored on the control plane with its inclusion proof. The log signs `StateFreshness` for each tenant's latest state; the bundle carries
  it. The enclave and the guardian use a state only with a statement for exactly it that is
  under `STATE_FRESHNESS_SECS` (24 h) old, plus one from a tenant-run signer when the state
  names `freshness_keys`. So replaying an older state, or a truncated root chain, works for
  at most 24 h; withholding a newer state makes the tenant unavailable after 24 h instead of
  quietly stale. A log statement for an older version than one it already logged is a
  signed, provable lie (`seal status --log` looks for them). Monotonic caches still
  reject rollback relative to remembered state.
- **Pending window** (`seal_verify::change`, `seal_verify::window`). The document in force is
  a pair: a state and the root that signed it. From it the tenant moves to a newer state as
  soon as one is admissible (the oldest of several admissible at once, so states apply in log
  order) and judges the rest again from there:
  - at once, from its `public_since`, when it does not widen the state in force and any newer
    root it comes with does not widen the root in force and carries the in-force root's
    threshold too (keys not yet in force cannot make an immediate change);
  - otherwise once its `public_since` (and that of every newer root up to its own) plus the
    window **of the state in force** is at most `lock_time(time, witnessed)`, the earlier of
    `time.earliest()` and the latest witness time of every checkpoint in the bundle, as for the
    release time lock.

  It never moves back, and a state signed under an older root than the one in force never
  applies, so a newer state that does not widen the one in force cancels every older pending
  one (a newer widening state does not). A difference is narrowing only when provably so;
  anything else, including a field the classifier does not know, is widening. The first state
  applies at once. **Every time is a `public_since`** from an inclusion proof, fetched by the
  control plane right after it logs the document: whoever serves proofs can make a document
  look later (delaying a cancel or a narrowing, as withholding it would), never a widening
  look earlier.
- **Anchors bound the bundle.** Which state is in force depends on the whole history, so a
  verifier without memory starts from an anchor: the tenant's first state, a state whose
  successor became public at least `MAX_PENDING_WINDOW_SECS` after it, the latest once that
  long has passed, or a `TenantAnchor` signed by a guardian it trusts
  (`TenantVerifier::with_anchor_keys`) for this tenant and chain, `at` no later than its
  `lock_time`, naming a state in the bundle. A guardian signs one for any bundle that verifies
  (`POST /v1/anchors`), as of `at = min(lock_time, fresh_until − STATE_FRESHNESS_SECS)`, a
  time the freshness statement proves no newer state existed. Every state newer than the one
  in force at `at` became public after `at − MAX_PENDING_WINDOW_SECS`, so a bundle needs only
  those: with the control plane refreshing anchors hourly, about 25 h of states. The enclave
  trusts its own platform's guardian and the guardian itself, so both start from the same
  anchor and agree on the state in force; admin tools and the browser trust every guardian in
  their trust. A wrong anchor needs a guardian key; a stale or withheld one only makes bundles
  bigger.
- Replicas reload their tenant's bundle every `STATE_RELOAD_SECS` (30 s), which bounds how
  long a grant removal, a clearance, an external signal or another replica's `SessionEnd`
  takes to reach every replica.
  Tenant wrapping keys are refetched after `TENANT_KEY_CACHE_SECS` (15 min), which bounds
  how long a revoked customer-managed key keeps working for new sessions. Both are compiled
  in, not deploy settings, because the deployer is untrusted.
- `TrustedTime` is an interval: "not before" checks (time locks) use its earliest end and
  "not after" checks (expiry, freshness) its latest, so clock uncertainty never helps an
  attacker. Retention and suspensions also use the earliest end, so neither ends early. The
  one exception is an attestation token's `nbf`, checked against the latest end plus 60 s:
  Google stamps `nbf` at the issuing second, a correct clock can read just before it, and
  using an attestation token early gains nothing.
  Every check takes a `TrustedTime` (clients without a trusted clock pass
  `TrustedTime::exact`); timestamps written into documents take its `now`.

## Known limits and unresolved items

### Accepted limits

- **Seal can destroy a platform root, never read it.** Each root sits in two of Seal's vaults
  in different regions, with 90-day purge protection and delete locks, so an accident or a
  regional outage loses nothing. But the vaults' owner can still delete both copies. That
  makes the platform's blobs unopenable, an outage that ends when customers reseal; it
  never exposes a secret, since Seal stores no customer data and the immutable release
  policies stop even the owner from reading a root.
- **Guardian succession has a window.** A frozen guardian hands its root to a successor
  guardian release that passes the same rules as an enclave release (M-of-N, log, time lock;
  `KeyPurpose::Succession`), so a platform format change, a guardian bug or a trust change
  `revoked_keys` cannot express (the log key) costs a release, not a reseal. The handover only
  works while the old guardian can still verify the successor; if a platform change outruns
  it, the fallback is a new root and every customer reseals.
- **Seal's guardian runs on Azure, so every cloud trusts Microsoft for key release.** Seal's
  ACI guardian (serving `azure_snp_aci`) holds its root wrapped under an exportable
  `RSA-HSM` key in Key Vault Premium whose release policy is immutable: neither Seal nor the
  subscription's owner can release it to anything but the guardian's measurement, but
  Microsoft Azure Attestation, the UVM endorsement and Key Vault's HSMs are trusted, and an
  Azure outage blocks enclave boots (running enclaves keep serving until their state goes
  stale). Premium holds the root in each vault listed; Managed HSM in two regions is designed,
  not built. A self-hosted guardian on AWS or GCP KMS avoids Azure but trusts that
  cloud's account administrators, who can always change who gets the key.
- **Competing tenant roots.** The registrar (Seal) can log a competing root v1 for an
  existing tenant's name. It gets a different `TenantRootId`, so unrelated keys: it opens
  none of the tenant's blobs, the tenant's pinned deployments refuse it, and SDKs with
  `root_id` set refuse enclaves serving it. A producer without a pinned root could still be
  steered to an enclave serving it and seal there. `seal status --log` detects it.
- **Freshness window.** A replayed older state works for at most `STATE_FRESHNESS_SECS`
  (24 h). With the log as the only freshness signer, the log operator (Seal) could sign for
  an older state; that is provable but not prevented. A tenant-run signer
  (`freshness_keys`) prevents it for every state signed after it was added.
- **OIDC binding.** OIDC JWTs (Azure managed identity) cannot embed the proof context; they
  are bound only by the attested channel and the JWT lifetime. Azure and GCP tokens are
  cached by their providers, so disabling such an identity takes effect only when its
  current token expires.
- **Sessions can mint credentials.** A consumer can do anything the sealed credential
  allows, including creating a credential of its own; adapters cannot reliably stop it.
  Upstream least privilege is the control.
- **Scrubbing.** Response scrubbing sees plain bytes only: it does not catch an upstream that
  transforms and then echoes a secret. Adapters therefore refuse response compression
  (HTTP asks for `identity`; the ClickHouse adapter is specified to refuse compressed
  connections), since a secret
  inside an LZ4, ZSTD or gzip frame never appears whole. Masking is visible, so it tells a
  consumer whether chosen text is the secret: a random secret of `MIN_SECRET_BYTES` is out of
  reach of that search, a guessable secret of any length is not.
- **Postgres cancels** reach only the replica holding the connection; one sent to another
  replica does nothing. A tunnel sends its connections to the replica that last answered, so
  a cancel lands there unless that replica stopped answering in between.
- **Anyone can start** a tenant's stopped hosted replica by connecting to
  `<tenant>.enclave.seal.zone`: it costs Seal a replica start and nothing else, is rate
  limited, and keeps nothing running, since unauthenticated requests do not count as activity.
  The first request after a quiet period waits for the replica to start (about a minute,
  within `UNREACHABLE_WAIT_SECS`).
- **Attested boot reads do not check the deployment identity.** Any released enclave build
  pinned to a tenant reads that tenant's bundle: the pin is unattested, but such an enclave
  holds the grants in memory nobody can inspect, finds its identity unlisted and stops.
- **The pending window passes late, never early.** It is measured by the witnessed time the
  bundle carries: the control plane's checkpoint cache (`CHECKPOINT_CACHE_SECS`, 60 s) plus
  `STATE_RELOAD_SECS` add up to about 90 s. A cancelling state needs the root in force: states
  are signed under the latest root and apply only with it, so while a root is pending, a
  cancel waits for it.
- **Anchors trust the verifier's platform guardian.** A holder of a platform root could sign
  a false anchor and fast-track a widening for that platform's enclaves (enclaves trust only
  their own platform's guardian); the same holder can already release that platform's keys.
  On a self-hosted guardian on AWS or GCP KMS, that includes the account's administrators.
- **Self-asserted endpoint reports.** The artifact check catches drift and
  tampering, not an attacker who controls the endpoint; stronger evidence plugs in through
  `EvidenceCheck`.
- **Telemetry tail.** A replica that dies can lose up to one buffer of unsent entries;
  readers see it as a stream without a `last` batch.
- **Ending is not instant everywhere.** A `SessionEnd` takes effect at once on the replica
  that created it and within `STATE_RELOAD_SECS` on the others; a control plane that
  withholds it delays that until the session's last token expires (at most
  `SESSION_TOKEN_SECS` after its last extend).
- **Unpinned destinations** trust every baked root, so a CA that misissues a certificate for
  the destination host can intercept. Pins close this per blob.

### Unresolved

- **Endpoint reports of interpreted apps.** The default `ExecutableHash` reports the
  interpreter, so an artifact check pins Python, not the app; apps can pass an
  `endpoint_reporter` (`seal.EndpointReport(artifact=...)`). A better default (an image
  digest, a bundle hash) is open.
- **AWS identity in Python.** Release wheels are built without the `aws` feature (a large
  tree), so they have no `AwsIdentity`; whether to include it is undecided.
- **`MIN_SECRET_BYTES`.** 16 refuses some existing short database passwords; 12 would still
  put a random secret of a full alphabet out of reach.
- **Bundle size in bytes.** Bundles carry about 25 h of states, and `HttpsClient` caps a
  response at 1 MiB, which also bounds `/documents` (`since_version` keeps it small); a tenant
  submitting hundreds of states a day could pass it. A per-tenant rate on submits would make
  the bound strict.
- **Root changes that drop the in-force admins cannot be vetoed.** A pending root is
  cancelled by a newer root its own keys sign; if it leaves fewer than its threshold of the
  current admins, they cannot sign one, and the window only makes it public. Requiring
  rotations to keep a threshold of the previous admins would close it.
- **Version gaps and lost states.** Verifiers need consecutive state versions, but the dev
  log accepts any higher version; the log should refuse gaps. A state logged but held nowhere
  (neither stored nor proposed) leaves its successor unverifiable until it has been public for
  `MAX_PENDING_WINDOW_SECS`; `seal dev init` supersedes one, and verifiers accept the new
  state only after that long.
- **Production log API.** The control plane appends documents to the log and reads proofs
  and entries (`POST /v1/entries`, `POST /v1/tenants/{t}/states`, `GET /v1/proof/{i}`,
  `/v1/entries/{i}`), as the dev log serves them; the production log must serve the same.
- **Vendored crates are not committed.** An image rebuilds from the repository plus crates
  fetched and checked against `Cargo.lock` before the build; committing `vendor/` (about
  360 MB) would make "from the repository alone" literal.
- **Boot failures are hard to see.** ACI keeps no output of a confidential container that
  exited, so a refusal at boot (for example a release still inside its time lock, which the
  restart policy retries) shows only in the control plane's request log. Two guardians, right
  after their root ceremony, each exited once on their first start with no output and booted
  on the second; not reproduced.
- **Tenant onboarding.** The registrar's API (`seal-registrar`) is called only by Seal's
  console and is not part of this contract.
- **AWS, still to test**: the accuracy of the NSM attestation timestamp `NitroClock` uses
  (AWS documents what it is, not how the hypervisor's clock is disciplined; `RADIUS` is 1 s
  until measured); vsock proxy throughput for the data plane; booting a Nitro image
  whose boot blobs Seal builds from source (a 6.6 kernel) instead of AWS's (4.14), which
  would end the dependency on AWS keeping the pinned blob bytes available.
- **GCP managed databases.** Cloud SQL in Google-managed shared-CA mode chains to one public
  root valid until 2049 (`Google Cloud SQL Root Server CA`, the same for every customer), so
  it can be baked; its certificates name the host with a trailing dot (`….sql.goog.`), which
  `seal_net::UpstreamConnector` matches after the chain verifies, as its only exception to
  exact name matching.
  Memorystore for Redis Cluster and for Valkey in shared-CA mode have per-region roots valid
  25 years but intermediates valid one year, so they can be baked only if servers send their
  intermediate; Redis Cluster also needs cluster redirects, which the Redis adapter does not
  follow. Standalone Memorystore for Redis and every per-instance or customer-managed CA
  mode need the Custom plan. Still to test on live instances: the exact SANs, and whether
  the servers send their intermediates.
- **GCP Confidential Space attests TDX only.** On SEV-SNP the launcher gets no token
  (`UNSUPPORTED_CC_TECHNOLOGY`) and plain SEV is refused (no memory integrity), so enclaves
  and guardians on Confidential Space run on TDX (`c3-*`); `GCP_AMD_SEV_SNP` is accepted once
  Google attests it. PKI tokens carry the report data as one 64-character hex nonce, are about
  11 KB and last an hour. TDX tokens' Intel TCB status is in `Tcb` (`tdx_tcb_status`,
  `tdx_tcb_evaluation_data_number`); a `min_tcb` naming them refuses tokens without the claim.
- **Azure Key Vault, measured.** An ACI confidential group's guardian attests at Microsoft
  Azure Attestation's shared East US endpoint (`POST /attest/SevSnpVm`: the report, the VCEK
  with the baked ASK and ARK, the UVM endorsement) and gets claims an immutable release policy
  can pin (`x-ms-attestation-type`, `x-ms-compliance-status` = `azure-compliant-uvm`,
  `x-ms-sevsnpvm-hostdata`, `-is-debuggable`, `-vmpl`); a group with another `host_data` is
  refused (403, "attestation does not meet key release requirements"). `POST
  /keys/<name>/release` without a version releases the current one. The release JWS is signed
  with a certificate that chains to a public root and names the vault's host, so webpki checks
  it; its payload carries the key's attributes and release policy, and names a released
  `RSA-HSM` key `kty: "RSA"`. An immutable policy binds every later version of the key: a new
  version with another policy is refused (`AKV.SKR.1020`), so each guardian measurement needs a
  key of its own. In a container policy, a variable set to `""` reaches the env rules as its
  bare name, and rules are Go RE2: a counted repetition above 1000 never matches.
- **Azure, still to test** (the docs are silent):
  - whether attestation providers other than Microsoft's shared regional endpoints can emit
    the `x-ms-*` claims a release policy pins;
  - whether Key Vault release policies now evaluate comparison operators (the grammar lists
    them); TCB floors stay in checkpoint policy either way;
  - importing an exportable `oct-HSM` key with an immutable release policy into Managed HSM
    (the Managed HSM root ceremony needs it; this build implements Premium's `RSA-HSM` only);
  - which regions offer confidential container groups (no current list; eastus does, on
    Genoa hosts);
  - cross-tenant key release for customer-managed KMS. The federated-credential setup that
    cross-tenant customer-managed keys use should carry the release role, but no doc says so;
  - whether ARM updates a running confidential group in place when `ccePolicy` and the image
    change, or needs delete and create (`seal deploy upgrade`'s error names that fallback),
    and whether the group keeps its private IP across it;
  - whether `az container show` returns `ccePolicy` (it returns non-secure variable values;
    `upgrade` reads the running release and pin from them: without the policy it proceeds with
    "release unknown", without the pin it refuses);
  - `seal deploy azure`'s audience registration against a real Entra tenant: that
    `api://<app id>` passes identifier-URI restrictions, and that an IMDS v1 token requested
    for it carries it as `aud`.
- **Zero-touch upgrades.** Upgrades are run by the customer: `seal deploy upgrade` (the same
  checks as `seal deploy azure`; it keeps the group's identity, network and pin, and refuses
  to go back to a release older than the one the group runs while that one still verifies).
  Open: an Azure managed application (Seal pushes upgrades) or an enclave that redeploys
  itself, only to releases passing `ReleaseVerifier`.
- **Endpoint discovery.** Clients take replica endpoints from `SEAL_ENDPOINT`; reading them
  from signed tenant state (an additive field) is open.

## Check the contract

- `cargo test -p sealzone-proto --test vectors` checks every v1 wire vector and that all
  signing labels are distinct.
- `cargo check -p sealzone --example contract` and the crate-level doc example check the
  client-facing usage.
- `cargo test --workspace --all-features` includes policy decoding and request-binding
  tests.
- `scripts/py-test.sh` builds the simulator and a `sim` wheel into a virtualenv and runs the
  Python SDK's tests (`crates/sdk/seal-py/tests`) against it; extra arguments go to pytest.
- `scripts/e2e.sh` runs the end-to-end tests (`tests/e2e`) the same way: one freshly booted
  system per test, driven through the Python SDK and the CLI. Needs Docker or Podman.
- `crates/sdk/seal-verify-wasm/build.sh --test` builds `@sealzone/verify` and runs its
  vectors (`tests/vectors.json`, also checked natively by `cargo test -p sealzone-verify-wasm`)
  under Node.
- Both vector files are regenerated only for a deliberate format change
  (`SEAL_WRITE_VECTORS=1` on the test), and the diff is reviewed.
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` and `scripts/check-deps.sh` on every
  push and pull request.
