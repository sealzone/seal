# Seal contract

This file describes Seal's public interface: roles, SDK surface, runtime ports, per-crate
ownership, request binding, vocabulary and known limits. It is for people who build on Seal
(SDK and CLI users, tenant admins) and for people who verify or audit it. Crate boundaries,
dependency rules and topology are in [ARCHITECTURE.md](ARCHITECTURE.md). The code is the
source of truth. If this file and a crate's public signatures disagree, the code wins and
this file gets corrected.

**Status.** Released. Until 1.0, minor versions may still change the SDK and CLI interfaces; wire format v1 is frozen.
[ARCHITECTURE.md](ARCHITECTURE.md#scope) lists what is built and what is only specified.

**Wire format v1 is frozen.** Every type that is signed, hashed, used as associated data or
read by a guardian has canonical bytes and digests in
`crates/shared/seal-proto/tests/vectors/wire-v1.json`. A test fails if any of them change.
Within v1, a type may only gain optional fields that are omitted when unset, so existing
bytes stay identical. Labels never change. Any other change gets a new label version
(`…/v2`) next to the old one. A frozen guardian decodes these bytes for its whole life. It
checks signatures over what it re-encodes, so it refuses a document that carries a field it
was built without. Every field a tenant may set must therefore be in the guardian before the
guardian freezes.

## Vocabulary

| Term | Meaning |
| --- | --- |
| seal | Encrypt a secret together with its policy into a portable blob (`Client::seal`, `/v1/blobs`) |
| open | Decrypt a blob, literally open the seal. Only the enclave does this (`BlobCipher::open`) |
| session | Use a blob through the enclave without receiving its plaintext (`Client::session`, `/v1/sessions`) |
| extend | Replace a session's token with a fresh identity proof (`Session::extend`, `/v1/sessions/extend`, `TunnelPreamble::Extend`) |
| end | Stop a session on every replica before its token expires (`Session::close`, `/v1/sessions/end`, `Verdict::End`). It is recorded as a `SessionEnd` |
| signal | An input saying an endpoint may be compromised. It comes from a workload about itself (`signal`, `/v1/signals`), from a detector or from an external source |
| integrity | The tenant's policy for acting on signals. The App Integrity add-on extends it (`seal_proto::integrity`, `seal-integrity`) |
| telemetry | The signed record of what the enclave did. Only the enclave writes it (`seal_proto::telemetry`, `seal telemetry`) |
| `PlatformMasterKey` | The per-platform root key. It exists only inside that platform's guardian |
| `TenantRootId` | Identifies a tenant beyond its name. It is the digest of the tenant's root v1. Every tenant key derives from it, blob headers carry it, and deployments pin it (`SEAL_TENANT=<tenant>@<root id>`) |
| `TenantWrappingKey`, `TenantWrappingKeyScope` | The private X25519 wrap key for one (platform, tenant, root id, tenant key version). Only that platform's enclaves get it |
| `TenantWrapKey` | The public half of a `TenantWrappingKey`, certified by that platform's guardian. Any enclave HPKE-wraps a blob's DEK to it, so blobs work on every platform the tenant enables |
| `TenantKeyVersion`, `TenantKeyVersions { current, oldest_accepted }` | The version of a tenant wrapping key, and the tenant's window of accepted versions |
| `ServiceKeyVersion`, `ServiceKeyScope` | The version of one tenant's service key set (token, ingest, telemetry, TLS, ticket). No service key is shared across tenants |
| `ServiceKeyCertificate` | The guardian's signed statement that it released a tenant's service keys. SDKs require it |
| `StateFreshness` | "This `TenantState` is the tenant's latest as of T", signed by the log, and by a tenant-run signer if the state names one. A state without a current statement is not used |
| pending window | How long a state or root that widens access waits in public before it takes effect. Narrowing changes apply at once (`seal_verify::change`). See below the table |
| network rule | The networks an app may start, extend and connect sessions from (`TenantState::app_networks`). See below the table |
| state in force | The state, and the root that signed it, that verifiers apply (`VerifiedTenant::state`, `root`). A newer state that widens it stays pending until its window passes (`latest_state`, `pending`) |
| `TenantAnchor` | A guardian's signed statement that a state was in force at a given time (`POST /v1/anchors`). Verifiers start from it, so a bundle carries only about a day of states |
| proposal | A root or state on the control plane that collects admin signatures one at a time. Once it has the latest root's threshold, it is submitted, which means logged and stored |
| deployment identity | Who runs an enclave replica: an ACI group's managed identity, a Nitro parent's instance role, or a Confidential Space VM's project and service account. It must be in `TenantState::deployments` before the enclave requests keys. Seal's hosted entry (an Azure or Confidential Space identity) also carries a `HostedMode` |
| `HostedMode` | Marks the tenant's signed deployment entry for Seal's hosted replicas. With `HostedMode::Sessions`, those replicas seal and serve sessions like the tenant's own replicas, and exit when idle |
| front door | The Seal-run TCP front that `<tenant>.enclave.seal.zone` resolves to. It reads only the TLS SNI, starts the tenant's stopped hosted replica, holds the connection until the replica serves, then writes a PROXY protocol v2 header naming the client's address and splices the connection through after it. TLS stays end to end. The SDK only retries unreachable endpoints for `UNREACHABLE_WAIT_SECS` |
| periodic attestation | The enclave attests every `ATTESTATION_REFRESH_SECS` (30 s) and serves that attestation to every client. Clients accept it within `ATTESTATION_MAX_AGE_SECS` (120 s) |
| challenged attestation | `GET /v1/attestation?nonce=`: a replica's answer, on the TLS connection that asked, signed by a challenge key its periodic evidence attests. The SDK requires one on the connection before it sends a secret, a proof or a token |
| `ProofTicket`, `TicketKey` | A stateless, MAC'd challenge that an identity proof binds to, and the key that issues it |
| `ConsumerTier`, `PlatformTier` | One assurance floor per attacker. `ConsumerTier` (Base < Hardened) is how much the *endpoint* proved. Base is identity, grants and the artifact rule. Hardened adds verified integrity evidence at every start and extend. `PlatformTier` is how well the *enclave* is protected |
| `SpkiPin` | The SHA-256 of an upstream key that the sealed policy requires in the upstream's certificate chain |
| `TrustedTime` | The current time as an interval (`now ± radius`). Every check takes one |
| `ErrorCode::Expired` | The blob is past `expires_at`, or its tenant key version is retired |
| `ErrorCode::SessionEnded` | The session was ended early. Start a new one |
| `ErrorCode::ResealRequired` | The blob has no DEK wrap for the enclave's platform, because it was sealed before the tenant enabled that platform. Seal it again |

**Tenant key versions.** New blobs use `current`. Advancing `current` alone does not reject
older blobs. Retiring a version means advancing `oldest_accepted` and applying that state,
and retiring does not erase keys already released. KDF label strings (`seal_crypto::kdf`)
are frozen and need not match type names.

**Pending window.** `TenantState::pending_window_secs` holds the window, at most
`MAX_PENDING_WINDOW_SECS` (24 h). It is omitted when 0. A written 0 or a longer window does
not decode, so each window has one signed encoding.

**Freshness window.** `TenantState::freshness_secs` sets how long a `StateFreshness` keeps
the state usable, from `MIN_STATE_FRESHNESS_SECS` (5 min) up to `STATE_FRESHNESS_SECS`
(24 h), for the log's statement and the tenant signers' alike. It is omitted for 24 h. A
written 24 h or a value outside the bounds does not decode. Verifiers apply the shorter of
the latest state's window and the state in force's, so shortening it narrows access and
applies at once, while lengthening or clearing it widens and waits the pending window
(`seal_verify::change`). A shorter window bounds how long a replayed older state works. The
tenant then also survives an unreachable log, or a missed tenant signature, only that long.
The control plane refetches the log's statement once it is a quarter of the window old, at
most hourly (`LOG_FRESHNESS_REFRESH_SECS`), and replicas pick it up at their next reload. Set
it with `seal settings freshness window`.

**Network rules.** `TenantState::app_networks` lists CIDRs in one canonical spelling
(`seal_proto::net::Cidr`). The enclave checks the connection's source address against them
at session start, at extend and on every data connection. An app with no rule may connect
from anywhere, and an app with an empty rule from nowhere. An unknown source is in no
network. Adding an app's first network narrows access, adding another widens it, removing
one narrows it, and removing the rule widens it (`seal_verify::change`). A rule guards
against a credential used from elsewhere. It does not guard against the host, which controls
the network, and it works only where replicas see clients' own addresses. A Seal-hosted
replica is reachable only from Seal's front door, which names the client in a PROXY protocol
v2 header before the TLS handshake. The replica takes the client's address from that header
only while its tenant's state lists it as Seal's hosted deployment (`HostedMode`). Any other
replica reads past a header and keeps the connection's own address, since a header is only
what the connecting side wrote (`seal-enclave` `proxy`). States that use no rules omit the
field. `seal grant network APP CIDR…` sets a rule.

## Roles

| Role | Authority | Does not imply |
| --- | --- | --- |
| Producer | Anyone: supply plaintext, seal for named apps. No grant, no identity | Permission to start a session |
| Consumer | Start sessions on blobs for an app matched by its identity and listed in the blob policy | Use of a blob that does not list its app |
| Admin | Sign tenant roots/state and manage app grants | Runtime consumer authority |

- An admin can change grants, but updated grants confer runtime permissions only once they
  are verified and applied. Storage write credentials alone cannot authorize unsigned
  changes.
- **Sealing is open.** `POST /v1/blobs` carries no proof, and the enclave checks no grant.
  Sealing only ever adds a blob. That blob opens nothing but the secret its sealer supplied,
  and only for the apps it names. Blobs carry no producer, telemetry records seals without
  an identity, and the enclave rate-limits seals per connection source. Which blob an app
  loads is the app's configuration. A blob swapped for another with the same apps (the
  sealer's own credential, or another destination) is outside what Seal claims.
- Consumer roles are grants that the enclave checks, not SDK types. One `seal::Client`
  exposes every operation, and calls the workload is not granted fail with `NotAllowed`.

## SDK surface (`sealzone` on crates.io and PyPI, used as `seal`)

One client does everything a workload may do. Anyone may seal, with no identity. The enclave
decides on every call whether the workload may start sessions (an app grant), from the
tenant's signed grants. The SDK has no role types.

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

- **Shape.** Required arguments are positional in Rust and required keywords in Python.
  Options chain before `.await` in Rust and are keywords in Python. Both languages use the
  same names. Bad arguments surface as `ClientError::Invalid` (`BadRequest`).
- **`Client::from_env`** reads `SEAL_ENDPOINT` (the tenant's enclave replicas,
  comma-separated) and `SEAL_TENANT` (`<tenant>@<root id>`, or `<tenant>` for a client that
  never seals). It uses the first identity `detect_identity` finds. Sealing needs no
  identity; without one, sessions and signals fail with `NoIdentity`. `Client::builder()` sets any of these explicitly. The
  identity hints are `SEAL_APP_KEY`, `SEAL_AZURE_AUDIENCE` (Azure managed identity, with
  `AZURE_CLIENT_ID`), GitHub's `ACTIONS_ID_TOKEN_REQUEST_*`, `SEAL_KUBERNETES_TOKEN_FILE`
  (default `/var/run/secrets/seal.zone/token`), the GCP metadata server and the AWS
  credential chain (`aws` feature).

  Replicas share keys and template-fixed ports, so a session works on any of them, and the
  SDK fails over to the next one without a load balancer. Sealers outside the tenant's
  network (CI runners, laptops, the console) use Seal's hosted replica for the tenant
  (`<tenant>.enclave.seal.zone`), which also serves sessions. Blobs sealed there open in the
  tenant's own replicas, and the other way round. A tenant that wants its apps only on its
  own replicas gives them only those endpoints, or disables Seal's.
- **Unreachable replicas.** The SDK makes a pass over the endpoints at connect, when
  re-verifying past `ATTESTATION_MAX_AGE_SECS`, and on any API call. A pass reaches no
  replica when none completes a TCP connection and TLS handshake within the 10 s connect
  timeout, or, when verifying, none serves an attestation. The SDK then repeats the pass with
  backoff (2 s, doubling to 15 s) until a replica answers or `UNREACHABLE_WAIT_SECS` (120 s)
  pass. After that it fails with `Unavailable`. Every client does this, whatever its
  endpoints. It rides out a replica restarting, and a Seal-hosted replica that Seal's front
  door is starting on the connection. The SDK retries an API request only when no connection
  was made, so it never sends one twice. Whatever answers is verified as on any call. A
  failed verification, a key other than the attested one, or an error code from the enclave
  is the result at once and is never retried. A tunnel holds an app connection the same way
  while no replica is reachable, until the app closes it or the tunnel stops.
- **Release trust.** The client verifies enclaves against a `seal::Trust`, whose JSON is
  `trust.json`'s (as in `deploy/example/trust.json`). By default it uses the trust compiled
  into the SDK: Seal's production trust (`crates/sdk/seal-client/release-trust.json`),
  published with the `sealzone` crate so every build carries the same anchors, or the file
  `SEAL_RELEASE_TRUST` names at build time. A build with neither fails to connect with
  `VerificationFailed` until it is given a trust. `ClientBuilder::trust` takes another trust, usually
  `seal::Trust::from_json` of a published `trust.json`. That returns `BadRequest` on unknown
  fields, or on a threshold or quorum of 0 or above its keys. The trust is code or build
  input, never the environment. Only sim builds read `SEAL_TRUST`.
- **Verification.** The client checks the enclave's periodic attestation (`GET
  /v1/attestation`). That covers the evidence from Azure, Nitro or Confidential Space, the
  release, and the binding, whose `attested_at` must be within `ATTESTATION_MAX_AGE_SECS` of
  the client's clock. The client accepts the enclave only with the guardian's
  `ServiceKeyCertificate` for exactly the keys the enclave attests to
  (`seal_verify::verify_service_certificate` with `Trust::guardians`). The certificate exists
  only for keys the guardian released. So the guardian's time lock, revocations and the
  tenant's co-signature protect SDK traffic too, and an enclave that made up its own keys is
  refused. A root id (from `SEAL_TENANT=<tenant>@<root id>` or `ClientBuilder::root_id`)
  also makes the client refuse enclaves serving another chain for the tenant's name.
- **Challenged attestation.** The periodic attestation proves which keys an approved release
  holds, not that a connection ends in one. Every replica of a tenant and service key version
  shares the service keys, so whoever copied them out of a build later revoked, or out of
  hardware later below `min_tcb`, could present the TLS key and replay any replica's
  attestation. So every call that carries a sealed secret, an identity proof or a session
  token (seal, session start, extend, end, signal; not tickets) first sends `GET
  /v1/attestation?nonce=<32 random bytes, base64url>` on the TLS connection it will use. The
  answer (`ChallengedAttestation`) must verify as the periodic one does, for exactly the keys
  the client verified, with evidence committing to the binding and the replica's challenge
  key (`ATTESTATION_KEY_LABEL`) and that key's signature over the nonce and the connection's
  TLS 1.3 exporter (`ATTESTATION_CHALLENGE_LABEL`, exporter label
  `EXPORTER-seal-attestation-challenge-v1`). Only the two ends of a connection know its
  exporter, so a relay holding the keys cannot pass on an honest replica's answer. Anything
  else, an enclave that cannot answer included, is `VerificationFailed`, and the call is not
  sent. Tunnel connections are challenged the same way through their preamble (below). The
  browser verifier
  (`seal-verify-wasm`) seals through a relay, with no connection to the replica to
  challenge, so its seals rest on the ingest key alone: that key is safe until
  `min_service_key_version` passes it.
- **`seal(secret, to, apps)`** builds the `SecretPolicy`, so every policy check applies. It
  HPKE-seals the secret and policy to the attested ingest key and returns the `seal1.…` text.
  It needs a root id: a client without one fails with `Invalid` (`BadRequest`) before
  anything is sent, so a competing root registered for the tenant's name never receives a
  secret. The console's Connect page and `seal status` show the pin. Sessions need none,
  since the blob names its root and the enclave must serve it.
- **`session(blob)`** ends with one of three calls. `.http()` returns an `HttpSession`
  (`url()`, `key()`). `.database()` returns a `DatabaseSession` (`dsn()`, `protocol()`, one
  of Postgres, Redis or ClickHouse). `.await` returns `Session::{Http, Database}` for code
  that handles any blob. These are the frozen `s.url`, `s.key`, `s.dsn`. The kind comes from
  the blob's clear-text policy, so asking for the wrong one fails with `Invalid` before
  anything is sent. Every session has `info()`, `extend` and `close`. The tunnel extends by
  itself, and `extend` extends now. `close` ends the session on the server and waits for
  cleanup. Dropping a session starts the same in the background.

  The session options work as follows. `reload_with` re-reads the blob on `Expired`, for
  example after a rotation. `endpoint_reporter` defaults to `integrity::ExecutableHash` and
  receives the request's `evidence_challenge()`. That is the digest of the request with the
  report stripped, which can be computed before the report exists, where
  `expected_purpose()` would be circular. `integrity::HostAgentReporter` (App Integrity
  add-on) asks the seal host agent over the local `host-agent/v1` socket. It puts the
  agent's artifact and signed, challenge-bound evidence into the report. It falls back to
  `ExecutableHash` whenever the agent is absent, so hosts without the add-on keep passing the
  artifact check. `ResealRequired` names the attested platform the blob was not sealed for
  ("this blob was sealed before Azure (ACI) was enabled; reseal it").
- **Everything a caller touches is re-exported** from `seal` (`Severity`, `ConsumerTier`,
  `SessionInfo`, `ErrorCode`, `Trust`, …). No one needs `seal_proto` directly.
- `IdentityProvider` proves workload identity, and `detect_identity` picks one.
- **Admin surface.** `admin` (`Admin`, `ControlClient`, re-exported from
  `seal_control::client`, and `LogClient`) is a separate surface for the CLI. It verifies
  everything it fetches before showing or re-signing it. Its control-plane requests carry a
  console control token, or are signed with an admin key (`SigningKeyCredential`) or, for
  `seal settings freshness sign`, a freshness key. The write token only publishes releases
  and stores a development registrar's root version 1.

  Changes go through proposals: `Admin::draft` builds the next state on the state in force
  and classifies each difference, and the proposal calls collect M-of-N signatures across
  machines and browsers. `seal::built_in_trust()` is the trust `SEAL_RELEASE_TRUST` named at
  build time.
- **The `seal` CLI** (`sealzone-cli`) keeps no admin key and no credential in `$SEAL_HOME`.
  Its `config.json` there names the tenant, its root id, its console workspace and the URLs
  of the console, the control plane and the log (Seal's by default). The trust is the
  built-in one, or `--trust FILE`. `SEAL_TRUST` also sets it; here it is the CLI's own
  option, unlike the SDK's.
  - `seal login` signs in to the console with a device code that the user approves in the
    browser. The `sealcli_…` bearer token goes to the OS keychain (service `seal`, account
    `console:<origin>`). A host without a keychain (servers, containers, SSH) keeps it in
    `$SEAL_HOME/logins/<console host>`, readable only by its owner, and `seal login` says so
    before it asks for a code. `SEAL_CONSOLE_TOKEN` overrides both. `seal logout` revokes
    the token. `seal use TENANT` looks up the tenant's root id and workspace, and verifies
    the root chain against the trust and the state against the log before saving.
  - Each change (`seal grant|revoke app|enclave|network …`, `seal settings …`, `seal deploy
    azure`'s grant) is drafted on the verified state in force and shown as its classified
    differences. By default the CLI then proposes it, opens its console page for the
    admins' passkeys and follows it. Once the proposal has the root's threshold, the CLI submits it and reports
    it logged. Ctrl-C leaves it pending, and `--no-wait` exits at once. `--key-file F`
    (repeat for M-of-N) signs locally, and publishes when the keys meet the threshold or
    else proposes with their signatures. Changes to the admin keys or the threshold (`seal
    settings admins add|rm|threshold`) propose the next root and the state re-signed under
    it, and submit them together. Read commands need only the login (or a `--key-file` key)
    and take `--json`.
  - `seal changes` lists open proposals and logged states not yet in force. `seal changes
    show|sign|submit|cancel ID` acts on one, and an id prefix will do. `sign` with
    `--key-file` submits a state that reaches the threshold. `sign --passkey` signs with an
    admin passkey on a USB security key (CTAP2). It needs the `passkey` feature, which is on
    by default for the `seal` binary and in the macOS wheels. It makes the assertion a
    browser would make, asks for the key's PIN when it has one, and keeps the assertion only
    when it verifies under one of the root's passkeys.
  - `seal changes --watch [--once] [--interval D] [--json]` follows pending roots and states
    and verifies them locally. It uses the log's own freshness statement, so a control plane
    hiding a newer state fails the check. `--once` exits 0 when nothing is pending and 3
    when something is. `seal status --log` also scans the log for roots of the tenant
    outside its chain and for stale freshness statements.
  - `seal key create [--out F]` writes an Ed25519 key file, which the user keeps. `seal
    settings admins add KEY` or the console's Admins page makes it an admin. `seal key
    public F` prints its public key. The CLI writes every key it generates (`seal key
    create`, `seal grant app … key --generate`, `seal settings telemetry-readers add
    --generate`) only where asked. It never replaces a file, never sends a key to a
    terminal, and shows each key by its public key. Grants list app keys by public key.
  - `seal dev init` (development registrars, hidden from the help) creates root version 1
    and state version 1, and resumes a failed run given the same keys and options.
  - Exit status: 0 done, 1 an error (with the next step to take), 2 a usage error, 3 `seal
    changes --watch --once` found something pending, 130 stopped following a proposal.
- **`seal-py`** (PyPI `sealzone`, `import seal`) binds the same client.
  `seal.Client(endpoints=, tenant=, root_id=, identity=, trust=)` connects. Unset arguments
  come from the environment, as in `from_env`. `trust` is a `trust.json` path or its JSON as
  bytes, and defaults to the wheel's own. `await seal.AsyncClient.connect(...)` is the
  asyncio form. Module-level `seal.seal`, `seal.session` and `seal.signal` use
  `seal.default_client()`.

  `seal(secret, *, to, apps, header, format, pin, expires, methods, deny, sealed_only,
  hardened_only, with_receipt)` returns the blob, or `(blob, receipt)`. `session(blob, *,
  kind, min_tier, reload_with, on_reseal, endpoint_reporter)` returns an `HttpSession`
  (`url`, `key`) or a `DatabaseSession` (`dsn`, `protocol`). Both have `info`, `receipts()`,
  `extend()`/`aextend()` and `close()`/`aclose()`. Leaving `with` or `async with` closes the
  session, and closes it once more if that close failed.

  Errors are `seal.SealError` subclasses named after `ErrorCode`, with `code` and
  `retryable`. `seal.BadRequest` is also a `ValueError`. The identities are
  `seal.AppKeyIdentity`, `AzureManagedIdentity`, `KubernetesIdentity`, `GcpIdentity`,
  `GitHubActionsIdentity` and `AwsIdentity` (`aws` feature). Enum values are their wire
  names (`severity="high"`, `min_tier="hardened"`).

  Python differs from Rust in a few ways. Callbacks run on a worker thread and may be
  coroutine functions. One tokio runtime per process runs every call. Blocking calls release
  the GIL and stay interruptible. A forked child (gunicorn, Celery prefork) gets its own
  runtime and default client. Clients and sessions made in the parent raise `RuntimeError`
  in the child, and the child never ends its copy of a parent's session.

### Sessions

The proxy runs in the enclave. Its protocol adapters parse traffic, inject the secret and
enforce the policy. The only thing next to the app is the SDK's tunnel, a loopback byte
forwarder that never sees the secret. Apps reach the data plane only through the tunnel.
`url`, `key` and `dsn` name the tunnel on `127.0.0.1`, the key is a local key worthless
elsewhere, and the session token never leaves the SDK.

- **Start** (`POST /v1/sessions`). The request carries an identity proof, the blob, options
  and an endpoint report. The enclave returns a token valid for `SESSION_TOKEN_SECS`
  (10 min) for a new random `session_id`.
- **Extend** (`POST /v1/sessions/extend`). The SDK re-proves its identity every
  `SESSION_EXTEND_SECS` (5 min). The enclave requires the same caller and rechecks grants,
  suspension, expiry and the endpoint report. It recomputes the granted tier from the fresh
  endpoint report and holds it to the blob's `min_tier` and to the `min_tier` the session
  started with (carried in the token), so a hardened floor holds for the session's whole
  life. It then issues a
  new token for the same `session_id`. Identity is therefore re-verified at least every 5
  minutes. A workload disabled at its identity provider loses access within one extend for
  app keys, SigV4 (replayed to STS each time), GitHub and Kubernetes. For GitHub and
  Kubernetes, tokens older than `MAX_OIDC_TOKEN_AGE_SECS` (10 min) are refused. Azure and GCP
  serve cached tokens, so their tokens keep working until they expire (up to 24 h for an
  Azure managed identity).
- **Extend live connections.** The tunnel extends at half the token's remaining life. It
  then sends `TunnelPreamble::Extend` with the new token to every replica that holds one of
  its connections, and the replica moves their expiry. Connections that are not extended
  close at expiry. On a `SessionExpired` extend, the tunnel restarts the session on the same
  blob. On `Expired` it restarts through `reload_with`. `SessionEnded` or `IntegrityFailed`
  stop the tunnel for good.
- **Wire.** `POST /v1/blobs` carries `canonical(SealPayload)` HPKE-sealed to the attested
  ingest key, and nothing else. The HPKE info is `ingest_info(tenant)`. The AAD is
  `canonical(IngestContext)`, which names the tenant, service key version and TLS key the
  payload was sealed for. The SDK refuses a returned blob that does not name its tenant, the
  attested root and exactly the policy it sent. A destination whose protocol the image has
  no adapter for (ClickHouse, until it is built) is `BadRequest`.

  A replica has one port, its endpoint's, which carries the API and tunnel connections.
  Tunnel connections offer TLS ALPN `seal_proto::tunnel::ALPN` (`seal-tunnel/1`) instead of
  `http/1.1`. They are pinned to the attested key and start with the tunnel preamble, and
  the session's blob says which protocol follows. Before its `Connect` or `Extend` preamble,
  a connection may send one `TunnelPreamble::Challenge { nonce }`. The replica answers with
  `u32 length || canonical(ChallengedAttestation)` for that nonce and the connection's TLS 1.3
  exporter, as `GET /v1/attestation?nonce=` does, or closes the connection. The SDK
  challenges every tunnel connection, and sends the token only after the answer verifies, as
  for API calls. An enclave that cannot answer gets nothing, so enclaves roll out before
  SDKs. A connection without a challenge is served as before. The SDK verifies a replica's
  challenge evidence in full once per attestation period; later answers carrying the same
  evidence cost a signature check. Names play no part, since the certificate
  carries one fixed name. A replica is reached at whatever address `SEAL_ENDPOINT` lists,
  and the release templates use port 8443. A replica that serves no sessions (draining, or
  not listed in the state in force) drops a tunnel on its ClientHello, before the handshake.

  The port holds at most `MAX_CONNECTIONS` (1024) connections at once, API and tunnels
  together, and `MAX_CONNECTIONS_PER_SOURCE` (512) from one source, an IPv4 address or an
  IPv6 /64 (callers behind one translated address share it). A connection past either is
  closed before its TLS handshake, and the PROXY header and handshake must finish within
  10 s. A tunnel holds its place until it ends, an API connection until it goes 120 s with no
  byte moving either way. The open calls' rate limits use the same sources.
- **Tunnel connections.** Each goes to the replica that last answered. When that replica
  does not answer, the tunnel tries the others at once and uses the first to answer from
  then on. The challenge costs one round trip when a connection opens; the tunnel keeps one
  spare connection, already challenged, so a connection that takes it pays none. The
  `Connect` preamble goes out with the app's first bytes.
- **End** (`POST /v1/sessions/end`, authorized by the token alone, which must not have
  expired: `session_expired` otherwise, so an extended session's older tokens cannot end it
  once past their own expiry). The replica signs a
  `SessionEnd`, closes its connections of the session at once and publishes the
  `SessionEnd`. The other replicas refuse the session's tokens and close its connections
  within `STATE_RELOAD_SECS`. The SDK ends a session in `close(&self)`. The first call stops
  extending and closes the tunnel, whatever the answer. If it returns an error (the replica
  ended the session but could not publish its `SessionEnd`), calling it again resends the
  end, and the replica republishes it. After one call succeeds, further calls do nothing. A
  closed session is never extended or restarted. Dropping a session that was not closed
  successfully sends one more end in the background. The enclave ends a session itself when
  a detector's finding maps to `Verdict::End`. The tunnel never restarts an ended session.
- **Every connection and request** is checked against the session (expiry, grants,
  suspension) and passes `Session::observe`. A tunnel's session is checked on its `Connect`
  preamble, against the connection's address too, before any adapter runs. Live connections
  are rechecked on every tenant state change, each against its tunnel's address, so a
  network rule added or narrowed later also ends tunnels already open from outside it.

### How access ends

Seal does not store blobs, so it has no per-blob kill switch. Access ends through these
mechanisms:

| Mechanism | Scope | Who |
| --- | --- | --- |
| `expires_at` in the sealed policy | One blob, every copy of it | Whoever seals it, at seal time |
| Removing an identity from an app's grants | Every session that identity starts | Admin (signed tenant state) |
| Removing a deployment from `deployments` | Everything the replicas with that identity serve, except attestation and session ends | Admin (signed tenant state) |
| Raising `oldest_accepted` | Every blob below that tenant key version | Admin (signed tenant state) |
| Revoking the credential at the upstream | The secret itself | Whoever owns the upstream account |
| Ending the session (`SessionEnd`) | One session: its tokens and every connection | The client (`close`), or the enclave on an integrity finding |
| Integrity suspension | Everything one identity does | Tenant integrity policy, on signals (below) |

Live sessions are rechecked whenever the tenant's verified state changes
(`Session::ended`). So a grant removal or a published `SessionEnd` also ends connections
already established, once a replica has loaded the new state. The admin mechanisms narrow
access, so they apply as soon as they are logged, whatever the pending window. Rotating a
secret means sealing the new value (`seal secret`). Revoking the old credential at the
upstream is its owner's job.

The admin mechanisms hold against replay. A state is used only with a current
`StateFreshness` for exactly that state. So nobody can bring back an older state for more
than the state's freshness window (`STATE_FRESHNESS_SECS`, 24 h, unless the tenant sets a
shorter `freshness_secs`), whether a control plane, a host restarting replicas, or a holder
of a revoked credential running their own enclave. See "Binding and freshness".

## Telemetry and integrity

**Signals in, telemetry out.** Three words cover everything here:

- **Signal.** An input saying a workload's endpoint may be compromised. The SDK, host
  agents, in-enclave detectors and external systems (EDR) send signals. None of them write
  telemetry.
- **Integrity.** The tenant's policy for acting on signals (log, refuse, end the session,
  suspend the identity). The App Integrity add-on plugs detectors and evidence checks in.
- **Telemetry.** The signed record of what the enclave did, including what it did about each
  signal. Only the enclave writes it, so a compromised endpoint can send signals but never
  write history. Metrics (specified, not built) are aggregated telemetry.

```
 SDK / host agent ─ endpoint report, self-signal ─┐
 EDR / external ─── signal (control plane) ───────┤ signals
 adapter ─ Observation (before forwarding) ───────┤──► integrity: detectors, policy
                                                  │      └─► Verdict (forward / refuse / end)
 adapter ─ Completion (after) ─┐                  │
 runtime ─ seal, session, extend, end, refusal ───┴──► telemetry: one entry per event,
                                                         signed batches → control plane
```

Adapters report each request to their session before forwarding (`Session::observe`,
obeying the returned `Verdict`) and after it ends (`Session::complete`). They never judge
integrity, never write telemetry and never see the identity behind the session. The enclave
runtime attributes both reports, runs the detectors, applies the policy and writes
telemetry.

### Telemetry

- **Entries.** A `TelemetryEntry` holds the time from the enclave's trusted clock
  (`seal_tee::Clock`), the tenant, the acting identity and a `TelemetryEvent`. The event is
  one of `Seal`, `Session`, `Extend`, `End`, `Refused`, `Request` (one data-plane request
  with its `Completion`), `Integrity` (a signal applied and the action taken) or `Dropped`.
  Entries are numbered across their stream.
- **Refusals say why** (`Refused::context`, a `RefusalContext`). The caller hears only the
  `ErrorCode`. The tenant's telemetry gets the cause and the values the enclave checked.
  Examples are `outside_networks` with the app and the address the caller came from,
  `no_grant` with the verified caller and the blob's apps, `unknown_app_key`,
  `tier_too_low` with the required and offered tiers, `blob_expired`, `suspended` with the
  signal's code and until when, `other_tenant`, `stale_state`, and `unavailable` with the
  service. On a Seal-hosted replica, until it reads the front door's PROXY header, the
  address in `outside_networks` is the front's. `bad_proof` and `malformed` carry the
  enclave's fixed sentence for the check that failed (`what`), never the caller's text.
  An entry without a context encodes without the field. A verifier
  re-encodes what it parsed to check the batch signature. So readers (the control plane, the
  SDK, the console's verifier) must know `context` before enclaves that write it run.
- **What it never contains.** Telemetry never contains the secret, a credential, payload
  bodies or upstream-supplied text. An upstream error is recorded only as its kind. That is
  an HTTP status, or a Postgres `ErrorResponse`'s SQLSTATE (`UpstreamErrorKind::Sqlstate`,
  five digits or upper-case letters, `XX000` when malformed). A Postgres cancel request is
  recorded as a `Completion` with action `CANCEL`.
- **Shipping.** The `Telemetry` port batches entries into `TelemetryBatch`es, signs them
  with the enclave's telemetry key and posts them to the control plane (`POST
  /v1/tenants/{tenant}/telemetry`). Each replica boot starts a random `stream` and numbers
  its batches. So the untrusted control plane can drop batches only visibly, and can never
  forge or edit them.
- **Encryption.** When `TenantState::telemetry_readers` names X25519 keys, entries are
  sealed to them (`TelemetryEntries::Sealed`). Seal then sees only batch metadata (stream,
  sequence, entry numbers, time range). With no readers, entries are in clear and still
  signed.
- **Receipts.** `SealResponse` and `SessionResponse` carry a `TelemetryReceipt` (stream,
  entry). A client that keeps them can prove an entry was withheld, even a whole stream the
  control plane never showed. The SDK hands them out. `SealBuilder::with_receipt()` returns
  `(blob, receipt)`, and `Session::receipts()` covers the start and every restart. The SDK
  appends receipts as JSON lines (`seal::receipts::append`, `seal secret --receipt-file F`)
  in the format `seal telemetry --receipts F` reads.
- **Loss.** A replica flushes at least every `TELEMETRY_FLUSH_SECS` (5 s) and holds at most
  `TELEMETRY_BUFFER_ENTRIES` (10 000) unsent entries. When the buffer is full, the replica
  drops data-plane `Request` entries first and records every drop in a `Dropped` entry.
  Requests are never blocked. A graceful shutdown marks its final batch `last`, so a stream
  without one may have lost its unsent tail (at most one buffer). Batches cover contiguous
  runs of entry numbers. Dropped entries therefore show as gaps between batches, and the gaps
  add up to the stream's `Dropped` counts.
- **Reading.** `GET /v1/tenants/{tenant}/telemetry?since=T&after=C&limit=N`
  (`ControlClient::get_telemetry`, `seal telemetry`) is open to console members and admins
  only. A page holds batches with entries at or after `T`, ordered by `(stream, sequence)`,
  strictly after the cursor `C`. The cursor is `<stream hex>-<sequence>` of the previous
  page's last batch. A page holds at most `N` (default and maximum 1 000) and stops before
  768 KiB of JSON, with at least one batch. A short page is not the end; an empty one is.

  Readers verify batches with the telemetry public keys an enclave attests to
  (`AttestationBinding::telemetry_public_keys`, certified by the guardian;
  `seal_verify::telemetry::certified_keys`). They decrypt sealed batches with a reader key.
  A key of a service key version below its platform's `min_service_key_version` in a
  verified checkpoint (`seal_verify::telemetry_keys_in_force`) signs nothing that counts:
  readers drop its batches whatever their dates (the log does not record when a version was
  retired, and a batch's dates are its signer's own), enclaves its signals and session ends,
  and the control plane refuses all three and its credential. Without a verified checkpoint
  each certificate counts only its own version's key. `seal telemetry` fetches
  `GET /v1/checkpoint`; the browser passes it to `certifiedTelemetryKeys`.
  They report sequence gaps, streams without a `last` batch and receipts with no entry
  (`seal_verify::telemetry::analyze`, shared by the CLI and the browser).

### Integrity

Integrity covers signals that a workload's endpoint may be compromised, and the tenant's
rules for acting on them. Seal treats signals as opaque and acts only on **which identity**
and **how severe**. What a source detected, and how, stays with the source. The signal
carries a short `code` that admins see and telemetry records, and Seal never interprets it.
Integrating an EDR or a detector means producing `(identity, severity, code)`.

| Source | How it reaches Seal | Signed by |
| --- | --- | --- |
| SDK, at session start and extend | `EndpointReport` in `SessionRequest` / `ExtendRequest`, bound into the proof | Enclave telemetry key. On a mismatch, `AuthzError::ArtifactMismatch` carries the `artifact-mismatch` signal (severity `High`) for the caller |
| SDK or host agent, about itself | `POST /v1/signals` (`Client::signal`). It names only the caller | Enclave telemetry key |
| In-enclave detector (SQL injection, unusual API calls) | Adapters pass each request to `Session::observe`, and `seal_integrity::Detector`s judge it | Enclave telemetry key |
| The seal host agent (findings about its enrolled endpoints) | `POST /v1/signals` on a replica, with a pre-signed signal (`SealService::signal`). No workload proof; the signature is the authority | The agent's key, registered in `IntegrityPolicy::sources`. The receiving replica verifies it, applies the policy at once and publishes it |
| External system (EDR) | `POST /v1/tenants/{t}/signals` on the control plane (`ControlClient::post_signal`) | The source's key, registered in `IntegrityPolicy::sources` |

`POST /v1/signals` takes both the SDK's self-signal and a host agent's pre-signed signal.
The payload's shape picks the verifier.

- **Policy** (`TenantState.integrity`, admin-signed). It holds the allowed artifacts per app,
  trusted external sources, the action per severity (`LogOnly`, `Deny`, `Suspend { secs }`;
  empty means log only), and clearances that lift a suspension.
- **Evaluation.** Every replica evaluates the same policy over the same verified signals
  (`TenantBundle.signals`, with invalid ones dropped), so replicas agree without
  coordinating. The replica that creates a signal applies it at once. If the signal
  suspends, that replica also publishes it (`TenantStore::publish_signal`), and the others
  apply it within `STATE_RELOAD_SECS`. A host agent's finding follows the same rule through
  the replica that received it. That replica verifies the finding against the registered
  source key and applies it immediately, so the identity's sessions on that replica end
  without waiting for `STATE_RELOAD_SECS`. It then publishes the finding for the others.
  Every signal, published or not, is in telemetry.
- **Retention.** A signal is live while it suspends someone (`IntegrityPolicy::is_live`).
  That means its action is `Suspend`, it is not cleared, and its duration has not run out.
  The control plane may drop signals that are no longer live under the latest policy.
- **Sources.** Verification uses the latest state's `sources`. So removing a source (for
  example after its key leaks) voids all its signals and lifts their suspensions on the
  next reload, with no per-identity clearing needed.
- **Evidence.** `EndpointReport.evidence` is opaque. Each provider gets a
  `seal_integrity::EvidenceCheck` compiled into the image (`Components::evidence_checks`).
  Evidence from a provider without one is ignored. A check receives four inputs: the whole
  report, the evidence item, the public key the tenant registered for its provider in
  `IntegrityPolicy::sources`, and the `evidence_challenge()` of the request being
  authorized. There is one enrollment per source, and a `None` key means the provider is not
  enrolled, so the check ignores the evidence. With these inputs, a check that verifies
  signatures holds self-asserted fields to signed ones and refuses evidence replayed from
  another request. None ship in the open build; the host-agent check belongs to the add-on.
- **Detector findings** take the action for their severity. `LogOnly` forwards the request.
  `Deny` refuses it (`Verdict::Refuse`). `Suspend` ends the session (`Verdict::End`, a
  published `SessionEnd`) and suspends the identity.
- **Suspension** stops the identity's session starts, extends and seals, and ends its live
  sessions (`ErrorCode::IntegrityFailed`). Blobs it sealed keep working for other
  identities. A suspension lifts when its duration ends or an admin clears the identity.
  Suspensions and clearances name a workload by the immutable ids grants match on
  (`WorkloadIdentity::same_subject`), never its names: a GitHub identity is its repository
  (`repository_id`, `repository_owner_id`) whatever environment or ref a run names, so a
  suspended workflow cannot step out by switching branch, environment or repository name.
- **The artifact check is enforced.** An app listed in `artifacts` starts and extends
  sessions only with a matching `EndpointReport`. The report is self-asserted, so it catches
  drift and tampering, not an attacker who controls the endpoint. No detectors ship in this
  repository. Only compiled-in evidence checks evaluate the evidence in
  `EndpointReport.evidence`, and none ship here. In-enclave observation content never leaves
  the enclave.

## SecretPolicy

`SecretPolicy` is the one policy type that the SDK, the encrypted upload, the blob and the
adapters share. Every way of building or decoding one requires a normalized destination and
injection, at least one app, and HTTP options only for HTTPS destinations. HTTP paths
reject encoded or ambiguous forms.

**The policy cannot be changed without breaking the blob.** The policy travels in clear text
next to the header, so anyone can read where a blob may be used. But the header holds
`labeled_digest(POLICY_LABEL, policy)`, and the header is the associated data of both AEAD
layers (the DEK wrap and the secret). Editing the policy breaks the digest check. Editing
the digest too breaks decryption. Making a new blob needs the tenant wrapping key, which only
attested enclaves hold. The policy reaches the enclave inside the HPKE-sealed upload, and
session requests carry no destination, so neither the network nor a consumer can redirect a
secret. The enclave uses only the policy of the `OpenedBlob`.

**The secret goes only to the sealed destination.** The adapter connects with
`UpstreamConnector::connect(policy.destination(), policy.pins())`, which uses the
destination's host for SNI and certificate verification. The HTTP adapter accepts
origin-form requests only, sets `Host` to the destination, relays redirects instead of
following them, and refuses `CONNECT` and `Upgrade`. Database adapters authenticate as the
destination's user and database, replacing what the client sent. Each adapter adds its own
rules:

- **HTTP** refuses method and URL override headers (`X-HTTP-Method-Override`,
  `X-HTTP-Method`, `X-Method-Override`, `X-Original-URL`, `X-Rewrite-URL`) and a `_method`
  query parameter, and drops `Range` and `If-Range`, so an echoed secret comes back whole for
  the scrubber. When the policy restricts methods, it refuses `multipart/form-data` bodies,
  and reads a URL-encoded body (or one without a `Content-Type`) whole, up to 1 MiB, refusing
  it if it is longer or has a `_method` field. It reads a body Laravel takes as JSON (a
  `Content-Type` containing `/json` or `+json`) the same way, refusing it if it is longer,
  if its top-level object has a `_method` key (any case), or if it does not parse
  (serde_json is stricter than PHP: deeper than 128 levels, numbers out of range). Other
  bodies stream. When the policy restricts
  paths, a `;` after the destination prefix is refused, and denied prefixes match ignoring
  ASCII case and also cover a `.` suffix (`/v1/keys` covers `/v1/keys.json`); the
  destination prefix matches exactly.
- **Postgres** drops startup `options` and refuses replication and `FunctionCall`. It gives
  the client a `BackendKeyData` of its own, random per connection and never the upstream's.
  A `CancelRequest` naming that key, on a new tunnel connection to the same replica while the
  connection lives, passes `Session::observe` (action `CANCEL`). That tunnel's own session
  must be live, as for any tunnel, and must be the connection's session
  (`Session::same_session`). The cancel then goes upstream with the upstream's key over
  a new verified TLS connection. Any other pair, or a tunnel of another session, is closed
  without a reply. Postgres
  authenticates upstream with SCRAM-SHA-256 only (SCRAM-SHA-256-PLUS bound to the TLS
  connection when offered) and never sends the secret any other way.
- **Redis** refuses re-`AUTH` and `HELLO … AUTH`. It also refuses commands outside the
  destination's db (`SELECT` of another db, `SWAPDB`, `MOVE`, `COPY … DB`, `FLUSHALL`,
  `MIGRATE`), commands that break one reply per command (`RESET`, `CLIENT REPLY OFF|SKIP`,
  `MONITOR`, `SYNC`, `PSYNC`, `REPLCONF`) and administration (`ACL`, `CONFIG`, `MODULE`,
  `DEBUG`, `SHUTDOWN`, `REPLICAOF`, `SLAVEOF`, `FAILOVER`, `CLIENT KILL|PAUSE|UNPAUSE`).
- **ClickHouse** (specified, a stub here) sets the destination's database as the default.

**Secrets are at least `MIN_SECRET_BYTES` (16) long.** The SDK and the enclave check this at
seal time (`SecretPolicy::validate_secret`). Adapters mask every echo of the secret. So a
consumer who can make the upstream return chosen text learns whether that text contains the
secret. At 16 bytes, a random secret is out of reach of that search.

**A session can do whatever the credential can.** That includes minting a credential the
consumer then holds (`ALTER ROLE … PASSWORD`, Redis `ACL SETUSER`, an API's key-creation
endpoint). Adapter command filters are best effort against dynamic SQL and scripts. The
control is least privilege at the upstream, plus `HttpRules` for HTTP (`--deny` for
key-management paths).

**Tier floor** (`SecretPolicy::min_tier`, `--hardened-only`, `SealBuilder::hardened_only`).
Only hardened sessions may use the blob. The enclave recomputes the achieved tier from the
fresh endpoint report at every start and extend. So the blob stops working within one extend
of the endpoint's attestation going silent. When that is why a hardened start or extend was
refused, the replica records an `agent-silent` signal. An image without compiled-in evidence
checks for an enrolled source cannot reach Hardened. Hardened blobs fail closed there rather
than trust unverified bytes.

**Platforms** (`SecretPolicy::min_platform`, `--sealed-only`). The enclave wraps the DEK
only for the tenant's platforms at or above this floor, so a weaker platform the tenant
enables later cannot open the blob. Unset means every platform the tenant enables, and the
field is then omitted from the blob.

**Pins** (`SecretPolicy::pins`, `--pin sha256/<base64>`, at most `MAX_PINS` = 4) narrow the
baked roots for one blob. The upstream's chain must verify against the baked roots, and a
pinned key must be on a path that verifies. Otherwise the connection fails with
`NetError::PinMismatch`. The path covers the leaf's key, or an intermediate or baked root
the leaf chains to. Pin a CA key to survive leaf renewals. A pinned certificate that is
merely sent along does not count. Pins stop a misissued certificate for the destination
host. Unpinned blobs carry no pin field at all. The first pin adds about 54 characters to
the blob text, and each further one about 45.

Upstreams are TLS-only. `Destination` cannot represent a plaintext upstream. `http://`,
`redis://` and plain Postgres are refused at parse time. A Postgres server that answers `N`
to `SSLRequest` is refused (`NetError::NoTls`), never downgraded. Upstream certificates are
verified only against `seal_net::baked_roots()`, which is the Mozilla set plus the AWS RDS
global bundle (`crates/shared/seal-net/certs/`). Azure Database and Azure Cache roots are
already in the Mozilla set. Any other CA needs a custom image. The enclave and the guardian
check certificate validity (handshake and pins, for upstreams, the guardian, the control
plane, OIDC and STS) at trusted time, never the host-set system clock: the latest end of the
latest `seal_tee::Clock` reading, advanced by the monotonic clock (`seal_tee::tls_time()`,
`seal_net::BakedRootsConnector::with_time`). A handshake before the first reading fails.

## Enclave runtime

The enclave's internal ports and components are in the crate docs and
[ARCHITECTURE.md](ARCHITECTURE.md). This section covers what a tenant or client can observe.

- **Boot order.** A replica verifies its release evidence against its trust, then the tenant
  bundle (a chain matching the root id, a fresh state, and the state in force worked out
  from its own platform's guardian anchors), then its deployment identity. The cloud
  supplies a `DeploymentProof`: the ACI group's managed-identity token, a SigV4 request the
  Nitro parent presigned with its instance role, or the project and service account from
  the enclave's own Confidential Space attestation. The replica checks it against
  `TenantState::deployments` before requesting any key. So a genuine enclave that someone
  deploys for a tenant that never authorized it holds none of that tenant's keys. Service
  keys come with the guardian's `ServiceKeyCertificate`, which the replica serves in
  `AttestationResponse`. The platform master key never leaves the guardian.
- **What a replica serves** comes from the entries of the state in force that match its own
  deployment identity, checked on every operation.
  - With no matching entry (the tenant removed it), everything but `attestation` and `end`
    fails with `NotAllowed`. Data-plane connections are closed and live sessions end, within
    `STATE_RELOAD_SECS`.
  - An entry with a `HostedMode` marks Seal's hosted replica, which serves as the tenant's
    own replicas do and exits when idle. An identity listed more than once is hosted if any
    of its entries is.

  Only the tenant's admins sign entries, and a widening entry waits out the pending window.
  So neither Seal nor the host can make a replica the tenant did not list serve, or make a
  customer's replica idle out.
- **Hosted replicas exit when idle.** A replica whose matching entry has a `HostedMode` stops
  once it has gone `HOSTED_IDLE_SECS` (900) with no live session connection and no session,
  extend, end or signal by an authenticated caller. Seals, tickets, attestations and
  requests that fail authentication do not count, since anyone can send them. A seal in
  flight only holds off the drain until it ends. Once draining, later operations fail with
  `Unavailable` after authenticating, and data-plane connections are closed. The replica
  stops accepting, lets open API requests finish, ships the `last` telemetry batch and
  exits 0. Customer replicas never exit on their own, unless their deployer sets the exit
  timer.
- **Exit timer.** A deployer may set `SEAL_EXIT_AFTER_SECS` (whole seconds, 60 to 604 800) on
  any replica: that long after start it stops accepting, lets open API requests finish, ships
  the `last` telemetry batch and exits 0, as on SIGTERM. It is for short-lived replicas whose
  host stops them with no grace (an ACI stop or delete kills the container within a second),
  so their telemetry still ends cleanly. The deployer can stop a replica anyway, so the timer
  decides nothing it couldn't; the release's container and launch policies allow it, digits
  only. A value outside the range refuses to boot.
- **Tenant pin.** A `TenantPin` (`<tenant>@<root id>`, delivered as each cloud allows) pins a
  deployment to one tenant and its root chain. Every other tenant or chain is refused with
  `NotAllowed` (sessions, extends, ends, signals, session tokens). A seal upload for another
  tenant does not decrypt (`BadRequest`), tickets are issued only for the pinned tenant, and
  keys are requested only for it. The deployer sets the pin, and it is not attested. It can
  only narrow what the enclave serves.
- **Fail closed.** Once the cached state's `fresh_until` passes without a fresh bundle,
  every operation and connection fails with `Unavailable`.
- **Errors.** A caller sees only an `ErrorCode`. The enclave's detail text never reaches it.
- **Attestation.** `attestation()` keeps answering while the tenant state is stale, when
  everything else fails closed. It fails only once the latest periodic attestation is
  `ATTESTATION_MAX_AGE_SECS` old. The served release evidence carries a checkpoint within
  `FRESH_CHECKPOINT_SECS`, and every verifier checks it. Challenges are answered under the
  same rule, and only on TLS 1.3 connections (`BadRequest` otherwise).
- **Compiled-in timing.** `STATE_RELOAD_SECS` (30), `TENANT_KEY_CACHE_SECS` (900),
  `TELEMETRY_FLUSH_SECS` (5), `TELEMETRY_BUFFER_ENTRIES` (10 000) and `HOSTED_IDLE_SECS`
  (900; sim builds take `hosted_idle_secs` in `SEAL_ENCLAVE_CONFIG`). Compile-time checks
  keep two bounds:
  - `SESSION_END_RETAIN_SECS` (900) ≥ `SESSION_TOKEN_SECS` + `STATE_RELOAD_SECS`, so a
    `SessionEnd` outlives every token a not-yet-reloaded replica can still issue;
  - `HOSTED_IDLE_SECS` ≥ `SESSION_TOKEN_SECS`, so no token an idle replica issued outlives
    the replica.
- **Clock.** Between trusted clock reads, expiry checks widen the clock's radius by 1 s plus
  1 s per 1000 s, so a live connection may end up to about a second early.

## Control plane (`seal-control`)

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

- **Credentials** (`Authorization`) take one of four forms:
  - `Bearer sealct_…`, a console control token, served only for its tenant and root chain.
  - `SealSigned <base64url(JSON Signed<ControlRequest>)>`, signed by an admin key of the
    latest root, else by a telemetry key still in force of a certified
    `ServiceKeyCertificate` posted for the chain, else by a freshness key of the latest state (or, for the bundle and posting
    statements, of an earlier state stored since the guardians' oldest anchor, so the state
    in force's signers keep vouching while a change of signers is pending).
  - `SealAttested <base64url(JSON AttestedControlRequest)>`, for the bundle only. Its
    evidence must verify and commit to the request as report data. It must come from an
    enclave release stored on the control plane that passes `ReleaseVerifier` under the
    configured release trust, with a TCB meeting the release policy.
  - `Bearer <write token>`.

  A missing or invalid credential gets 401. A valid one that is not admitted here, or that
  is for another tenant or chain, gets 403. A tenant without a stored chain answers 401 to
  signed and attested requests.
- **Sealing reads nothing** here. It goes through an enclave, whose bundle holds the wrap
  keys. Only what sealing and booting need is public, and it reveals nothing secret.
- **Proposals** (`/proposals/{id}`, `Proposal { id, kind, document, created_at, updated_at
  }`) hold an unsigned or partly signed root or state. The id is the lowercase hex of the
  digest admins sign (`labeled_digest(TENANT_STATE_LABEL | TENANT_ROOT_LABEL, body)`). A PUT
  merges the signatures it brings. Each must verify for an admin key of the root the
  document needs, which is the latest root, or a proposed next root for a state signed
  under it. A document that cannot follow the stored chain and state gets 409. A threshold
  that does not fit its keys gets 400. A tenant has at most `MAX_PROPOSALS` (32) proposals,
  each with at most `MAX_PROPOSAL_SIGNATURES` (64).

  Submit needs the latest root's threshold. The control plane then logs the document
  itself, checks its inclusion proof, stores it and answers with the proof (`LoggedRoot` or
  `LoggedState`). A retried submit finds a document the log already holds among its last
  `LOG_LOOKBACK_ENTRIES` (1 024). Proposals overtaken by the chain or state are dropped. PUT
  `/state` takes a `LoggedState`, or a bare signed state that the control plane logs the
  same way.
- **Documents** (`GET /documents?since_version=N`) returns every root, the logged states
  above `N` oldest first, each with the proof fetched right after it was logged, and the
  log's latest checkpoint. This is the history the pending window is judged from.
- **Bundles** carry the states since an anchor (see "Binding and freshness"), the latest
  checkpoint, and each tenant platform's guardian's newest anchor, refreshed hourly
  (`ANCHOR_REFRESH_SECS`).
- **Releases.** `GET /v1/releases/{platform}` lists the stored evidence in log order.
  `/v1/releases/{platform}/{measurement}/template` serves a release's deployment template
  (for Azure, the ARM template with its `ccePolicy`), which `seal deploy` checks by
  measurement.

## Binding and freshness

- **Periodic attestation** (`GET /v1/attestation`). The binding carries `attested_at`, the
  enclave's trusted time, instead of a client challenge. An old one is refused after
  `ATTESTATION_MAX_AGE_SECS`. A replayed recent one convinces only a client that also gets
  the TLS handshake with the attested key, which a holder of copied service keys can do, so
  the SDK sends nothing secret on its strength alone (challenged attestation, above).
- **Challenged attestation** (`GET /v1/attestation?nonce=`). Each replica generates an
  Ed25519 challenge key in its own memory at start; it is never released, stored or shared.
  With each periodic attestation the replica also attests
  `labeled_digest(ATTESTATION_KEY_LABEL, AttestationKeyBinding { binding, challenge_key })`,
  so two hardware reports or Confidential Space tokens per 30 s serve every client. Each
  challenge costs one signature and no report, so a flood of challenges cannot exhaust the
  TEE or Google's per-project token quota, and the route has no rate limit of its own. The
  signature binds the connection through its TLS 1.3 exporter. TLS 1.2 is refused, since
  its exporter without the extended master secret can be made equal on two connections.
- `GuardianChallenge` is stateless and MAC'd with the platform's challenge key, so any
  guardian instance verifies it and nobody can exhaust it. Reuse within its 60 s is
  harmless, because a replayed `KeyRequest` only gets keys sealed again to the original
  requester's ephemeral key.
- `ProofTicket` (`POST /v1/tickets`, for the enclave's tenant) is MAC-authenticated and
  reusable until expiry. It is not a one-time-execution guarantee.
- `expected_purpose()` commits the full session blob and options, the extended token and
  endpoint report, or the self-signal. Seal uploads carry no proof. Their HPKE AAD
  (`IngestContext`) binds them to the enclave they were sealed for. The outer `ProofContext`
  binds tenant, server TLS key and ticket. OIDC cannot sign this commitment. Its
  bearer/channel assurance is recorded as `ProofAssurance::BearerOverAttestedChannel`.
- Caller authorization intersects the exact originally authenticated matchers with current
  app grants, checks the identity and honors authentication expiry. This preserves Azure
  audience constraints. A caller's original JWT expiry does not expire the blobs it uses.
- **Control-plane requests** (`seal_proto::control`). A signed or attested request names
  exactly one request, `ControlRequest { tenant, root_id, method, path (with its query, as
  sent), body_sha256, issued_at }` under `CONTROL_REQUEST_LABEL`. The control plane accepts
  it within `CONTROL_REQUEST_MAX_AGE_SECS` (300 s) of its own clock, either way. An attested
  request's report data is its labeled digest. Requests travel only over TLS, so a captured
  one is useless for another request, tenant or chain, or after its window. The enclave's
  `issued_at` comes from the host's clock. A host that moves that clock only gets reads
  refused.
- **State freshness.** Each `TenantState` is logged as a digest leaf, which the log accepts
  only with valid admin signatures and a higher version. The admin tool logs it, or the
  control plane does when a proposal is submitted. The control plane stores it with its
  inclusion proof. The log signs `StateFreshness` for each tenant's latest state, and the
  bundle carries it. The enclave and the guardian use a state only with a statement for
  exactly that state, younger than its freshness window: the shorter `freshness_secs` of
  the latest state and the state in force, `STATE_FRESHNESS_SECS` (24 h) when neither sets
  one. When the state names `freshness_keys`, they also need one from a tenant-run signer,
  within the same window, and likewise one from a signer of the state in force when that
  names any. Any one listed signer suffices, so adding a signer to a non-empty set widens and
  removing the last widens (both wait the pending window, during which the signers in force
  still vouch); the first signer, or removing one while others remain, narrows. So replaying an older state, or a truncated root chain, works for
  at most that window. Withholding a newer state makes the tenant unavailable after it
  instead of quietly stale. A log statement for an older
  version than one the log already logged is a signed, provable lie (`seal status --log`
  looks for them). Monotonic caches still reject rollback relative to remembered state.
- **Pending window** (`seal_verify::change`, `seal_verify::window`). The document in force
  is a pair, a state and the root that signed it. From it, the tenant moves to a newer state
  as soon as one is admissible, and judges the rest again from there. When several are
  admissible at once it takes the oldest, so states apply in log order. A newer state is
  admissible:
  - at once, from its `public_since`, when it does not widen the state in force, and any
    newer root it comes with does not widen the root in force and also carries the
    in-force root's threshold. Keys not yet in force cannot make an immediate change;
  - otherwise, once its `public_since` (and that of every newer root up to its own) plus
    the window **of the state in force** is at most `lock_time(time, witnessed)`. That is the
    earlier of `time.earliest()` and the latest witness time of every checkpoint in the
    bundle, as for the release time lock.

  The tenant never moves back, and a state signed under an older root than the one in force
  never applies. So a newer state that does not widen the one in force cancels every older
  pending one. A newer widening state does not. A difference is narrowing only when it
  provably is. Anything else, including a field the classifier does not know, is widening.
  The first state applies at once. **Every time is a `public_since`** from an inclusion
  proof, which the control plane fetches right after it logs the document. Whoever serves
  proofs can make a document look later (delaying a cancel or a narrowing, as withholding it
  would), but never make a widening look earlier.
- **Anchors bound the bundle.** Which state is in force depends on the whole history, so a
  verifier without memory starts from an anchor. An anchor is one of:
  - the tenant's first state;
  - a state whose successor became public at least `MAX_PENDING_WINDOW_SECS` after it;
  - the latest state, once that long has passed;
  - a `TenantAnchor` signed by a guardian the verifier trusts
    (`TenantVerifier::with_anchor_keys`) for this tenant and chain, with `at` no later than
    its `lock_time`, naming a state in the bundle.

  A guardian signs a `TenantAnchor` for any bundle that verifies (`POST /v1/anchors`), as of
  `at = min(lock_time, signed_at)`, where `signed_at` is when the earliest-expiring required
  freshness statement was signed. The freshness statement proves
  no newer state existed at that time. Every state newer than the one in force at `at`
  became public after `at − MAX_PENDING_WINDOW_SECS`, so a bundle needs only those. With the
  control plane refreshing anchors hourly, that is about 25 h of states. The enclave trusts
  its own platform's guardian, and the guardian trusts itself, so both start from the same
  anchor and agree on the state in force. Admin tools and the browser trust every guardian
  in their trust. A wrong anchor needs a guardian key. A stale or withheld one only makes
  bundles bigger.
- Replicas reload their tenant's bundle every `STATE_RELOAD_SECS` (30 s). That bounds how
  long a grant removal, a clearance, an external signal or another replica's `SessionEnd`
  takes to reach every replica. Tenant wrapping keys are refetched after
  `TENANT_KEY_CACHE_SECS` (15 min). That bounds how long a revoked customer-managed key keeps
  working for new sessions. Both are compiled in, not deploy settings, because the deployer
  is untrusted.
- `TrustedTime` is an interval. "Not before" checks (time locks) use its earliest end, and
  "not after" checks (expiry, freshness) use its latest, so clock uncertainty never helps an
  attacker. Retention and suspensions also use the earliest end, so neither ends early. The
  one exception is an attestation token's `nbf`, which is checked against the latest end
  plus 60 s. Google stamps `nbf` at the issuing second, a correct clock can read just before
  it, and using an attestation token early gains nothing. Every check takes a
  `TrustedTime`, and clients without a trusted clock pass `TrustedTime::exact`. Timestamps
  written into documents take its `now`.

## Known limits and unresolved items

### Accepted limits

- **Seal can destroy a platform root, never read it.** Each root sits in two of Seal's
  vaults in different regions, with 90-day purge protection and delete locks, so an
  accident or a regional outage loses nothing. But the vaults' owner can still delete both
  copies. That makes the platform's blobs unopenable, an outage that ends when customers
  reseal. It never exposes a secret, since Seal stores no customer data and the immutable
  release policies stop even the owner from reading a root.
- **Guardian succession has a window.** A frozen guardian hands its root to a successor
  guardian release that passes the same rules as an enclave release (M-of-N, log, time
  lock; `KeyPurpose::Succession`). So a platform format change, a guardian bug, or a trust
  change that `revoked_keys` cannot express (the log key) costs a release, not a reseal. The
  handover only works while the old guardian can still verify the successor. If a platform
  change outruns it, the fallback is a new root, and every customer reseals.
- **Seal's guardian runs on Azure, so every cloud trusts Microsoft for key release.** Seal's
  ACI guardian (serving `azure_snp_aci`) holds its root wrapped under an exportable
  `RSA-HSM` key in Key Vault Premium, whose release policy is immutable. Neither Seal nor the
  subscription's owner can release the key to anything but the guardian's measurement. But
  Microsoft Azure Attestation, the UVM endorsement and Key Vault's HSMs are trusted, and an
  Azure outage blocks enclave boots. Running enclaves keep serving until their state goes
  stale. Premium holds the root in each vault listed. Managed HSM in two regions is
  designed, not built. A self-hosted guardian on AWS or GCP KMS avoids Azure, but trusts that
  cloud's account administrators, who can always change who gets the key.
- **Competing tenant roots.** The registrar (Seal) can log a competing root v1 for an
  existing tenant's name. That root gets a different `TenantRootId`, and so unrelated keys.
  It opens none of the tenant's blobs, the tenant's pinned deployments refuse it, and SDKs
  with `root_id` set refuse enclaves serving it. A sealer without a pinned root could still
  be steered to an enclave serving it and seal there. `seal status --log` detects it.
- **Freshness window.** A replayed older state works for at most its freshness window,
  `STATE_FRESHNESS_SECS` (24 h) unless the tenant sets a shorter one (down to 5 min). With
  the log as the only freshness signer, the log operator (Seal) could sign for
  an older state. That is provable but not prevented. A tenant-run signer
  (`freshness_keys`) prevents it for every state signed after the signer was added.
- **OIDC binding.** OIDC JWTs (Azure managed identity) cannot embed the proof context. Only
  the attested channel and the JWT lifetime bind them. Azure and GCP providers cache their
  tokens, so disabling such an identity takes effect only when its current token expires.
- **Sessions can mint credentials.** A consumer can do anything the sealed credential
  allows, including creating a credential of its own, and adapters cannot reliably stop it.
  Upstream least privilege is the control.
- **Scrubbing.** Response scrubbing masks the secret plain, under one layer of JSON or URL
  escaping, and in base64 (standard or URL-safe, any alignment, every character carrying
  any of its bits, the edge ones shared with neighbouring bytes included). It
  does not catch any other transformation an upstream echoes: hex, a hash, a substring,
  double escaping. A secret inside an LZ4, ZSTD or gzip frame
  never appears whole, so adapters refuse response compression. HTTP asks for `identity`,
  and the ClickHouse adapter is specified to refuse compressed connections. Masking is
  visible, so it tells a consumer whether chosen text is the secret. A random secret of
  `MIN_SECRET_BYTES` is out of reach of that search. A guessable secret of any length is
  not. When and in what pieces the scrubber releases bytes depends only on how many arrived
  and when, never on what they were: it always holds back a fixed window (the longest
  spelling of any needle, less one) and releases it at a protocol message boundary, at the
  end of a body, or, for HTTP, once the upstream has sent nothing for `QUIET_RELEASE`
  (100 ms). So echoing a guess cannot tell how much of the secret it matches. An echo of the
  secret itself that the upstream pauses in the middle of for that long goes out unmasked up
  to the pause. Scanning costs the same per byte whatever the bytes are and however much of
  the secret they match: one bit-parallel automaton steps over every spelling state of
  every pattern at each byte. That cost grows with the secret's length: about 8 ms per MiB
  of response for a 28-byte HTTP key and 170 ms per MiB for a 1 KiB one, on one core.
  Building a scrubber, which adapters do per connection (HTTP: per response), costs the same
  for every secret of a length: the automaton's tables are its classes transposed, a fixed
  sequence of word operations. The secret's length is not hidden: masking keeps it, and an
  upstream's header size limit can reveal the injected header's. An HTTP response header or
  trailer whose name carries a needle in any of these forms, in any ASCII case (names arrive
  lowercased), is dropped.
- **Timing of secret checks.** Comparisons of secret-derived bytes take time set by their
  lengths alone: ticket and guardian challenge MACs (`Mac::verify_slice`), a tunnel's local
  key against `local_key_sha256` and against the key an HTTP connection is bound to, and
  `SecretVec` and `Bearer` equality (`seal_proto::secret::ct_eq`). Session tokens and blobs
  fail only at their AEAD tag, after checks of public header fields. Ed25519 (dalek), X25519,
  AES-GCM and HMAC are constant time. The guardian's RSA-OAEP decryptions (`rsa`,
  RUSTSEC-2023-0071) are blinded and happen at boot only, at most once per Key Vault key the
  build names, on a copy the host supplies (DEPS.md).
- **Postgres cancels** reach only the replica holding the connection. One sent to another
  replica does nothing. A tunnel sends its connections to the replica that last answered, so
  a cancel lands there unless that replica stopped answering in between.
- **Connection slots are first come.** A caller with many sources (IPv6 /64s are cheap)
  that keeps connections open, sending a byte within every 120 s, can hold the port's
  `MAX_CONNECTIONS` and keep new callers out until it stops. Live tunnels need a session.
- **Anyone can start** a tenant's stopped hosted replica by connecting to
  `<tenant>.enclave.seal.zone`. It costs Seal a replica start and nothing else. Starts are
  rate limited and keep nothing running, since unauthenticated requests do not count as
  activity. The first request after a quiet period waits for the replica to start (about a
  minute, within `UNREACHABLE_WAIT_SECS`).
- **Attested boot reads do not check the deployment identity.** Any released enclave build
  pinned to a tenant reads that tenant's bundle. The pin is unattested, but such an enclave
  holds the grants in memory nobody can inspect, finds its identity unlisted and stops.
- **The pending window passes late, never early.** It is measured by the witnessed time the
  bundle carries. The control plane's checkpoint cache (`CHECKPOINT_CACHE_SECS`, 60 s) and
  `STATE_RELOAD_SECS` add up to about 90 s. A cancelling state needs the root in force.
  States are signed under the latest root and apply only with it, so while a root is
  pending, a cancel waits for it.
- **Anchors trust the verifier's platform guardian.** A holder of a platform root could sign
  a false anchor and fast-track a widening for that platform's enclaves, since enclaves
  trust only their own platform's guardian. The same holder can already release that
  platform's keys. On a self-hosted guardian on AWS or GCP KMS, that includes the account's
  administrators.
- **Self-asserted endpoint reports.** The artifact check catches drift and tampering, not an
  attacker who controls the endpoint. Stronger evidence plugs in through `EvidenceCheck`.
- **Telemetry tail.** A replica that dies can lose up to one buffer of unsent entries.
  Readers see this as a stream without a `last` batch.
- **Ending is not instant everywhere.** A `SessionEnd` takes effect at once on the replica
  that created it and within `STATE_RELOAD_SECS` on the others. A control plane that
  withholds it delays that until the session's last token expires (at most
  `SESSION_TOKEN_SECS` after its last extend).
- **Unpinned destinations** trust every baked root, so a CA that misissues a certificate for
  the destination host can intercept. Pins close this per blob.

### Unresolved

- **Endpoint reports of interpreted apps.** The default `ExecutableHash` reports the
  interpreter, so an artifact check pins Python, not the app. Apps can pass an
  `endpoint_reporter` (`seal.EndpointReport(artifact=...)`). A better default (an image
  digest, a bundle hash) is open.
- **AWS identity in Python.** Release wheels are built without the `aws` feature (a large
  tree), so they have no `AwsIdentity`. Whether to include it is undecided.
- **`MIN_SECRET_BYTES`.** 16 refuses some existing short database passwords. 12 would still
  put a random secret of a full alphabet out of reach.
- **Bundle size in bytes.** Bundles carry about 25 h of states, and `HttpsClient` caps a
  response at 1 MiB. The cap also bounds `/documents`, which `since_version` keeps small. A
  tenant submitting hundreds of states a day could pass it. A per-tenant rate on submits
  would make the bound strict.
- **Root changes that drop the in-force admins cannot be vetoed.** A pending root is
  cancelled by a newer root its own keys sign. If the pending root leaves fewer than its
  threshold of the current admins, they cannot sign one, and the window only makes it
  public. Requiring rotations to keep a threshold of the previous admins would close this.
- **Version gaps and lost states.** Verifiers need consecutive state versions, but the dev
  log accepts any higher version. The log should refuse gaps. A state logged but held
  nowhere (neither stored nor proposed) leaves its successor unverifiable until it has been
  public for `MAX_PENDING_WINDOW_SECS`. `seal dev init` supersedes such a state, and
  verifiers accept the new state only after that long.
- **Production log API.** The control plane appends documents to the log and reads proofs
  and entries (`POST /v1/entries`, `POST /v1/tenants/{t}/states`, `GET /v1/proof/{i}`,
  `/v1/entries/{i}`), as the dev log serves them. The production log must serve the same.
- **Vendored crates are not committed.** An image rebuilds from the repository plus crates
  fetched and checked against `Cargo.lock` before the build. Committing `vendor/` (about
  360 MB) would make "from the repository alone" literal.
- **Boot failures are hard to see.** ACI keeps no output of a confidential container that
  exited. So a refusal at boot (for example a release still inside its time lock, which the
  restart policy retries) shows only in the control plane's request log. Right after their
  root ceremony, two guardians each exited once on their first start with no output and
  booted on the second. This has not been reproduced.
- **Tenant onboarding.** The registrar's API (`seal-registrar`) is called only by Seal's
  console and is not part of this contract.
- **AWS, still to test.**
  - The accuracy of the NSM attestation timestamp that `NitroClock` uses. AWS documents
    what it is, not how the hypervisor's clock is disciplined. `RADIUS` is 1 s until
    measured.
  - vsock proxy throughput for the data plane.
  - Booting a Nitro image whose boot blobs Seal builds from source (a 6.6 kernel) instead
    of AWS's (4.14). That would end the dependency on AWS keeping the pinned blob bytes
    available.
- **GCP managed databases.** Cloud SQL in Google-managed shared-CA mode chains to one public
  root valid until 2049 (`Google Cloud SQL Root Server CA`, the same for every customer), so
  it can be baked. Its certificates name the host with a trailing dot (`….sql.goog.`).
  `seal_net::UpstreamConnector` matches that name after the chain verifies, as its only
  exception to exact name matching. Memorystore for Redis Cluster and for Valkey in
  shared-CA mode have per-region roots valid 25 years but intermediates valid one year. They
  can be baked only if servers send their intermediate. Redis Cluster also needs cluster
  redirects, which the Redis adapter does not follow. Standalone Memorystore for Redis and
  every per-instance or customer-managed CA mode need the Custom plan. Still to test on live
  instances are the exact SANs, and whether the servers send their intermediates.
- **GCP Confidential Space attests TDX only.** On SEV-SNP the launcher gets no token
  (`UNSUPPORTED_CC_TECHNOLOGY`), and plain SEV is refused (no memory integrity). So enclaves
  and guardians on Confidential Space run on TDX (`c3-*`). `GCP_AMD_SEV_SNP` is accepted
  once Google attests it. PKI tokens carry the report data as one 64-character hex nonce,
  are about 11 KB and last an hour. TDX tokens' Intel TCB status is in `Tcb`
  (`tdx_tcb_status`, `tdx_tcb_evaluation_data_number`). A `min_tcb` naming them refuses
  tokens without the claim.
- **Azure TCB floors are per chip family.** An Azure `Tcb` names its hardware components
  after the chip family whose AMD key signed the report (`milan.bootloader`, `.tee`, `.snp`,
  `.microcode`; the same for `genoa`; `turin` adds `.fmc`), plus `uvm_svn` with no family.
  A `min_tcb` entry `family.component` applies only to that family (`Tcb::passes`), and once
  any family is named, evidence of a family the floor does not name is refused. Admitting a
  family is adding its floor; witnesses allow that, since it only rises afterwards. A
  component without its family (`snp`) is in no Azure evidence, so it refuses all of them.
  The floors take effect only in builds that name components this way: a guardian or SDK
  built before reads them as components its evidence lacks and refuses Azure.
- **Azure Key Vault, measured.** An ACI confidential group's guardian attests at Microsoft
  Azure Attestation's shared East US endpoint (`POST /attest/SevSnpVm`, with the report, the
  VCEK with the baked ASK and ARK, and the UVM endorsement). It gets back claims an
  immutable release policy can pin (`x-ms-attestation-type`, `x-ms-compliance-status` =
  `azure-compliant-uvm`, `x-ms-sevsnpvm-hostdata`, `-is-debuggable`, `-vmpl`). A group with
  another `host_data` is refused (403, "attestation does not meet key release
  requirements"). `POST /keys/<name>/release` without a version releases the current one.

  The release JWS is signed with a certificate that chains to a public root and names the
  vault's host, so webpki checks it. Its payload carries the key's attributes and release
  policy, and names a released `RSA-HSM` key `kty: "RSA"`. An immutable policy binds every
  later version of the key. A new version with another policy is refused (`AKV.SKR.1020`),
  so each guardian measurement needs a key of its own. In a container policy, a variable
  set to `""` reaches the env rules as its bare name. Rules are Go RE2, where a counted
  repetition above 1000 never matches.
- **Azure, still to test.** The docs are silent on these:
  - whether attestation providers other than Microsoft's shared regional endpoints can emit
    the `x-ms-*` claims a release policy pins;
  - whether Key Vault release policies now evaluate comparison operators (the grammar lists
    them). TCB floors stay in checkpoint policy either way;
  - importing an exportable `oct-HSM` key with an immutable release policy into Managed HSM.
    The Managed HSM root ceremony needs it, and this build implements Premium's `RSA-HSM`
    only;
  - which regions offer confidential container groups. There is no current list; eastus
    does, on Genoa hosts;
  - cross-tenant key release for customer-managed KMS. The federated-credential setup that
    cross-tenant customer-managed keys use should carry the release role, but no doc says
    so;
  - whether ARM updates a running confidential group in place when `ccePolicy` and the image
    change, or needs delete and create (`seal deploy upgrade`'s error names that fallback),
    and whether the group keeps its private IP across it;
  - whether `az container show` returns `ccePolicy`. It returns non-secure variable values,
    and `upgrade` reads the running release and pin from them. Without the policy, `upgrade`
    proceeds with "release unknown". Without the pin, it refuses;
  - `seal deploy azure`'s audience registration against a real Entra tenant. That means
    checking that `api://<app id>` passes identifier-URI restrictions, and that an IMDS v1
    token requested for it carries it as `aud`.
- **Zero-touch upgrades.** The customer runs upgrades with `seal deploy upgrade`. It makes
  the same checks as `seal deploy azure` and keeps the group's identity, network and pin. It
  refuses to go back to a release older than the one the group runs, while that one still
  verifies. Still open are an Azure managed application, where Seal pushes upgrades, or an
  enclave that redeploys itself, only to releases passing `ReleaseVerifier`.
- **Endpoint discovery.** Clients take replica endpoints from `SEAL_ENDPOINT`. Reading them
  from signed tenant state (an additive field) is open.

## Check the contract

- `cargo test -p sealzone-proto --test vectors` checks every v1 wire vector and that all
  signing labels are distinct. `crates/sdk/seal-verify-wasm/build.sh --test` runs the
  browser verifier's vectors (`tests/vectors.json`) under Node.
- Both vector files are regenerated only for a deliberate format change
  (`SEAL_WRITE_VECTORS=1` on the test), and the diff is reviewed.
- `cargo check -p sealzone --example contract` and the crate-level doc example check the
  client-facing usage.

The other tests and CI are in [CONTRIBUTING.md](../CONTRIBUTING.md).
