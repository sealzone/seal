# Seal: module boundaries

The public interface contract (roles, SDK surface, ports, vocabulary, known limits) is
[CONTRACT.md](CONTRACT.md). This file covers crate layout, boundaries, rules and hosting.
Dependency policy is in [DEPS.md](DEPS.md). Where a document and the code disagree, the code
is right and the document is fixed.

Platforms: **Azure confidential containers on ACI (SEV-SNP)**, **AWS Nitro Enclaves**, **GCP
Confidential Space (TDX; SEV-SNP once Google attests it)** and the local **simulator**, all behind
the same enums. Azure and Confidential Space are built; for Nitro only evidence verification
(`seal_attest::nitro`) is, and its attestor, clock, egress proxy and key source are stubs.
Seal's guardian runs on Azure.

## Layout

Crates are grouped by role under `crates/`. Crate names do not change with the folder.

| Folder | Crates | Runs |
| --- | --- | --- |
| `shared/` | seal-proto, seal-crypto, seal-tlog, seal-verify, seal-attest, seal-net, seal-tee | Used by more than one realm: all of them in the enclave and guardian; seal-tee never in the SDK |
| `enclave/` | seal-enclave, seal-cloud, seal-authz, seal-integrity | Customer's cloud, inside the enclave TEE |
| `enclave/adapters/` | seal-adapter, seal-adapter-{http,pg,redis,clickhouse} | Inside the enclave TEE; upstream protocols only, one crate each |
| `guardian/` | seal-guardian | Seal-run, its own TEE; a release is frozen, and a successor release takes over its root |
| `control-plane/` | seal-control, seal-registrar | Seal-run, no TEE: the control plane is untrusted; the registrar signs only root version 1 of new tenants |
| `sdk/` | seal-client, seal-cli, seal-py, seal-node, seal-ffi (and the Go module `seal-go`, not a crate), seal-verify-wasm | Customer's processes and machines; seal-verify-wasm in admins' browsers |
| `sim/` | seal-sim, seal-release (`publish = false`) | Developer machines only, never shipped: seal-sim sets up and drives the whole system on the simulator; seal-release (production SDK, no `sim` feature) measures, signs, logs and publishes releases and drives the same flows against live deployments |

The enclave and the guardian are separate realms: the enclave runs on every cloud and changes
with each release; Seal's guardian runs on Azure (or where a customer self-hosts it), and
never changes once frozen. Code only one realm needs lives in that realm's folder: the guardian's key
sources in `seal-guardian`, the enclave's per-cloud wiring in `seal-cloud`. Checking evidence
(`seal-attest`) and being a TEE (`seal-tee`) are shared.

Platforms are a closed set, so platform code dispatches with a `match` on an enum
(`seal_proto::Evidence`, `seal_tee::{Attestor, Clock}`, `seal_cloud::Cloud`,
`seal_guardian::KeySource`), never a trait object: adding a cloud fails to compile until every
match handles it. Outside `seal-attest`, `seal-tee`, `seal-cloud` and the guardian's key sources,
no crate names a cloud.

### Published names

The brand handle everywhere is **`sealzone`** (domain `seal.zone`, GitHub `sealzone`). Only
what customers install is published; every other crate is `publish = false` and keeps its
`seal-*` name. Published crates keep their `seal_*` library names, so code inside the repo
never changes with packaging.

| Ecosystem | Package | Users write | Built from |
| --- | --- | --- | --- |
| crates.io | `sealzone` | `use seal::Client` | `sdk/seal-client` |
| crates.io | `sealzone-{proto,crypto,tlog,verify,net,attest,control}` | (pulled in by `sealzone`) | the SDK's dependencies in `shared/` and `control-plane/` |
| crates.io | `sealzone-cli` | `cargo install sealzone-cli` → the `seal` binary | `sdk/seal-cli` |
| PyPI | `sealzone` | `import seal` | `sdk/seal-py` |
| npm | `@sealzone/verify` (the browser verifier, WASM) | `import { verifyTenant } from "@sealzone/verify"` | `sdk/seal-verify-wasm` (`build.sh`) |
| npm | `@sealzone/sdk` (napi-rs; one prebuilt package per platform) | `import { Client } from "@sealzone/sdk"` | `sdk/seal-node` (`build.sh`) |
| Go | module `seal.zone/go` (`seal.zone` serves the `go-import` tag for `github.com/sealzone/seal-go`) | `seal.FromEnv(ctx)` | `sdk/seal-go` over the C ABI in `sdk/seal-ffi` (`build.sh`: a static library per platform) |

`cargo -p` takes the package name: `-p sealzone`, `-p sealzone-proto`; unpublished crates keep
theirs (`-p seal-enclave`). `cargo publish --workspace --dry-run` must pass.

Folder rule: every folder depends only on `shared/`, plus the two service clients:
`seal_guardian::client` (used by `enclave/`) and `seal_control::client` (used by `enclave/`
and `sdk/`). Each service ships its own client, so callers never re-implement its API.
`sim/` is the exception: it may depend on `sdk/` and on the dev features of `shared/`.

## Dependency graph (acyclic; an arrow means "may depend on")

```
seal-proto    ◄── everything. Data only: ids, codec, error, secret, signed, time, policy, blob,
                  identity, integrity, freshness, session, api, state, release, tunnel, telemetry.
seal-crypto   ──► proto                                  pure crypto, no IO
seal-tlog     ──► proto, crypto                          pure log primitives (+ `dev` log/witness server)
seal-verify   ──► proto, crypto, tlog                    pure release + tenant-bundle verification (ONE impl)
seal-net      ──► proto                                  `Dialer`, outbound TLS with baked roots; `UpstreamStream`
seal-attest   ──► proto, crypto                          pure evidence verification, one `verify` for every platform
seal-tee      ──► proto, crypto, attest, net             being a TEE: `Attestor`, `Clock` (Roughtime)
seal-authz    ──► proto, crypto, verify, net             proof contexts, identity proofs, state cache, decisions
seal-cloud     ──► proto, net, tee, attest, authz         the enclave's cloud: `Cloud` (pin, deployment proof, dialer)
seal-integrity ──► proto                                 App Integrity plug-ins: observations, detectors, verdicts
seal-adapter  ──► proto, net, integrity                  upstream adapter contract (+ `testing` doubles)
seal-adapter-{http,pg,redis,clickhouse} ──► adapter, proto     one wire protocol each
seal-guardian ──► proto, crypto, tlog, verify, attest, tee, net   key guardian lib + bin + `client`; `KeySource`
seal-control  ──► proto, crypto, tlog, verify, attest, net   untrusted signed-document store: bin + `client`
seal-registrar ──► proto, crypto, net                    signs root version 1 of new tenants: bin
seal-enclave  ──► everything above                       composition root + bin
seal-client   ──► proto, crypto, tlog, verify, attest, net, control(client)   SDK core (+ `admin`)
seal-cli      ──► client, crypto, verify, attest, proto  `seal` binary
seal-py       ──► client, proto                          Python bindings
seal-node     ──► client, proto                          Node bindings (napi-rs)
seal-ffi      ──► client, proto                          C ABI for the Go module
seal-verify-wasm ──► proto, crypto, tlog, verify         the browser verifier (`wasm-bindgen` on `wasm32` only)
```

Forbidden edges: adapters → anything but adapter/net/proto/integrity; integrity → anything but proto; authz → adapter/attest/tee/cloud;
anything → enclave/client/cli/py/node/ffi/verify-wasm; proto → anything internal; attest → anything but proto/crypto;
guardian → authz/adapter/cloud/control; SDK crates → tee/cloud;
anything outside `seal-control` → its server code (only `seal_control::client`).

## Boundary rules

1. **Public items are the contract between crates.** Private items are free; a change to a
   public signature, or a new public item another crate uses, updates CONTRACT.md in the
   same change.
2. **Wire format v1 is frozen** (CONTRACT.md): a `seal-proto` type that is signed, hashed,
   used as associated data or read by a guardian may only gain optional fields omitted when
   unset; anything else is a new label version. The vectors in
   `crates/shared/seal-proto/tests/vectors/wire-v1.json` enforce it.
3. **Pure cores, IO at the edges.** Decisions (`seal-authz::decide`, `seal-guardian::authorize`,
   `seal-tlog::verify`, all of `seal-crypto`, every `seal_integrity::{Detector, EvidenceCheck}`) take every input as arguments: no clock,
   no network, no globals, no randomness except an injected RNG. Time arrives as a
   `seal_proto::TrustedTime`, never a bare `UnixTime`.
4. **Secrets**: only `seal_proto::{SecretVec, Bearer}`, `seal-crypto` key types,
   `seal_crypto::SecretBytes` and `seal_adapter::Session` hold secrets or bearer credentials. They zeroize on drop and
   redact `Debug`. Never `Display`, `Serialize`, log, or put a secret in an error.
5. **Errors**: each crate has one error type with `code() -> seal_proto::ErrorCode`, the only
   part that crosses to a caller; messages shown to callers never include secrets or internals.
6. **Signatures** always sign `codec::labeled_digest(LABEL, &msg)` with a label constant from
   `seal-proto`. **Hashes/AAD** always use `codec::canonical`.
7. **No plaintext upstreams.** Only `seal_net::UpstreamConnector::connect(&Destination)` produces
   a stream you may send a secret on (`UpstreamStream`, verified TLS by construction). Upstream
   trust = `seal_net::baked_roots()`; extra roots only behind the `sim` feature.
8. **Production builds exclude `sim`.** Any code that weakens trust (sim evidence, extra CAs,
   config-file guardian rules, system clock as trusted time) lives behind `feature = "sim"`.

## Conventions

- Rust 2021, MSRV 1.92, toolchain pinned in `rust-toolchain.toml`, formatted with the
  repository's `rustfmt.toml`. No `unsafe` outside the bindings: `seal-ffi` (the C ABI),
  `seal-node` (what napi-rs expands to), `seal-py` (its per-process runtime pointer) and
  `seal-verify-wasm` (`deny`, allowed only in the module `#[wasm_bindgen]` expands in); the
  SNP device ioctl goes through `sev`.
- async = tokio; HTTP = hyper 1 (server and client), axum for the control plane and enclave
  APIs; TLS = rustls 0.23 with the `ring` provider.
- Unit tests live next to the code. `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings` and `cargo test --workspace` pass on every change (CI runs
  them).
- **Dependencies follow [DEPS.md](DEPS.md)**: versions live only in the root
  `[workspace.dependencies]`, crates opt in with `.workspace = true`, and
  `scripts/check-deps.sh` must pass.

## Hosting and runtime topology

```
app host  (customer's cloud, the app's VNet)
|
|-- app process  (the enclave cannot see into it)
|    \-- SDK: seal - session - extend (every 5 min) - end - signal
|         \-- tunnel: loopback byte forwarder, never sees the secret
|
\-- seal host agent  (root on the host; the App Integrity add-on, separate)
     |-- watches /proc outside the app process (shells, tracers, swaps, mem)
     |-- evidence --> SDK's reporter over a local socket (challenge-bound;
     |                 rides every session start and extend)
     \-- findings --> POST /v1/signals on a replica (signed; the
                       replica verifies, applies at once, publishes)
     [watchdog pair + systemd: recovery only]

        SDK ---- API + data plane (TLS, pinned key) ---->
        agent -- findings (signed, CA pinned) ---------->   |
                                                           v
          seal-enclave replicas  (own TEE, pinned <tenant>@<root id>)
            |-- authz, sessions, BlobCipher::open (the only place a blob is decrypted)
            |-- the granted tier, recomputed from the fresh report at every
            |   start and extend: a hardened floor is the deadman (a killed
            |   agent stops hardened blobs within one extend; agent-silent)
            |-- integrity: detectors, evidence checks, policy
            |-- telemetry: signed batches ----------------> seal-control
            |-- reload TenantBundle every 30 s <--------- seal-control
            \-- adapters = the proxy: http - postgres - redis
                   | TLS, baked roots + sealed pins
                   v
             upstreams: private DBs in the VNet, public APIs

seal-run, shared by all customers
  seal-guardian (own TEE) ...... boot: KeyRequest --> the replicas
  seal-control (no TEE, untrusted) <.. telemetry, signals, ends, admin CLI, EDR
  transparency log + witnesses
```

- **The customer runs only enclave replicas**, in the app's network on their own cloud,
  deployed with `seal deploy azure` (and `seal deploy upgrade`; AWS and GCP are designed, not
  built) from the
  release's published templates. Never inside the app's own TEE or container group: that
  would put the app into the measurement. An Azure release's template is the `seal-release
  aci-policy` output, published untrusted next to the evidence (`seal-release publish
  --template`, served at `/v1/releases/{platform}/{measurement}/template`): its policy
  authenticates itself, since `measurement(SHA-256(policy))` must be a release the CLI
  verified (`ReleaseVerifier` under `trust.releases`, plus the admins' co-signature for
  `cosign_releases` tenants). The CLI takes only the policy and Seal's container from it
  (one container, image by digest, only `SEAL_TENANT` set, TCP ports) and renders the deployed
  ARM template itself: one confidential container group, `restartPolicy: Always`, the
  user-assigned managed identity, the checked subnet, a private address, run with
  `az deployment group create` under the customer's own `az` login. A template from an
  untrusted source cannot add a resource, role assignment or container.

  | Cloud | Replica | Measurement | Tenant pin | Deployment identity | Locked down by |
  | --- | --- | --- | --- | --- | --- |
  | Azure | Confidential container group (ACI) | Container policy hash (`host_data`) | `SEAL_TENANT`, allowed by an anchored re2 rule in the policy | Group's managed identity | The policy: no exec, no stack dumps, no unencrypted scratch, Seal's container unprivileged, no env var dropping (a rule for every variable ACI injects, including `APP_IDENTITY_ENDPOINT`), fixed mounts, and no Microsoft infra fragment (it would let containers join the group without changing `host_data`). ACI adds its own containers to every confidential group (`atlas-mount-resolv-conf`; with a managed identity `msi-atlas-adapter` and `atlas-netstats`; two of them privileged), so the release policy lists those three itself, copied from the infra fragment, and is refreshed when Microsoft changes them. Nothing outside the framework skeleton: seal-release refuses a policy with any other line (a rule of its own, a comment, a framework rule bound to another or not in `FRAMEWORK_RULES`) |
  | AWS | Nitro enclave on an EC2 parent | PCR0/1/2 of the enclave image | First message from the parent over vsock | Parent's instance role (SigV4) | Nitro: no network, no shell, no debug or attached console (PCRs zero, refused) |
  | GCP | Confidential Space VM (TDX, `c3-*`; SEV-SNP once Google attests it) | Container image digest | `tee-env-SEAL_TENANT` (read as `SEAL_TENANT`), the only override the image's launch policy allows (`tee.launch_policy.allow_env_override`) | Project number and the one service account, from the attestation token (PKI type, audience `seal_attest::gcp::AUDIENCE`) | The launch policy: production Confidential Space image, no other env or command overrides, logs not redirected; only the ports the image `EXPOSE`s are open |

  The pin is unattested everywhere; it can only narrow what the enclave serves.
- **One container image per release, three measurements.** The image holds every platform's
  attestor and picks the one whose TEE device is present (`seal_tee::Attestor::detect`).
  ACI and Confidential Space run it directly; the Nitro enclave image is built from it by
  `nitro-cli build-enclave` with a pinned boot blob set (`bzImage`, `cmdline`, `init`,
  `nsm.ko`, `linuxkit`, by SHA-256, committed at `source_commit`). Each platform gets its
  own signed, logged, time-locked manifest. The image runs the same under all three: Nitro
  starts `CMD` as root from `/` and ignores `USER`, `WORKDIR` and `ENTRYPOINT`, so the image
  uses `CMD` only and needs neither.
- **The release configuration is compiled in.** `deploy/enclave.Dockerfile` and
  `deploy/guardian.Dockerfile` build with `SEAL_RELEASE_ENCLAVE_CONFIG` /
  `SEAL_RELEASE_GUARDIAN_CONFIG` naming a JSON file (`deploy/example/` holds an example): the
  trust, guardian and control-plane URLs, the one port it listens on (`listen`), and
  for a guardian its platforms and key service (Key Vault keys on ACI, Cloud KMS keys on Confidential Space). A production binary without one refuses to start, and refuses
  sim-only settings (extra roots, a root file, the system clock). Since one enclave image serves
  every platform and each platform has its own guardian, `guardian` may map platforms to
  URLs. A replica names no address or host of its own: clients reach it at their
  `SEAL_ENDPOINT` and pin its attested key, so Seal-hosted replicas of every tenant run one
  release. `scripts/vendor.sh` runs before the image build. `seal-release` turns
  a build into a release: the image digest (GCP) or the rewritten `az confcom` policy's
  `host_data` (Azure), 2-of-3 signatures, the log entry and its proof, the upload (with the
  deployable template for Azure); and it checks a booted guardian's attested key before it
  enters the trust.
- **Enclaves hold no customer secrets or credentials.** Keys come from the guardian on
  attestation; configuration is signed tenant state. Each deployment is pinned to one tenant
  and its root chain (its `TenantPin`, from `seal_cloud::Cloud::tenant_pin`).
- **Only authorized deployments get keys.** Each deployment's identity (table above) is
  listed in `TenantState::deployments`: `seal deploy azure` makes that grant before deploying,
  as any change (proposed and signed with the admins' passkeys in the console, or signed with
  `--key-file`; a widening change: with a pending window the replica gets keys once it is in
  force, and the restart policy retries until then), or with `--skip-grant` prints the `seal
  grant enclave azure` command for an admin elsewhere. An enclave whose identity is not
  listed requests no keys, so deploying a genuine enclave for someone else's tenant yields
  nothing; removing it makes running replicas refuse everything from their next reload.
- **After deploy, only Seal releases need action** (`seal deploy upgrade`: the same checks,
  keeping the group's identity, subnet and pin, never back to an older release). Retiring a
  release through `ReleaseConstraints` makes SDKs refuse it, which forces the upgrade. Grants,
  tenant key versions and container restarts need nothing.
- **No load balancer.** Replicas share keys and serve the API and SDK tunnels on one port,
  8443 in the release templates (TLS ALPN tells them apart); the SDK takes the replica list (`SEAL_ENDPOINT`), keeps to the
  replica that last answered and fails over to whichever other answers first.
- **Seal-hosted replicas stop when idle.** The enclave binary exits on SIGTERM, and on a
  hosted replica (one whose deployment entry has a `HostedMode`) also after
  `HOSTED_IDLE_SECS` without authenticated work; with `restartPolicy: Never` its ACI
  container group stops. `<tenant>.enclave.seal.zone` points at Seal's front door, a TCP
  front that reads only the TLS SNI, starts the stopped replica on a connection, holds the
  connection until the replica serves and splices it through (TLS stays end to end, pinned to
  the attested key). The SDK knows nothing of hosting: any client that reaches no replica
  retries for up to `UNREACHABLE_WAIT_SECS` (120 s). What a hosted replica serves, and
  whether it idles, come only from the tenant's signed entry.
- **Every enclave connection is TLS except Roughtime's signed datagrams** (UDP, Azure and GCP). The guardian sits
  behind an ordinary, untrusted TLS-terminating proxy: a `KeyRequest` carries the tenant's
  grants, which must not cross the network in clear, while its security rests on attestation
  and on HPKE-sealed responses, so the frozen guardian holds no certificate.
- **Seal runs the guardians, control plane and log.** One guardian per enclave platform, each
  with its own platform root. **Seal's guardian runs on ACI with its root behind Key Vault
  Premium**: the guardian generated the root in its TEE at the ceremony and keeps it only
  RSA-OAEP-wrapped under an exportable `RSA-HSM` key whose release policy is immutable and
  pins the guardian's `host_data` (`seal_guardian::keysource::KeyVaultKeySource`). Only Azure Key Vault has a
  release policy the account owner cannot change (AWS and GCP KMS policies stay editable by
  the account or org owner), so Seal's cloud admins cannot take the root. Enclaves on every
  cloud reach their guardian over the network. Running enclaves keep keys in memory, so a
  Seal or cloud outage blocks enclave boots and first-time tenant key fetches at once, and
  running enclaves only after `STATE_FRESHNESS_SECS` (24 h) without a fresh state statement.
- **Guardians hand their root to a successor.** A guardian release is frozen, so when its
  code must change, a successor release takes the root over. The production binary does it
  when started with `SEAL_GUARDIAN_SUCCEED_FROM` (the predecessor's URL) and
  `SEAL_GUARDIAN_RELEASES` (the control plane, which serves the successor's own release
  evidence): it asks the predecessor for the root with `KeyPurpose::Succession` (the
  predecessor checks the successor's evidence and release as it would an enclave's), refuses
  a root that does not derive the guardian key in `trust.guardians` for the served platform,
  stores it under its own key service and prints the wrapped roots, as the root ceremony
  does. The guardian key does not change, so no client trust and no blob changes. On ACI the
  release policy admits the two variables by anchored rules (`seal-release aci-policy
  --component guardian`).
- **Self-hosted guardians** run where the customer chooses: on Azure with their own locked Key
  Vault (trusting no cloud administrator), or on Nitro or Confidential Space with that
  cloud's KMS (`seal_guardian::KeySource::GcpKms`; AWS KMS with Nitro), which means trusting their own
  account administrators. Each (served platform, platform it runs on) pair is its
  own guardian build and freeze.
- **Blobs work on every platform the tenant enables.** The sealing enclave HPKE-wraps the DEK
  to each enabled platform's guardian-certified wrap key (`TenantBundle::wrap_keys`), so a
  blob sealed on Azure opens on Nitro; each private wrap key goes only to its platform's
  enclaves.
- **No key below the guardian is shared across tenants.** Service keys and tenant wrapping
  keys derive per tenant root, so the tenant's replicas share them and nobody else does:
  extracting one enclave's keys, or exploiting one enclave, exposes only that enclave's
  tenant. Secrecy rests on the attested code, not on who operates the host.
- **Network.** Every replica reaches: its guardian, the control plane, the log, Roughtime,
  OIDC JWKS endpoints, AWS STS and the upstreams.
  - Azure: a subnet delegated to container groups, no public IPs, egress through a NAT
    gateway (the only supported ACI VNet egress; `seal deploy azure` adds a subnet `seal` in a
    free /27 of the apps' VNet and a NAT gateway when it has none, and checks a `--subnet` it
    is given for both); also AMD certificate fallbacks
    (`global.acccache.azure.net`, then `kdsintf.amd.com`; IMDS THIM is not served on ACI). Reports
    come from `/dev/sev-guest` in the container itself (VMPL 0, no sidecar); the VCEK and UVM
    endorsement from the security context directory (`UVM_SECURITY_CONTEXT_DIR`). IMDS serves the deployment identity's token,
    inside the subnet and outside one, without the infra fragment: a v1 token (issuer
    `sts.windows.net/<tid>/`, about 24 h); IMDS answers 500 for an audience no Entra
    application has, so each tenant registers its own app ID URI as the audience. A
    replica with a public IP (Seal's hosted replicas) sees every caller at a private address
    ACI translates to, so network rules (`TenantState::app_networks`) cannot tell callers
    apart there; they work on replicas in the apps' VNet, which see the callers' addresses.
  - AWS: the enclave has no network interface. The parent runs an egress proxy (the enclave
    dials it over vsock and sends `CONNECT host:port`) and forwards the enclave's port
    inbound. The parent is the untrusted host. Trusted time needs no network:
    the hypervisor's signed attestation timestamp (`seal_tee::nitro::NitroClock`) replaces
    Roughtime.
  - GCP: a VPC subnet without external IPs, egress through Cloud NAT; also Google's
    attestation service.
- **The tenant pin is the only varying setting.** The measurement therefore stays the same
  for every customer. No secret is ever passed as an environment variable or launch
  parameter: the measurement or the host would see it. `seal deploy` refuses a template or
  image whose measurement is not the release's.

Local sim: every box is a process on localhost; Postgres and Redis in Docker
with a test CA trusted via the sim-only extra-roots hook. A `sim` build runs as the simulator
only with `SEAL_SIM=1` (measuring its own binary); the sim cloud then takes its pin from
`SEAL_TENANT`, its deployment identity from `SEAL_SIM_DEPLOYMENT` (a `WorkloadIdentity` as
JSON) and an optional `SEAL_SIM_CLOCK_OFFSET`, and its `SEAL_ENCLAVE_CONFIG` may set
`hosted_idle_secs`. Production builds have none of this.
`crates/sim/seal-sim` sets it up: a release logged in the dev log, the guardian on a file root
behind a TLS proxy (`seal-sim proxy`; `GuardianClient` is HTTPS only), the control plane, two
enclave replicas (127.0.0.1 and 127.0.0.2, same ports) and an HTTPS test upstream
(`seal-sim upstream`), all under a name-constrained test CA for `localhost`.
`scripts/sim-demo.sh` runs the flow step by step (`SEAL_SIM_HOLD=1` keeps it running);
`scripts/e2e.sh` runs the end-to-end tests (`tests/e2e`, pytest over the Python SDK and the
CLI; one fresh system per test, with sim-only one-second state reloads). Dev builds optimize `sha2`, since sim attestors hash their
own binary.

## Scope

Built: the Base tier; sessions through the SDK tunnel; HTTP (header injection), Postgres and
Redis; the key guardian with M-of-N releases, the log and the time lock (plus an optional
auditor or tenant co-signature) and succession; signed tenant state with the pending window,
freshness from the log (tenant-run signers optional) and network rules; telemetry with
receipts and optional encryption; the CLI, the Rust, Python, Node and Go SDKs and the browser
verifier; the Azure (customer enclaves, Seal's hosted replicas, Seal's guardian on Key Vault
Premium), GCP Confidential Space and sim platforms; customer-deployed enclaves pinned to one
tenant (`seal deploy azure`, `seal deploy upgrade`); blobs wrapped per platform (HPKE to
certified wrap keys); periodic attestation; sessions with 10-minute tokens extended every
5 minutes and ended server-side on close or an integrity finding; upstream key pins in the
sealed policy; per-tenant keys with guardian certificates; deployment identities; and the
integrity interfaces, with the artifact-hash check enforced (CONTRACT.md). Seal-hosted
replicas, one tenant each, seal and serve sessions on every plan, and a tenant can always
disable them.

Specified, with hooks only: the ClickHouse adapter (`seal-adapter-clickhouse` is a stub), the
Hardened tier in practice (it needs compiled-in evidence checks, and none ship here),
aggregated telemetry metrics, leases, budgets.

Designed, not built: AWS Nitro and customer-run enclaves on GCP Confidential Space
(`seal deploy aws|gcp`); the guardian's root on Managed HSM in two regions; self-hosted
guardians on Nitro with AWS KMS (not built; Confidential Space with Cloud
KMS, `KeySource::GcpKms`, is built, and Azure with the customer's own Key Vault is the
`KeyVault` source); customer-managed KMS with Seal's guardian. The last is Azure Key Vault only: Seal's guardian
performs Key Vault SKR against the customer's own key, whose immutable release policy pins
the guardian's measurement. The tenant root names that key, and the tenant's wrapping keys
derive from it instead of from the platform master key. A customer who wants AWS or GCP KMS
self-hosts the guardian there. Seal-managed is the zero-setup default.

## Design points

- Tenant roots form a logged chain from a registrar-signed version 1; each link signed by the
  previous admins. The chain's `TenantRootId` (digest of version 1) goes into every tenant key,
  so a competing chain for the same name shares nothing with it.
- Release retirement and firmware floors come from witnessed checkpoint policy (`ReleaseConstraints`),
  which only tightens; the guardian requires a checkpoint < 24 h old. When its code must change
  anyway (a platform format it cannot read, a bug), it hands its root to a successor guardian
  release under the same rules as an enclave release (`KeyPurpose::Succession`, above), early,
  while it can still verify the successor.
- Service keys (token, ingest, telemetry, TLS, ticket) are per tenant root and `ServiceKeyVersion`,
  derived identically on the tenant's enclaves of that version; the TLS chain (a CA and the leaf it
  signs) is deterministic, so clients can pin the key or trust the CA. The guardian certifies each set (`ServiceKeyCertificate`, signed with
  the guardian key, which never changes), and SDKs accept only certified keys, so every
  guardian check also protects SDK traffic.
- Tenant states are logged (digest leaves) and the log signs `StateFreshness` for each
  tenant's latest; enclaves and the guardian use only fresh states. A state or root that
  widens access takes effect only after the tenant's pending window, measured by witness time
  from its inclusion proof; guardians sign anchors of the state in force, so bundles carry
  about a day of states (CONTRACT.md, "Binding and freshness").
- Witnesses are run by parties other than Seal: their timestamps measure the release time
  lock. `ReleaseConstraints` also revokes single keys and releases, only ever adding.
- Releases are reproducible: `source_commit` rebuilds to the same container image, and with the
  published templates and the pinned Nitro blob set to the same three measurements
  (`host_data`, PCRs, image digest). The image build fixes everything a digest or PCR2 sees:
  `SOURCE_DATE_EPOCH` with rewritten timestamps, provenance and SBOM attestations off, fixed
  file modes, an x86_64 builder, only vendored crates (checked against `Cargo.lock`) built with
  no network, on a digest-pinned base image that holds the pinned toolchain. Without that, the
  log proves a release was published, not what it does.
- Every replica attests every `ATTESTATION_REFRESH_SECS` (30 s) and serves that attestation
  to all clients: one hardware report or Confidential Space token per period, whatever the
  traffic (Google's attestation service allows 5 requests/s per project and region).
- Platform verifiers use roots that outlive any release and can be baked into a guardian that
  never changes: AMD's ARK per chip family, AWS's Nitro root (30-year lifetime), Google's
  Confidential Space PKI-token root (rotated every 10 years; OIDC tokens are not used, since
  their keys rotate and need network to fetch).
- Proof tickets are stateless and MAC'd; `seal_authz::RequestAuthenticator` owns context and identity checks.
- Azure `Measurement` = hash of the container-policy `host_data` (what Key Vault pins), not the UVM.
- Azure TCB minimums are per component (`Tcb`), never packed integers: AMD reorders the packed
  fields between CPU generations. TCB floors live in checkpoint policy, enforced by the
  guardian, so they can rise without touching an immutable release policy.
- Key Vault holding a platform root: Key Vault Premium, the root generated by the guardian at
  the root ceremony and RSA-OAEP-wrapped under an exportable `RSA-HSM` key; or two Managed HSMs in different regions, each holding the same root as an `oct-HSM`
  key (imported by the guardian; designed, not built). Either way: RBAC mode with only the
  release role granted to the guardian's identity, purge protection at 90 days, delete locks,
  separate admins, a key per guardian measurement, its release policy immutable and requiring
  attestation type `sevsnpvm`, `azure-compliant-uvm`, the guardian's host_data, not
  debuggable, VMPL 0 and a Microsoft shared attestation authority
  (`seal_guardian::keysource::KeyVaultKeySource`).

Known limits and unresolved items are listed in [CONTRACT.md](CONTRACT.md#known-limits-and-unresolved-items).
