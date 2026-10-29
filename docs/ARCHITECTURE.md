# Seal: module boundaries

How the crates are laid out, which crate may depend on which, the rules every crate follows,
and how Seal is hosted. The public interface (roles, SDK surface, wire format, vocabulary, known
limits) is in [CONTRACT.md](CONTRACT.md), and dependency policy is in [DEPS.md](DEPS.md). Where
a document and the code disagree, the code is right and the document gets fixed.

Seal supports four platforms behind the same enums: Azure confidential containers on ACI
(SEV-SNP, where Seal's guardian runs), GCP Confidential Space (TDX; SEV-SNP once Google attests
it), AWS Nitro Enclaves, and the simulator. [Scope](#scope) says what is built for each.

## Layout

Crates are grouped by role under `crates/`. A crate's name does not change with its folder.

| Folder | Crates | Runs |
| --- | --- | --- |
| `shared/` | seal-proto, seal-crypto, seal-tlog, seal-verify, seal-attest, seal-net, seal-tee | In more than one realm, and all in the enclave and the guardian. seal-tee never runs in the SDK |
| `enclave/` | seal-enclave, seal-cloud, seal-authz, seal-integrity | In the customer's cloud, inside the enclave TEE |
| `enclave/adapters/` | seal-adapter, seal-adapter-{http,pg,redis,clickhouse} | Inside the enclave TEE. One upstream protocol per crate |
| `guardian/` | seal-guardian | Run by Seal in its own TEE. A release is frozen; a successor release takes over its root |
| `control-plane/` | seal-control, seal-registrar | Run by Seal with no TEE, untrusted. The registrar signs only root version 1 of new tenants |
| `sdk/` | seal-client, seal-cli, seal-py, seal-node, seal-ffi, seal-verify-wasm, and the Go module `seal-go` (not a crate) | On customers' processes and machines. seal-verify-wasm runs in admins' browsers |
| `sim/` | seal-sim, seal-release (`publish = false`) | On developer machines only. seal-sim drives the whole system on the simulator. seal-release uses the production SDK (no `sim` feature) to measure, sign, log and publish releases, and drives the same flows against live deployments |

The enclave and the guardian are separate realms. The enclave runs on every cloud and changes
with each release. The guardian runs on Azure (or wherever a customer self-hosts it) and never
changes once frozen. Code only one realm needs lives in that realm's folder: the guardian's key
sources in `seal-guardian`, the enclave's per-cloud wiring in `seal-cloud`. Checking evidence
(`seal-attest`) and being a TEE (`seal-tee`) are shared.

Platforms are a closed set, so platform code dispatches with a `match` on an enum, never a
trait object: `seal_proto::Evidence`, `seal_tee::{Attestor, Clock}`, `seal_cloud::Cloud` and
`seal_guardian::KeySource`. Adding a cloud fails to compile until every match handles it.
Outside `seal-attest`, `seal-tee`, `seal-cloud` and the guardian's key sources, no crate names a
cloud.

### Published names

The brand handle is `sealzone` (domain `seal.zone`, GitHub `sealzone`). Seal publishes only
what customers install. Every other crate is `publish = false` and keeps its `seal-*` name.
Published crates keep their `seal_*` library names, so code in the repo never changes with
packaging.

| Ecosystem | Package | Users write | Built from |
| --- | --- | --- | --- |
| crates.io | `sealzone` | `use seal::Client` | `sdk/seal-client` |
| crates.io | `sealzone-{proto,crypto,tlog,verify,net,attest,control}` | (pulled in by `sealzone`) | the SDK's dependencies in `shared/` and `control-plane/` |
| crates.io | `sealzone-cli` | `cargo install sealzone-cli`, the `seal` binary | `sdk/seal-cli` |
| PyPI | `sealzone` | `import seal`, and the `seal` CLI compiled into its native module (`seal._cli`) | `sdk/seal-py` over `sdk/seal-cli`, which is also a library (`seal_cli::run`) |
| npm | `@sealzone/verify` (browser verifier, WASM) | `import { verifyTenant } from "@sealzone/verify"` | `sdk/seal-verify-wasm` (`build.sh`) |
| npm | `@sealzone/sdk` (napi-rs, one prebuilt package per platform) | `import { Client } from "@sealzone/sdk"` | `sdk/seal-node` (`build.sh`) |
| Go | `seal.zone/go` (`seal.zone` serves the `go-import` tag for `github.com/sealzone/seal-go`) | `seal.FromEnv(ctx)` | `sdk/seal-go` over the C ABI in `sdk/seal-ffi`; its `build.sh` builds a static library per platform |

`cargo -p` takes the package name (`-p sealzone`, `-p sealzone-proto`); unpublished crates keep
their own (`-p seal-enclave`). `cargo publish --workspace --dry-run` must pass.

### Folder rule

Every folder depends only on `shared/`, plus two service clients: `seal_guardian::client` (used
by `enclave/`) and `seal_control::client` (used by `enclave/` and `sdk/`). Each service ships
its own client, so callers never re-implement its API. `sim/` is the exception: it may depend
on `sdk/` and on the dev features of `shared/`.

## Dependency graph

The graph is acyclic. An arrow means "may depend on".

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

| From | Must not depend on |
| --- | --- |
| adapters | anything but adapter, net, proto, integrity |
| integrity | anything but proto |
| authz | adapter, attest, tee, cloud |
| anything | enclave, client, cli, py, node, ffi, verify-wasm |
| proto | anything internal |
| attest | anything but proto, crypto |
| guardian | authz, adapter, cloud, control |
| SDK crates | tee, cloud |
| anything outside `seal-control` | its server code (only `seal_control::client`) |

## Boundary rules

1. **Public items are the contract between crates.** Private items may change freely. A change
   to a public signature, or a new public item another crate uses, updates CONTRACT.md in the
   same change.
2. **Wire format v1 is frozen** (CONTRACT.md). A `seal-proto` type that is signed, hashed, used
   as associated data or read by a guardian may only gain optional fields omitted when unset.
   Any other change is a new label version. The vectors in
   `crates/shared/seal-proto/tests/vectors/wire-v1.json` and
   `crates/sdk/seal-verify-wasm/tests/vectors.json` enforce this. Regenerate them only for a
   deliberate format change, with `SEAL_WRITE_VECTORS=1`, and review the diff in the same
   change.
3. **Pure cores, IO at the edges.** `seal-authz::decide`, `seal-guardian::authorize`,
   `seal-tlog::verify`, all of `seal-crypto` and every `seal_integrity::{Detector,
   EvidenceCheck}` take every input as an argument. No clock, no network, no globals, no
   randomness except an injected RNG. Time arrives as a `seal_proto::TrustedTime`, never a bare
   `UnixTime`.
4. **Secrets.** Only `seal_proto::{SecretVec, Bearer}`, the `seal-crypto` key types,
   `seal_crypto::SecretBytes` and `seal_adapter::Session` hold secrets or bearer credentials.
   They zeroize on drop and redact `Debug`. Never `Display`, `Serialize` or log a secret, and
   never put one in an error.
5. **Errors.** Each crate has one error type with `code() -> seal_proto::ErrorCode`. Only the
   code crosses to a caller. Messages shown to callers never include secrets or internals.
6. **Signatures and hashes.** Signatures sign `codec::labeled_digest(LABEL, &msg)` with a label
   constant from `seal-proto`. Hashes and AAD use `codec::canonical`.
7. **No plaintext upstreams.** Only `seal_net::UpstreamConnector::connect(&Destination)`
   produces a stream a secret may go on: an `UpstreamStream`, verified TLS by construction.
   Upstream trust is `seal_net::baked_roots()`. Extra roots exist only behind `sim`.
8. **Production builds exclude `sim`.** Anything that weakens trust lives behind
   `feature = "sim"`: sim evidence, extra CAs, config-file guardian rules, the system clock as
   trusted time.

## Conventions

Rust 2021, MSRV 1.92, toolchain pinned in `rust-toolchain.toml`, formatted with `rustfmt.toml`.
Async is tokio. HTTP is hyper 1 for server and client, with axum for the control plane and
enclave APIs. TLS is rustls 0.23 with the `ring` provider. Unit tests live next to the code.
Dependencies follow [DEPS.md](DEPS.md).

No `unsafe` outside the bindings; the SNP device ioctl goes through `sev`. The bindings that use
it are `seal-ffi` (the C ABI), `seal-node` (in what napi-rs expands to), `seal-py` (its
per-process runtime pointer) and `seal-verify-wasm`, which sets `deny` and allows it only in the
module `#[wasm_bindgen]` expands in.

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

### Customer deployments

The customer runs only enclave replicas, in the app's network on its own cloud, never inside
the app's TEE or container group (that would put the app into the measurement). `seal deploy
azure` deploys them from the release's published template and `seal deploy upgrade` upgrades
them. AWS and GCP deployment is designed, not built.

An Azure release's template is the output of `seal-release aci-policy`, published untrusted
next to the evidence by `seal-release publish --template` and served by the control plane at
`/v1/releases/{platform}/{measurement}/template`. It authenticates itself:
`measurement(SHA-256(policy))` must be a release the CLI verified with `ReleaseVerifier` under
`trust.releases` (plus the admins' co-signature for `cosign_releases` tenants). The CLI takes
only the policy and Seal's container (one container, image by digest, only `SEAL_TENANT` set,
TCP ports) from it. It renders the ARM template itself (one confidential container group,
`restartPolicy: Always`, the user-assigned managed identity, the checked subnet, a private
address) and deploys it with `az deployment group create` under the customer's `az` login. An
untrusted template therefore cannot add a resource, a role assignment or a container.

| Cloud | Replica | Measurement | Tenant pin | Deployment identity | Locked down by |
| --- | --- | --- | --- | --- | --- |
| Azure | Confidential container group (ACI) | Container policy hash (`host_data`) | `SEAL_TENANT`, allowed by an anchored re2 rule in the policy | Group's managed identity | The policy: no exec, no stack dumps, no unencrypted scratch, no env var dropping (a rule for every variable ACI injects, including `APP_IDENTITY_ENDPOINT`). Seal's container is unprivileged with fixed mounts. No Microsoft infra fragment, which would let containers join without changing `host_data`. ACI adds its own containers to every confidential group (`atlas-mount-resolv-conf`, plus `msi-atlas-adapter` and `atlas-netstats` with a managed identity; two are privileged); the release policy lists those three itself, copied from the infra fragment and refreshed when Microsoft changes them. seal-release refuses a policy with any line outside the framework skeleton, such as its own rule, a comment, or a framework rule bound to another or not in `FRAMEWORK_RULES` |
| AWS | Nitro enclave on an EC2 parent | PCR0/1/2 of the enclave image | First message from the parent over vsock | Parent's instance role (SigV4) | Nitro: no network, shell, debug or attached console (zero PCRs are refused) |
| GCP | Confidential Space VM (TDX, `c3-*`; SEV-SNP once Google attests it) | Container image digest | `tee-env-SEAL_TENANT` (read as `SEAL_TENANT`), the only override the launch policy allows (`tee.launch_policy.allow_env_override`) | Project number and the one service account, from the attestation token (PKI type, audience `seal_attest::gcp::AUDIENCE`) | The launch policy: the production Confidential Space image, no other env or command overrides, no log redirect. Only the ports the image `EXPOSE`s are open |

The tenant pin is unattested everywhere and can only narrow what the enclave serves. It is the
only setting that varies, so the measurement is the same for every customer. No secret is ever
an environment variable or launch parameter, since the measurement or the host would see it.
`seal deploy` refuses a template or image whose measurement is not the release's.

Enclaves hold no customer secrets or credentials. Keys come from the guardian on attestation,
configuration is signed tenant state, and each deployment is pinned to one tenant and its root
chain (its `TenantPin`, from `seal_cloud::Cloud::tenant_pin`).

Only authorized deployments get keys. Each deployment's identity is listed in
`TenantState::deployments`. `seal deploy azure` makes that grant before deploying, like any
change: admins sign it with passkeys in the console or with `--key-file`. It widens access, so
with a pending window the replica gets keys once the change is in force, and the restart policy
retries until then. With `--skip-grant` the CLI prints the `seal grant enclave azure` command
for an admin elsewhere. An unlisted enclave requests no keys, so a genuine enclave deployed for
someone else's tenant yields nothing. Removing an identity makes running replicas refuse
everything from their next reload.

After deploy, only Seal releases need action. `seal deploy upgrade` runs the same checks, keeps
the group's identity, subnet and pin, and never goes back to an older release. Retiring a
release through `ReleaseConstraints` makes SDKs refuse it, which forces the upgrade. Grants,
tenant key versions and container restarts need nothing.

There is no load balancer. Replicas share keys and serve the API and SDK tunnels on one port
(8443 in the release templates), told apart by TLS ALPN. The SDK takes the replica list
(`SEAL_ENDPOINT`), keeps to the replica that last answered, and fails over to whichever other
replica answers first.

### Seal-hosted replicas

A hosted replica is one whose deployment entry has a `HostedMode`. The enclave binary exits on
SIGTERM, and a hosted replica also exits after `HOSTED_IDLE_SECS` without authenticated work;
with `restartPolicy: Never` its ACI container group then stops.

`<tenant>.enclave.seal.zone` points at Seal's front door, a TCP front that reads only the TLS
SNI. On a connection it starts the stopped replica, holds the connection until the replica
serves, and splices it through after a PROXY protocol v2 header naming the client's address.
TLS stays end to end, pinned to the attested key.

The SDK knows nothing of hosting. A client that reaches no replica retries for up to
`UNREACHABLE_WAIT_SECS` (120 s). What a hosted replica serves, and whether it idles, come only
from the tenant's signed entry.

### Releases and images

One container image per release yields three measurements. The image holds every platform's
attestor and picks the one whose TEE device is present (`seal_tee::Attestor::detect`). ACI and
Confidential Space run it directly. `nitro-cli build-enclave` builds the Nitro image from it
with a boot blob set (`bzImage`, `cmdline`, `init`, `nsm.ko`, `linuxkit`) pinned by SHA-256 and
committed at `source_commit`. Each platform gets its own signed, logged, time-locked manifest.
Nitro starts `CMD` as root from `/` and ignores `USER`, `WORKDIR` and `ENTRYPOINT`, so the image
uses `CMD` only.

The release configuration is compiled in. `deploy/enclave.Dockerfile` and
`deploy/guardian.Dockerfile` build with `SEAL_RELEASE_ENCLAVE_CONFIG` and
`SEAL_RELEASE_GUARDIAN_CONFIG`, each naming a JSON file (example in `deploy/example/`). It sets
the trust, guardian and control-plane URLs, the one port the binary listens on (`listen`), and
for a guardian its platforms and key service (Key Vault on ACI, Cloud KMS on Confidential
Space). One enclave image serves every platform and each platform has its own guardian, so
`guardian` may map platforms to URLs. A production binary without this configuration, or with
sim-only settings (extra roots, a root file, the system clock), refuses to start. A replica
names no address of its own: clients reach it at their `SEAL_ENDPOINT` and pin its attested key,
so Seal-hosted replicas of every tenant run one release.

`seal-release` turns a build into a release: the measurement (the image digest on GCP, the
`host_data` of the rewritten `az confcom` policy on Azure), 2-of-3 signatures, the log entry and
the upload. It also checks a booted guardian's attested key before that key enters the trust,
and a checkpoint policy before the log takes it (`seal-release policy`).

### Guardians and keys

Every enclave connection is TLS except Roughtime's signed datagrams (UDP, on Azure and GCP).
The guardian sits behind an ordinary untrusted TLS-terminating proxy. TLS is needed because a
`KeyRequest` carries the tenant's grants, which must not cross the network in clear. The
guardian's security rests on attestation and HPKE-sealed responses, so it holds no certificate.

Seal runs the guardians, control plane and log, with one guardian per enclave platform, each
with its own platform root, reached over the network. Running enclaves keep keys in memory, so a
Seal or cloud outage blocks enclave boots and first-time tenant key fetches at once, and
running enclaves only after the tenant's freshness window (`STATE_FRESHNESS_SECS`, 24 h, unless
the state sets a shorter one) without a fresh state statement.

Seal's guardian runs on ACI with its root behind Key Vault Premium. It generated the root in
its TEE at the ceremony and keeps it only RSA-OAEP-wrapped under an exportable `RSA-HSM` key
whose immutable release policy pins the guardian's `host_data`
(`seal_guardian::keysource::KeyVaultKeySource`). Only Azure Key Vault has a release policy the
account owner cannot change (AWS and GCP KMS policies stay editable by the account or org
owner), so Seal's cloud admins cannot take the root. The vault uses RBAC mode with only the
release role granted to the guardian's identity, 90-day purge protection, delete locks,
separate admins, and a key per guardian measurement whose release policy requires attestation
type `sevsnpvm`, `azure-compliant-uvm`, the guardian's `host_data`, not debuggable, VMPL 0 and a
Microsoft shared attestation authority. A layout with two Managed HSMs in different regions,
each holding the root as an imported `oct-HSM` key, is designed, not built.

A guardian release is frozen, so when its code must change (a platform format it cannot read,
a bug), a successor release takes over the root, early, while the old guardian can still verify
it. A production guardian started with `SEAL_GUARDIAN_SUCCEED_FROM` (the predecessor's URL) and
`SEAL_GUARDIAN_RELEASES` (the control plane, serving its own release evidence) asks for the root
with `KeyPurpose::Succession`. The predecessor checks it as it would an enclave release. The
successor refuses a root that does not derive the guardian key in `trust.guardians` for the
served platform, and stores it under its own key service. The guardian key does not change, so no client
trust or blob changes. On ACI the release policy admits the two variables by anchored rules
(`seal-release aci-policy --component guardian`).

Self-hosted guardians run on Azure with the customer's own locked Key Vault (trusting no cloud
administrator), or on Nitro or Confidential Space with that cloud's KMS
(`seal_guardian::KeySource::GcpKms`, or AWS KMS with Nitro), trusting the customer's own account
administrators. Each pair of (served platform, platform it runs on) is its own guardian build
and freeze.

Blobs open on every platform the tenant enables. The sealing enclave HPKE-wraps the DEK to each
enabled platform's guardian-certified wrap key (`TenantBundle::wrap_keys`), and each private
wrap key goes only to its own platform's enclaves.

No key below the guardian is shared across tenants. Service keys and tenant wrapping keys derive
per tenant root and are shared only by that tenant's replicas, so extracting one enclave's keys
or exploiting one enclave exposes only that enclave's tenant. Secrecy rests on the attested
code, not on who operates the host.

### Network

Every replica reaches its guardian, the control plane, the log, Roughtime, OIDC JWKS endpoints,
AWS STS and the upstreams. Network rules (`TenantState::app_networks`) check the caller address
the replica takes, as below.

**Azure.** Replicas run in a subnet delegated to container groups, with no public IPs, and
egress through a NAT gateway (the only supported ACI VNet egress). `seal deploy azure` adds a
subnet `seal` in a free /27 of the apps' VNet, and a NAT gateway when the VNet has none; it
checks a given `--subnet` for both. Replicas also reach the AMD certificate fallbacks,
`global.acccache.azure.net` then `kdsintf.amd.com` (IMDS THIM is not served on ACI). Reports
come from `/dev/sev-guest` in the container itself (VMPL 0, no sidecar), and the VCEK and UVM
endorsement from `UVM_SECURITY_CONTEXT_DIR`. IMDS serves the deployment identity's token inside
or outside a subnet, without the infra fragment: a v1 token (issuer `sts.windows.net/<tid>/`,
valid about 24 h). IMDS answers 500 for an audience no Entra application has, so each tenant
registers its own app ID URI as the audience.

Caller addresses: a replica with a public IP sees every caller at a private address ACI
translates to, and replicas in the apps' VNet see the callers' own addresses. A Seal-hosted
replica takes the caller's address from the front door's PROXY header instead, and only while
its tenant's state lists it as Seal's hosted deployment (`seal-enclave` `proxy`). Any other
replica reads past a header and keeps the connection's address, since the connecting side wrote
the header.

**AWS.** The enclave has no network interface. The parent, the untrusted host, runs an egress
proxy the enclave dials over vsock with `CONNECT host:port`, and forwards the enclave's port
inbound. Trusted time needs no network: the hypervisor's signed attestation timestamp
(`seal_tee::nitro::NitroClock`) stands in for Roughtime.

**GCP.** Replicas run in a VPC subnet without external IPs, with egress through Cloud NAT, and
also reach Google's attestation service.

### Local simulator

Every box is a process on localhost. Postgres and Redis run in Docker, with a test CA trusted
through the sim-only extra-roots hook. A `sim` build runs as the simulator only with
`SEAL_SIM=1`, and then measures its own binary (so dev builds optimize `sha2`). The sim cloud
reads `SEAL_TENANT` (its pin), `SEAL_SIM_DEPLOYMENT` (its deployment identity, a
`WorkloadIdentity` as JSON), optional `SEAL_SIM_CLOCK_OFFSET`, and `SEAL_ENCLAVE_CONFIG`, which
may set `hosted_idle_secs`.

`crates/sim/seal-sim` starts the whole system under a name-constrained test CA for `localhost`,
with the guardian behind a TLS proxy (`seal-sim proxy`, since `GuardianClient` is HTTPS only)
and two replicas on 127.0.0.1 and 127.0.0.2 with the same ports. `scripts/sim-demo.sh` and
`scripts/e2e.sh` drive it ([CONTRIBUTING.md](../CONTRIBUTING.md#build-and-test)).

## Scope

**Built:** the Base tier; sessions through the SDK tunnel; HTTP (header injection), Postgres and
Redis; the key guardian with M-of-N releases, the log and the time lock (plus an optional
auditor or tenant co-signature), and succession; signed tenant state with the pending window,
freshness from the log (tenant-run signers optional) and network rules; telemetry with receipts
and optional encryption; the CLI, the Rust, Python, Node and Go SDKs and the browser verifier;
the Azure platform (customer enclaves, Seal's hosted replicas, Seal's guardian on Key Vault
Premium), GCP Confidential Space and the sim platform; customer-deployed enclaves pinned to one
tenant (`seal deploy azure`, `seal deploy upgrade`); blobs wrapped per platform (HPKE to
certified wrap keys); periodic attestation; sessions with 10-minute tokens, extended every 5
minutes and ended server-side on close or on an integrity finding; upstream key pins in the
sealed policy; per-tenant keys with guardian certificates; deployment identities; the integrity
interfaces, with the artifact-hash check enforced (CONTRACT.md); self-hosted guardians on
Confidential Space with Cloud KMS (`KeySource::GcpKms`) and on Azure with the customer's own Key
Vault (the `KeyVault` source).

Seal-hosted replicas, one tenant each, seal and serve sessions on every plan. A tenant can
always disable them.

**Specified, with hooks only:** the ClickHouse adapter (`seal-adapter-clickhouse` is a stub);
the Hardened tier in practice (it needs compiled-in evidence checks, and none ship here);
aggregated telemetry metrics; leases; budgets.

**Designed, not built:** AWS Nitro (only evidence verification, `seal_attest::nitro`, is built;
the attestor, clock, egress proxy and key source are stubs), and customer-run enclaves on GCP Confidential Space (`seal
deploy aws|gcp`); the guardian's root on Managed HSM in two regions; self-hosted guardians on
Nitro with AWS KMS; customer-managed KMS with Seal's guardian. That last one is Azure Key Vault
only: Seal's guardian performs Key Vault SKR against the customer's own key, whose immutable
release policy pins the guardian's measurement, and the tenant root names that key so the
tenant's wrapping keys derive from it instead of the platform master key. A customer who wants
AWS or GCP KMS self-hosts the guardian there. Seal-managed is the zero-setup default.

## Design points

Tenant roots, tenant state freshness, the pending window, periodic attestation and proof tickets
are specified in [CONTRACT.md](CONTRACT.md#binding-and-freshness). The points below are about
how the code is built.

- `ReleaseConstraints` (witnessed checkpoint policy) carries release retirement, firmware
  floors and revocations of single keys and releases. It only tightens; revocations are only
  added. The guardian requires a checkpoint less than 24 h old. Witnesses are run by parties
  other than Seal, and their timestamps measure the release time lock.
- Azure TCB minimums are per component (`Tcb`), never packed integers, because AMD reorders the
  packed fields between CPU generations. They are also per chip family (`milan.snp`,
  `genoa.snp`, `turin.fmc`), because each family numbers its firmware on its own scale: a
  family's floor applies only to that family's reports, and once a floor names any family, a
  family it does not name is refused, so new hardware needs a floor of its own before it is
  accepted. `uvm_svn` has no family and applies to all. The floors live in checkpoint policy
  and the guardian enforces them, so they rise without touching an immutable release policy.
  `seal-release policy` (`seal_attest::check_floor`) refuses a floor naming a component the
  platform's evidence lacks, which would refuse that platform for good. Azure's `Measurement`
  is the hash of the container-policy `host_data`, which Key Vault pins, not the UVM.
- Service keys (token, ingest, telemetry, TLS, ticket) are per tenant root and
  `ServiceKeyVersion`, derived identically by that version's enclaves. The TLS chain (a CA and
  the leaf it signs) is deterministic, so clients can pin the key or trust the CA. The guardian
  certifies each set (`ServiceKeyCertificate`) with the guardian key, which never changes, and
  SDKs accept only certified keys.
- Platform roots outlive any release, so a guardian that never changes can bake them in: AMD's
  ARK per chip family, AWS's Nitro root (30-year lifetime), Google's Confidential Space
  PKI-token root (rotated every 10 years). OIDC tokens are not used, since their keys rotate
  and need network to fetch.
- `source_commit` rebuilds to the same container image and, with the published templates and
  the pinned Nitro blob set, the same three measurements (`host_data`, PCRs, image digest). The
  image build fixes everything a digest or PCR2 sees: `SOURCE_DATE_EPOCH` with rewritten
  timestamps, provenance and SBOM attestations off, fixed file modes, an x86_64 builder, only
  vendored crates checked against `Cargo.lock` and built with no network, and a digest-pinned
  base image holding the pinned toolchain. Without that, the log proves a release was
  published, not what it does.
- Every replica attests every `ATTESTATION_REFRESH_SECS` (30 s), whatever the traffic, which
  keeps within Google's attestation limit of 5 requests/s per project and region.

Known limits and unresolved items are in
[CONTRACT.md](CONTRACT.md#known-limits-and-unresolved-items).
