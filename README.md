# Seal

Use secrets without holding them. A producer seals a secret (an API key, a database password)
for named apps; an app starts a session on the sealed blob and gets a stand-in, while an
attested enclave injects the real secret on the way to the upstream. The app, its host and
Seal's own control plane never see the secret.

```python
import seal

blob = seal.seal(secret, to="https://api.openai.com/v1", apps=["checkout"], header="x-api-key")

with seal.session(blob) as s:      # the app gets a stand-in key; the enclave injects the real one
    client = OpenAI(base_url=s.url, api_key=s.key)
```

The same flow in Rust is `seal.seal(secret, to, apps).header(..).await?`, then
`seal.session(&blob).http().await?`; both SDKs use the same names.

## How it works

```
 app process ── SDK ──► enclave replica (TEE) ──► upstream (API, Postgres, Redis)
                  │      verifies the caller, decrypts the blob, injects the secret
                  │            ▲                         │
   verifies the enclave        │ keys, at boot           │ signed telemetry, signals
   against a signed release    │                         ▼
                         guardian (TEE)            control plane (untrusted)
                                                   transparency log + witnesses
```

- **Enclave**: runs in the customer's network on a confidential-computing platform (or as
  Seal's hosted replica, for producers outside it), pinned to one tenant. It is the only place a blob is decrypted. It authorizes each workload by its
  cloud identity, then proxies HTTP, Postgres or Redis traffic with the real secret injected.
- **Guardian**: holds the platform root in its own TEE and releases keys only to enclaves
  whose attested measurement is a release signed by M of N release keys, logged, and past
  its time lock.
- **Control plane**: stores and serves signed tenant state, telemetry and signals. It is
  untrusted: enclaves verify every document they get from it, so it can withhold data but
  cannot grant access or read secrets.
- **SDK**: verifies the enclave's attestation against the release trust before sending
  anything, pins its TLS key, and fails over between replicas (`SEAL_ENDPOINT`).

## Trust model

- **Trusted**: the TEE hardware and its attestation (AMD SEV-SNP on Azure; Intel TDX and
  Google's attestation service on Confidential Space), and the released enclave and guardian
  code. Releases are reproducible from a source commit, signed by M of N release keys,
  recorded in a transparency log checked by independent witnesses, and time-locked, so a
  release is public before anything accepts it. Seal's guardian keeps its root in Azure Key
  Vault under an immutable release policy, which adds Microsoft's attestation service and
  HSMs.
- **Not trusted**: the control plane, the hosts and cloud accounts the enclaves run in, the
  network, and Seal's operators. Tenant state is signed by the tenant's own admins and
  logged; a change that widens access waits out a public pending window. An untrusted party
  can withhold service, never read a secret or grant access; the narrow, detectable
  exceptions (a stale state replayed for up to 24 hours, a competing tenant root) are listed in
  CONTRACT.md.
- **Not protected**: what the app does with a session. An app that holds a session can make
  any request the credential allows; the secret itself never reaches it.

The full model is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and the public interface
(roles, SDK surface, wire format, known limits) in [docs/CONTRACT.md](docs/CONTRACT.md).

## Status

Pre-release; interfaces may still change. Built: Azure confidential containers (SEV-SNP) and
GCP Confidential Space (TDX) enclaves, the local simulator, HTTP header injection, Postgres
and Redis, sessions through the SDK tunnel, the guardian with M-of-N releases, a transparency
log and succession, signed tenant state, network rules, telemetry, the `seal` CLI and the
Rust, Python, Node/TypeScript and Go SDKs. Designed but not built: AWS Nitro Enclaves, the
ClickHouse adapter, and in-enclave integrity detectors (the artifact-hash check is enforced).
Accepted limits and open items are listed in
[docs/CONTRACT.md](docs/CONTRACT.md#known-limits-and-unresolved-items).

The SDKs and the CLI are not yet published to crates.io, PyPI or npm, and `seal.zone/go` does
not serve the Go module yet; install them from source (below).

## Getting started

You need Rust (the toolchain is pinned in `rust-toolchain.toml` and installed by rustup),
Docker or Podman (the demo and the end-to-end tests run Postgres and Redis in containers), and
Python 3.9+ for the Python SDK and the end-to-end tests. Node.js and Go are needed only for
those SDKs.

Run the whole system on the simulator: a release, a guardian, the control plane, a tenant
created with the CLI, an enclave, a producer sealing an API key, and an app using it without
ever holding it.

```sh
scripts/sim-demo.sh
```

Tests:

```sh
cargo test --workspace              # unit and integration tests
scripts/e2e.sh                      # the end-to-end tests on the simulator (tests/e2e)
scripts/py-test.sh                  # the Python SDK against the simulator
```

Install the SDKs and CLI from source:

```sh
pip install ./crates/sdk/seal-py                # Python: import seal
crates/sdk/seal-node/build.sh --release         # Node/TypeScript: import { Client } from "@sealzone/sdk"
crates/sdk/seal-go/build.sh                     # Go: import seal "seal.zone/go"
cargo install --path crates/sdk/seal-cli        # the `seal` command
```

```toml
# Rust: use seal::Client
seal = { package = "sealzone", git = "https://github.com/sealzone/seal" }
```

## The `seal` CLI

```sh
seal login                       # a code you approve in the browser; the login stays in the OS keychain (or a private file without one)
seal use acme                    # pick a tenant: its root chain and state are verified here
seal status                      # admin keys, state in force, grants, pending changes
seal grant app checkout azure --object-id OID --entra-tenant TID --audience api://seal-acme
seal secret --to https://api.openai.com/v1 --app checkout --header authorization < key.txt > openai.blob
seal deploy azure                # an enclave replica in the VNet your apps run in: asks which, makes its subnet, NAT gateway, identity and audience, then the grant
```

A change is shown as its differences from the state in force (and whether it waits the
pending window), then proposed: the CLI opens the console, where the admins sign it with
their passkeys, and reports it once it is logged. `--key-file admin.key` signs with an admin
key file instead (`seal key create --out admin.key`, then `seal settings admins add KEY`); the
CLI stores no key of its own. `seal --help` lists every command; `seal changes --watch` follows
pending changes; `seal completion zsh` writes completions. Every build verifies against the
trust compiled in from `crates/sdk/seal-client/release-trust.json` (Seal's production public
keys); `--trust FILE` verifies against another, such as the simulator's, and building with
`SEAL_RELEASE_TRUST=FILE` compiles another in.

## Repository

| Path | What |
| --- | --- |
| `crates/shared/` | Protocol types, crypto, attestation checks, transparency log, verification |
| `crates/enclave/` | The enclave runtime, authorization, per-cloud wiring, integrity, and upstream adapters |
| `crates/guardian/` | The guardian and its key sources (Azure Key Vault, Cloud KMS) |
| `crates/control-plane/` | The untrusted control plane and the tenant registrar |
| `crates/sdk/` | The Rust SDK (`sealzone`), the `seal` CLI, the Python, Node/TypeScript and Go SDKs (bindings over the Rust one) and the browser verifier (WASM) |
| `crates/sim/` | The simulator and release tooling |
| `deploy/` | Reproducible image builds and [example release configurations](deploy/example/README.md) |
| `docs/` | [Architecture](docs/ARCHITECTURE.md), [interface contract](docs/CONTRACT.md), [dependency policy](docs/DEPS.md) |
| `tests/e2e/` | [End-to-end tests](tests/e2e/README.md) on the simulator, through the Python SDK and the CLI |
| `scripts/` | The demo, the test runners, the dependency checks, vendoring for image builds |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for building, testing and the rules a change follows,
and [RELEASING.md](RELEASING.md) for how SDKs and images are released.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0; see [LICENSE](LICENSE).
