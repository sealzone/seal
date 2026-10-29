# Roadmap

What Seal does today, what comes next, and what is still an open question. The details of
each item are in [ARCHITECTURE.md](docs/ARCHITECTURE.md#scope) and
[CONTRACT.md](docs/CONTRACT.md#known-limits-and-unresolved-items).

## Shipped

- Enclaves on Azure confidential containers (SEV-SNP) and GCP Confidential Space (TDX), plus
  a local simulator.
- Customer-run enclave replicas pinned to one tenant (`seal deploy azure`,
  `seal deploy upgrade`), and Seal-hosted replicas for callers outside your network.
- HTTP header injection, Postgres and Redis.
- Sessions through the SDK tunnel: 10-minute tokens, extended every 5 minutes, ended on close
  or on an integrity finding.
- The guardian, with M-of-N releases, the transparency log, the time lock and succession.
  Self-hosted guardians on Confidential Space with Cloud KMS, and on Azure with your own Key
  Vault.
- Signed tenant state with a pending window for changes that widen access, and network rules.
- Telemetry with receipts and optional encryption.
- App Integrity interfaces, with the artifact-hash check enforced.
- The `seal` CLI, the Rust, Python, Node/TypeScript and Go SDKs, and the browser verifier.

## Next

These are specified, and the code has hooks for them:

- The ClickHouse adapter.
- The Hardened tier in practice, which needs evidence checks compiled into the enclave.
- In-enclave integrity detectors.
- Aggregated telemetry metrics.
- Leases and budgets.
- Replica endpoints read from signed tenant state, instead of only from `SEAL_ENDPOINT`.

## Later

These are designed but not built:

- AWS Nitro Enclaves. Evidence verification is built; the attestor, clock, egress proxy and
  key source are not.
- Customer-run enclaves on AWS and GCP (`seal deploy aws` and `seal deploy gcp`).
- Self-hosted guardians on Nitro with AWS KMS.
- Customer-managed keys with Seal's guardian: the guardian unwraps against your own Azure Key
  Vault key, whose release policy pins the guardian's measurement.
- The guardian's root on Managed HSM in two regions.

## Open questions

- Zero-touch upgrades. Today you run `seal deploy upgrade`. The choice is between an Azure
  managed application that Seal pushes upgrades to, and an enclave that redeploys itself to
  releases it has verified.
- Endpoint reports for interpreted apps, where hashing the executable says little about the
  code that runs.

The full list, with the limits Seal accepts on purpose, is in
[CONTRACT.md](docs/CONTRACT.md#known-limits-and-unresolved-items).
