# Security policy

Seal protects other people's secrets, so we take reports seriously. We credit reporters who
want credit.

## Reporting a vulnerability

Report privately through GitHub, with **Security → Report a vulnerability** on
[sealzone/seal](https://github.com/sealzone/seal/security/advisories/new). Please do not open
a public issue, pull request or discussion for a suspected vulnerability.

Include what you can:

- the affected component (enclave, guardian, SDK, control plane, attestation checks)
- the version or commit
- steps to reproduce
- the impact you expect

We aim to acknowledge a report within three business days, and to agree on a disclosure date
with you.

## Scope

Everything in this repository is in scope. That includes attestation and release
verification, the enclave and guardian, the SDKs and CLI, and the reproducible image builds.

The simulator (`sim` features, `crates/sim/`) is for development only and is not a security
boundary. An issue that needs a `sim` build is out of scope unless it also affects release
builds.

[docs/CONTRACT.md](docs/CONTRACT.md) lists the known and accepted limits, under "Known limits
and unresolved items".
