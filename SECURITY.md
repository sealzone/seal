# Security policy

Seal protects other people's secrets, so we take reports seriously and credit reporters who
want it.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on
[sealzone/seal](https://github.com/sealzone/seal/security/advisories/new). Please do not open
a public issue, pull request or discussion for a suspected vulnerability.

Include what you can: the affected component (enclave, guardian, SDK, control plane,
attestation checks), the version or commit, steps to reproduce, and the impact you expect.
We aim to acknowledge reports within three business days and to agree on a disclosure date
with you.

## Scope

In scope: everything in this repository, including attestation and release verification,
the enclave and guardian, the SDKs and CLI, and the reproducible image builds.

The simulator (`sim` features, `crates/sim/`) is for development only and is not a security
boundary; issues that need a `sim` build are out of scope unless they affect release builds.

Known and accepted limits are listed in [docs/CONTRACT.md](docs/CONTRACT.md), "Known limits
and unresolved items".
