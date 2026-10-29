# Contributing

Report security issues as [SECURITY.md](SECURITY.md) describes. Never put them in a public issue or pull request.

## Build and test

`rust-toolchain.toml` pins the toolchain, and rustup installs it on first use. Enclave and
guardian images must build bit for bit, so the pin changes only on purpose, with a release.
The published crates keep an MSRV of 1.92 (`rust-version` in `Cargo.toml`).

```sh
cargo build --workspace
cargo test --workspace --locked     # unit and integration tests; no containers needed
scripts/e2e.sh                      # end-to-end tests on the simulator (tests/e2e/README.md)
scripts/py-test.sh                  # the Python SDK's own tests against the simulator
scripts/sim-demo.sh                 # the whole system, step by step
```

`scripts/e2e.sh` and `scripts/sim-demo.sh` need Docker or Podman and Python 3.9+. The Node
and Go SDK tests also need Node.js and Go, and they are skipped without them.
`crates/sdk/seal-verify-wasm/build.sh --test` checks the browser verifier under Node.

## Before a pull request

CI (`.github/workflows/ci.yml`) runs these on every push and pull request. Run them first:

```sh
cargo fmt --all --check                                  # rustfmt.toml: 120 columns
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
scripts/check-deps.sh                                    # needs cargo-deny
```

## Rules a change follows

[ARCHITECTURE.md](docs/ARCHITECTURE.md) has the full set: the folder and dependency rules and
the [boundary rules](docs/ARCHITECTURE.md#boundary-rules). The ones reviews catch most:

- Wire format v1 is frozen. Signed, hashed or guardian-read types only gain optional fields.
  Regenerate the vector files only for a deliberate format change, with `SEAL_WRITE_VECTORS=1`,
  and review the diff in the same pull request.
- Dependencies follow [DEPS.md](docs/DEPS.md). A change to what the enclave or guardian compiles
  in also updates `tee-deps/` (`scripts/check-deps.sh --update`).
- Anything that weakens trust stays behind the `sim` feature.
- A change to a crate's public items, a route, a constant or a CLI command updates
  [CONTRACT.md](docs/CONTRACT.md) or ARCHITECTURE.md in the same change.

## Releasing

SDKs and images are released separately, with different keys. Enclave and guardian images are
reproducible builds, signed by M of N release keys, logged and time-locked (`seal-release`; see
[ARCHITECTURE.md](docs/ARCHITECTURE.md#releases-and-images)). SDKs verify enclaves against the
image releases, so an SDK release never needs a new image, and an image release needs a new SDK
only when the protocol changed.

`.github/workflows/release.yml` publishes the SDKs from a version tag: the Rust crates
(`sealzone`, `sealzone-cli` and the `sealzone-*` crates they use), `sealzone` on PyPI,
`@sealzone/sdk` on npm, and the Go module `seal.zone/go`. Windows is not built.

1. Bump the version in the root `Cargo.toml` (`[workspace.package] version`) and in
   `crates/sdk/seal-node/package.json` (`version` and its `optionalDependencies`). Commit.
2. Optionally, run the `release` workflow by hand with `dry_run` on. It builds, tests and lays
   out every package and publishes nothing.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`. The `check` job confirms the tag
   matches the version, checks the release trust, and runs the publish dry run, the tests and
   `scripts/e2e.sh`. Then each ecosystem's job publishes: crates in dependency order (every
   crate not `publish = false`), Python wheels for Linux (manylinux 2.28 and musllinux 1.2,
   x86_64 and aarch64) and macOS (x86_64, arm64), one `@sealzone/sdk-<platform>` npm package per target
   (`crates/sdk/seal-node/npm-packages.mjs`) then `@sealzone/sdk`, and, after `go test`, a
   commit with `libseal_ffi.a` for linux and darwin (amd64, arm64) to
   `github.com/sealzone/seal-go`, tagged with the same version.

A crates.io version can be yanked but never replaced, so fix forward.

### Release trust

Every build compiles in `crates/sdk/seal-client/release-trust.json`, which is committed here and
published inside the `sealzone` crate, so every SDK verifies enclaves against the same auditable
anchors. It has the shape of `deploy/example/trust.json`, filled with Seal's production public
keys: release keys and threshold, the log and its witnesses, registrar keys and guardian keys.
The workflow refuses to run without it or with the example's development keys. Changing it is a
release of its own, since every SDK built before keeps the anchors it shipped with.

### Setup

| What | Where | Used by |
| --- | --- | --- |
| `release-trust.json` from the key ceremony | this repository | every build |
| Trusted publisher for every published crate, environment `crates-io` | crates.io | `publish-crates` |
| Trusted publisher for `sealzone`, environment `pypi` | pypi.org | `publish-pypi` |
| Trusted publisher for each `@sealzone/sdk*` package, environment `npm`, set with `npm trust github <package> --file release.yml --repo sealzone/seal --env npm --allow-publish` | npmjs.com | `publish-npm` |
| `SEAL_GO_DEPLOY_KEY`, a deploy key with write access to `sealzone/seal-go` | secret in environment `go` | `publish-go` |
| `seal.zone/go` answers `go get` with `<meta name="go-import" content="seal.zone/go git https://github.com/sealzone/seal-go">` | the seal.zone website | Go users |

Every trusted publisher names this repository and workflow `release.yml`. crates.io and npm
trust only existing packages, so each package's first version is published by
hand with a token. Protect the `crates-io`, `pypi`, `npm` and `go` environments with required
reviewers, so a pushed tag waits for a person before anything is published. Private
vulnerability reporting must be on (Settings, Code security) for the link in SECURITY.md to
work.

Contributions are licensed under Apache-2.0, like the rest of the repository ([LICENSE](LICENSE)).
