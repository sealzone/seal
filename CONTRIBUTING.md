# Contributing

Security issues go to [SECURITY.md](SECURITY.md), never to a public issue or pull request.

## Build and test

The toolchain is pinned in `rust-toolchain.toml` (rustup installs it on first use): enclave
and guardian images must build bit for bit, so it changes only deliberately, with a release.
The published crates keep an MSRV of 1.92 (`rust-version` in `Cargo.toml`).

```sh
cargo build --workspace
cargo test --workspace --locked     # unit and integration tests; no containers needed
scripts/e2e.sh                      # end-to-end tests on the simulator (tests/e2e/README.md)
scripts/py-test.sh                  # the Python SDK's own tests against the simulator
scripts/sim-demo.sh                 # the whole system, step by step
```

`scripts/e2e.sh` and `scripts/sim-demo.sh` need Docker or Podman and Python 3.9+; the Node
and Go SDK tests also need Node.js and Go and are skipped without them.
`crates/sdk/seal-verify-wasm/build.sh --test` checks the browser verifier under Node.

## Before a pull request

CI (`.github/workflows/ci.yml`) runs these on every push and pull request; run them first:

```sh
cargo fmt --all --check                                  # rustfmt.toml: 120 columns
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
scripts/check-deps.sh                                    # needs cargo-deny
```

## Rules a change follows

- **Wire format v1 is frozen.** Types that are signed, hashed or read by a guardian only gain
  optional fields omitted when unset ([CONTRACT.md](docs/CONTRACT.md)). The vector files
  (`crates/shared/seal-proto/tests/vectors/wire-v1.json`,
  `crates/sdk/seal-verify-wasm/tests/vectors.json`) are regenerated only for a deliberate
  format change, with `SEAL_WRITE_VECTORS=1` on that test, and the diff is reviewed in the
  same pull request.
- **Dependencies** follow [DEPS.md](docs/DEPS.md): versions only in the root
  `[workspace.dependencies]`, and a change to what the enclave or guardian compiles in updates
  `tee-deps/` (`scripts/check-deps.sh --update`, reviewed).
- **Anything that weakens trust** (simulator evidence, extra CAs, the system clock as trusted
  time) lives behind the `sim` feature, never in a production build.
- **Public interfaces and the docs move together.** A change to a crate's public items, a
  route, a constant or a CLI command updates [CONTRACT.md](docs/CONTRACT.md) or
  [ARCHITECTURE.md](docs/ARCHITECTURE.md) in the same change.

Contributions are licensed under Apache-2.0, as the repository is ([LICENSE](LICENSE)).
