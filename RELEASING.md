# Releasing

Two kinds of release, on different keys and schedules:

- **SDKs** (this file): the Rust crates on crates.io (`sealzone`, `sealzone-cli` and the
  `sealzone-*` crates they use), `sealzone` on PyPI, `@sealzone/sdk` on npm, and the Go module
  `seal.zone/go`, built and published by `.github/workflows/release.yml` from a version tag.
- **Enclave and guardian images**: reproducible builds signed by M of N release keys, logged
  and time-locked (`seal-release`; see docs/ARCHITECTURE.md). The SDKs verify enclaves against
  these releases, so an SDK release never needs a new image, and an image release never needs
  a new SDK unless the protocol changed.

## SDK release

1. Bump the version in the root `Cargo.toml` (`[workspace.package] version`) and in
   `crates/sdk/seal-node/package.json` (`version` and its `optionalDependencies`); commit.
2. Optional dry run: run the `release` workflow by hand (`dry_run` on): it builds and tests
   every platform and lays out every package, and publishes nothing.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`. The workflow:
   - **check**: the tag is the packages' version; the release trust (below);
     `cargo publish --workspace --dry-run`; `cargo test --workspace`; the end-to-end tests
     (`scripts/e2e.sh`).
   - **crates**: `cargo publish --workspace`, every crate not marked `publish = false`, in
     dependency order.
   - **python**: wheels for Linux (manylinux 2.28 and musllinux 1.2, x86_64 and aarch64) and
     macOS (x86_64, arm64), then PyPI.
   - **node**: the addon for every target in `package.json`, then one
     `@sealzone/sdk-<platform>` package each (`crates/sdk/seal-node/npm-packages.mjs`), then
     `@sealzone/sdk`.
   - **go**: `libseal_ffi.a` for linux and darwin, amd64 and arm64, tested with `go test`,
     then one commit to `github.com/sealzone/seal-go` with the module and the libraries,
     tagged with the same version.

Every build compiles in the production release trust: `crates/sdk/seal-client/release-trust.json`,
committed here and published inside the `sealzone` crate, so the binary SDKs and every build
from crates.io verify enclaves against the same anchors, and anyone can audit them. It is the
shape of `deploy/example/trust.json` with Seal's production keys (release keys and threshold,
the log and its witnesses, registrar keys, guardian keys): public keys only. The workflow
refuses to run without it, or with the example's development keys in it. Changing it is a
release of its own: every SDK built before keeps the anchors it shipped with.
Windows is not built: neither the npm package nor the Go module supports it yet.

## One-time setup

| What | Where | Used by |
| --- | --- | --- |
| `crates/sdk/seal-client/release-trust.json`: the production trust (above), from the key ceremony | committed to this repository | every build |
| crates.io trusted publisher for every published crate: this repository, workflow `release.yml`, environment `crates-io` (the first version of each crate is published by hand with a token; trusted publishing applies after) | crates.io | `publish-crates` |
| PyPI trusted publisher for `sealzone`: this repository, workflow `release.yml`, environment `pypi` | pypi.org | `publish-pypi` |
| npm trusted publisher for each `@sealzone/sdk*` package: this repository, workflow `release.yml`, environment `npm` (`npm trust github <package> --file release.yml --repo sealzone/seal --env npm --allow-publish`; npm trusts only existing packages, so a package's first version is published by hand) | npmjs.com | `publish-npm` |
| `SEAL_GO_DEPLOY_KEY`: a deploy key with write access to `sealzone/seal-go` | secret in environment `go` | `publish-go` |
| `seal.zone/go` answers `go get` with `<meta name="go-import" content="seal.zone/go git https://github.com/sealzone/seal-go">` | the seal.zone website | Go users |

Protect the `crates-io`, `pypi`, `npm` and `go` environments (required reviewers) so a pushed tag waits for
a person before anything is published.

## Notes

- The Go module carries prebuilt static libraries (release builds, tens of MB each), one
  commit per release; consider Git LFS for `lib/` in `seal-go` if its history grows too large.
- The crates' `sim` feature is insecure (it accepts simulator evidence) and documented so;
  it stays available for tests.
- A crates.io version can be yanked, never replaced: fix forward with a new version.

## Before the repository is public

A checklist for the first publication; each item is done once.

- [ ] Private vulnerability reporting is on (**Settings → Code security**), so the link in
      SECURITY.md works.
- [ ] The package names are claimed: on crates.io `sealzone`, `sealzone-cli` and
      `sealzone-{proto,crypto,tlog,verify,net,attest,control}` (a first version published by
      hand, then the trusted publisher above); `sealzone` on PyPI; the `@sealzone` npm
      organization (`@sealzone/sdk`, `@sealzone/sdk-<platform>`, `@sealzone/verify`).
- [ ] `sealzone/seal-go` exists (public), with `SEAL_GO_DEPLOY_KEY` as a deploy key, and
      `https://seal.zone/go?go-get=1` answers with its `go-import` tag.
- [ ] `crates/sdk/seal-client/release-trust.json` holds the production trust from the key
      ceremony; until then the `release` workflow fails in its `check` job.
- [ ] `.github/workflows/ci.yml` passes on `main`, and branch protection requires it for pull
      requests.
- [ ] The `crates-io`, `pypi`, `npm` and `go` environments have required reviewers.
