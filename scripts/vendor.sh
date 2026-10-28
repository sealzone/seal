#!/usr/bin/env bash
# Vendors every crate Cargo.lock names into vendor/, the only crate source the enclave and
# guardian image builds read (they build with --network=none). Cargo checks each vendored crate
# against the checksum in Cargo.lock, so a modified vendor/ fails the build. Run it before
# `docker buildx build -f deploy/{enclave,guardian}.Dockerfile`; vendor/ is not committed.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf vendor
cargo vendor --locked --quiet vendor >/dev/null
echo "vendored $(find vendor -mindepth 1 -maxdepth 1 -type d | wc -l) crates into vendor/"
