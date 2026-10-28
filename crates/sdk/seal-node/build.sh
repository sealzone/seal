#!/usr/bin/env bash
# Builds the native addon of @sealzone/sdk for this machine, as `seal.<platform>.node` next to
# index.js (where native.js looks first):
#
#   crates/sdk/seal-node/build.sh                   debug build
#   crates/sdk/seal-node/build.sh --release         release build, what the per-platform package ships
#   crates/sdk/seal-node/build.sh --sim             against the simulator (`sim` feature), for tests
#   crates/sdk/seal-node/build.sh --aws             with AWS workload identity (`AwsIdentity`)
#   crates/sdk/seal-node/build.sh --test            then run the unit tests (test/, no simulator)
#
# Needs Rust and Node 20+. Publishing: one package per target in package.json's `napi`
# section (`@sealzone/sdk-<platform>`, holding that platform's `seal.<platform>.node`), and
# this package listing them as optional dependencies, as napi-rs lays them out.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

profile=debug
features=()
test=
for arg in "$@"; do
    case "$arg" in
        --release) profile=release ;;
        --sim) features+=(sim) ;;
        --aws) features+=(aws) ;;
        --test) test=1 ;;
        *) echo "unknown argument $arg" >&2; exit 2 ;;
    esac
done

args=(--locked -p seal-node)
[[ "$profile" == release ]] && args+=(--release)
[[ ${#features[@]} -gt 0 ]] && args+=(--features "$(IFS=,; echo "${features[*]}")")
# From the checkout, so cargo picks up its rust-toolchain.toml.
(cd "$root" && cargo build --quiet "${args[@]}")

target=$(cd "$root" && cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
case "$(uname -s)" in
    Darwin) lib="$target/$profile/libseal_node.dylib" ;;
    *) lib="$target/$profile/libseal_node.so" ;;
esac
platform=$(node -p 'require(process.argv[1]).platform()' "$here/native.js")
out="$here/seal.$platform.node"
# A copy, not a link: Node maps the file, and the next cargo build rewrites it in place.
rm -f "$out"
cp "$lib" "$out"
echo "built $out (${profile}${features:+, ${features[*]}})"

if [[ -n "$test" ]]; then
    node --test "$here/test/unit.test.mjs"
fi
