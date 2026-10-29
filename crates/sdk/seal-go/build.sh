#!/usr/bin/env bash
# Builds seal-ffi (the C ABI over the Rust SDK core) and puts the static library and its
# header where cgo looks for them:
#
#   lib/seal.h
#   lib/<GOOS>_<GOARCH>/libseal_ffi.a
#
#   crates/sdk/seal-go/build.sh            a release build, for the host
#   crates/sdk/seal-go/build.sh --sim      with the simulator (tests against seal-sim)
#   crates/sdk/seal-go/build.sh --aws      with AWS workload identity (seal.AWSIdentity)
#   crates/sdk/seal-go/build.sh --debug    a debug build: much faster to build, much larger
#
# Go then builds as usual: `go build ./...`, `go test ./...`. The published seal-go
# repository carries these files prebuilt; lib/ is not committed here.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

profile=release
features=()
for arg in "$@"; do
    case "$arg" in
        --sim) features+=(sim) ;;
        --aws) features+=(aws) ;;
        --debug) profile=debug ;;
        *) echo "usage: $0 [--sim] [--aws] [--debug]" >&2; exit 2 ;;
    esac
done

cd "$root"
args=(build --quiet --locked -p seal-ffi)
if [[ $profile == release ]]; then
    args+=(--release)
fi
if ((${#features[@]})); then
    args+=(--features "$(IFS=,; echo "${features[*]}")")
fi
cargo "${args[@]}"

target=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
platform="$(go env GOOS)_$(go env GOARCH)"
mkdir -p "$here/lib/$platform"
cp "$target/$profile/libseal_ffi.a" "$here/lib/$platform/libseal_ffi.a"
# Go's linker uses neither the LLVM bitcode rustc embeds for cross-language LTO (two thirds of
# the archive) nor debug info; without them the archive stays well under GitHub's 100 MB file
# limit for the seal-go repository.
if [[ $(go env GOOS) == linux ]]; then
    strip --strip-debug --remove-section=.llvmbc --remove-section=.llvmcmd "$here/lib/$platform/libseal_ffi.a"
fi
cp crates/sdk/seal-ffi/seal.h "$here/lib/seal.h"
echo "$here/lib/$platform/libseal_ffi.a (${profile}${features:+, ${features[*]}})"
