#!/usr/bin/env bash
# Builds the npm package @sealzone/verify from this crate:
#
#   crates/sdk/seal-verify-wasm/build.sh            into crates/sdk/seal-verify-wasm/pkg
#   crates/sdk/seal-verify-wasm/build.sh OUT        into OUT
#   crates/sdk/seal-verify-wasm/build.sh --test     build, then run js/test.mjs (Node 20+) against it
#
# Two modules: the verifier (`@sealzone/verify`) and, with the `seal` feature, the sealing one
# (`@sealzone/verify/seal`), which only pages that seal load.
#
# Needs the wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`) and
# wasm-bindgen-cli at exactly the workspace's wasm-bindgen version
# (`cargo install wasm-bindgen-cli --version =<version> --locked`).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

test=
out="$here/pkg"
for arg in "$@"; do
    case "$arg" in
        --test) test=1 ;;
        *) out=$(realpath -m "$arg") ;;
    esac
done

want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' "$root/Cargo.toml")
have=$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)
if [[ "$have" != "$want" ]]; then
    echo "needs wasm-bindgen-cli $want (found ${have:-none}): cargo install wasm-bindgen-cli --version =$want --locked" >&2
    exit 1
fi

target="$root/target/wasm"
# From the checkout, so cargo picks up its rust-toolchain.toml and the wasm target with it.
(cd "$root" && CARGO_TARGET_DIR="$target" cargo build --locked --release -p sealzone-verify-wasm --target wasm32-unknown-unknown)
rm -rf "$out"
mkdir -p "$out"
wasm-bindgen --target web --out-dir "$out" "$target/wasm32-unknown-unknown/release/seal_verify_wasm.wasm"
# The sealing module (`/seal`): the same crate with the sealing exports, in a target dir of its own.
(cd "$root" && CARGO_TARGET_DIR="$target-seal" cargo build --locked --release -p sealzone-verify-wasm --features seal --target wasm32-unknown-unknown)
wasm-bindgen --target web --out-dir "$out/seal" --out-name seal_wasm "$target-seal/wasm32-unknown-unknown/release/seal_verify_wasm.wasm"
cp "$here/js/index.js" "$here/js/index.d.ts" "$here/js/seal.js" "$here/js/seal.d.ts" "$out/"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
sed "s/@VERSION@/$version/" "$here/js/package.json" > "$out/package.json"
echo "built @sealzone/verify $version in $out"

if [[ -n "$test" ]]; then
    SEAL_VERIFY_PKG="$out" node --test "$here/js/test.mjs"
fi
