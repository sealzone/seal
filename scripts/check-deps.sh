#!/usr/bin/env bash
# Supply-chain checks. Policy and reasons: docs/DEPS.md.
#
#   scripts/check-deps.sh            check
#   scripts/check-deps.sh --update   accept the current TEE dependency sets (review the diff!)
#
# 1. cargo deny: advisories (RustSec), licenses, banned crates, crates.io as the only source.
# 2. TEE budget: the crates compiled into each TEE image, exactly as the image builds them
#    (one package, default features, no `sim`), must match tee-deps/<crate>.txt. A new crate
#    in a TEE fails until someone reviews it and commits the updated list.
set -euo pipefail
cd "$(dirname "$0")/.."

TEE_CRATES=(seal-enclave seal-guardian)
NEVER_IN_TEE='^(aws-lc-rs|aws-lc-sys|openssl|openssl-sys|native-tls|reqwest)$'

cargo deny --locked check

status=0
for crate in "${TEE_CRATES[@]}"; do
    current=$(cargo tree --locked -p "$crate" -e normal,build --prefix none --format '{p}' \
        | cut -d' ' -f1 | grep -vE '^seal(zone)?(-|$)' | sort -u)
    if bad=$(grep -E "$NEVER_IN_TEE" <<<"$current"); then
        echo "error: $crate pulls crates that never belong in a TEE: $bad" >&2
        status=1
    fi
    list="tee-deps/$crate.txt"
    if [[ "${1:-}" == "--update" ]]; then
        echo "$current" > "$list"
        echo "updated $list ($(wc -l < "$list") crates)"
    elif ! diff -u "$list" <(echo "$current") >&2; then
        echo "error: $crate's TEE dependency set changed (- removed, + added). Review it, then run $0 --update." >&2
        status=1
    fi
done
exit $status
