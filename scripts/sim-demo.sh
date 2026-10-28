#!/usr/bin/env bash
# The whole system on the simulator, step by step: a release approved by dev release keys and
# logged in the dev log, a guardian with a file root behind a TLS proxy, the control plane, a
# tenant created with the `seal` CLI, an enclave booting from all of them, a producer sealing an
# API key for a local HTTPS upstream, and an app using it through the enclave without ever
# holding it; then a Postgres password used the same way, and telemetry. Needs Docker or Podman.
#
#   scripts/sim-demo.sh                 build (sim features) and run (tests: scripts/e2e.sh)
#   SEAL_SIM_KEEP=1 scripts/sim-demo.sh keep the work directory (configs, logs, keys)
#   SEAL_SIM_PORT_BASE=47300            first of nine local ports (default 47300)
#   SEAL_SIM_HOLD=1                     keep everything running after the app's flow, until Ctrl-C
#   SEAL_CONTAINER_RUNTIME=podman       the container runtime (default: docker, else podman)
#
# Every process logs to <work>/logs/; all of them, the Postgres container and (unless kept) the
# work directory are removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT_BASE=${SEAL_SIM_PORT_BASE:-47300}
TENANT=acme
SECRET="sk-live-demo-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run() { printf '\033[2m$ %s\033[0m\n' "$*" >&2; "$@"; }

bold "Build with sim features"
cargo build --quiet \
    -p sealzone-tlog --features sealzone-tlog/dev \
    -p seal-guardian --features seal-guardian/sim \
    -p sealzone-control --features sealzone-control/sim \
    -p seal-enclave --features seal-enclave/sim \
    -p sealzone-cli --features sealzone-cli/sim \
    -p seal-sim --features seal-sim/sim
BIN=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug

WORK=$(mktemp -d "${TMPDIR:-/tmp}/seal-sim.XXXXXX")
mkdir -p "$WORK/logs"
PIDS=()
PG_CONTAINER=
PG_RUNTIME=
cleanup() {
    local status=$?
    # Newest first, so the enclave ships its final telemetry batch while the control plane runs.
    for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
        kill "${PIDS[i]}" 2>/dev/null || true
        wait "${PIDS[i]}" 2>/dev/null || true
    done
    [[ -n "$PG_CONTAINER" ]] && "$PG_RUNTIME" rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    if [[ $status -ne 0 ]]; then
        echo "failed; the last lines of each log:" >&2
        for log in "$WORK"/logs/*.log; do [[ -f "$log" ]] && { echo "--- $log" >&2; tail -n 15 "$log" >&2; }; done
    fi
    if [[ -n "${SEAL_SIM_KEEP:-}" ]]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# Starts a process in the background with its output in logs/NAME.log.
start() {
    local name=$1; shift
    "$@" >"$WORK/logs/$name.log" 2>&1 &
    PIDS+=($!)
    echo "started $name (pid $!, log logs/$name.log)"
}
wait_port() {
    for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done
    echo "nothing listens on port $1" >&2; return 1
}
wait_log() {
    for _ in $(seq 1 150); do grep -q "$2" "$WORK/logs/$1.log" && return 0; sleep 0.2; done
    echo "$1 did not log '$2'" >&2; return 1
}

D=$WORK/env
bold "Set up the environment: dev release keys, the release logged, guardian root, test CA, configs"
run "$BIN/seal-sim" setup --dir "$D" --enclave-bin "$BIN/seal-enclave" --port-base "$PORT_BASE"
port() { sed -n "s/.*\"$1\": \([0-9]*\).*/\1/p" "$D/sim.json"; }
LOG_SEED=$(sed -n 's/.*"log_seed": "\([0-9a-f]*\)".*/\1/p' "$D/sim.json")
DEPLOYMENT='{"kind":"confidential_space","project_number":1,"service_account":"enclave@sim.seal.zone"}'
PRODUCER_PUBLIC=$(sed -n 's/.*"producer_public_key": "\([0-9a-f]*\)".*/\1/p' "$D/sim.json")
WRITE_TOKEN=$(sed -n 's/.*"write_token": "\([0-9a-f]*\)".*/\1/p' "$D/sim.json")

bold "Start the dev log, the guardian (file root) behind a TLS proxy, and the control plane"
start log "$BIN/seal-tlog-dev" --dir "$D/log" --listen "127.0.0.1:$(port log)" --seed "$LOG_SEED"
SEAL_SIM=1 SEAL_GUARDIAN_CONFIG="$D/guardian.json" start guardian "$BIN/seal-guardian"
start proxy "$BIN/seal-sim" proxy --dir "$D"
start control "$BIN/seal-control" --config "$D/control.json"
wait_port "$(port log)"; wait_port "$(port guardian)"; wait_port "$(port guardian_tls)"; wait_port "$(port control)"
grep -h "guardian booted" "$WORK/logs/guardian.log"

bold "Publish the release evidence to the control plane"
run "$BIN/seal-sim" publish-release --dir "$D"

bold "Create the tenant with the seal CLI"
export SEAL_HOME=$D/admin SEAL_TRUST=$D/trust.json SEAL_NO_BROWSER=1
SEAL="$BIN/seal"
ADMIN_KEY=$D/admin.key
run "$SEAL" key create --out "$ADMIN_KEY"
SEAL_CONTROL_TOKEN=$WRITE_TOKEN run "$SEAL" dev init --tenant "$TENANT" --key-file "$ADMIN_KEY" --registrar-key "$D/registrar.key" --yes \
    | tee "$WORK/init.out"
ROOT_ID=$(sed -n "s/^SEAL_TENANT=$TENANT@//p" "$WORK/init.out")
run "$SEAL" grant app checkout key --generate --out "$D/checkout.key" --key-file "$ADMIN_KEY" --yes
run "$SEAL" grant producer key --public "$PRODUCER_PUBLIC" --key-file "$ADMIN_KEY" --yes
run "$SEAL" grant enclave sim "$DEPLOYMENT" --key-file "$ADMIN_KEY" --yes
run "$SEAL" settings platforms add sim --key-file "$ADMIN_KEY" --yes

bold "Boot the enclave: release, bundle and deployment verified, keys from the guardian"
SEAL_SIM=1 SEAL_TENANT="$TENANT@$ROOT_ID" SEAL_SIM_DEPLOYMENT="$DEPLOYMENT" SEAL_ENCLAVE_CONFIG="$D/enclave.json" \
    start enclave "$BIN/seal-enclave"
ENCLAVE_PID=${PIDS[-1]}
wait_log enclave "serving the API"
grep -h "booted" "$WORK/logs/enclave.log"

bold "Start the HTTPS test upstream (its CA is trusted through the sim extra roots)"
start upstream "$BIN/seal-sim" upstream --dir "$D"
wait_port "$(port upstream)"

export SEAL_ENDPOINT="https://localhost:$(port api)" SEAL_TENANT="$TENANT@$ROOT_ID" SEAL_TRUST="$D/trust.json"
bold "The producer seals the API key for the upstream (the secret goes only into the enclave)"
printf '%s' "$SECRET" | SEAL_APP_KEY=$(cat "$D/producer.key") run "$SEAL" secret --to "https://localhost:$(port upstream)/v1" \
    --app checkout --header authorization --format 'Bearer {key}' > "$WORK/api.blob"
echo "blob: $(cut -c1-60 "$WORK/api.blob")…"

bold "The app uses the blob: tunnel and direct sessions, extend, close"
SEAL_APP_KEY=$(cat "$D/checkout.key") run "$BIN/seal-sim" app http --blob-file "$WORK/api.blob"
echo
echo "what the upstream saw:"
cat "$WORK/logs/upstream.log"
grep -q "Bearer $SECRET" "$WORK/logs/upstream.log" \
    && echo "-> the upstream got the real key; the app only ever held stand-ins"

bold "Postgres: seal a password, query through a database session"
PG_PASSWORD="pg-demo-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s' "$PG_PASSWORD" | "$BIN/seal-sim" postgres --dir "$D" | tee "$WORK/pg.out"
PG_RUNTIME=$(sed -n 's/^runtime //p' "$WORK/pg.out")
PG_CONTAINER=$(sed -n 's/^container //p' "$WORK/pg.out")
PG_DEST=$(sed -n 's/^destination //p' "$WORK/pg.out")
printf '%s' "$PG_PASSWORD" | SEAL_APP_KEY=$(cat "$D/producer.key") run "$SEAL" secret --to "$PG_DEST" --app checkout \
    > "$WORK/pg.blob"
SEAL_APP_KEY=$(cat "$D/checkout.key") run "$BIN/seal-sim" app pg --blob-file "$WORK/pg.blob"

if [[ -n "${SEAL_SIM_HOLD:-}" ]]; then
    bold "Holding: everything keeps running until Ctrl-C"
    echo "export SEAL_HOME=$SEAL_HOME SEAL_ENDPOINT=$SEAL_ENDPOINT SEAL_TENANT=$SEAL_TENANT SEAL_TRUST=$SEAL_TRUST"
    echo "app key: $D/checkout.key   producer key: $D/producer.key   blob: $WORK/api.blob   binaries: $BIN"
    while :; do sleep 1; done
fi

bold "Stop the enclave: its final telemetry batch closes the stream"
kill "$ENCLAVE_PID"
wait "$ENCLAVE_PID" || true
grep -h "shutting down" "$WORK/logs/enclave.log"

bold "Telemetry, verified with the certificate the enclave posted at boot"
# The control plane does not serve certificates yet: take them from its store.
cp "$D/control/tenants/$TENANT/service-key-certificates.json" "$WORK/certificates.json"
run "$SEAL" telemetry --certificates "$WORK/certificates.json"

bold "Done"
