# Sourced by scripts/e2e.sh and scripts/py-test.sh: builds the simulator's binaries (sim
# features) and installs the `sealzone` wheel into a virtualenv. Sets TARGET, VENV and BINS.
#
#   SEAL_PY_VENV=DIR     the virtualenv (default target/py-venv)
#   SEAL_PY=python3.12   the interpreter it is made from (default python3)

cargo build --quiet --locked \
    -p sealzone-tlog --features sealzone-tlog/dev \
    -p seal-guardian --features seal-guardian/sim \
    -p sealzone-control --features sealzone-control/sim \
    -p seal-enclave --features seal-enclave/sim \
    -p sealzone-cli --features sealzone-cli/sim \
    -p seal-sim --features seal-sim/sim
TARGET=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
BINS="$TARGET/debug"

VENV=${SEAL_PY_VENV:-$TARGET/py-venv}
if [[ ! -x "$VENV/bin/python" ]]; then
    "${SEAL_PY:-python3}" -m venv "$VENV"
fi
VENV=$(cd "$VENV" && pwd)
if ! "$VENV/bin/python" -c 'import maturin, pytest, psycopg, redis' 2>/dev/null; then
    "$VENV/bin/python" -m pip install --quiet --upgrade pip 'maturin>=1.5,<2' pytest 'psycopg[binary]>=3.2,<4' 'redis>=5,<7'
fi

# A wheel, as users get it, rather than an editable install: the tests import what ships.
rm -rf "$TARGET/py-wheels"
"$VENV/bin/maturin" build --quiet --locked --features sim --manifest-path crates/sdk/seal-py/Cargo.toml \
    --interpreter "$VENV/bin/python" --out "$TARGET/py-wheels"
"$VENV/bin/python" -m pip install --quiet --force-reinstall --no-deps "$TARGET"/py-wheels/sealzone-*.whl
