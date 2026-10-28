#!/usr/bin/env bash
# The Python SDK's tests: builds the simulator's binaries and the `sealzone` wheel (sim
# features) into a virtualenv, then runs pytest against the simulator
# (crates/sdk/seal-py/tests; conftest.py stands it up as scripts/sim-demo.sh does).
#
#   scripts/py-test.sh                   build and run every test
#   scripts/py-test.sh -k tunnel -x      extra arguments go to pytest
#   SEAL_PY_VENV=DIR                     the virtualenv (default target/py-venv)
#   SEAL_PY=python3.12                   the interpreter it is made from (default python3)
#   SEAL_SIM_KEEP=1                      keep the simulator's work directory (configs, logs)
set -euo pipefail
cd "$(dirname "$0")/.."

source scripts/sim-env.sh

cd crates/sdk/seal-py
PYTHONDONTWRITEBYTECODE=1 SEAL_SIM_BIN_DIR="$BINS" exec "$VENV/bin/python" -m pytest -p no:cacheprovider "$@"
