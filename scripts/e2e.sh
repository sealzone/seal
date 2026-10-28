#!/usr/bin/env bash
# The end-to-end tests (tests/e2e): builds the simulator's binaries and the `sealzone` wheel,
# then runs pytest. Each test boots its own system on localhost; see tests/e2e/README.md.
#
#   scripts/e2e.sh                       build and run every test
#   scripts/e2e.sh -k failover           extra arguments go to pytest
#   SEAL_SIM_KEEP=1                      keep each test's work directory (configs, logs)
#   SEAL_CONTAINER_RUNTIME=podman        the container runtime (default: docker, else podman)
#
# Needs Docker or Podman (the Postgres upstream).
set -euo pipefail
cd "$(dirname "$0")/.."

source scripts/sim-env.sh

cd tests/e2e
PYTHONDONTWRITEBYTECODE=1 SEAL_SIM_BIN_DIR="$BINS" exec "$VENV/bin/python" -m pytest -p no:cacheprovider "$@"
