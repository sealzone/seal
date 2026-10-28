"""The simulator for the Python SDK's tests: the end-to-end tests' `World` (tests/e2e/world.py:
Seal's own binaries on localhost, tenant `acme`, app `checkout`, one replica, the HTTPS test
upstream), booted once per test run.

`SEAL_SIM_BIN_DIR` names the directory with the sim builds; `scripts/py-test.sh` builds them
and sets it. Tests that need the simulator are skipped without it. Every process logs to
`<work>/logs/`; `SEAL_SIM_KEEP=1` keeps the work directory.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterator

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tests" / "e2e"))
from world import SECRET as SECRET  # noqa: E402
from world import World  # noqa: E402


@dataclasses.dataclass
class Sim:
    """What the SDK tests use of the world."""

    world: World
    work: Path
    endpoint: str
    tenant: str
    trust: Path
    app_key: str
    stranger_key: str
    upstream: str

    def env(self) -> Dict[str, str]:
        """What an app's environment holds: endpoint, tenant pin, trust (sim builds) and its key."""
        return {
            "SEAL_ENDPOINT": self.endpoint,
            "SEAL_TENANT": self.tenant,
            "SEAL_TRUST": str(self.trust),
            "SEAL_APP_KEY": self.app_key,
        }

    def log(self, name: str) -> str:
        return self.world.log(name)


@pytest.fixture(scope="session")
def sim() -> Iterator[Sim]:
    bins = os.environ.get("SEAL_SIM_BIN_DIR")
    if not bins:
        pytest.skip("SEAL_SIM_BIN_DIR is not set (scripts/py-test.sh builds the simulator)")
    world = World.boot(Path(bins), Path(tempfile.mkdtemp(prefix="seal-py-sim.")))
    ok = False
    try:
        yield Sim(world=world, work=world.work, endpoint=world.endpoint(), tenant=world.pin,
                  trust=world.path("trust.json"), app_key=world.app_key, stranger_key=world.stranger_key,
                  upstream=world.upstream_url)
        ok = True
    finally:
        world.shutdown(failed=not ok)


@pytest.fixture(scope="session")
def app_env(sim: Sim) -> Iterator[Sim]:
    """The app's environment in `os.environ`, for clients built from it."""
    saved = {k: v for k, v in os.environ.items() if k.startswith("SEAL_")}
    os.environ.update(sim.env())
    yield sim
    for k in sim.env():
        os.environ.pop(k, None)
    os.environ.update(saved)


@pytest.fixture(scope="session")
def blob(app_env: Sim) -> str:
    """The upstream's API key, sealed for `checkout` by a stranger (anyone may seal)."""
    import seal

    stranger = seal.Client(
        endpoints=[app_env.endpoint],
        tenant=app_env.tenant,
        identity=seal.AppKeyIdentity(app_env.stranger_key),
    )
    return stranger.seal(SECRET, to=app_env.upstream, apps=["checkout"], header="authorization", format="Bearer {key}")
