"""Fixtures: `world` is a freshly booted system for one test; `make_world(...)` boots one with
options. Run through `scripts/e2e.sh`, which builds everything first."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Iterator, List

import pytest

from world import World


def pytest_configure(config: pytest.Config) -> None:
    """Fails fast, before any test, when something the tests need is missing."""
    bins = os.environ.get("SEAL_SIM_BIN_DIR")
    if not bins or not (Path(bins) / "seal-enclave").exists():
        pytest.exit("SEAL_SIM_BIN_DIR names no sim build: run the tests with scripts/e2e.sh", returncode=4)
    runtime = os.environ.get("SEAL_CONTAINER_RUNTIME")
    runtimes = [runtime] if runtime else ["docker", "podman"]
    if not any(shutil.which(r) and subprocess.run([r, "info"], capture_output=True).returncode == 0 for r in runtimes):
        pytest.exit("Docker or Podman is required (for the Postgres upstream)", returncode=4)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):  # type: ignore[no-untyped-def]
    """Remembers whether a test failed, so its world prints the processes' logs."""
    report = yield
    if report.failed:
        item.stash[FAILED] = True
    return report


FAILED = pytest.StashKey[bool]()


@pytest.fixture
def make_world(request: pytest.FixtureRequest) -> Iterator[Callable[..., World]]:
    """Boots a world: `make_world(release_stale_in=10)`. Shut down after the test."""
    worlds: List[World] = []

    def make(**options: object) -> World:
        work = Path(tempfile.mkdtemp(prefix=f"seal-e2e-{request.node.name[:40]}."))
        world = World.boot(Path(os.environ["SEAL_SIM_BIN_DIR"]), work, **options)  # type: ignore[arg-type]
        worlds.append(world)
        return world

    yield make
    for world in worlds:
        world.shutdown(failed=request.node.stash.get(FAILED, False))


@pytest.fixture
def world(make_world: Callable[..., World]) -> World:
    """A freshly booted system: tenant `acme`, app `checkout`, one replica."""
    return make_world()
