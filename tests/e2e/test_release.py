"""Release evidence: the fresh checkpoint uploaded with a release runs out after a day, yet
replicas keep booting, because the control plane serves the log's latest checkpoint with it."""

from __future__ import annotations

import time
from typing import Callable

from world import SECRET, World, get

STALE_IN = 10  # seconds after setup that the uploaded evidence's fresh checkpoint runs out


def test_a_replica_boots_after_the_uploaded_release_evidence_goes_stale(make_world: Callable[..., World]) -> None:
    world = make_world(release_stale_in=STALE_IN)
    time.sleep(STALE_IN + 1)

    world.start_replica(2)
    world.stop_replica(1)
    blob = world.seal_with_cli(SECRET, world.upstream_url)
    with world.client().session(blob, kind="http") as s:
        assert get(s.url, s.key)[0] == 200, "replica 2 serves"
