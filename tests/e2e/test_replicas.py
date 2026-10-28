"""Several replicas of one tenant: they share keys, honour each other's tokens, and clients
and their tunnels fail over between them."""

from __future__ import annotations

import json

import pytest

import seal
from world import SECRET, World, get


def test_replicas_share_keys_and_tokens(world: World) -> None:
    world.start_replica(2)
    certificates = json.loads(world.path("control/tenants/acme/service-key-certificates.json").read_text())
    assert len(certificates) == 1, "both replicas hold the same certified keys"

    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    s = world.client().session(blob, kind="http")
    assert get(s.url, s.key)[0] == 200
    # Replica 1 issued the session; once it is gone, the tunnel's next connection reaches
    # replica 2, which takes replica 1's token.
    world.stop_replica(1)
    assert get(s.url, s.key)[0] == 200, "replica 2 takes replica 1's token"
    s.close()


def test_a_close_while_the_control_plane_is_down_is_retried(world: World) -> None:
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    s = world.client().session(blob, kind="http")
    url, key = s.url, s.key
    assert get(url, key)[0] == 200

    # The end cannot be published: close fails, and the tunnel closes anyway.
    world.stop("control")
    with pytest.raises(seal.Unavailable):
        s.close()
    assert get(url, key)[0] != 200, "the tunnel closed"
    # Closing again once the control plane is back publishes the end.
    world.start_control()
    s.close()


def test_clients_and_live_tunnels_fail_over(world: World) -> None:
    world.start_replica(2)
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    app = world.client()
    live = app.session(blob, kind="http")
    assert get(live.url, live.key)[0] == 200

    world.stop_replica(1)
    assert get(live.url, live.key)[0] == 200, "the live tunnel fails over to replica 2"
    with app.session(blob, kind="http") as s:
        assert get(s.url, s.key)[0] == 200, "new sessions start on replica 2"
    live.close()
