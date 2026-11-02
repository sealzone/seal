"""Named secrets: an admin publishes a blob under a name, apps start sessions on the name, and a
new version reaches a running session at its next extend without the app restarting."""

from __future__ import annotations

import os

import pytest
import seal

from world import APP, SECRET, World, eventually, get

ROTATED = "sk-live-e2e-rotated-" + os.urandom(6).hex()


def publish(world: World, secret: str, name: str) -> str:
    """Seals `secret` for `checkout` and publishes it as `name`'s next version; returns the blob."""
    env = {"SEAL_TENANT": world.pin, "SEAL_ENDPOINT": ",".join(world.endpoints())}
    return world.admin("secret", "--to", world.upstream_url, "--app", APP, "--format", "Bearer {key}",
                       "--name", name, "--key-file", str(world.admin_key), stdin=secret, env=env).strip()


def secrets(world: World, *args: str) -> str:
    return world.admin("secrets", *args, "--key-file", str(world.admin_key))


def test_apps_follow_a_named_secret_to_its_new_version(world: World) -> None:
    publish(world, SECRET, "upstream")
    listed = secrets(world)
    assert "upstream" in listed and "v1" in listed, listed

    app = world.client()
    s = app.session("upstream", kind="http")
    key = s.key
    status, body = get(s.url, s.key)
    assert status == 200, body
    assert world.upstream_seen()[-1]["authorization"] == f"Bearer {SECRET}"

    publish(world, ROTATED, "upstream")
    assert "v2" in secrets(world)

    def rotated() -> bool:
        s.extend()
        status, _ = get(s.url, s.key)
        return status == 200 and world.upstream_seen()[-1]["authorization"] == f"Bearer {ROTATED}"

    # The enclave holds a name for 30 s before it fetches it again.
    eventually("the running session moves to version 2", rotated, timeout=45)
    assert s.key == key, "the app keeps its stand-in"
    s.close()

    with pytest.raises(seal.NotAllowed):
        world.client(world.stranger_key).session("upstream")
    with pytest.raises(seal.NotAllowed):
        app.session("never-published")

    secrets(world, "delete", "upstream", "--yes")
    assert "upstream" not in secrets(world)
