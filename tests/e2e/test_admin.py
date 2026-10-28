"""Admin changes made with the `seal` CLI reach running replicas on their next state reload
(every second in these tests; `STATE_RELOAD_SECS` in a release)."""

from __future__ import annotations

import time

import pytest

import seal
from world import SECRET, World, eventually, get

WINDOW = 8  # seconds; the pending window used below


def key_version(blob: str) -> int:
    """The tenant key version a blob was sealed under (`seal1.<tenant>.<version>.…`)."""
    return int(blob.split(".")[2])


def test_a_tenant_key_bump_reaches_running_replicas(world: World) -> None:
    producer = world.client(world.producer_key)
    blobs = [producer.seal(SECRET, to=world.upstream_url, apps=["checkout"])]
    assert key_version(blobs[0]) == 1

    def seal_again() -> int:
        blobs.append(producer.seal(SECRET, to=world.upstream_url, apps=["checkout"]))
        return key_version(blobs[-1])

    world.admin("settings", "tenant-key", "bump", "--yes")
    eventually("new blobs use tenant key version 2", lambda: seal_again() == 2)

    app = world.client()
    for blob in (blobs[0], blobs[-1]):
        with app.session(blob, kind="http") as s:
            assert get(s.url, s.key)[0] == 200, "blobs of both key versions open"


def test_the_pending_window_delays_widening_changes(world: World) -> None:
    # Lengthening the window narrows access, so it applies at once.
    world.admin("settings", "window", f"{WINDOW}s", "--yes")

    # Adding a producer widens access: it waits, in public, for the window to pass.
    out = world.admin("grant", "producer", "key", "--generate", "--out", str(world.path("cancelled.key")), "--yes")
    assert "this widens access" in out, out
    code, out = world.admin_status("changes", "--watch", "--once")
    assert code == 3 and "+ producer: app key" in out and "(widening)" in out, out

    # A change built on the state in force supersedes the pending one, which never applies.
    out = world.admin("settings", "window", f"{WINDOW + 1}s", "--yes")
    assert "this narrows access" in out and "never take effect" in out, out
    assert world.admin_status("changes", "--watch", "--once")[0] == 0, "nothing pending once superseded"

    world.admin("grant", "producer", "key", "--generate", "--out", str(world.path("added.key")), "--yes")
    published = time.monotonic()
    added = world.client(world.path("added.key").read_text().strip())
    cancelled = world.client(world.path("cancelled.key").read_text().strip())

    def may_seal(client: seal.Client) -> bool:
        try:
            client.seal(SECRET, to=world.upstream_url, apps=["checkout"])
            return True
        except seal.NotAllowed:
            return False

    time.sleep(2)  # a reload after the publish, still within the window
    assert not may_seal(added) and not may_seal(cancelled), "neither is a producer yet"
    eventually("the added producer takes effect after the window", lambda: may_seal(added), timeout=WINDOW + 15)
    assert time.monotonic() - published >= WINDOW + 1, "not before the window passed"
    assert not may_seal(cancelled), "the superseded producer never takes effect"
    assert world.path("control/tenants/acme/anchors.json").exists(), "the control plane holds the guardian's anchor"


def test_removing_the_app_ends_its_sessions(world: World) -> None:
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    app = world.client()
    live = app.session(blob, kind="http")
    assert get(live.url, live.key)[0] == 200

    world.admin("revoke", "app", "checkout", "--yes")  # narrows: applies on the next reload
    eventually("the live session ends with the app's grant", lambda: get(live.url, live.key)[0] != 200)
    with pytest.raises(seal.NotAllowed):
        app.session(blob, kind="http")
    with pytest.raises(seal.SealError):
        live.extend()
