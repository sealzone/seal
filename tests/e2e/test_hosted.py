"""A Seal-hosted replica for the tenant: it seals and serves sessions and exits when idle, and a
client that finds it stopped keeps retrying until it serves again."""

from __future__ import annotations

import json
import threading
import time

from world import SECRET, World, get

IDLE_SECS = 5  # how long the hosted replica stays up idle (`HOSTED_IDLE_SECS` in a release)
HOSTED = {"kind": "confidential_space", "project_number": 2, "service_account": "t-acme@hosted.sim.seal.zone"}
RESTART_SECS = 3  # how long the stopped replica takes to come back
RESTARTED_IDLE_SECS = 30  # the restarted replica's idle exit, past the client's retries


def test_a_hosted_replica_serves_idles_out_and_clients_wait_for_it(world: World) -> None:
    # The tenant's signed consent to a Seal-hosted replica.
    world.admin("grant", "enclave", "sim", json.dumps(HOSTED), "--hosted", "--yes")
    config = world.replica_config("hosted", ip="127.0.0.3", hosted_idle_secs=IDLE_SECS)
    hosted = f"https://127.0.0.3:{world.port('api')}"
    world.start("hosted", "seal-enclave", env=world.replica_env(config, HOSTED))
    world.wait_for_log("hosted", "serving the API")

    # Sealers outside the tenant's network seal there, and apps use it beside the tenant's own
    # replicas: the blob opens on either.
    blob = world.seal_with_cli(SECRET, world.upstream_url, endpoints=[hosted])
    with world.client(endpoints=[hosted]).session(blob, kind="http") as s:
        assert get(s.url, s.key)[0] == 200, "a session on the hosted replica"
    with world.client(endpoints=[world.endpoint(1)]).session(blob, kind="http") as s:
        assert get(s.url, s.key)[0] == 200, "the same blob on the tenant's own replica"

    # Idle: it drains and exits cleanly, so its VM would stop.
    assert world.procs["hosted"].wait(timeout=IDLE_SECS + 30) == 0
    assert "hosted replica idle" in world.log("hosted") and "ERROR" not in world.log("hosted")

    # The SDK finds nothing listening and keeps retrying; it seals once the replica is back. (Seal's
    # front door starts a stopped hosted replica on the connection; here the test starts it.)
    # The restarted replica stays up longer than the client's retry backoff and a seal's round
    # trips (seals do not keep a replica up), so the client reaches it before it idles out.
    config_2 = world.replica_config("hosted-2", ip="127.0.0.3", hosted_idle_secs=RESTARTED_IDLE_SECS)

    def start_hosted_again() -> None:
        world.start("hosted-2", "seal-enclave", env=world.replica_env(config_2, HOSTED))

    restart = threading.Timer(RESTART_SECS, start_hosted_again)
    started = time.monotonic()
    restart.start()
    blob = world.seal_with_cli(SECRET, world.upstream_url, endpoints=[hosted])
    restart.join()
    assert blob.startswith("seal1.acme.")
    assert time.monotonic() - started > RESTART_SECS, "sealed by the restarted replica"

    # Telemetry of both hosted boots is complete: each idle exit sends its last batch.
    assert world.procs["hosted-2"].wait(timeout=RESTARTED_IDLE_SECS + 30) == 0
    world.stop_replica(1)
    certificates = str(world.path("control/tenants/acme/service-key-certificates.json"))
    out = world.admin("telemetry", "--certificates", certificates)
    streams = {line.split()[1].split("#")[0] for line in out.splitlines() if len(line.split()) > 1}
    assert len(streams) == 3, f"the tenant's replica and two hosted boots:\n{out}"
    assert "FOUND" not in out, out
