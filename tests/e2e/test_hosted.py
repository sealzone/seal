"""A Seal-hosted replica for the tenant: it seals and serves sessions, exits when idle, and is
woken by the SDK through the wake URL."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, List

from world import SECRET, World, get

IDLE_SECS = 5  # how long the hosted replica stays up idle (`HOSTED_IDLE_SECS` in a release)
HOSTED = {"kind": "confidential_space", "project_number": 2, "service_account": "t-acme@hosted.sim.seal.zone"}


class WakeStandIn:
    """Stands in for the console's wake URL: on the first POST, records the body and starts the
    hosted replica; answers 202 every time."""

    def __init__(self, start_replica: Callable[[], None]) -> None:
        self.bodies: List[str] = []
        started = threading.Lock()
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                stand_in.bodies.append(self.rfile.read(int(self.headers["content-length"])).decode())
                if started.acquire(blocking=False):
                    start_replica()
                self.send_response(202)
                self.send_header("content-length", "0")
                self.end_headers()

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/v1/wake"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def test_a_hosted_replica_serves_idles_out_and_wakes(world: World) -> None:
    # The tenant's signed consent to a Seal-hosted replica.
    world.admin("grant", "enclave", "sim", json.dumps(HOSTED), "--hosted", "--yes")
    config = world.replica_config("hosted", ip="127.0.0.3", hosted_idle_secs=IDLE_SECS)
    hosted = f"https://127.0.0.3:{world.port('api')}"
    world.start("hosted", "seal-enclave", env=world.replica_env(config, HOSTED))
    world.wait_for_log("hosted", "serving the API")

    # Producers outside the tenant's network seal there, and apps use it beside the tenant's own
    # replicas: the blob opens on either.
    blob = world.seal_with_cli(SECRET, world.upstream_url, endpoints=[hosted])
    with world.client(endpoints=[hosted]).session(blob, kind="http") as s:
        assert get(s.url, s.key)[0] == 200, "a session on the hosted replica"
    with world.client(endpoints=[world.endpoint(1)]).session(blob, kind="http") as s:
        assert get(s.url, s.key)[0] == 200, "the same blob on the tenant's own replica"

    # Idle: it drains and exits cleanly, so its VM would stop.
    assert world.procs["hosted"].wait(timeout=IDLE_SECS + 30) == 0
    assert "hosted replica idle" in world.log("hosted") and "ERROR" not in world.log("hosted")

    # The SDK finds nothing listening, asks the wake URL once, and seals once it is back.
    def start_hosted_again() -> None:
        world.start("hosted-2", "seal-enclave", env=world.replica_env(config, HOSTED))

    wake = WakeStandIn(start_hosted_again)
    blob = world.seal_with_cli(SECRET, world.upstream_url, endpoints=[hosted], wake_url=wake.url)
    assert blob.startswith("seal1.acme.")
    assert wake.bodies == ['{"tenant":"acme"}']

    # Telemetry of both hosted boots is complete: each idle exit sends its last batch.
    assert world.procs["hosted-2"].wait(timeout=IDLE_SECS + 30) == 0
    world.stop_replica(1)
    certificates = str(world.path("control/tenants/acme/service-key-certificates.json"))
    out = world.admin("telemetry", "--certificates", certificates)
    streams = {line.split()[1].split("#")[0] for line in out.splitlines() if len(line.split()) > 1}
    assert len(streams) == 3, f"the tenant's replica and two hosted boots:\n{out}"
    assert "FOUND" not in out, out
