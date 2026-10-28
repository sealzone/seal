# End-to-end tests

The whole system on one machine: Seal's own binaries (log, guardian, control plane, enclave
replicas, the `seal` CLI) run as local processes on the simulator, and the tests drive them the
way people do, through the Python SDK and the CLI.

```sh
scripts/e2e.sh                  # build everything, run every test (about two minutes)
scripts/e2e.sh -k failover      # one test, or any pytest arguments
SEAL_SIM_KEEP=1 scripts/e2e.sh  # keep each test's configs and logs
```

Needs Rust, Python 3.9+, and Docker or Podman (`SEAL_CONTAINER_RUNTIME=podman` to choose). The
Node and Go SDK tests also need Node.js and Go, and are skipped without them.

## How a test reads

Each test gets its own fresh system, `world`, already booted: tenant `acme` with app
`checkout`, one producer, one enclave replica, and an HTTPS upstream that records what it
receives. The test adds what it needs and checks what happens.

```python
def test_clients_and_live_tunnels_fail_over(world: World) -> None:
    world.start_replica(2)
    blob = world.seal_with_cli(SECRET, world.upstream_url)
    live = world.client().session(blob, kind="http")

    world.stop_replica(1)
    assert get(live.url, live.key)[0] == 200, "the live tunnel fails over to replica 2"
```

`world.py` is the whole harness. What a test can do:

| Call | What it does |
| --- | --- |
| `world.admin("revoke", "app", "checkout", "--yes")` | the `seal` CLI as the tenant's admin, signing with its admin key file |
| `world.seal_with_cli(secret, to)` | seal with the CLI as the producer; returns the blob |
| `world.client(key=None)` | an SDK client acting as the app (or as `key`) |
| `world.start_replica(n)` / `stop_replica(n)` | replica n on 127.0.0.n |
| `world.stop("control")` / `start_control()` | take the control plane down and back |
| `world.start_postgres()` / `start_redis()` | a Postgres or Redis upstream in a container; returns what to seal to |
| `world.upstream_seen()` | every request the HTTPS upstream received |
| `world.log("replica-1")` | a process's log |
| `get(url, key, context=, at=)` | one request through a session: `(status, body)` |
| `eventually("what", check)` | wait until `check()` holds |
| `make_world(release_stale_in=10)` | a world with options, instead of `world` |

Replicas reload tenant state every second here (`STATE_RELOAD_SECS`, 30 s, in a release), so
admin changes show up within a second or two.

## The tests

| File | Test | What it shows |
| --- | --- | --- |
| `test_sessions.py` | `test_an_api_key_is_used_without_the_app_holding_it` | an HTTP session through the tunnel: the upstream gets the real key, the app only a stand-in; extend, close |
| | `test_a_database_password_is_used_through_the_tunnel` | Postgres through the tunnel, with a real Postgres driver |
| | `test_a_redis_password_is_used_through_the_tunnel` | Redis (TLS) through the tunnel with redis-py; a command outside the sealed database is refused |
| `test_replicas.py` | `test_replicas_share_keys_and_tokens` | both replicas hold the same certified keys; one replica's token works on the other |
| | `test_a_close_while_the_control_plane_is_down_is_retried` | an unpublished end, retried once the control plane is back |
| | `test_clients_and_live_tunnels_fail_over` | a replica goes away; clients and live tunnels move to the next |
| `test_admin.py` | `test_a_tenant_key_bump_reaches_running_replicas` | new blobs use the new tenant key; old ones keep working |
| | `test_the_pending_window_delays_widening_changes` | widening changes wait for the window; a superseded one never applies |
| | `test_removing_the_app_ends_its_sessions` | removing a grant ends live sessions |
| `test_telemetry.py` | `test_telemetry_is_complete_and_matches_kept_receipts` | every event is in signed telemetry; a withheld entry is reported |
| `test_hosted.py` | `test_a_hosted_replica_serves_idles_out_and_wakes` | Seal's hosted replica: seals and serves sessions, exits when idle, woken by the SDK |
| `test_release.py` | `test_a_replica_boots_after_the_uploaded_release_evidence_goes_stale` | replicas boot on stale release evidence via the log's latest checkpoint |
| `test_node_sdk.py` | `test_an_api_key_is_used_from_node_without_holding_it` | the Node SDK: a tunnel session, extend, close, typed errors |
| | `test_a_producer_seals_from_node` | sealing from Node with a receipt; the Python SDK uses that blob |
| `test_go_sdk.py` | `test_the_go_sdk_uses_a_sealed_key_and_seals_one` | the Go SDK: a tunnel session, sealing with a receipt, typed errors, context cancellation |

## Adding a test

Pick the file whose topic fits (or start a new `test_<topic>.py`), take `world`, and write
the scenario top to bottom with a short comment per step. Name the test after what it shows.
If it needs something `world.py` cannot do yet, add one small method there.

When a test fails, it prints the last lines of every process's log; `SEAL_SIM_KEEP=1` keeps
them all under `/tmp/seal-e2e-<test>.*/`.
