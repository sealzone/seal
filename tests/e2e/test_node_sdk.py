"""The Node SDK (`@sealzone/sdk`, crates/sdk/seal-node) against the same world: an app uses a
sealed key through a tunnel session, and anyone seals from Node."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict

import pytest

from world import APP, SECRET, World, clean_env, get

PACKAGE = Path(__file__).resolve().parents[2] / "crates" / "sdk" / "seal-node"


@pytest.fixture(scope="module")
def node_sdk() -> Path:
    """The addon, built for the simulator (`build.sh --sim`); the package directory."""
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")
    subprocess.run([str(PACKAGE / "build.sh"), "--sim"], check=True, timeout=900)
    return PACKAGE


def run_node(world: World, package: Path, *args: str, env: Dict[str, str] | None = None) -> dict:
    """`examples/e2e.mjs` with the app's environment; its JSON output. Fails the test if the
    output (or anything it logged) holds the secret."""
    app_env = {"SEAL_ENDPOINT": ",".join(world.endpoints()), "SEAL_TENANT": world.pin,
               "SEAL_TRUST": str(world.path("trust.json")), "SEAL_APP_KEY": world.app_key, **(env or {})}
    out = subprocess.run(["node", str(package / "examples" / "e2e.mjs"), *args], capture_output=True, text=True,
                         env=clean_env(app_env), timeout=120)
    print(f"$ node e2e.mjs {args[0]}\n{out.stdout}{out.stderr}")
    assert out.returncode == 0, out.stderr
    assert SECRET not in out.stdout + out.stderr, "the Node program never sees or prints the secret"
    return json.loads(out.stdout)


def test_an_api_key_is_used_from_node_without_holding_it(world: World, node_sdk: Path) -> None:
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    out = run_node(world, node_sdk, "sessions", blob)
    assert out["tenant"] == "acme"

    # Tunnel: two calls with an extend between, through a callback reporter; closing ends it.
    tunnel = out["tunnel"]
    assert tunnel["isHttp"] and tunnel["loopback"] and tunnel["unchanged"], tunnel
    assert tunnel["info"]["app"] == APP and tunnel["info"]["tenant"] == "acme", tunnel
    assert tunnel["receipts"] >= 1 and tunnel["reports"] >= 2, tunnel
    assert tunnel["challenges"] == tunnel["reports"], "each report gets its own 32-byte challenge"
    assert tunnel["afterClose"] != 200, "a closed tunnel refuses"

    assert out["statuses"] == [200, 200], out["bodies"]
    assert out["wrongKind"] == "BadRequest:bad_request", out

    # The upstream got the real key every time; Node only ever had stand-ins.
    seen = world.upstream_seen()
    assert len(seen) == 2, seen
    assert all(r["authorization"] == f"Bearer {SECRET}" and r["path"] == "/v1/models" for r in seen), seen


def test_anyone_seals_from_node(world: World, node_sdk: Path) -> None:
    receipts = world.path("node-receipts.jsonl")
    out = run_node(world, node_sdk, "seal", world.upstream_url, str(receipts),
                   env={"SEAL_E2E_SECRET": SECRET, "SEAL_E2E_STRANGER_KEY": world.stranger_key})
    blob = out["blob"]
    assert blob.startswith("seal1.acme.") and SECRET not in blob
    assert out["notAllowed"] == "NotAllowed:not_allowed", "a stranger is not one of the blob's apps"
    assert out["badPin"] == "BadRequest:bad_request", out
    assert out["status"] == 200, "the Node app used the Node-sealed blob"

    # The receipt went to the file in the CLI's format.
    lines = [json.loads(line) for line in receipts.read_text().splitlines()]
    assert lines == [{"stream": lines[0]["stream"], "entry": out["entry"]}], lines

    # The Python SDK uses the same blob: the formats are one.
    s = world.client().session(blob, kind="http")
    assert get(s.url, s.key)[0] == 200
    s.close()
    seen = world.upstream_seen()
    assert len(seen) == 2 and all(r["authorization"] == f"Bearer {SECRET}" for r in seen), seen
