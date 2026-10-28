"""The Go SDK (`seal.zone/go`, a cgo binding over the Rust core through `seal-ffi`): a Go app
uses a sealed API key through a tunnel session without holding it, and seals one as anyone may.
The Go side is `crates/sdk/seal-go/examples/e2e`, run as the app or as a stranger."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator, Optional

import pytest

from world import APP, SECRET, World, clean_env

ROOT = Path(__file__).resolve().parents[2]
SEAL_GO = ROOT / "crates" / "sdk" / "seal-go"


@pytest.fixture(scope="module")
def go_e2e() -> Iterator[Path]:
    """The Go program, linked against a `sim` build of `seal-ffi` (`build.sh --sim --debug`)."""
    if not shutil.which("go"):
        pytest.skip("Go is not installed")
    out = Path(tempfile.mkdtemp(prefix="seal-e2e-go."))
    env = clean_env()
    subprocess.run([str(SEAL_GO / "build.sh"), "--sim", "--debug"], check=True, env=env, timeout=900)
    subprocess.run(["go", "build", "-o", str(out / "e2e"), "./examples/e2e"], cwd=SEAL_GO, check=True, env=env,
                   timeout=600)
    yield out / "e2e"
    shutil.rmtree(out, ignore_errors=True)


def run_go(world: World, program: Path, *args: str, key: str, stdin: Optional[str] = None) -> dict:
    """The program acting as `key`, configured by the environment as an app would be."""
    env = clean_env({"SEAL_ENDPOINT": ",".join(world.endpoints()), "SEAL_TENANT": world.pin,
                     "SEAL_TRUST": str(world.path("trust.json")), "SEAL_APP_KEY": key})
    out = subprocess.run([str(program), *args], input=stdin or "", capture_output=True, text=True, env=env,
                         timeout=180)
    print(f"$ e2e {args[0]}\n{out.stdout}{out.stderr}")
    assert SECRET not in out.stdout + out.stderr, "the Go program never sees the secret"
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def check_sessions(out: dict) -> None:
    """What `e2e app` saw: the session worked, extended and closed, holding only stand-ins."""
    assert out["tenant"] == "acme"
    assert out["wrong_kind"] == "bad_request", "an HTTP blob asked for as a database fails before sending"
    for name in ("tunnel",):
        s = out[name]
        assert s["kind"] == "http" and s["app"] == APP and s["tier"] == "base", s
        assert all(c["status"] == 200 for c in s["calls"]), s["calls"]
        assert all('"authorization":"*' in c["body"] for c in s["calls"]), "the upstream's echo is scrubbed"
        assert s["receipts"] >= 1 and s["expires_in"] > 0, s
        assert s["extend_after"] == "session_ended", "a closed session cannot be extended"
    tunnel = out["tunnel"]
    assert tunnel["url"].startswith("http://127.0.0.1:")
    assert tunnel["keys"][0] == tunnel["keys"][1], "the tunnel's local key survives an extend"
    assert tunnel["after_close"]["status"] != 200, "closing ends the tunnel"
    canceled = out["canceled"]
    assert canceled["deadline_exceeded"] and canceled["ms"] < 3000, f"a cancelled call returns at once: {canceled}"


def test_the_go_sdk_uses_a_sealed_key_and_seals_one(world: World, go_e2e: Path) -> None:
    # A Go app uses a blob the CLI sealed: a tunnel session, called, extended, closed.
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    check_sessions(run_go(world, go_e2e, "app", blob, key=world.app_key))

    # A stranger seals the same key from Go, keeps the receipt, and may not use the blob itself.
    receipts = world.path("go-receipts.jsonl")
    sealed = run_go(world, go_e2e, "seal", world.upstream_url, str(receipts), key=world.stranger_key, stdin=SECRET)
    assert sealed["blob"].startswith("seal1.acme.") and sealed["tenant"] == "acme"
    assert sealed["stranger_session"] == "not_allowed" and sealed["is_not_allowed"], sealed
    assert sealed["bad_seal"] == "bad_request" and sealed["bad_signal_code"] == "bad_request", sealed
    assert sealed["bad_signal_level"] == "bad_request" and sealed["trust_file_missing"], sealed
    lines = [json.loads(line) for line in receipts.read_text().splitlines()]
    assert lines == [sealed["receipt"]] and len(lines[0]["stream"]) == 22, lines

    # The app uses the Go-sealed blob the same way.
    check_sessions(run_go(world, go_e2e, "app", sealed["blob"], key=world.app_key))

    # The upstream got the real key every time: two calls per session, one session per blob.
    seen = world.upstream_seen()
    assert len(seen) == 4, seen
    assert all(r["authorization"] == f"Bearer {SECRET}" and r["path"] == "/v1/models" for r in seen), seen
