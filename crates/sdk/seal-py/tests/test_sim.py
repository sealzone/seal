"""The Python SDK against the simulator: seal, sessions through the local tunnel used by the
standard library's HTTP clients, extend, close, receipts, callbacks, errors, asyncio."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import http.client
import json
import os
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import warnings
from typing import Optional, Tuple

import pytest

import seal
from conftest import SECRET, Sim

pytestmark = pytest.mark.skipif(not seal._seal.SIM, reason="the native module was built without the `sim` feature")


def get(url: str, key: str) -> Tuple[int, dict]:
    """`GET <url>/models` with `Authorization: Bearer <key>`; the upstream echoes what it got."""
    request = urllib.request.Request(url.rstrip("/") + "/models", headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode(errors="replace")}


def assert_upstream_got_the_secret(sim: Sim, body: dict) -> None:
    """The upstream logged the real key; its echo of it reached the app redacted."""
    assert f"with Authorization: Bearer {SECRET}" in sim.log("upstream")
    assert body["path"] == "/v1/models"
    assert SECRET not in json.dumps(body)


def conn_get(conn: http.client.HTTPConnection, path: str, key: str) -> Tuple[int, bytes]:
    conn.request("GET", path, headers={"Authorization": f"Bearer {key}"})
    response = conn.getresponse()
    return response.status, response.read()


def test_tunnel_session_through_the_local_proxy(app_env: Sim, blob: str) -> None:
    with seal.session(blob) as s:
        assert isinstance(s, seal.HttpSession)
        assert s.url.startswith("http://127.0.0.1:") and urllib.parse.urlsplit(s.url).path == "/v1"
        assert s.key.startswith("seallk_") and SECRET not in s.key
        assert s.info.tenant == "acme" and s.info.app == "checkout" and s.info.platform == "sim"
        assert s.info.expires_at > time.time()

        # urllib: the upstream got the real key, the app only ever held the stand-in.
        status, body = get(s.url, s.key)
        assert status == 200, body
        assert_upstream_got_the_secret(app_env, body)

        # http.client on one kept-alive connection, across an extend.
        parsed = urllib.parse.urlsplit(s.url)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
        assert conn_get(conn, parsed.path + "/models", s.key)[0] == 200
        url, key, expires = s.url, s.key, s.info.expires_at
        s.extend()
        # The local URL and key never change; the expiry moves.
        assert (s.url, s.key) == (url, key) and s.info.expires_at >= expires
        status, body = conn_get(conn, parsed.path + "/models", s.key)
        assert status == 200
        assert_upstream_got_the_secret(app_env, json.loads(body))

    # Leaving the block closed the session and its tunnel; closing again does nothing.
    s.close()
    with pytest.raises((OSError, http.client.HTTPException)):
        conn_get(conn, parsed.path + "/models", key)
    with pytest.raises(OSError):
        get(url, key)


def test_dropping_a_session_ends_it(app_env: Sim, blob: str) -> None:
    s = seal.session(blob, kind="http")
    url, key = s.url, s.key
    assert get(url, key)[0] == 200
    del s
    gc.collect()
    # The tunnel stops at once; the end is sent in the background.
    deadline = time.monotonic() + 15
    while True:
        try:
            get(url, key)
        except OSError:
            break
        assert time.monotonic() < deadline, "the dropped session's tunnel still answers"
        time.sleep(0.2)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork")
def test_forked_children(app_env: Sim, blob: str) -> None:
    """Prefork servers' workers: each builds its own default client and session; what it
    inherited from the parent is refused, and dropping it leaves the parent's session alone.
    Several forks while the parent's runtime is busy, since a fork copies whatever its threads
    were doing at that instant."""
    parent_client = seal.default_client()
    s = seal.session(blob, kind="http")

    def child() -> int:
        with seal.session(blob, kind="http") as mine:
            if get(mine.url, mine.key)[0] != 200:
                return 2
        if seal.default_client() is parent_client:
            return 3
        for inherited in (lambda: parent_client.tenant, lambda: s.url, s.close):
            try:
                inherited()
                return 4
            except RuntimeError as e:
                if "before a fork" not in str(e):
                    return 5
        return 0

    for _ in range(5):
        busy = [seal.session(blob, kind="http") for _ in range(2)]  # runtime threads at work
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads running
            pid = os.fork()
        if pid == 0:
            status = 1
            try:
                status = child()
                del s, busy
                gc.collect()
            except BaseException:
                traceback.print_exc()
            finally:
                os._exit(status)
        for b in busy:
            b.close()
        deadline = time.monotonic() + 60
        while True:
            done, code = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            if time.monotonic() > deadline:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                pytest.fail("a forked child hung")
            time.sleep(0.05)
        assert os.waitstatus_to_exitcode(code) == 0
    assert get(s.url, s.key)[0] == 200
    s.close()


def test_receipts(app_env: Sim, tmp_path) -> None:
    producer = seal.Client(identity=seal.AppKeyIdentity(app_env.producer_key))
    blob, receipt = producer.seal(
        b"sk-receipts-0123456789", to=app_env.upstream, apps="checkout", with_receipt=True
    )
    assert blob.startswith("seal1.")
    assert isinstance(receipt, seal.TelemetryReceipt)
    assert len(receipt.stream) == 16 and receipt.entry >= 0

    with seal.session(blob) as s:
        starts = s.receipts()
    assert len(starts) == 1 and starts[0].stream == receipt.stream and starts[0] != receipt

    path = tmp_path / "receipts.jsonl"
    seal.receipts.append(path, [receipt])
    seal.receipts.append(path, starts)
    lines = path.read_text().splitlines()
    assert lines == [receipt.to_json(), starts[0].to_json()]
    assert json.loads(lines[1])["entry"] == starts[0].entry


def test_endpoint_reporter_runs_at_start_and_extend(app_env: Sim, blob: str) -> None:
    challenges = []

    def report(challenge: bytes) -> seal.EndpointReport:
        challenges.append(challenge)
        return seal.EndpointReport(artifact=("app", hashlib.sha256(b"my app").digest()))

    with seal.session(blob, endpoint_reporter=report) as s:
        assert len(challenges) == 1
        s.extend()
        assert len(challenges) == 2
    assert all(isinstance(c, bytes) and len(c) == 32 for c in challenges)
    assert challenges[0] != challenges[1], "each request has its own challenge"


def test_the_host_agent_reporter_falls_back_without_an_agent(app_env: Sim, blob: str) -> None:
    reporter = seal.HostAgentReporter(socket="/nonexistent/agent.sock", app_key=app_env.app_key)
    with seal.session(blob, endpoint_reporter=reporter) as s:
        s.extend()


def test_callback_errors_keep_their_code(app_env: Sim, blob: str) -> None:
    def broken(challenge: bytes) -> seal.EndpointReport:
        raise seal.Unavailable("the host agent is down")

    with pytest.raises(seal.Unavailable) as raised:
        seal.session(blob, endpoint_reporter=broken)
    assert raised.value.code is seal.ErrorCode.Unavailable and raised.value.retryable

    with pytest.raises(seal.BadRequest):
        seal.session(blob, endpoint_reporter=lambda challenge: "not a report")


def test_errors(app_env: Sim, blob: str) -> None:
    client = seal.default_client()
    with pytest.raises(seal.BadRequest) as raised:
        client.seal("x", to="http://plaintext.example.com", apps=["checkout"])
    assert isinstance(raised.value, ValueError) and raised.value.code is seal.ErrorCode.BadRequest

    with pytest.raises(seal.BadRequest, match="not a database"):
        client.session(blob, kind="database")
    with pytest.raises(seal.BadRequest):
        client.session("seal1.garbage")

    # The producer holds no app grant: the enclave refuses, with the protocol's code.
    producer = seal.Client(identity=seal.AppKeyIdentity(app_env.producer_key))
    with pytest.raises(seal.NotAllowed) as raised:
        producer.session(blob)
    assert raised.value.code is seal.ErrorCode.NotAllowed and not raised.value.retryable

    # The app holds no producer grant.
    with pytest.raises(seal.NotAllowed):
        client.seal(SECRET, to=app_env.upstream, apps=["checkout"])

    with pytest.raises(seal.TierTooLow):
        client.session(blob, min_tier="hardened")


def test_trust_from_a_file_or_bytes(app_env: Sim, monkeypatch) -> None:
    """Without `SEAL_TRUST` (sim only) a client takes the release trust it is given: a path or
    the JSON itself; this test build ships none."""
    monkeypatch.delenv("SEAL_TRUST")
    with pytest.raises(seal.VerificationFailed, match="ships no release trust"):
        seal.Client()
    assert seal.Client(trust=app_env.trust).tenant == "acme"
    assert seal.Client(trust=str(app_env.trust)).tenant == "acme"
    client = seal.Client(trust=app_env.trust.read_bytes())
    client.signal("py-test-trust", severity="low")

    with pytest.raises(seal.BadRequest, match="trust"):
        seal.Client(trust=b'{"releases": {}}')
    trust = json.loads(app_env.trust.read_text())
    trust["releases"]["release_threshold"] = 0
    with pytest.raises(ValueError, match="release_threshold is 0"):
        seal.Client(trust=json.dumps(trust).encode())
    with pytest.raises(FileNotFoundError):
        seal.Client(trust=app_env.work / "missing.json")
    # A trust naming another guardian key accepts no enclave.
    trust = json.loads(app_env.trust.read_text())
    trust["guardians"]["sim"] = trust["releases"]["release_keys"][0]
    with pytest.raises(seal.VerificationFailed):
        seal.Client(trust=json.dumps(trust).encode())

    async def main() -> str:
        client = await seal.AsyncClient.connect(trust=app_env.trust)
        return client.tenant

    assert asyncio.run(main()) == "acme"


def test_asyncio(app_env: Sim, blob: str) -> None:
    async def main() -> Optional[str]:
        client = await seal.AsyncClient.connect()
        producer = await seal.AsyncClient.connect(identity=seal.AppKeyIdentity(app_env.producer_key))
        sealed = await producer.seal(SECRET, to=app_env.upstream, apps=["checkout"])

        async with client.session(sealed, kind="http") as s:
            status, body = await asyncio.get_running_loop().run_in_executor(None, get, s.url, s.key)
            assert status == 200
            assert_upstream_got_the_secret(app_env, body)
            await s.aextend()

        d = await client.session(sealed)
        assert isinstance(d, seal.HttpSession) and d.url.startswith("http://127.0.0.1:")
        await d.aclose()

        # Async callbacks run on the client's loop.
        async def report(challenge: bytes) -> seal.EndpointReport:
            await asyncio.sleep(0)
            return seal.EndpointReport()

        async with client.session(sealed, endpoint_reporter=report) as s:
            assert isinstance(s, seal.HttpSession)

        with pytest.raises(seal.BadRequest):
            await client.session(sealed, kind="database")

        await client.signal("py-test-async", severity="low")
        return client.tenant

    assert asyncio.run(main()) == "acme"


def test_cancelling_an_awaitable(app_env: Sim, blob: str) -> None:
    async def main() -> None:
        client = await seal.AsyncClient.connect()
        task = asyncio.ensure_future(client.session(blob))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())


def test_signal(app_env: Sim) -> None:
    seal.signal("py-test", severity="low")
    with pytest.raises(seal.BadRequest):
        seal.signal("Not A Code", severity="low")
    with pytest.raises(seal.BadRequest):
        seal.signal("py-test", severity="severe")  # type: ignore[arg-type]


def test_a_hardened_only_blob_refuses_a_base_session(app_env: Sim) -> None:
    producer = seal.Client(identity=seal.AppKeyIdentity(app_env.producer_key))
    blob = producer.seal(SECRET, to=app_env.upstream, apps=["checkout"], hardened_only=True)
    with pytest.raises(seal.SealError) as refused:
        seal.session(blob)
    assert refused.value.code is seal.ErrorCode.TierTooLow, refused.value
