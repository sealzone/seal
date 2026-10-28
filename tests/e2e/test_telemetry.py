"""Telemetry: every seal, session start, extend, request, end and refusal is recorded in batches
the replica signs, and `seal telemetry` checks them against the receipts clients kept."""

from __future__ import annotations

import json

import pytest

import seal
import seal.receipts
from world import SECRET, World, get


def test_telemetry_is_complete_and_matches_kept_receipts(world: World) -> None:
    receipts = world.path("receipts.jsonl")
    certificates = str(world.path("control/tenants/acme/service-key-certificates.json"))

    # Things worth recording, each with a receipt where the SDK or the CLI hands one out.
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--receipt-file", str(receipts))
    stranger = world.client(world.stranger_key)
    _, receipt = stranger.seal(SECRET, to=world.upstream_url, apps=["checkout"], with_receipt=True)
    seal.receipts.append(receipts, [receipt])
    s = world.client().session(blob, kind="http")
    seal.receipts.append(receipts, s.receipts())
    assert get(s.url, s.key)[0] == 200  # a request
    s.extend()
    key = s.key
    s.close()  # an end
    with pytest.raises(seal.NotAllowed):
        stranger.session(blob, kind="http")  # a refusal: anyone may seal, only the app may use it

    # Telemetry is complete once the replica stops gracefully and sends its last batch.
    world.stop_replica(1)
    out = world.admin("telemetry", "--certificates", certificates, "--receipts", str(receipts))
    for kind in ("seal", "session", "extend", "request", "end", "refused"):
        assert f'{{"kind":"{kind}"' in out, f"no {kind} entry:\n{out}"
    assert "FOUND" not in out, f"every kept receipt is in a verified batch:\n{out}"
    assert SECRET not in out and key not in out

    # A receipt for an entry no batch holds is reported.
    withheld = json.loads(receipt.to_json())
    withheld["entry"] = 1_000_000
    with receipts.open("a") as f:
        f.write(json.dumps(withheld) + "\n")
    out = world.admin("telemetry", "--certificates", certificates, "--receipts", str(receipts))
    found = [line for line in out.splitlines() if line.startswith("FOUND")]
    assert len(found) == 1 and "entry 1000000: no verified batch holds it" in found[0], out
