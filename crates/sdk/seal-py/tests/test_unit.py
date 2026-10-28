"""What the SDK checks before anything reaches the network, and the exception mapping."""

from __future__ import annotations

import pytest

import seal
from seal import _errors


def test_exceptions_carry_their_code() -> None:
    for code in seal.ErrorCode:
        error = _errors.from_code(code.value, "text")
        assert isinstance(error, seal.SealError)
        assert type(error).__name__ == code.name
        assert error.code is code and error.message == "text" and str(error) == "text"
    assert _errors.from_code("unavailable", "x").retryable
    assert not _errors.from_code("not_allowed", "x").retryable
    assert isinstance(_errors.from_code("bad_request", "x"), ValueError)
    assert type(_errors.from_code("from_the_future", "x")) is seal.SealError


def test_bad_configuration_fails_before_connecting() -> None:
    with pytest.raises(seal.BadRequest):
        seal.Client(endpoints=["https://localhost:1"], tenant="Not A Tenant")
    with pytest.raises(seal.BadRequest):
        seal.Client(endpoints=["https://localhost:1"], tenant="acme@12")
    with pytest.raises(seal.BadRequest):
        seal.Client(endpoints=["not a url"], tenant="acme")
    with pytest.raises(seal.BadRequest):
        seal.AppKeyIdentity("sealak_short")


def test_unreachable_enclave_is_unavailable() -> None:
    with pytest.raises((seal.Unavailable, seal.VerificationFailed)) as raised:
        seal.Client(
            endpoints=["https://127.0.0.1:1"],
            tenant="acme",
            identity=seal.AppKeyIdentity("sealak_" + "A" * 43),
        )
    assert raised.value.code in (seal.ErrorCode.Unavailable, seal.ErrorCode.VerificationFailed)


def test_endpoint_report() -> None:
    seal.EndpointReport(artifact=("app", bytes(32)), evidence=[("tpm", b"\x01")])
    with pytest.raises(ValueError):
        seal.EndpointReport(artifact=("app", b"short"))


def test_identity_kinds() -> None:
    assert seal.AppKeyIdentity("sealak_" + "A" * 43).kind == "app-key"
    assert isinstance(seal.KubernetesIdentity(), seal.IdentityProvider)
    assert isinstance(seal.AzureManagedIdentity("api://seal", client_id="c"), seal.IdentityProvider)


def test_the_host_agent_reporter_takes_both_settings_or_neither() -> None:
    seal.HostAgentReporter()
    with pytest.raises(seal.BadRequest):
        seal.HostAgentReporter(socket="/run/seal/agent.sock")
    with pytest.raises(seal.BadRequest):
        seal.HostAgentReporter(socket="/run/seal/agent.sock", app_key="not an app key")
