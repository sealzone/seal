"""Seal: use secrets without holding them.

    import seal

    blob = seal.seal(secret, to="https://api.openai.com/v1", apps=["checkout"], header="x-api-key")

    with seal.session(blob) as s:      # leaving the block ends the session everywhere
        client = OpenAI(base_url=s.url, api_key=s.key)

    with seal.session(db_blob) as db:
        conn = psycopg.connect(db.dsn)

    seal.signal("edr-alert", severity="high")

The module-level `seal`, `session` and `signal` use a default `Client` built from the
environment on first use (`SEAL_ENDPOINT`, `SEAL_TENANT`, the detected workload identity);
`seal.Client(endpoints=[...], tenant="acme", identity=...)` configures one explicitly, and
`seal.AsyncClient` is the asyncio form. `session` returns an `HttpSession` (`url`, `key`) or a
`DatabaseSession` (`dsn`, `protocol`), whichever the blob is; both have `info`, `receipts()`,
`extend()` and `close()`.

Whether this workload may seal or start sessions is decided by the enclave from the tenant's
grants, never by the SDK. Errors are `SealError`s named after their `ErrorCode`: `Expired`,
`NotAllowed`, `TierTooLow`, `IntegrityFailed`, `SessionEnded`, `Unavailable`,
`VerificationFailed`, `BadRequest`, `ResealRequired`, ...
"""

from __future__ import annotations

import os
import threading
from typing import Any, Awaitable, Callable, Literal, Optional, Tuple, Union, overload

from . import receipts
from ._client import (
    AsyncClient,
    Client,
    DatabaseSession,
    Expiry,
    HttpSession,
    Reporter,
    Secret,
    Session,
    Severity,
    Strings,
    Tier,
)
from ._errors import (
    BadRequest,
    BudgetExceeded,
    ErrorCode,
    Expired,
    IntegrityFailed,
    Internal,
    NotAllowed,
    PolicyDenied,
    ResealRequired,
    SealError,
    SessionEnded,
    SessionExpired,
    TierTooLow,
    Unavailable,
    VerificationFailed,
)
from ._seal import (
    AppKeyIdentity,
    AzureManagedIdentity,
    EndpointReport,
    HostAgentReporter,
    GcpIdentity,
    GitHubActionsIdentity,
    IdentityProvider,
    KubernetesIdentity,
    SessionInfo,
    TelemetryReceipt,
)

try:
    from ._seal import AwsIdentity  # noqa: F401  (wheels built with the `aws` feature)
except ImportError:
    pass

_default: Optional[Client] = None
_default_lock = threading.Lock()


def _forget_default() -> None:
    """In a forked child: the parent's default client is refused there (its connections and
    locks were copied mid-flight), and so may be the lock guarding it. Start over."""
    global _default, _default_lock
    _default = None
    _default_lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_forget_default)


def default_client() -> Client:
    """The client the module-level functions use, built from the environment on first use in
    each process."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Client()
        return _default


@overload
def seal(
    secret: Secret,
    *,
    to: str,
    apps: Strings,
    header: Optional[str] = ...,
    format: Optional[str] = ...,
    pin: Optional[Strings] = ...,
    expires: Optional[Expiry] = ...,
    methods: Optional[Strings] = ...,
    deny: Optional[Strings] = ...,
    sealed_only: bool = ...,
    hardened_only: bool = ...,
    with_receipt: Literal[False] = ...,
) -> str: ...
@overload
def seal(
    secret: Secret,
    *,
    to: str,
    apps: Strings,
    header: Optional[str] = ...,
    format: Optional[str] = ...,
    pin: Optional[Strings] = ...,
    expires: Optional[Expiry] = ...,
    methods: Optional[Strings] = ...,
    deny: Optional[Strings] = ...,
    sealed_only: bool = ...,
    hardened_only: bool = ...,
    with_receipt: Literal[True],
) -> Tuple[str, TelemetryReceipt]: ...
def seal(secret: Secret, **kwargs: Any) -> Union[str, Tuple[str, TelemetryReceipt]]:
    """`Client.seal` on the default client."""
    return default_client().seal(secret, **kwargs)  # type: ignore[no-any-return]


@overload
def session(
    blob: str,
    *,
    kind: Literal["http"],
    min_tier: Optional[Tier] = ...,
    reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
    on_reseal: Optional[Callable[[str], Any]] = ...,
    endpoint_reporter: Optional[Reporter] = ...,
) -> HttpSession: ...
@overload
def session(
    blob: str,
    *,
    kind: Literal["database"],
    min_tier: Optional[Tier] = ...,
    reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
    on_reseal: Optional[Callable[[str], Any]] = ...,
    endpoint_reporter: Optional[Reporter] = ...,
) -> DatabaseSession: ...
@overload
def session(
    blob: str,
    *,
    kind: None = ...,
    min_tier: Optional[Tier] = ...,
    reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
    on_reseal: Optional[Callable[[str], Any]] = ...,
    endpoint_reporter: Optional[Reporter] = ...,
) -> Session: ...
def session(blob: str, **kwargs: Any) -> Session:
    """`Client.session` on the default client; use it as a context manager."""
    return default_client().session(blob, **kwargs)  # type: ignore[no-any-return]


def signal(code: str, *, severity: Severity) -> None:
    """`Client.signal` on the default client."""
    default_client().signal(code, severity=severity)


__all__ = [
    "AppKeyIdentity",
    "AsyncClient",
    "AzureManagedIdentity",
    "BadRequest",
    "BudgetExceeded",
    "Client",
    "DatabaseSession",
    "EndpointReport",
    "HostAgentReporter",
    "ErrorCode",
    "Expired",
    "GcpIdentity",
    "GitHubActionsIdentity",
    "HttpSession",
    "IdentityProvider",
    "IntegrityFailed",
    "Internal",
    "KubernetesIdentity",
    "NotAllowed",
    "PolicyDenied",
    "ResealRequired",
    "SealError",
    "Session",
    "SessionEnded",
    "SessionExpired",
    "SessionInfo",
    "TelemetryReceipt",
    "TierTooLow",
    "Unavailable",
    "VerificationFailed",
    "default_client",
    "receipts",
    "seal",
    "session",
    "signal",
]
