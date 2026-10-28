"""The native module (pyo3 over the Rust SDK). Apps use `seal`, not this module."""

import asyncio
import os
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

SIM: bool

class IdentityProvider:
    """A workload identity a client proves itself with."""

    @property
    def kind(self) -> str: ...

class AppKeyIdentity(IdentityProvider):
    """An app key, `sealak_…` (what `SEAL_APP_KEY` holds)."""

    def __init__(self, key: str) -> None: ...

class AzureManagedIdentity(IdentityProvider):
    """An Azure managed identity's token for `audience`, the Entra app ID URI the tenant
    registered; `client_id` picks a user-assigned identity."""

    def __init__(self, audience: str, *, client_id: Optional[str] = None) -> None: ...

class KubernetesIdentity(IdentityProvider):
    """A projected service account token (audience `seal:<tenant>`, `expirationSeconds: 600`)."""

    def __init__(self, path: Union[str, os.PathLike[str]] = "/var/run/secrets/seal.zone/token") -> None: ...

class GcpIdentity(IdentityProvider):
    """A GCP service account's identity token from the metadata server."""

    def __init__(self, tenant: str) -> None: ...

class GitHubActionsIdentity(IdentityProvider):
    """GitHub Actions OIDC (`permissions: id-token: write`)."""

    def __init__(self, tenant: str) -> None: ...

class AwsIdentity(IdentityProvider):
    """An IAM role from the default AWS credential chain. Only in wheels built with `aws`."""

    def __init__(self) -> None: ...

class SessionInfo:
    """Session id (base64url), tiers, tenant, app, blob id, expiry (Unix seconds)."""

    @property
    def session_id(self) -> str: ...
    @property
    def platform(self) -> str: ...
    @property
    def tier(self) -> str: ...
    @property
    def tenant(self) -> str: ...
    @property
    def app(self) -> str: ...
    @property
    def blob_id(self) -> str: ...
    @property
    def expires_at(self) -> int: ...

class TelemetryReceipt:
    """Where telemetry recorded a seal or a session start."""

    @property
    def stream(self) -> bytes: ...
    @property
    def entry(self) -> int: ...
    def to_json(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class HostAgentReporter:
    """The seal host agent (App Integrity add-on) as an `endpoint_reporter`: from the
    environment (`SEAL_AGENT_SOCKET`, `SEAL_APP_KEY`), or with both `socket` and `app_key`."""

    def __init__(self, *, socket: Optional[str] = None, app_key: Optional[str] = None) -> None: ...

class EndpointReport:
    """What an `endpoint_reporter` returns: `artifact=(name, sha256)` and opaque
    `evidence=[(provider, bytes), ...]`."""

    def __init__(
        self,
        *,
        artifact: Optional[Tuple[str, bytes]] = None,
        evidence: Sequence[Tuple[str, bytes]] = (),
    ) -> None: ...

class Session:
    @property
    def kind(self) -> str: ...
    @property
    def url(self) -> Optional[str]: ...
    @property
    def key(self) -> Optional[str]: ...
    @property
    def dsn(self) -> Optional[str]: ...
    @property
    def protocol(self) -> Optional[str]: ...
    @property
    def info(self) -> SessionInfo: ...
    def receipts(self) -> List[TelemetryReceipt]: ...
    def extend(self) -> None: ...
    def extend_async(self) -> asyncio.Future[None]: ...
    def close(self) -> None: ...
    def close_async(self) -> asyncio.Future[None]: ...

class Client:
    @staticmethod
    def connect(
        *,
        endpoints: Optional[List[str]] = None,
        tenant: Optional[str] = None,
        root_id: Optional[str] = None,
        identity: Optional[IdentityProvider] = None,
        trust: Optional[bytes] = None,
    ) -> Client: ...
    @staticmethod
    def connect_async(
        *,
        endpoints: Optional[List[str]] = None,
        tenant: Optional[str] = None,
        root_id: Optional[str] = None,
        identity: Optional[IdentityProvider] = None,
        trust: Optional[bytes] = None,
    ) -> asyncio.Future[Client]: ...
    @property
    def tenant(self) -> str: ...
    def seal(
        self,
        secret: bytes,
        to: str,
        apps: List[str],
        *,
        header: Optional[str] = None,
        format: Optional[str] = None,
        pins: List[str] = ...,
        expires: Optional[int] = None,
        methods: List[str] = ...,
        deny: List[str] = ...,
        sealed_only: bool = False,
        hardened_only: bool = False,
        with_receipt: bool = False,
    ) -> Any: ...
    def seal_async(
        self,
        secret: bytes,
        to: str,
        apps: List[str],
        *,
        header: Optional[str] = None,
        format: Optional[str] = None,
        pins: List[str] = ...,
        expires: Optional[int] = None,
        methods: List[str] = ...,
        deny: List[str] = ...,
        sealed_only: bool = False,
        hardened_only: bool = False,
        with_receipt: bool = False,
    ) -> asyncio.Future[Any]: ...
    def session(
        self,
        blob: str,
        *,
        kind: Optional[str] = None,
        min_tier: Optional[str] = None,
        reload_with: Optional[Callable[[], str]] = None,
        on_reseal: Optional[Callable[[str], Any]] = None,
        endpoint_reporter: Optional[Union[Callable[[bytes], EndpointReport], HostAgentReporter]] = None,
    ) -> Session: ...
    def session_async(
        self,
        blob: str,
        *,
        kind: Optional[str] = None,
        min_tier: Optional[str] = None,
        reload_with: Optional[Callable[[], str]] = None,
        on_reseal: Optional[Callable[[str], Any]] = None,
        endpoint_reporter: Optional[Union[Callable[[bytes], EndpointReport], HostAgentReporter]] = None,
    ) -> asyncio.Future[Session]: ...
    def signal(self, code: str, severity: str) -> None: ...
    def signal_async(self, code: str, severity: str) -> asyncio.Future[None]: ...

def append_receipts(path: Union[str, os.PathLike[str]], receipts: List[TelemetryReceipt]) -> None: ...
