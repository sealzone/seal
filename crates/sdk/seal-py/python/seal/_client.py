"""The client and its sessions, over the native module `seal._seal`."""

from __future__ import annotations

import asyncio
import datetime
import inspect
import os
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
    overload,
)

from . import _seal
from ._errors import SealError
from ._seal import EndpointReport, HostAgentReporter, IdentityProvider, SessionInfo, TelemetryReceipt

Secret = Union[bytes, bytearray, memoryview, str]
Strings = Union[str, Sequence[str]]
Severity = Literal["low", "medium", "high", "critical"]
Tier = Literal["base", "hardened"]
# An `endpoint_reporter`: called with the request's 32-byte challenge, or the host agent's.
Reporter = Union[Callable[[bytes], Union[EndpointReport, Awaitable[EndpointReport]]], HostAgentReporter]
Expiry = Union[int, datetime.datetime]
Trust = Union[str, "os.PathLike[str]", bytes, bytearray]


def _strings(value: Optional[Strings]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _trust(trust: Optional[Trust]) -> Optional[bytes]:
    """A release trust's JSON: bytes as given, a path's contents."""
    if trust is None or isinstance(trust, (bytes, bytearray)):
        return None if trust is None else bytes(trust)
    with open(os.fspath(trust), "rb") as f:
        return f.read()


def _secret(secret: Secret) -> bytes:
    if isinstance(secret, str):
        return secret.encode()
    return bytes(secret)


def _expires(expires: Optional[Expiry]) -> Optional[int]:
    if isinstance(expires, datetime.datetime):
        return int(expires.timestamp())
    return expires


def _seal_args(
    secret: Secret,
    to: str,
    apps: Strings,
    header: Optional[str],
    format: Optional[str],
    pin: Optional[Strings],
    expires: Optional[Expiry],
    methods: Optional[Strings],
    deny: Optional[Strings],
    sealed_only: bool,
    hardened_only: bool,
    with_receipt: bool,
) -> Tuple[Tuple[Any, ...], Dict[str, Any]]:
    args = (_secret(secret), to, _strings(apps))
    kwargs = dict(
        header=header,
        format=format,
        pins=_strings(pin),
        expires=_expires(expires),
        methods=_strings(methods),
        deny=_strings(deny),
        sealed_only=sealed_only,
        hardened_only=hardened_only,
        with_receipt=with_receipt,
    )
    return args, kwargs


def _callback(fn: Optional[Callable[..., Any]], loop: Optional[asyncio.AbstractEventLoop]) -> Optional[Callable[..., Any]]:
    """`fn` as the native module calls it, on a worker thread: a coroutine it returns runs on
    `loop` (the async client's) or, without one, on a loop of its own."""
    if fn is None:
        return None

    def call(*args: Any) -> Any:
        result = fn(*args)
        if not inspect.isawaitable(result):
            return result
        if loop is not None and loop.is_running():
            return asyncio.run_coroutine_threadsafe(_await(result), loop).result()
        return asyncio.run(_await(result))

    return call


async def _await(awaitable: Awaitable[Any]) -> Any:
    return await awaitable


def _session_kwargs(
    kind: Optional[str],
    min_tier: Optional[Tier],
    reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]],
    on_reseal: Optional[Callable[[str], Any]],
    endpoint_reporter: Optional[Reporter],
    loop: Optional[asyncio.AbstractEventLoop],
) -> Dict[str, Any]:
    return dict(
        kind=kind,
        min_tier=min_tier,
        reload_with=_callback(reload_with, loop),
        on_reseal=_callback(on_reseal, loop),
        endpoint_reporter=(
            endpoint_reporter if isinstance(endpoint_reporter, HostAgentReporter) else _callback(endpoint_reporter, loop)
        ),
    )


def _wrap(native: _seal.Session) -> Union[HttpSession, DatabaseSession]:
    if native.kind == "http":
        return HttpSession(native)
    return DatabaseSession(native)


class _Session:
    """What every session has: `info`, `receipts()`, `extend`, `close`, and use
    as a context manager (sync or async) that closes it on exit."""

    __slots__ = ("_native",)

    def __init__(self, native: _seal.Session) -> None:
        self._native = native

    @property
    def info(self) -> SessionInfo:
        """Session id, tiers, tenant, app, blob id, expiry."""
        return self._native.info

    def receipts(self) -> List[TelemetryReceipt]:
        """Where telemetry recorded the start and every restart, oldest first."""
        return self._native.receipts()

    def extend(self) -> None:
        """Extend now with a fresh identity proof and move `info.expires_at`. The tunnel
        extends the session by itself before every expiry; `url`, `key` and `dsn` never change."""
        self._native.extend()

    async def aextend(self) -> None:
        await self._native.extend_async()

    def close(self) -> None:
        """End the session on the server (every replica refuses its tokens from then on) and
        close the tunnel. On an error the end may not have reached every replica: call it
        again to resend it. Once it succeeds, further calls do nothing."""
        self._native.close()

    async def aclose(self) -> None:
        await self._native.close_async()

    def __enter__(self) -> Any:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        try:
            self.close()
        except SealError:
            # The end may have reached only one replica: resend it once.
            try:
                self.close()
            except SealError:
                if exc_type is None:
                    raise

    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        try:
            await self.aclose()
        except SealError:
            try:
                await self.aclose()
            except SealError:
                if exc_type is None:
                    raise


class HttpSession(_Session):
    """A session on an HTTP blob: point the app's client at `url` with `key` where the real
    key would go."""

    __slots__ = ()

    @property
    def url(self) -> str:
        """The local tunnel (`http://127.0.0.1:…`). The path continues the sealed destination's."""
        url = self._native.url
        assert url is not None
        return url

    @property
    def key(self) -> str:
        """A stand-in key worthless outside this tunnel."""
        key = self._native.key
        assert key is not None
        return key

    def __enter__(self) -> HttpSession:
        return self

    async def __aenter__(self) -> HttpSession:
        return self

    def __repr__(self) -> str:
        return f"HttpSession(url={self.url!r}, info={self.info!r})"


class DatabaseSession(_Session):
    """A session on a Postgres, Redis or ClickHouse blob: connect with `dsn`."""

    __slots__ = ()

    @property
    def dsn(self) -> str:
        """A complete connection string for the app's driver, through the local tunnel."""
        dsn = self._native.dsn
        assert dsn is not None
        return dsn

    @property
    def protocol(self) -> Literal["postgres", "redis", "click_house"]:
        return self._native.protocol  # type: ignore[return-value]

    def __enter__(self) -> DatabaseSession:
        return self

    async def __aenter__(self) -> DatabaseSession:
        return self

    def __repr__(self) -> str:
        return f"DatabaseSession(protocol={self.protocol!r}, info={self.info!r})"


Session = Union[HttpSession, DatabaseSession]


class Client:
    """A verified connection to the tenant's enclaves, acting as one workload identity.

    Arguments not given come from the environment: `SEAL_ENDPOINT` (the enclave replicas,
    comma-separated), `SEAL_TENANT` (`<tenant>` or `<tenant>@<root id>`) and the first workload
    identity found (`SEAL_APP_KEY`, Azure, Kubernetes, GCP, GitHub Actions). `trust` is the
    release trust (`trust.json`): a path, or its JSON as bytes; by default the one this build
    ships. Verifies the enclave before returning. Safe to share between threads.
    """

    __slots__ = ("_native",)

    def __init__(
        self,
        *,
        endpoints: Optional[Strings] = None,
        tenant: Optional[str] = None,
        root_id: Optional[str] = None,
        identity: Optional[IdentityProvider] = None,
        trust: Optional[Trust] = None,
    ) -> None:
        self._native = _seal.Client.connect(
            endpoints=_strings(endpoints) or None,
            tenant=tenant,
            root_id=root_id,
            identity=identity,
            trust=_trust(trust),
        )

    @property
    def tenant(self) -> str:
        return self._native.tenant

    @overload
    def seal(
        self,
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
        self,
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
    def seal(
        self,
        secret: Secret,
        *,
        to: str,
        apps: Strings,
        header: Optional[str] = None,
        format: Optional[str] = None,
        pin: Optional[Strings] = None,
        expires: Optional[Expiry] = None,
        methods: Optional[Strings] = None,
        deny: Optional[Strings] = None,
        sealed_only: bool = False,
        hardened_only: bool = False,
        with_receipt: bool = False,
    ) -> Union[str, Tuple[str, TelemetryReceipt]]:
        """Seal `secret` so only the named `apps` can use it, and only with `to`. Returns the
        portable blob text (`seal1.…`), safe to store anywhere; with `with_receipt=True`,
        `(blob, receipt)`. Needs a producer grant.

        `to` is the destination URL (`https://`, `postgres://`, `clickhouse://`, `rediss://`).
        HTTP options: `header` (default `authorization`), `format` (`{key}` where the secret
        goes; default `Bearer {key}` for `authorization`), `methods`, `deny` (path prefixes).
        `pin`: upstream keys (`sha256/<base64>`, up to 4) required in its certificate chain.
        `expires`: when every copy stops working. `sealed_only`: only sealed-tier enclaves. `hardened_only`: only hardened-tier sessions.
        """
        args, kwargs = _seal_args(
            secret, to, apps, header, format, pin, expires, methods, deny, sealed_only, hardened_only, with_receipt
        )
        return self._native.seal(*args, **kwargs)  # type: ignore[no-any-return]

    @overload
    def session(
        self,
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
        self,
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
        self,
        blob: str,
        *,
        kind: None = ...,
        min_tier: Optional[Tier] = ...,
        reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
        on_reseal: Optional[Callable[[str], Any]] = ...,
        endpoint_reporter: Optional[Reporter] = ...,
    ) -> Session: ...
    def session(
        self,
        blob: str,
        *,
        kind: Optional[Literal["http", "database"]] = None,
        min_tier: Optional[Tier] = None,
        reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = None,
        on_reseal: Optional[Callable[[str], Any]] = None,
        endpoint_reporter: Optional[Reporter] = None,
    ) -> Session:
        """Start a session on `blob`: the enclave opens it and the app gets a stand-in. Needs
        an app grant listed in the blob's policy. Returns an `HttpSession` or a
        `DatabaseSession`, whichever the blob is; `kind="http"` or `"database"` asks for one
        and fails with `BadRequest` before anything is sent if the blob is the other kind.

        The SDK runs a local tunnel to the enclave and extends the session before every
        expiry. `min_tier`: refuse a weaker session. `reload_with()`: returns the blob again when it
        comes back `Expired` (e.g. after a rotation). `on_reseal(blob)`: receives the secret
        resealed under the tenant's current key version. `endpoint_reporter(challenge)`:
        returns the `EndpointReport` sent at start and every extend, with any signed evidence
        covering the 32-byte `challenge` (default: the running executable's hash); or
        `HostAgentReporter()` for the seal host agent. Callbacks run on a worker thread; they
        may be coroutine functions.
        """
        native = self._native.session(
            blob,
            **_session_kwargs(kind, min_tier, reload_with, on_reseal, endpoint_reporter, None),
        )
        return _wrap(native)

    def signal(self, code: str, *, severity: Severity) -> None:
        """Signal that this workload's own endpoint may be compromised. Names only this
        identity; under the tenant's integrity policy it may suspend the identity at once.
        `code` is opaque to Seal (`[a-z0-9-.]`, 1 to 64 characters)."""
        self._native.signal(code, severity)


class _SessionStart:
    """`AsyncClient.session(...)`: await it for the session, or use it in `async with`."""

    __slots__ = ("_start", "_session")

    def __init__(self, start: Awaitable[_seal.Session]) -> None:
        self._start = start
        self._session: Optional[Session] = None

    def __await__(self) -> Generator[Any, None, Any]:
        return self._open().__await__()

    async def _open(self) -> Any:
        return _wrap(await self._start)

    async def __aenter__(self) -> Any:
        self._session = await self._open()
        return self._session

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        if self._session is not None:
            await self._session.__aexit__(exc_type, exc, tb)


class _HttpSessionStart(_SessionStart):
    __slots__ = ()

    def __await__(self) -> Generator[Any, None, HttpSession]:
        return self._open().__await__()

    async def __aenter__(self) -> HttpSession:
        return await super().__aenter__()  # type: ignore[no-any-return]


class _DatabaseSessionStart(_SessionStart):
    __slots__ = ()

    def __await__(self) -> Generator[Any, None, DatabaseSession]:
        return self._open().__await__()

    async def __aenter__(self) -> DatabaseSession:
        return await super().__aenter__()  # type: ignore[no-any-return]


class AsyncClient:
    """`Client` for asyncio: `client = await AsyncClient.connect(...)`, then the same
    operations as coroutines. Sessions are the same objects (`async with`, `aclose()`,
    `aextend()`)."""

    __slots__ = ("_native",)

    def __init__(self, native: _seal.Client) -> None:
        self._native = native

    @classmethod
    async def connect(
        cls,
        *,
        endpoints: Optional[Strings] = None,
        tenant: Optional[str] = None,
        root_id: Optional[str] = None,
        identity: Optional[IdentityProvider] = None,
        trust: Optional[Trust] = None,
    ) -> AsyncClient:
        """As `Client(...)`: unset arguments come from the environment."""
        native = await _seal.Client.connect_async(
            endpoints=_strings(endpoints) or None,
            tenant=tenant,
            root_id=root_id,
            identity=identity,
            trust=_trust(trust),
        )
        return cls(native)

    @property
    def tenant(self) -> str:
        return self._native.tenant

    @overload
    async def seal(
        self,
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
    async def seal(
        self,
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
    async def seal(
        self,
        secret: Secret,
        *,
        to: str,
        apps: Strings,
        header: Optional[str] = None,
        format: Optional[str] = None,
        pin: Optional[Strings] = None,
        expires: Optional[Expiry] = None,
        methods: Optional[Strings] = None,
        deny: Optional[Strings] = None,
        sealed_only: bool = False,
        hardened_only: bool = False,
        with_receipt: bool = False,
    ) -> Union[str, Tuple[str, TelemetryReceipt]]:
        """`Client.seal`."""
        args, kwargs = _seal_args(
            secret, to, apps, header, format, pin, expires, methods, deny, sealed_only, hardened_only, with_receipt
        )
        return await self._native.seal_async(*args, **kwargs)  # type: ignore[no-any-return]

    @overload
    def session(
        self,
        blob: str,
        *,
        kind: Literal["http"],
        min_tier: Optional[Tier] = ...,
        reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
        on_reseal: Optional[Callable[[str], Any]] = ...,
        endpoint_reporter: Optional[Reporter] = ...,
    ) -> _HttpSessionStart: ...
    @overload
    def session(
        self,
        blob: str,
        *,
        kind: Literal["database"],
        min_tier: Optional[Tier] = ...,
        reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
        on_reseal: Optional[Callable[[str], Any]] = ...,
        endpoint_reporter: Optional[Reporter] = ...,
    ) -> _DatabaseSessionStart: ...
    @overload
    def session(
        self,
        blob: str,
        *,
        kind: None = ...,
        min_tier: Optional[Tier] = ...,
        reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = ...,
        on_reseal: Optional[Callable[[str], Any]] = ...,
        endpoint_reporter: Optional[Reporter] = ...,
    ) -> _SessionStart: ...
    def session(
        self,
        blob: str,
        *,
        kind: Optional[Literal["http", "database"]] = None,
        min_tier: Optional[Tier] = None,
        reload_with: Optional[Callable[[], Union[str, Awaitable[str]]]] = None,
        on_reseal: Optional[Callable[[str], Any]] = None,
        endpoint_reporter: Optional[Reporter] = None,
    ) -> _SessionStart:
        """`Client.session`: `s = await client.session(blob)`, or
        `async with client.session(blob) as s:`, which closes it on exit."""
        loop = asyncio.get_running_loop()
        start = self._native.session_async(
            blob,
            **_session_kwargs(kind, min_tier, reload_with, on_reseal, endpoint_reporter, loop),
        )
        if kind == "http":
            return _HttpSessionStart(start)
        if kind == "database":
            return _DatabaseSessionStart(start)
        return _SessionStart(start)

    async def signal(self, code: str, *, severity: Severity) -> None:
        """`Client.signal`."""
        await self._native.signal_async(code, severity)
