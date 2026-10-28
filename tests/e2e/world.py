"""The test world: Seal's own binaries running on localhost, one fresh system per test.

`World.boot()` writes a simulator environment (`seal-sim setup --fast-reload`) and starts:

    log        seal-tlog-dev   the dev transparency log, holding the dev release
    guardian   seal-guardian   holds the root; behind `proxy`, an untrusted TLS proxy
    control    seal-control    the untrusted control plane
    upstream   seal-sim        an HTTPS API that records what it receives and echoes it
    replica-1  seal-enclave    the tenant's first enclave replica, on 127.0.0.1

and creates tenant `acme` with the `seal` CLI, as an admin would, signing with an admin key file
(`seal key create`, then `seal dev init`, the development registrar's way): app `checkout`
(with an app key), a producer, the replica's enclave identity and the `sim` platform. Tests
then add whatever they need: more replicas, Postgres, admin changes.

Every process logs to `<work>/logs/<name>.log`; a failing test prints their tails.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import shutil
import signal
import socket
import ssl
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import seal

TENANT = "acme"
APP = "checkout"
SECRET = "sk-live-e2e-" + os.urandom(6).hex()
PG_PASSWORD = "Seal-E2E-pg-" + os.urandom(4).hex()
REDIS_PASSWORD = "Seal-E2E-redis-" + os.urandom(4).hex()


class World:
    def __init__(self, bins: Path, work: Path) -> None:
        self.bins = bins
        self.work = work
        self.dir = work / "env"  # what `seal-sim setup` writes
        self.procs: Dict[str, subprocess.Popen] = {}
        self.containers: List[Tuple[str, str]] = []  # (runtime, id)
        self.replicas: List[int] = []  # n of each running replica-n
        self.pin = ""  # SEAL_TENANT: acme@<root id>
        self.conf: dict = {}
        (work / "logs").mkdir(parents=True)

    # ---- starting the system -------------------------------------------------------------

    @classmethod
    def boot(cls, bins: Path, work: Path, *, release_stale_in: Optional[int] = None) -> "World":
        w = cls(bins, work)
        try:
            w._boot(release_stale_in)
        except BaseException:
            w.shutdown(failed=True)
            raise
        return w

    def _boot(self, release_stale_in: Optional[int]) -> None:
        w, bins = self, self.bins
        setup = ["setup", "--dir", str(w.dir), "--enclave-bin", str(bins / "seal-enclave"),
                 "--port-base", str(free_port_base()), "--fast-reload"]
        if release_stale_in is not None:
            setup += ["--release-stale-in", str(release_stale_in)]
        w.run("seal-sim", *setup)
        w.conf = json.loads((w.dir / "sim.json").read_text())

        w.start("log", "seal-tlog-dev", "--dir", str(w.dir / "log"),
                "--listen", f"127.0.0.1:{w.port('log')}", "--seed", w.conf["log_seed"])
        w.start("guardian", "seal-guardian", env={"SEAL_SIM": "1", "SEAL_GUARDIAN_CONFIG": str(w.dir / "guardian.json")})
        w.start("proxy", "seal-sim", "proxy", "--dir", str(w.dir))
        w.start_control()
        w.start("upstream", "seal-sim", "upstream", "--dir", str(w.dir), "--record", str(w.dir / "upstream.jsonl"))
        for name in ("log", "guardian", "guardian_tls", "upstream"):
            wait_for_port(w.port(name))
        w.run("seal-sim", "publish-release", "--dir", str(w.dir))

        w.admin("key", "create", "--out", str(w.admin_key))
        init = w.admin("dev", "init", "--tenant", TENANT, "--key-file", str(w.admin_key),
                       "--registrar-key", str(w.dir / "registrar.key"), "--yes")
        w.pin = next(line.split("=", 1)[1] for line in init.splitlines() if line.startswith("SEAL_TENANT="))
        w.admin("grant", "app", APP, "key", "--generate", "--out", str(w.dir / "checkout.key"), "--yes")
        w.admin("grant", "producer", "key", "--public", w.conf["producer_public_key"], "--yes")
        w.admin("grant", "enclave", "sim", json.dumps(w.conf["deployment"]), "--yes")
        w.admin("settings", "platforms", "add", "sim", "--yes")

        w.start_replica(1)
        assert "keys released purpose=service" in w.log("guardian")

    def start_control(self) -> None:
        """The control plane keeps its state in files, so a restart picks up where it was."""
        self.start("control", "seal-control", "--config", str(self.dir / "control.json"))
        wait_for_port(self.port("control"))

    def start_replica(self, n: int) -> None:
        """Replica n listens on 127.0.0.n. Replicas share keys and ports; only addresses differ."""
        config = self.replica_config(f"replica-{n}", ip=f"127.0.0.{n}")
        self.start(f"replica-{n}", "seal-enclave", env=self.replica_env(config, self.conf["deployment"]))
        self.wait_for_log(f"replica-{n}", "serving the API")
        self.replicas.append(n)

    def replica_config(self, name: str, ip: str, **settings: object) -> Path:
        """The first replica's `enclave.json`, listening on `ip`, with `settings` added."""
        text = (self.dir / "enclave.json").read_text().replace('"127.0.0.1:', f'"{ip}:')
        config = {**json.loads(text), **settings}
        path = self.dir / f"{name}.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def replica_env(self, config: Path, deployment: object) -> Dict[str, str]:
        return {"SEAL_SIM": "1", "SEAL_TENANT": self.pin, "SEAL_ENCLAVE_CONFIG": str(config),
                "SEAL_SIM_DEPLOYMENT": json.dumps(deployment)}

    def stop_replica(self, n: int) -> None:
        self.stop(f"replica-{n}")
        self.replicas.remove(n)

    def start_postgres(self) -> str:
        """A Postgres upstream in Docker or Podman, with `PG_PASSWORD`; returns what to seal to."""
        return self.start_container("postgres", PG_PASSWORD)

    def start_redis(self) -> str:
        """A Redis upstream (TLS) in Docker or Podman, with `REDIS_PASSWORD`; returns what to seal to."""
        return self.start_container("redis", REDIS_PASSWORD)

    def start_container(self, kind: str, password: str) -> str:
        out = self.run("seal-sim", kind, "--dir", str(self.dir), stdin=password)
        fields = dict(line.split(" ", 1) for line in out.splitlines() if " " in line)
        self.containers.append((fields["runtime"], fields["container"]))
        return fields["destination"]

    # ---- processes -----------------------------------------------------------------------

    def start(self, name: str, binary: str, *args: str, env: Optional[Dict[str, str]] = None) -> None:
        log = open(self.work / "logs" / f"{name}.log", "w")
        self.procs[name] = subprocess.Popen([str(self.bins / binary), *args], stdout=log, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, env=clean_env(env))

    def stop(self, name: str) -> None:
        """Stops `name` gracefully (SIGTERM) and checks it logged no error."""
        proc = self.procs.pop(name)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
        assert "ERROR" not in self.log(name), self.log(name)

    def run(self, binary: str, *args: str, stdin: Optional[str] = None,
            env: Optional[Dict[str, str]] = None, check: bool = True) -> str:
        out = subprocess.run([str(self.bins / binary), *args], input=stdin, capture_output=True, text=True,
                             env=clean_env(env), timeout=180)
        print(f"$ {binary} {' '.join(args)}\n{out.stdout}{out.stderr}")
        if check and out.returncode != 0:
            raise AssertionError(f"{binary} {' '.join(args)} failed ({out.returncode}):\n{out.stdout}{out.stderr}")
        return out.stdout

    def log(self, name: str) -> str:
        path = self.work / "logs" / f"{name}.log"
        return path.read_text() if path.exists() else ""

    def wait_for_log(self, name: str, needle: str, timeout: float = 30) -> None:
        eventually(f"{name} logs {needle!r}", lambda: needle in self.log(name), timeout)

    def shutdown(self, failed: bool) -> None:
        for name in reversed(list(self.procs)):  # newest first: replicas can still reach the control plane
            proc = self.procs.pop(name)
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
        for runtime, container in self.containers:
            subprocess.run([runtime, "rm", "-f", container], capture_output=True)
        if failed:
            for log in sorted((self.work / "logs").glob("*.log")):
                print(f"--- {log}\n" + "\n".join(log.read_text().splitlines()[-25:]))
        if os.environ.get("SEAL_SIM_KEEP"):
            print(f"kept {self.work}")
        else:
            shutil.rmtree(self.work, ignore_errors=True)

    # ---- acting as the admin, the producer and the app -----------------------------------

    @property
    def admin_key(self) -> Path:
        """The tenant's admin key file: the CLI signs with it (`--key-file`), keeps no key itself."""
        return self.dir / "admin.key"

    def admin_env(self) -> Dict[str, str]:
        """The admin's `seal` environment: its home, the sim trust and the dev write token."""
        return {"SEAL_HOME": str(self.dir / "admin"), "SEAL_TRUST": str(self.dir / "trust.json"),
                "SEAL_CONTROL_TOKEN": self.conf["write_token"], "SEAL_NO_BROWSER": "1"}

    def admin_args(self, args: Tuple[str, ...]) -> List[str]:
        """`args`, signed with the admin key when the command reads or changes the tenant."""
        signs = args and args[0] in ("grant", "revoke", "changes", "settings", "status", "telemetry", "release", "deploy")
        return [*args, "--key-file", str(self.admin_key)] if signs else list(args)

    def admin(self, *args: str, stdin: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> str:
        """The `seal` CLI as the tenant's admin; fails the test if it fails."""
        return self.run("seal", *self.admin_args(args), stdin=stdin, env={**self.admin_env(), **(env or {})})

    def admin_status(self, *args: str) -> Tuple[int, str]:
        """The `seal` CLI as the admin; its exit code and output, whatever they are."""
        args = tuple(self.admin_args(args))
        out = subprocess.run([str(self.bins / "seal"), *args], capture_output=True, text=True, timeout=60,
                             env=clean_env(self.admin_env()))
        print(f"$ seal {' '.join(args)}\n{out.stdout}{out.stderr}")
        return out.returncode, out.stdout

    def seal_with_cli(self, secret: str, to: str, *extra: str, endpoints: Optional[List[str]] = None,
                      wake_url: Optional[str] = None) -> str:
        """Seals `secret` for `checkout` with the CLI, as the producer; returns the blob."""
        env = {"SEAL_APP_KEY": self.producer_key, "SEAL_TENANT": self.pin,
               "SEAL_ENDPOINT": ",".join(endpoints or self.endpoints())}
        if wake_url:
            env["SEAL_WAKE_URL"] = wake_url
        return self.admin("secret", "--to", to, "--app", APP, *extra, stdin=secret, env=env).strip()

    def client(self, key: Optional[str] = None, endpoints: Optional[List[str]] = None) -> seal.Client:
        """An SDK client acting as `key` (default: the app's), for every running replica."""
        return seal.Client(endpoints=endpoints or self.endpoints(), tenant=self.pin,
                           identity=seal.AppKeyIdentity(key or self.app_key), trust=self.dir / "trust.json")

    def upstream_seen(self) -> List[dict]:
        """Every request the upstream received: method, path and the Authorization it got."""
        path = self.dir / "upstream.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    # ---- addresses and keys --------------------------------------------------------------

    def port(self, name: str) -> int:
        return self.conf["ports"][name]

    def endpoint(self, n: int = 1) -> str:
        """Replica n's API, what `SEAL_ENDPOINT` lists."""
        return f"https://localhost:{self.port('api')}" if n == 1 else f"https://127.0.0.{n}:{self.port('api')}"

    def endpoints(self) -> List[str]:
        return [self.endpoint(n) for n in self.replicas]

    @property
    def upstream_url(self) -> str:
        return f"https://localhost:{self.port('upstream')}/v1"

    @property
    def app_key(self) -> str:
        return (self.dir / "checkout.key").read_text().strip()

    @property
    def producer_key(self) -> str:
        return (self.dir / "producer.key").read_text().strip()

    def path(self, name: str) -> Path:
        return self.dir / name


# ---- helpers --------------------------------------------------------------------------------


def get(url: str, key: str, *, context: Optional[ssl.SSLContext] = None, at: Optional[str] = None,
        conn: Optional[http.client.HTTPConnection] = None) -> Tuple[int, str]:
    """`GET <url>/models` with `Authorization: Bearer <key>`: the status and body, or (0, error)
    when the connection fails. `at` connects to that address instead of the URL's host (still
    checking the certificate for the URL's host): how a test reaches replica 2's data plane,
    whose URLs name localhost. `conn` reuses a kept-alive connection."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/") + "/models"
    if conn is None:
        conn = connect(url, context=context, at=at)
    try:
        conn.request("GET", path, headers={"Authorization": f"Bearer {key}"})
        response = conn.getresponse()
        return response.status, response.read().decode(errors="replace")
    except (OSError, http.client.HTTPException) as e:
        conn.close()
        return 0, repr(e)


def connect(url: str, *, context: Optional[ssl.SSLContext] = None, at: Optional[str] = None) -> http.client.HTTPConnection:
    """A kept-alive HTTP(S) connection to `url`'s host (or to `at`, see `get`)."""
    parts = urlsplit(url)
    if parts.scheme == "http":
        conn: http.client.HTTPConnection = http.client.HTTPConnection(at or parts.hostname, parts.port, timeout=10)
    else:
        context = context or ssl.create_default_context()
        conn = http.client.HTTPSConnection(parts.hostname, parts.port, context=context, timeout=10)
        if at:
            raw = socket.create_connection((at, parts.port), timeout=10)
            conn.sock = context.wrap_socket(raw, server_hostname=parts.hostname)
    return conn


def eventually(what: str, check: Callable[[], bool], timeout: float = 15) -> None:
    """Polls `check` until it holds; fails with `what` after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, f"not within {timeout}s: {what}"
        time.sleep(0.25)


def wait_for_port(port: int, timeout: float = 30) -> None:
    def listening() -> bool:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            return False

    eventually(f"something listens on port {port}", listening, timeout)


def free_port_base() -> int:
    """The first of six consecutive free ports (`seal-sim setup --port-base`)."""
    for _ in range(200):
        base = random.randrange(20000, 32000)  # below the usual ephemeral range (32768+), so outgoing connections cannot take them
        socks = []
        try:
            for port in range(base, base + 6):
                s = socket.socket()
                s.bind(("127.0.0.1", port))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no nine consecutive free ports")


def clean_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """This process's environment without `SEAL_*` variables, plus `extra`."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SEAL_") or k == "SEAL_CONTAINER_RUNTIME"}
    env.update(extra or {})
    return env
