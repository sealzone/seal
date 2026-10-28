"""The wheel's `seal` command: the CLI compiled into the native module, installed as a script."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def seal(*args: str, home: Path) -> subprocess.CompletedProcess[str]:
    script = Path(sys.executable).parent / "seal"
    env = {**os.environ, "SEAL_HOME": str(home)}
    return subprocess.run([str(script), *args], capture_output=True, text=True, env=env, timeout=60)


def test_the_wheel_carries_the_seal_command(tmp_path: Path) -> None:
    out = seal("--version", home=tmp_path / "home")
    assert out.returncode == 0 and out.stdout.startswith("seal "), out
    key = tmp_path / "admin.key"
    out = seal("key", "create", "--out", str(key), home=tmp_path / "home")
    assert out.returncode == 0, out.stderr
    assert key.exists() and "public key" in out.stdout + out.stderr
    # A usage error exits 2, as the binary does.
    assert seal("no-such-command", home=tmp_path / "home").returncode == 2
