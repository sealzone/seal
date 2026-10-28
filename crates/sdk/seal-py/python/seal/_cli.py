"""The `seal` command, as `pip install sealzone` installs it: the same CLI as the `seal` binary,
compiled into this package's native module.
"""

from __future__ import annotations

import signal
import sys

from ._seal import cli


def main() -> None:
    # Ctrl-C stops the command at once, as it does the binary: Python's handler would only
    # raise once the native call returned.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sys.exit(cli(sys.argv))
