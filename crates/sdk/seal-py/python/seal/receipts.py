"""Telemetry receipts kept by clients, in the file format `seal telemetry --receipts` reads.

`Client.seal(..., with_receipt=True)` and `session.receipts()` hand them out; a client that
keeps them can prove the control plane withheld their entries, even a whole stream.
"""

from __future__ import annotations

import os
from typing import Iterable, Union

from ._seal import TelemetryReceipt, append_receipts


def append(path: Union[str, "os.PathLike[str]"], receipts: Iterable[TelemetryReceipt]) -> None:
    """Append `receipts` to `path` as JSON lines, creating the file when it is missing. One
    write per call, so processes appending to one file keep whole lines."""
    append_receipts(os.fspath(path), list(receipts))


__all__ = ["TelemetryReceipt", "append"]
