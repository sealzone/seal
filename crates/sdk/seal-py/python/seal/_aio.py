"""Resolves the asyncio futures the native module hands out, on their loop's thread."""

from __future__ import annotations

import asyncio
from typing import Any, Optional


def resolve(future: asyncio.Future[Any], error: Optional[BaseException], value: Any) -> None:
    if future.cancelled():
        return
    if error is not None:
        future.set_exception(error)
    else:
        future.set_result(value)
