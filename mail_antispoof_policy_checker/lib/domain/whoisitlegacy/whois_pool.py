"""
WhoisPool — optional concurrency limiter for whoisitlegacy async queries.

Usage
-----
::

    import whoisitlegacy

    pool = whoisitlegacy.create_whois_pool(max_concurrent=20)

    results = await asyncio.gather(*[
        whoisitlegacy.domain_async(d, whois_pool=pool)
        for d in many_domains
    ])
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, TypeVar

T = TypeVar("T")


class WhoisPool:
    """
    Simple asyncio-semaphore-based concurrency limiter for whoisitlegacy queries.

    Parameters
    ----------
    max_concurrent:
        Maximum number of simultaneous WHOIS TCP/43 queries.
        ``None`` (default) means no limit.
    """

    def __init__(self, max_concurrent: int | None = None) -> None:
        self.max_concurrent = max_concurrent
        self._semaphore: asyncio.Semaphore | None = (
            asyncio.Semaphore(max_concurrent) if max_concurrent else None
        )

    async def execute(self, coro: Awaitable[T]) -> T:
        """Run *coro* under the semaphore (if a limit is configured)."""
        if self._semaphore is not None:
            async with self._semaphore:
                return await coro
        return await coro
