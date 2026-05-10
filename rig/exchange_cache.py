"""In-process TTL cache for RFC 8693 exchanged tokens.

A single facility IdP request typically costs 50–500 ms; reusing the resulting
downstream access token across the (sub, facility, requested_scope) tuple for the
remainder of its natural lifetime saves both latency and IdP load. Each rig
worker keeps its own cache; rig has no shared in-memory state by design.

Cache key: ``(sub, facility, requested_scope or "")``
Cache value: ``"Bearer <access_token>"`` plus the absolute expiry monotonic
            timestamp at which the entry must be evicted.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import NamedTuple

from .logging import get_logger

logger = get_logger(__name__)


class _Entry(NamedTuple):
    authorization: str
    expires_at: float  # monotonic time


class ExchangeCache:
    """Bounded LRU TTL cache for exchanged downstream access tokens."""

    def __init__(self, max_entries: int = 4096):
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str, str], _Entry] = OrderedDict()
        self._lock = asyncio.Lock()

    def _key(self, sub: str | None, facility: str, requested_scope: str | None) -> tuple[str, str, str]:
        return (sub or "", facility, requested_scope or "")

    async def get(self, sub: str | None, facility: str, requested_scope: str | None) -> str | None:
        """Return the cached authorization, or None on miss / expiry."""
        key = self._key(sub, facility, requested_scope)
        now = time.monotonic()
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return entry.authorization

    async def set(
        self,
        sub: str | None,
        facility: str,
        requested_scope: str | None,
        authorization: str,
        ttl_seconds: float,
    ) -> None:
        """Insert / replace an entry with the given TTL (must be positive)."""
        if ttl_seconds <= 0:
            return
        key = self._key(sub, facility, requested_scope)
        expires_at = time.monotonic() + ttl_seconds
        async with self._lock:
            self._entries[key] = _Entry(authorization=authorization, expires_at=expires_at)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    async def invalidate(self, sub: str | None, facility: str, requested_scope: str | None) -> None:
        """Drop a single entry."""
        key = self._key(sub, facility, requested_scope)
        async with self._lock:
            self._entries.pop(key, None)

    async def clear(self) -> None:
        async with self._lock:
            self._entries.clear()

    async def size(self) -> int:
        async with self._lock:
            return len(self._entries)


# Module-level singleton — instantiated once per worker process and reused across
# all requests. Wired into the FastAPI app via ``app.state.exchange_cache`` at
# startup; tests can swap this out via monkeypatch.
default_cache = ExchangeCache()
