"""Token revocation checks: Redis-backed jti blocklist + DNSBL fallback.

RFC Section 2F describes a two-tier kill switch:

* The platform's own gateway consults a fast in-cluster Redis blocklist on every
  request (sub-millisecond latency once the connection is warm).
* Downstream / cross-facility callers consult a DNSBL — a DNSSEC-secured zone
  publishing hashed jti values. DNS lookups are highly cacheable and resolve
  even from network-isolated HPC compute nodes.

Both checks are independently togglable. When both are enabled, Redis is
checked first; on a miss, the DNSBL is queried. Either path returning "revoked"
causes the proxy to deny with 401 and emit a structured audit record.

The Redis check is **fail-open**: if Redis is unreachable or slow, the check
silently skips so revocation cannot become a single point of failure for the
entire proxy. Operators must monitor Redis health independently.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import OrderedDict

from .logging import get_logger

logger = get_logger(__name__)


def _hash_jti(jti: str) -> str:
    """Return the lowercase hex sha256 of a jti, used as the DNSBL leftmost label."""
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


class _DNSBLCache:
    """Bounded TTL cache for DNSBL answers."""

    def __init__(self, max_entries: int, ttl_seconds: int):
        self._max = max_entries
        self._ttl = ttl_seconds
        self._entries: OrderedDict[str, tuple[bool, float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> bool | None:
        now = time.monotonic()
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            revoked, expires_at = entry
            if expires_at <= now:
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return revoked

    async def set(self, key: str, revoked: bool) -> None:
        async with self._lock:
            self._entries[key] = (revoked, time.monotonic() + self._ttl)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)


class RevocationChecker:
    """Combined Redis + DNSBL revocation check.

    Either or both of the underlying checks can be disabled by passing falsy
    values for their respective configuration knobs. If both are disabled, the
    checker always returns ``(False, None)``.
    """

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        redis_key_prefix: str = "rig:blocklist:",
        redis_timeout_seconds: float = 0.5,
        dnsbl_zone: str = "",
        dnsbl_cache_max: int = 4096,
        dnsbl_ttl_seconds: int = 60,
    ):
        self._redis_url = redis_url
        self._redis_key_prefix = redis_key_prefix
        self._redis_timeout = redis_timeout_seconds
        self._dnsbl_zone = (dnsbl_zone or "").strip(".")
        self._redis_client = None  # populated lazily
        self._redis_lock = asyncio.Lock()
        self._dns_cache = _DNSBLCache(dnsbl_cache_max, dnsbl_ttl_seconds)

    # ------------------------------------------------------------------ Redis

    async def _get_redis(self):
        if not self._redis_url:
            return None
        if self._redis_client is not None:
            return self._redis_client
        async with self._redis_lock:
            if self._redis_client is not None:
                return self._redis_client
            try:
                import redis.asyncio as redis_async  # imported lazily so the dep
                # is only loaded when revocation is actually configured.

                self._redis_client = redis_async.from_url(
                    self._redis_url,
                    socket_timeout=self._redis_timeout,
                    socket_connect_timeout=self._redis_timeout,
                    decode_responses=False,
                )
            except Exception:
                logger.exception("revocation: failed to initialise Redis client; blocklist disabled")
                self._redis_url = None
        return self._redis_client

    async def _check_redis(self, jti: str) -> bool:
        client = await self._get_redis()
        if client is None:
            return False
        key = f"{self._redis_key_prefix}{jti}"
        try:
            result = await asyncio.wait_for(client.exists(key), timeout=self._redis_timeout)
            return bool(result)
        except Exception:
            logger.exception("revocation: Redis blocklist check failed; failing open")
            return False

    # ------------------------------------------------------------------ DNSBL

    async def _check_dnsbl(self, jti: str) -> bool:
        if not self._dnsbl_zone:
            return False
        name = f"{_hash_jti(jti)}.{self._dnsbl_zone}"
        cached = await self._dns_cache.get(name)
        if cached is not None:
            return cached
        revoked = False
        try:
            import dns.asyncresolver  # lazy import for optional dep
            import dns.exception
            import dns.resolver

            try:
                answer = await dns.asyncresolver.resolve(name, "TXT")
                revoked = len(answer) > 0
            except dns.resolver.NXDOMAIN:
                revoked = False
            except dns.resolver.NoAnswer:
                revoked = False
            except dns.exception.DNSException:
                logger.warning("revocation: DNSBL query for %s failed; failing open", name)
                revoked = False
        except Exception:
            logger.exception("revocation: DNSBL lookup raised; failing open")
            revoked = False
        await self._dns_cache.set(name, revoked)
        return revoked

    # ------------------------------------------------------------------ Public

    async def is_revoked(self, jti: str | None) -> tuple[bool, str | None]:
        """Return ``(revoked, source)``. Source is ``"redis"``, ``"dnsbl"``, or None."""
        if not jti:
            return False, None
        if await self._check_redis(jti):
            return True, "redis"
        if await self._check_dnsbl(jti):
            return True, "dnsbl"
        return False, None

    async def block(
        self,
        jti: str,
        *,
        ttl_seconds: int = 86400,
        reason: str | None = None,
    ) -> bool:
        """Add a jti to the Redis blocklist. Returns True on success, False otherwise.

        The reason (if provided) is stored as the value so an operator running
        ``redis-cli GET rig:blocklist:<jti>`` sees why the token was killed.
        Returns False when Redis is not configured, the blocklist is reachable
        but the SETEX failed, or the operation timed out — the caller decides
        whether that constitutes an HTTP 503 or a softer warning.
        """
        client = await self._get_redis()
        if client is None:
            return False
        if ttl_seconds <= 0:
            return False
        key = f"{self._redis_key_prefix}{jti}"
        value = (reason or "").encode("utf-8")
        try:
            await asyncio.wait_for(
                client.setex(key, ttl_seconds, value),
                timeout=self._redis_timeout,
            )
            return True
        except Exception:
            logger.exception("revocation: failed to add jti=%s to blocklist", jti)
            return False

    @property
    def enabled(self) -> bool:
        return bool(self._redis_url or self._dnsbl_zone)

    @property
    def can_write(self) -> bool:
        """True when there is a Redis backend that the admin endpoint can write to."""
        return bool(self._redis_url)
