"""RFC 8693 token exchange: converts an incoming Bearer token (e.g. Globus) into a
facility-local access token (e.g. SENSE-O) by calling the facility's IdP endpoint.

This module also enforces a configurable circuit-breaker timeout, an optional
``verify_tls`` override for self-signed development IdPs, audience / scope
overrides for facilities that demand specific RFC 8693 form parameters, an
excessive-privilege guard that rejects over-broad downstream tokens, and an
in-process TTL cache that avoids re-exchanging an already-valid token on every
request.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx

from .config import TokenExchangeConfig
from .exchange_cache import ExchangeCache
from .logging import get_logger

logger = get_logger(__name__)

_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

_DEFAULT_FALLBACK_TTL_SECONDS = 300


def _strip_bearer(authorization: str) -> str | None:
    """Return the raw token value from a 'Bearer <token>' header, or None."""
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Best-effort JWT payload decode (unverified). Opaque tokens return None."""
    segments = token.split(".")
    if len(segments) < 2:
        return None
    try:
        payload = segments[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def _split_scope_claim(claim: object) -> set[str]:
    """Normalize an OAuth scope claim, which may be a space-separated string or a list."""
    if isinstance(claim, str):
        return {s for s in claim.split() if s}
    if isinstance(claim, (list, tuple)):
        return {str(s) for s in claim}
    return set()


def _has_forbidden_scope(access_token: str, forbidden: list[str]) -> bool:
    """Return True if a JWT access token's scope claim intersects ``forbidden``."""
    if not forbidden:
        return False
    payload = _decode_jwt_payload(access_token)
    if not payload:
        return False
    granted = _split_scope_claim(payload.get("scope"))
    granted |= _split_scope_claim(payload.get("scp"))
    return bool(granted & set(forbidden))


def _derive_ttl_from_exp(access_token: str, fallback_seconds: int, skew_seconds: int) -> float:
    """Compute a cache TTL from a JWT's ``exp`` claim, minus a safety skew.

    Falls back to ``fallback_seconds`` when the token is opaque, has no exp, or
    has already expired.
    """
    payload = _decode_jwt_payload(access_token)
    if payload:
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            import time

            ttl = float(exp) - time.time() - float(skew_seconds)
            if ttl > 0:
                return ttl
    return float(fallback_seconds)


def _strip_caller_for_log(sub: str | None) -> str:
    return sub if sub else "<anon>"


async def exchange_token(
    authorization: str,
    cfg: TokenExchangeConfig,
    http_client: httpx.AsyncClient,
    *,
    sub: str | None = None,
    facility: str = "",
    cache: ExchangeCache | None = None,
) -> str | None:
    """Exchange ``authorization`` (a Bearer token from the caller) for a facility access token.

    Returns a ready-to-use ``"Bearer <access_token>"`` string, or ``None`` when
    the exchange fails so the caller can decide whether to fall back to a vault
    lookup or pass-through. ``sub`` and ``facility`` are used together with
    ``cfg.requested_scope`` as the cache key (when ``cache`` is provided).
    """
    subject_token = _strip_bearer(authorization)
    if not subject_token:
        logger.warning("token_exchange: authorization header is not a Bearer token — skipping")
        return None

    if cache is not None:
        cached = await cache.get(sub, facility, cfg.requested_scope)
        if cached is not None:
            logger.debug(
                "token_exchange: cache hit for sub=%s facility=%s",
                _strip_caller_for_log(sub),
                facility,
            )
            return cached

    data: dict[str, str] = {
        "grant_type": _GRANT_TYPE,
        "client_id": cfg.client_id,
        "subject_token": subject_token,
        "subject_token_type": _TOKEN_TYPE,
        "subject_issuer": cfg.subject_issuer,
        "audience": cfg.audience or cfg.client_id,
    }
    if cfg.client_secret:
        data["client_secret"] = cfg.client_secret
    if cfg.requested_scope:
        data["scope"] = cfg.requested_scope

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    timeout = httpx.Timeout(cfg.timeout_seconds, connect=min(cfg.timeout_seconds, 5.0))

    # When ``verify_tls`` is False the shared AsyncClient cannot help — its
    # ``verify`` setting is fixed at construction time. Use a one-off client
    # for the (rare) self-signed-IdP case so the override is actually honored.
    if cfg.verify_tls:
        post = lambda: http_client.post(cfg.auth_endpoint, data=data, headers=headers, timeout=timeout)
    else:
        async def post():
            async with httpx.AsyncClient(verify=False, timeout=timeout) as oneoff:
                return await oneoff.post(cfg.auth_endpoint, data=data, headers=headers)

    try:
        resp = await post()
        if resp.status_code >= 400:
            logger.error(
                "token_exchange: HTTP %d from %s — %s",
                resp.status_code,
                cfg.auth_endpoint,
                resp.text[:200],
            )
            return None
        token_data = resp.json()
    except httpx.TimeoutException:
        logger.warning(
            "token_exchange: timed out after %.1fs hitting %s",
            cfg.timeout_seconds,
            cfg.auth_endpoint,
        )
        return None
    except Exception:
        logger.exception("token_exchange: request to %s failed", cfg.auth_endpoint)
        return None

    access_token = token_data.get("access_token")
    if not access_token:
        error = token_data.get("error_description") or token_data.get("error") or "no access_token in response"
        logger.error("token_exchange: exchange succeeded but %s", error)
        return None

    if _has_forbidden_scope(access_token, cfg.forbidden_scopes):
        logger.error(
            "token_exchange: refusing facility token — granted scope intersects forbidden_scopes=%s",
            cfg.forbidden_scopes,
        )
        return None

    bearer = f"Bearer {access_token}"

    if cache is not None:
        ttl = (
            float(cfg.cache_ttl_seconds)
            if cfg.cache_ttl_seconds is not None
            else _derive_ttl_from_exp(access_token, _DEFAULT_FALLBACK_TTL_SECONDS, cfg.cache_skew_seconds)
        )
        await cache.set(sub, facility, cfg.requested_scope, bearer, ttl)

    logger.info(
        "token_exchange: obtained downstream access token (facility=%s, sub=%s)",
        facility or "<unspecified>",
        _strip_caller_for_log(sub),
    )
    return bearer
