"""JWKS-backed inbound JWT validation (RFC Section 3A).

This module implements local cryptographic verification of inbound bearer tokens
as defense in depth on top of Kong's edge OIDC validation. It is OFF by default
(see ``JWTValidationConfig.enabled``); enable it in production deployments where
rig is reachable from any path that is not gated by Kong.

PyJWT's ``PyJWKClient`` performs JWKS fetching and key caching internally, so we
do not duplicate caching here. The validator is safe to instantiate once at
process startup and reuse for every request.
"""

import threading
from typing import Final

import jwt
from jwt import PyJWKClient

from .config import JWTValidationConfig
from .logging import get_logger

logger = get_logger(__name__)


_INVALID_REASON_MISSING: Final[str] = "missing_authorization"
_INVALID_REASON_NOT_BEARER: Final[str] = "not_bearer"
_INVALID_REASON_EXPIRED: Final[str] = "token_expired"
_INVALID_REASON_BAD_ISSUER: Final[str] = "invalid_issuer"
_INVALID_REASON_BAD_AUDIENCE: Final[str] = "invalid_audience"
_INVALID_REASON_BAD_SIGNATURE: Final[str] = "invalid_signature"
_INVALID_REASON_KEY_LOOKUP: Final[str] = "key_lookup_failed"
_INVALID_REASON_DECODE: Final[str] = "decode_failed"


class JWTValidator:
    """Cryptographically validate inbound bearer JWTs against a configured JWKS endpoint.

    A single instance is intended to live for the lifetime of the rig process. It
    is safe to call :meth:`validate` concurrently — PyJWKClient is thread-safe
    for read access and we do not mutate per-call state.
    """

    def __init__(self, cfg: JWTValidationConfig):
        self.cfg = cfg
        self._jwks_client: PyJWKClient | None = None
        self._lock = threading.Lock()

    def _get_jwks_client(self) -> PyJWKClient:
        # Lazy-init so that disabled deployments never create a JWKS client and
        # so that a misconfigured but disabled validator never raises at import.
        if self._jwks_client is None:
            with self._lock:
                if self._jwks_client is None:
                    self._jwks_client = PyJWKClient(
                        self.cfg.jwks_url,
                        cache_jwks=True,
                        lifespan=self.cfg.cache_ttl_seconds,
                    )
        return self._jwks_client

    def validate(self, authorization: str | None) -> tuple[bool, str | None]:
        """Validate ``authorization``. Returns ``(valid, reason)``.

        When ``valid`` is True, ``reason`` is None. When ``valid`` is False,
        ``reason`` is a stable short token suitable for audit logs (e.g.
        ``"token_expired"``).
        """
        if not self.cfg.enabled:
            # Validator disabled — caller should not have invoked us, but be
            # defensive: silently treat as valid.
            return (True, None)

        if not authorization:
            return (False, _INVALID_REASON_MISSING)

        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return (False, _INVALID_REASON_NOT_BEARER)

        token = parts[1]
        try:
            signing_key = self._get_jwks_client().get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientError:
            logger.exception("JWKS key lookup failed")
            return (False, _INVALID_REASON_KEY_LOOKUP)
        except Exception:
            logger.exception("Unexpected JWKS error")
            return (False, _INVALID_REASON_KEY_LOOKUP)

        decode_kwargs: dict = {
            "algorithms": list(self.cfg.algorithms),
            "leeway": self.cfg.leeway_seconds,
        }
        if self.cfg.issuer:
            decode_kwargs["issuer"] = self.cfg.issuer
        if self.cfg.audience:
            # PyJWT accepts a string or list for audience; pass through directly.
            decode_kwargs["audience"] = list(self.cfg.audience)

        try:
            jwt.decode(token, signing_key, **decode_kwargs)
        except jwt.ExpiredSignatureError:
            return (False, _INVALID_REASON_EXPIRED)
        except jwt.InvalidIssuerError:
            return (False, _INVALID_REASON_BAD_ISSUER)
        except jwt.InvalidAudienceError:
            return (False, _INVALID_REASON_BAD_AUDIENCE)
        except jwt.InvalidSignatureError:
            return (False, _INVALID_REASON_BAD_SIGNATURE)
        except jwt.InvalidTokenError:
            logger.exception("JWT validation failed")
            return (False, _INVALID_REASON_DECODE)

        return (True, None)
