"""Admin endpoints for operational hooks (RFC Section 2F).

Currently exposes:

* ``POST /admin/blocklist`` — push a jti to the revocation blocklist. Designed
  to be called by anomaly-detection systems and SOC playbooks (RFC Section 2F
  "Emergency Token Revocation"). The endpoint is opt-in: it activates only when
  ``settings.admin_api_token`` is set, and it requires a matching bearer token
  on every call.

The router never exposes any non-revocation surface; rig's runtime configuration
remains read-only via this API.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import settings
from .logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


class BlocklistAddRequest(BaseModel):
    jti: str = Field(..., min_length=1, max_length=512)
    ttl_seconds: int = Field(default=86400, ge=1, le=86400 * 30)
    reason: str | None = Field(default=None, max_length=512)


def _require_admin(authorization: str | None) -> None:
    """Compare the inbound Bearer token against the configured admin token.

    Uses ``secrets.compare_digest`` to keep the comparison constant-time. Raises
    ``HTTPException(401)`` on any mismatch / missing config / malformed header.
    """
    expected = settings.admin_api_token
    if not expected:
        # Endpoint disabled when no token is configured.
        raise HTTPException(status_code=404, detail="Admin API disabled")
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must be Bearer")
    if not secrets.compare_digest(parts[1], expected):
        raise HTTPException(status_code=401, detail="Invalid admin token")


@router.post("/blocklist", status_code=201)
async def blocklist_add(
    request: Request,
    body: BlocklistAddRequest,
    authorization: Annotated[str | None, Header()] = None,
):
    """Add a jti to the Redis blocklist with the given TTL.

    Returns 201 on success, 503 when the revocation backend is unreachable or
    not configured for writes (i.e. no Redis URL).
    """
    _require_admin(authorization)
    checker = getattr(request.app.state, "revocation_checker", None)
    if checker is None or not checker.can_write:
        return JSONResponse(
            status_code=503,
            content={"error": "Revocation backend unavailable", "hint": "configure revocation_redis_url"},
        )
    ok = await checker.block(body.jti, ttl_seconds=body.ttl_seconds, reason=body.reason)
    if not ok:
        return JSONResponse(status_code=503, content={"error": "Failed to write blocklist entry"})
    logger.info(
        "rig.admin.blocklist_add",
        extra={
            "audit": True,
            "event": "admin_blocklist_add",
            "jti": body.jti,
            "ttl_seconds": body.ttl_seconds,
            "reason": body.reason,
        },
    )
    return {"jti": body.jti, "ttl_seconds": body.ttl_seconds, "reason": body.reason}
