"""FastAPI application entry point with httpx client lifespan and health endpoints."""

from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .admin import router as admin_router
from .config import resolve_tier, settings
from .jwt_validator import JWTValidator
from .logging import RequestIdMiddleware, configure_logging, get_logger
from .proxy import router as proxy_router
from .revocation import RevocationChecker

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage shared httpx.AsyncClient lifecycle and configure structured logging."""
    configure_logging(settings.log_level)
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.default_timeout, connect=10.0),
        limits=httpx.Limits(
            max_connections=settings.max_connections,
            max_keepalive_connections=settings.max_keepalive_connections,
        ),
        follow_redirects=False,
        http2=True,
    )
    app.state.http_client = client
    # Stash the JWT validator on app.state so the proxy route can reach it without a
    # module-level singleton. PyJWKClient lazy-fetches keys only on first use, so this
    # is cheap even when validation is disabled.
    app.state.jwt_validator = JWTValidator(settings.jwt_validation)
    app.state.revocation_checker = RevocationChecker(
        redis_url=settings.revocation_redis_url,
        redis_key_prefix=settings.revocation_redis_key_prefix,
        redis_timeout_seconds=settings.revocation_redis_timeout_seconds,
        dnsbl_zone=settings.revocation_dnsbl_zone,
        dnsbl_cache_max=settings.revocation_dnsbl_cache_max,
        dnsbl_ttl_seconds=settings.revocation_dnsbl_ttl_seconds,
    )
    logger.info(
        "RIG started",
        extra={
            "facilities": list(settings.facilities.keys()),
            "max_connections": settings.max_connections,
            "jwt_validation_enabled": settings.jwt_validation.enabled,
            "revocation_enabled": app.state.revocation_checker.enabled,
        },
    )
    yield
    await client.aclose()
    logger.info("RIG stopped")


app = FastAPI(
    title="RIG - Resource Integration Gateway",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(RequestIdMiddleware)
# Admin routes are registered first so the /admin/blocklist path matches before
# the /{facility}/{path:path} wildcard absorbs it.
app.include_router(admin_router)
app.include_router(proxy_router)


@app.get("/health")
async def health():
    """Liveness probe -- returns 200 if the process is running."""
    return {"status": "ok"}


@app.get("/ready")
async def ready(request: Request):
    """Readiness probe — returns 200 with the per-facility tier map when ready."""
    client: httpx.AsyncClient | None = getattr(request.app.state, "http_client", None)
    if client is None:
        return JSONResponse(status_code=503, content={"status": "not ready", "reason": "http client not initialized"})
    if client.is_closed:
        return JSONResponse(status_code=503, content={"status": "not ready", "reason": "http client closed"})
    facilities = [
        {"name": name, "tier": resolve_tier(cfg, settings.vault_backend)}
        for name, cfg in settings.facilities.items()
    ]
    return {"status": "ready", "facilities": facilities}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """Prometheus exposition: per-facility tier gauge.

    Hand-rolled plain-text format (avoids a prometheus_client dependency).
    Operators can scrape this endpoint to alert on unexpected tier changes
    (for example, a facility dropping from Tier 2 to Tier 3).
    """
    lines = [
        "# HELP rig_facility_tier RIG integration tier configured for the facility (1=passthrough, 2=token-exchange, 3=vault).",
        "# TYPE rig_facility_tier gauge",
    ]
    for name, cfg in settings.facilities.items():
        tier = resolve_tier(cfg, settings.vault_backend)
        # Facility names come from operator-controlled config, but quote escape
        # defensively in case anything ever flows in from elsewhere.
        safe_name = name.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'rig_facility_tier{{facility="{safe_name}"}} {tier}')
    return "\n".join(lines) + "\n"


def main():
    """CLI entry point -- run uvicorn with settings from config."""
    uvicorn.run(
        "rig.app:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
