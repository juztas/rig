"""FastAPI application entry point with httpx client lifespan and health endpoints."""

from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
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
    description=(
        "Stateless reverse proxy and identity broker for IRI Facility APIs.\n\n"
        "Click **Authorize** to paste a Bearer token, then use **Try it out** on any "
        "endpoint. For Tier-3 facilities the `X-Project` header is required."
    ),
    lifespan=lifespan,
    swagger_ui_parameters={
        # Keep the Authorize state across page reloads so users don't have to
        # re-paste their token on every refresh.
        "persistAuthorization": True,
    },
)


def _build_openapi():
    """Inject Bearer + X-Project security schemes so Swagger UI exposes both.

    Rig itself does not enforce these at the FastAPI layer — Kong already gates
    incoming requests with `bearer_only: true`, and the existing proxy handler
    reads ``X-Project`` directly off the request. The security blocks are
    documentation-only, so Swagger UI surfaces an **Authorize** button (for the
    bearer token) and a per-endpoint field for ``X-Project``.
    """
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})
    schema["components"]["securitySchemes"]["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "Paste a Globus / OIDC access token here. Get one from the MyAmSC portal's \"Raw Tokens\" panel.",
    }
    schema["components"]["securitySchemes"]["ProjectHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-Project",
        "description": "Project context. Required for Tier-3 (vaulted) facilities; ignored for Tier-1 pass-through.",
    }
    # Global security default; individual routes can still opt out by setting
    # security=[] on their decorator if needed.
    schema["security"] = [{"BearerAuth": [], "ProjectHeader": []}]
    app.openapi_schema = schema
    return schema


app.openapi = _build_openapi

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
