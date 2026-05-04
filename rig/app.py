"""FastAPI application entry point with httpx client lifespan and health endpoints."""

from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import settings
from .logging import RequestIdMiddleware, configure_logging, get_logger
from .proxy import router as proxy_router

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
    logger.info(
        "RIG started",
        extra={
            "facilities": list(settings.facilities.keys()),
            "max_connections": settings.max_connections,
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
app.include_router(proxy_router)


@app.get("/health")
async def health():
    """Liveness probe -- returns 200 if the process is running."""
    return {"status": "ok"}


@app.get("/ready")
async def ready(request: Request):
    """Readiness probe -- returns 200 if the httpx client is open, 503 otherwise."""
    client: httpx.AsyncClient | None = getattr(request.app.state, "http_client", None)
    if client is None:
        return JSONResponse(status_code=503, content={"status": "not ready", "reason": "http client not initialized"})
    if client.is_closed:
        return JSONResponse(status_code=503, content={"status": "not ready", "reason": "http client closed"})
    return {"status": "ready", "facilities": list(settings.facilities.keys())}


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
