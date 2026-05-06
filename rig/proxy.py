"""Wildcard reverse-proxy route that streams requests to upstream facility APIs."""

import time

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .config import settings
from .headers import filter_request_headers, filter_response_headers
from .identity import TRUSTED_USERINFO_HEADER, _extract_subject, _extract_subject_from_userinfo, resolve_identity
from .logging import get_logger, request_id_var
from .policy import is_allowed

logger = get_logger(__name__)

router = APIRouter()


def _merge_forwarded_prefix(existing_prefix: str | None, facility: str) -> str:
    """Append the selected facility to any existing forwarded prefix."""
    prefix = (existing_prefix or "").split(",")[0].strip().rstrip("/")
    facility_prefix = f"/{facility}"
    return f"{prefix}{facility_prefix}" if prefix else facility_prefix


@router.api_route(
    "/{facility}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(facility: str, path: str, request: Request) -> Response:
    """Resolve identity, check policy, and stream the request to the upstream facility."""
    request_id = request_id_var.get("-")
    http_client: httpx.AsyncClient = request.app.state.http_client

    facility_config = settings.facilities.get(facility)
    if not facility_config:
        return JSONResponse(
            status_code=404,
            content={"error": f"Unknown facility: {facility}", "known_facilities": list(settings.facilities.keys())},
        )

    authorization = request.headers.get("authorization")
    project = request.headers.get("x-project")
    user_identity = _extract_subject_from_userinfo(request.headers.get(TRUSTED_USERINFO_HEADER))
    if user_identity is None:
        user_identity = _extract_subject(authorization)
    resolved_auth = await resolve_identity(
        authorization,
        facility,
        project,
        http_client,
        settings,
        user_identity=user_identity,
    )

    if not await is_allowed(user_identity, facility, path, request.method, http_client, settings):
        return JSONResponse(status_code=403, content={"error": "Forbidden by policy"})

    upstream_headers = filter_request_headers(request.headers, request_id=request_id)
    upstream_headers["x-forwarded-host"] = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    upstream_headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto") or request.url.scheme
    upstream_headers["x-forwarded-prefix"] = _merge_forwarded_prefix(request.headers.get("x-forwarded-prefix"), facility)
    if resolved_auth:
        upstream_headers["authorization"] = resolved_auth

    upstream_url = f"{facility_config.base_url.rstrip('/')}/{path.lstrip('/')}"
    timeout = httpx.Timeout(facility_config.timeout, connect=10.0)

    t0 = time.monotonic()
    try:
        upstream_req = http_client.build_request(
            method=request.method,
            url=upstream_url,
            params=request.query_params.multi_items(),
            headers=upstream_headers,
            content=request.stream(),
            timeout=timeout,
        )
        upstream_resp = await http_client.send(upstream_req, stream=True)
    except httpx.TimeoutException:
        latency_ms = (time.monotonic() - t0) * 1000
        logger.warning("Upstream timeout", extra={"facility": facility, "path": path, "method": request.method, "latency_ms": int(latency_ms)})
        return JSONResponse(status_code=504, content={"error": "Upstream timeout"})
    except httpx.ConnectError:
        latency_ms = (time.monotonic() - t0) * 1000
        logger.error("Upstream connect error", extra={"facility": facility, "path": path, "method": request.method, "latency_ms": int(latency_ms)})
        return JSONResponse(status_code=502, content={"error": "Cannot connect to upstream"})
    except Exception:
        latency_ms = (time.monotonic() - t0) * 1000
        logger.exception("Upstream error", extra={"facility": facility, "path": path, "method": request.method, "latency_ms": int(latency_ms)})
        return JSONResponse(status_code=502, content={"error": "Upstream error"})

    latency_ms = (time.monotonic() - t0) * 1000

    logger.info(
        "Proxied request",
        extra={
            "facility": facility,
            "path": path,
            "method": request.method,
            "status": upstream_resp.status_code,
            "latency_ms": int(latency_ms),
        },
    )

    response_headers = filter_response_headers(upstream_resp.headers)
    response_headers["x-request-id"] = request_id
    response_headers["x-upstream-latency-ms"] = str(int(latency_ms))

    async def stream_body():
        try:
            async for chunk in upstream_resp.aiter_raw():
                yield chunk
        finally:
            await upstream_resp.aclose()

    return StreamingResponse(
        content=stream_body(),
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )
