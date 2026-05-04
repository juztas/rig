"""Hop-by-hop header filtering for proxied requests and responses."""

from starlette.datastructures import Headers

HOP_BY_HOP_HEADERS: frozenset[str] = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})

_STRIP_REQUEST: frozenset[str] = HOP_BY_HOP_HEADERS | {"host"}


def filter_request_headers(headers: Headers, *, request_id: str) -> dict[str, str]:
    """Strip hop-by-hop and host headers, inject X-Request-ID."""
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _STRIP_REQUEST:
            continue
        out[key] = value
    out["x-request-id"] = request_id
    return out


def filter_response_headers(headers: Headers) -> dict[str, str]:
    """Strip hop-by-hop headers from the upstream response."""
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
