"""Structured JSON logging and X-Request-ID ASGI middleware."""

import json
import logging
import time
import uuid
from contextvars import ContextVar

from starlette.types import ASGIApp, Receive, Scope, Send

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON with request context fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a log record to a JSON string."""
        entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", request_id_var.get("-")),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        for key in ("facility", "path", "method", "status", "latency_ms"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry, default=str)


class RequestIdMiddleware:
    """ASGI middleware that propagates or generates an X-Request-ID per request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Extract or generate request ID and store it in a context var."""
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        rid = headers.get(b"x-request-id", b"").decode() or str(uuid.uuid4())
        token = request_id_var.set(rid)

        scope.setdefault("state", {})
        scope["state"]["request_id"] = rid
        scope["state"]["request_start"] = time.monotonic()

        async def send_with_rid(message: dict) -> None:
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.append((b"x-request-id", rid.encode()))
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_rid)
        finally:
            request_id_var.reset(token)


def configure_logging(level: str = "INFO") -> None:
    """Set up the root logger with JSON formatting and suppress uvicorn access logs."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger instance."""
    return logging.getLogger(name)
