"""Lightweight OpenTelemetry helpers for the rig proxy (RFC Section 2E).

Rig uses the OTel API only — operators bring their own SDK (exporter, sampler,
processor) at deployment time. When no SDK is configured the API returns a
NoOp tracer, so these helpers are safe to call unconditionally.

Two responsibilities:

1. Continue any inbound trace context — ``traceparent`` / ``tracestate`` headers
   from Kong / the load balancer — so rig's span is a child of the caller's.
2. Inject the active context into the upstream request so the facility's own
   tracing can pick up where rig leaves off.

Identity-context attributes (``rig.sub``, ``rig.facility``, ``rig.tier``, …) are
attached to the active span by ``set_audit_attributes()``.
"""

from __future__ import annotations

from typing import Any, Mapping, MutableMapping

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.propagators.textmap import (
    DefaultGetter,
    DefaultSetter,
)
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

_tracer = trace.get_tracer("rig.proxy")
_propagator = TraceContextTextMapPropagator()
_getter = DefaultGetter()
_setter = DefaultSetter()


def get_tracer() -> trace.Tracer:
    return _tracer


def extract_context(headers: Mapping[str, str]) -> otel_context.Context:
    """Extract a parent context from inbound HTTP headers."""
    # FastAPI's Headers is case-insensitive but the propagator wants a Mapping.
    return _propagator.extract(carrier=dict(headers), getter=_getter)


def inject_context(headers: MutableMapping[str, str]) -> None:
    """Inject the *current* context into ``headers`` so the upstream sees it."""
    _propagator.inject(carrier=headers, setter=_setter)


def current_trace_ids() -> tuple[str, str] | None:
    """Return ``(trace_id_hex, span_id_hex)`` for the active span, or None."""
    span = trace.get_current_span()
    if span is None:
        return None
    ctx = span.get_span_context()
    if not ctx.is_valid:
        return None
    return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")


def set_audit_attributes(
    *,
    facility: str,
    tier: int | None = None,
    sub: str | None = None,
    jti: str | None = None,
    project: str | None = None,
    decision: str | None = None,
    status: int | None = None,
    reason: str | None = None,
    resolution_mechanism: str | None = None,
) -> None:
    """Set the canonical rig.* span attributes on the active span (no-op if there isn't one)."""
    span = trace.get_current_span()
    if span is None:
        return
    attrs: dict[str, Any] = {"rig.facility": facility}
    if tier is not None:
        attrs["rig.tier"] = tier
    if sub:
        attrs["rig.sub"] = sub
    if jti:
        attrs["rig.jti"] = jti
    if project:
        attrs["rig.project"] = project
    if decision:
        attrs["rig.decision"] = decision
    if status is not None:
        attrs["rig.status"] = status
    if reason:
        attrs["rig.reason"] = reason
    if resolution_mechanism:
        attrs["rig.resolution_mechanism"] = resolution_mechanism
    span.set_attributes(attrs)
