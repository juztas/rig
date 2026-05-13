"""Wildcard reverse-proxy route that streams requests to upstream facility APIs."""

import ipaddress
import json
import time

import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from opentelemetry import context as otel_context
from opentelemetry import trace as otel_trace

from .config import resolve_tier, settings
from .headers import filter_request_headers, filter_response_headers
from .identity import (
    TRUSTED_USERINFO_HEADER,
    _decode_jwt_payload,
    _extract_acr,
    _extract_act,
    _extract_amr,
    _extract_auth_time,
    _extract_idp,
    _extract_jti,
    _extract_project_context,
    _extract_subject,
    _extract_subject_from_userinfo,
    resolve_identity,
)
from .logging import get_logger, request_id_var
from .policy import is_allowed
from .tracing import (
    current_trace_ids,
    extract_context,
    get_tracer,
    inject_context,
    set_audit_attributes,
)

logger = get_logger(__name__)

router = APIRouter()


def _merge_forwarded_prefix(existing_prefix: str | None, facility: str) -> str:
    """Append the selected facility to any existing forwarded prefix."""
    prefix = (existing_prefix or "").split(",")[0].strip().rstrip("/")
    facility_prefix = f"/{facility}"
    return f"{prefix}{facility_prefix}" if prefix else facility_prefix


def _resolve_facility_project(project: str | None, facility: str) -> str | None:
    """Map an AmSC project id to the facility-native project/account identifier."""
    if not project:
        return None
    return settings.project_mappings.get(project, {}).get(facility)


def _client_ip(request: Request) -> str | None:
    """Extract the originating client IP — first hop of X-Forwarded-For, or socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    if request.client:
        return request.client.host
    return None


def _is_service_token(authorization: str | None, accepted_amr_values: list[str]) -> bool:
    """Treat a token as a service-account credential when it carries no recognized MFA assertion.

    Per RFC Section 3C "Compensating Controls", non-MFA actors are subject to network-zone
    constraints (IP allowlist) instead of biometric/2FA verification. We classify a
    token as a service token when its ``amr`` claim is missing or contains no value
    in ``accepted_amr_values``.
    """
    payload = _decode_jwt_payload(authorization)
    amr = payload.get("amr") if payload else None
    if not isinstance(amr, list):
        return True
    accepted = {v.lower() for v in accepted_amr_values}
    return not any(isinstance(v, str) and v.lower() in accepted for v in amr)


def _ip_in_allowlist(ip: str | None, cidrs: list[str]) -> bool:
    """Return True iff ``ip`` falls within any CIDR block in ``cidrs``."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _audit(
    *,
    decision: str,
    status: int,
    facility: str,
    tier: int | None,
    sub: str | None,
    jti: str | None,
    project: str | None,
    enclave: str | None,
    act: str | None,
    method: str,
    path: str,
    latency_ms: int | None = None,
    reason: str | None = None,
    resolution_mechanism: str | None = None,
) -> None:
    """Emit one structured audit record per request (RFC Section 2E, ZT-REQ-09/10/11).

    Also writes the canonical ``rig.*`` attributes onto the active OpenTelemetry
    span (when one is live) and, for log/trace correlation, includes the trace
    and span ids in the structured log entry.

    ``decision`` is one of: ``allow`` (the proxy decided to forward), ``deny`` (the
    proxy rejected the request before forwarding), ``error`` (the proxy could not
    reach the upstream).
    """
    extra = {
        "audit": True,
        "decision": decision,
        "status": status,
        "facility": facility,
        "tier": tier,
        "sub": sub,
        "jti": jti,
        "project": project,
        "enclave": enclave,
        "act": act,
        "method": method,
        "path": path,
        "latency_ms": latency_ms,
        "reason": reason,
    }
    if resolution_mechanism is not None:
        extra["resolution_mechanism"] = resolution_mechanism
    ids = current_trace_ids()
    if ids is not None:
        extra["trace_id"], extra["span_id"] = ids
    set_audit_attributes(
        facility=facility,
        tier=tier,
        sub=sub,
        jti=jti,
        project=project,
        enclave=enclave,
        act=act,
        decision=decision,
        status=status,
        reason=reason,
        resolution_mechanism=resolution_mechanism,
    )
    logger.info("rig.audit", extra=extra)


async def _publish_reauth_if_needed(
    request: Request,
    *,
    status: int,
    facility: str,
    tier: int | None,
    sub: str | None,
    jti: str | None,
    project: str | None,
    enclave: str | None,
    act: str | None,
    method: str,
    path: str,
    reason: str | None,
) -> None:
    """Best-effort publish of workflow-suspend events for 401/403 deny paths."""
    if status not in (401, 403):
        return
    publisher = getattr(request.app.state, "reauth_publisher", None)
    if publisher is None or not publisher.enabled:
        return
    ids = current_trace_ids()
    event = {
        "event": "reauth_required",
        "workflow_action": "suspend",
        "request_id": request_id_var.get("-"),
        "status": status,
        "facility": facility,
        "tier": tier,
        "sub": sub,
        "jti": jti,
        "project": project,
        "enclave": enclave,
        "act": act,
        "method": method,
        "path": path,
        "reason": reason,
        "challenge_uri": settings.auth_device_flow_uri or None,
        "trace_id": ids[0] if ids else None,
        "span_id": ids[1] if ids else None,
        "timestamp": int(time.time()),
    }
    await publisher.publish_suspend_event(event)


def _wants_html(request: Request) -> bool:
    """Decide whether the caller is a browser based on the Accept header."""
    accept = (request.headers.get("accept") or "").lower()
    return "text/html" in accept


def _challenge_401(request: Request, *, error: str, reason: str) -> Response:
    """Return the appropriate 401 response for the caller (RFC Section 3F).

    * Browsers (``Accept: text/html``) with ``auth_redirect_login_url`` configured
      get a 302 redirect to that URL. The original path is appended as a
      ``return_to`` query parameter so the login flow can bring the user back.
    * Non-browser callers get a JSON 401, optionally including ``challenge_uri``
      pointing at the configured device-flow URL so a CLI can self-recover.
    """
    if _wants_html(request) and settings.auth_redirect_login_url:
        target = settings.auth_redirect_login_url
        sep = "&" if "?" in target else "?"
        location = f"{target}{sep}return_to={request.url.path}"
        resp = RedirectResponse(url=location, status_code=302)
        resp.headers["x-amsc-auth-challenge"] = reason
        return resp
    body: dict[str, str] = {"error": error, "reason": reason}
    if settings.auth_device_flow_uri:
        body["challenge_uri"] = settings.auth_device_flow_uri
    return JSONResponse(status_code=401, content=body)


@router.api_route(
    "/{facility}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(facility: str, path: str, request: Request) -> Response:
    """Span-wrapping shim around :func:`_proxy_impl` (RFC Section 2E).

    Continues any inbound trace context (``traceparent`` / ``tracestate``) so the
    rig span is a child of the caller's, then runs the actual proxy logic with
    that span as the active context. Body / status attributes are written by
    ``_audit()`` via the active span.
    """
    parent_ctx = extract_context(request.headers)
    with get_tracer().start_as_current_span("rig.proxy", context=parent_ctx) as span:
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.target", request.url.path)
        return await _proxy_impl(facility, path, request)


async def _proxy_impl(facility: str, path: str, request: Request) -> Response:
    """Resolve identity, check policy, and stream the request to the upstream facility."""
    request_id = request_id_var.get("-")
    http_client: httpx.AsyncClient = request.app.state.http_client
    method = request.method

    facility_config = settings.facilities.get(facility)
    if not facility_config:
        _audit(
            decision="deny",
            status=404,
            facility=facility,
            tier=None,
            sub=None,
            jti=None,
            project=None,
            enclave=None,
            act=None,
            method=method,
            path=path,
            reason="unknown_facility",
        )
        return JSONResponse(
            status_code=404,
            content={"error": f"Unknown facility: {facility}", "known_facilities": list(settings.facilities.keys())},
        )

    tier = resolve_tier(facility_config, settings.vault_backend)
    vault_enclave = facility_config.vault_enclave

    authorization = request.headers.get("authorization")
    if not authorization:
        # Kong's kong-openid-connect plugin consumes the inbound Bearer header and re-exposes
        # the validated access token via X-Access-Token. Fall back to it so downstream auth
        # resolution (token exchange, pass-through) still has the caller's token.
        access_token = request.headers.get("x-access-token")
        if access_token:
            authorization = access_token if access_token.lower().startswith("bearer ") else f"Bearer {access_token}"

    # Defense-in-depth JWKS validation (RFC Section 3A). Off unless explicitly configured;
    # when enabled and the inbound bearer is malformed / expired / wrong-iss / etc.,
    # reject at ingress with 401 before performing any further work.
    jwt_validator = getattr(request.app.state, "jwt_validator", None)
    if jwt_validator is not None and settings.jwt_validation.enabled:
        valid, reason = jwt_validator.validate(authorization)
        if not valid:
            act = _extract_act(authorization)
            _audit(
                decision="deny",
                status=401,
                facility=facility,
                tier=tier,
                sub=_extract_subject(authorization),
                jti=_extract_jti(authorization),
                project=request.headers.get("x-project"),
                enclave=vault_enclave,
                act=act,
                method=method,
                path=path,
                reason=f"token_invalid:{reason}",
            )
            await _publish_reauth_if_needed(
                request,
                status=401,
                facility=facility,
                tier=tier,
                sub=_extract_subject(authorization),
                jti=_extract_jti(authorization),
                project=request.headers.get("x-project"),
                enclave=vault_enclave,
                act=act,
                method=method,
                path=path,
                reason=f"token_invalid:{reason}",
            )
            return _challenge_401(
                request,
                error="Invalid bearer token",
                reason=reason,
            )

    # Token revocation check (RFC Section 2F). Redis blocklist + DNSBL TXT lookup.
    # Both checks fail open — this is defense-in-depth on top of the natural
    # short token TTL, never the primary authorization gate.
    revocation_checker = getattr(request.app.state, "revocation_checker", None)
    if revocation_checker is not None and revocation_checker.enabled:
        jti_for_revocation = _extract_jti(authorization)
        if jti_for_revocation:
            revoked, source = await revocation_checker.is_revoked(jti_for_revocation)
            if revoked:
                act = _extract_act(authorization)
                _audit(
                    decision="deny",
                    status=401,
                    facility=facility,
                    tier=tier,
                    sub=_extract_subject(authorization),
                    jti=jti_for_revocation,
                    project=request.headers.get("x-project"),
                    enclave=vault_enclave,
                    act=act,
                    method=method,
                    path=path,
                    reason=f"revoked:{source}",
                )
                await _publish_reauth_if_needed(
                    request,
                    status=401,
                    facility=facility,
                    tier=tier,
                    sub=_extract_subject(authorization),
                    jti=jti_for_revocation,
                    project=request.headers.get("x-project"),
                    enclave=vault_enclave,
                    act=act,
                    method=method,
                    path=path,
                    reason=f"revoked:{source}",
                )
                return _challenge_401(
                    request,
                    error="Token revoked",
                    reason=f"revoked:{source}",
                )

    # IP allowlist for non-MFA service tokens (RFC Section 3C "Compensating Controls").
    # When the operator has configured ``service_account_allowed_cidrs`` and the
    # caller is a service token (no recognized MFA value in ``amr``), the request
    # must originate from an allowed CIDR block.
    if settings.service_account_allowed_cidrs and _is_service_token(
        authorization, settings.service_account_mfa_amr_values
    ):
        ip = _client_ip(request)
        if not _ip_in_allowlist(ip, settings.service_account_allowed_cidrs):
            act = _extract_act(authorization)
            _audit(
                decision="deny",
                status=403,
                facility=facility,
                tier=tier,
                sub=_extract_subject(authorization),
                jti=_extract_jti(authorization),
                project=request.headers.get("x-project"),
                enclave=vault_enclave,
                act=act,
                method=method,
                path=path,
                reason="service_token_outside_cidr",
            )
            await _publish_reauth_if_needed(
                request,
                status=403,
                facility=facility,
                tier=tier,
                sub=_extract_subject(authorization),
                jti=_extract_jti(authorization),
                project=request.headers.get("x-project"),
                enclave=vault_enclave,
                act=act,
                method=method,
                path=path,
                reason="service_token_outside_cidr",
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Service-account caller is outside the configured CIDR allowlist",
                    "client_ip": ip,
                },
            )

    project_header = request.headers.get("x-project")
    project_claim = _extract_project_context(authorization)
    act_claim = _extract_act(authorization)

    # ZT-REQ-04 / RFC Section 3F "Token-Based Context Derivation": if both the X-Project header
    # and the JWT amsc_project_context claim are present, they MUST agree.
    if project_header and project_claim and project_header != project_claim:
        sub_for_audit = _extract_subject_from_userinfo(request.headers.get(TRUSTED_USERINFO_HEADER)) or _extract_subject(authorization)
        _audit(
            decision="deny",
            status=403,
            facility=facility,
            tier=tier,
            sub=sub_for_audit,
            jti=_extract_jti(authorization),
            project=project_header,
            enclave=vault_enclave,
            act=act_claim,
            method=method,
            path=path,
            reason="project_mismatch",
        )
        await _publish_reauth_if_needed(
            request,
            status=403,
            facility=facility,
            tier=tier,
            sub=sub_for_audit,
            jti=_extract_jti(authorization),
            project=project_header,
            enclave=vault_enclave,
            act=act_claim,
            method=method,
            path=path,
            reason="project_mismatch",
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": "X-Project header does not match amsc_project_context claim",
                "header_project": project_header,
                "claim_project": project_claim,
            },
        )

    project = project_header or project_claim

    # ZT-REQ-08 / RFC Section 3F: Tier-3 (vault) facilities require a project context. Without it
    # the vault lookup cannot succeed deterministically, so fail closed at ingress instead
    # of silently passing through to the upstream.
    if tier == 3 and not project:
        sub_for_audit = _extract_subject_from_userinfo(request.headers.get(TRUSTED_USERINFO_HEADER)) or _extract_subject(authorization)
        _audit(
            decision="deny",
            status=400,
            facility=facility,
            tier=3,
            sub=sub_for_audit,
            jti=_extract_jti(authorization),
            project=None,
            enclave=vault_enclave,
            act=act_claim,
            method=method,
            path=path,
            reason="missing_project_for_tier3",
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "Tier-3 (vaulted) facility requires a project context",
                "hint": "Send the project as the X-Project header or as the amsc_project_context JWT claim.",
                "facility": facility,
            },
        )

    user_identity = _extract_subject_from_userinfo(request.headers.get(TRUSTED_USERINFO_HEADER))
    if user_identity is None:
        user_identity = _extract_subject(authorization)
    jti = _extract_jti(authorization)

    resolved_auth, resolution_mechanism = await resolve_identity(
        authorization,
        facility,
        project,
        http_client,
        settings,
        user_identity=user_identity,
    )

    if not await is_allowed(user_identity, facility, path, method, http_client, settings):
        _audit(
            decision="deny",
            status=403,
            facility=facility,
            tier=tier,
            sub=user_identity,
            jti=jti,
            project=project,
            enclave=vault_enclave,
            act=act_claim,
            method=method,
            path=path,
            reason="policy",
        )
        await _publish_reauth_if_needed(
            request,
            status=403,
            facility=facility,
            tier=tier,
            sub=user_identity,
            jti=jti,
            project=project,
            enclave=vault_enclave,
            act=act_claim,
            method=method,
            path=path,
            reason="policy",
        )
        return JSONResponse(status_code=403, content={"error": "Forbidden by policy"})

    upstream_headers = filter_request_headers(request.headers, request_id=request_id)
    upstream_headers["x-forwarded-host"] = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    upstream_headers["x-forwarded-proto"] = request.headers.get("x-forwarded-proto") or request.url.scheme
    upstream_headers["x-forwarded-prefix"] = _merge_forwarded_prefix(request.headers.get("x-forwarded-prefix"), facility)

    # RFC Section 3C "Global Request Traceability (Mandatory Headers)" — propagate AmSC identity
    # context to the upstream facility so its local logs can correlate with the AmSC trail
    # even in Tier-3 (legacy / opaque-credential) scenarios.
    upstream_headers["x-amsc-trace-id"] = request_id
    if user_identity:
        upstream_headers["x-amsc-user"] = user_identity
    if project:
        upstream_headers["x-amsc-project"] = project
    facility_project = _resolve_facility_project(project, facility)
    if facility_project:
        upstream_headers["x-iri-facility-project"] = facility_project
    if vault_enclave:
        upstream_headers["x-amsc-enclave"] = vault_enclave
    if act_claim:
        upstream_headers["x-amsc-act"] = act_claim

    # Authentication-context claims forwarded for facilities that enforce session
    # freshness or origin-IdP policy locally (RFC Section 3F "Session Freshness").
    auth_time = _extract_auth_time(authorization)
    if auth_time is not None:
        upstream_headers["x-amsc-auth-time"] = str(auth_time)
    amr_values = _extract_amr(authorization)
    if amr_values:
        upstream_headers["x-amsc-amr"] = ",".join(amr_values)
    acr_value = _extract_acr(authorization)
    if acr_value:
        upstream_headers["x-amsc-acr"] = acr_value
    idp_value = _extract_idp(authorization)
    if idp_value:
        upstream_headers["x-amsc-idp"] = idp_value

    # Propagate the OTel trace context so the upstream facility's spans
    # become children of rig's. Writes traceparent (+ tracestate when set).
    inject_context(upstream_headers)

    if resolved_auth:
        upstream_headers["authorization"] = resolved_auth

    # Signal to downstream services (Kong plugin chain or facility-side audit) that
    # credential resolution already happened at this hop (RFC Section 3B Path A).
    # "Completed" => RFC 8693 token exchange ran; "Vaulted" => bearer was substituted
    # from the AmSC Credential Vault.
    if resolution_mechanism == "exchange":
        upstream_headers["x-amsc-exchange-status"] = "Completed"
    elif resolution_mechanism == "vault":
        upstream_headers["x-amsc-exchange-status"] = "Vaulted"

    upstream_url = f"{facility_config.base_url.rstrip('/')}/{path.lstrip('/')}"
    timeout = httpx.Timeout(facility_config.timeout, connect=10.0)

    t0 = time.monotonic()
    try:
        upstream_req = http_client.build_request(
            method=method,
            url=upstream_url,
            params=request.query_params.multi_items(),
            headers=upstream_headers,
            content=request.stream(),
            timeout=timeout,
        )
        upstream_resp = await http_client.send(upstream_req, stream=True)
    except httpx.TimeoutException:
        latency_ms = (time.monotonic() - t0) * 1000
        _audit(decision="error", status=504, facility=facility, tier=tier, sub=user_identity, jti=jti, project=project, enclave=vault_enclave, act=act_claim, method=method, path=path, latency_ms=int(latency_ms), reason="upstream_timeout")
        return JSONResponse(status_code=504, content={"error": "Upstream timeout"})
    except httpx.ConnectError:
        latency_ms = (time.monotonic() - t0) * 1000
        _audit(decision="error", status=502, facility=facility, tier=tier, sub=user_identity, jti=jti, project=project, enclave=vault_enclave, act=act_claim, method=method, path=path, latency_ms=int(latency_ms), reason="upstream_connect")
        return JSONResponse(status_code=502, content={"error": "Cannot connect to upstream"})
    except Exception:
        latency_ms = (time.monotonic() - t0) * 1000
        logger.exception("Upstream error", extra={"facility": facility, "path": path, "method": method, "latency_ms": int(latency_ms)})
        _audit(decision="error", status=502, facility=facility, tier=tier, sub=user_identity, jti=jti, project=project, enclave=vault_enclave, act=act_claim, method=method, path=path, latency_ms=int(latency_ms), reason="upstream_exception")
        return JSONResponse(status_code=502, content={"error": "Upstream error"})

    latency_ms = (time.monotonic() - t0) * 1000

    _audit(
        decision="allow",
        status=upstream_resp.status_code,
        facility=facility,
        tier=tier,
        sub=user_identity,
        jti=jti,
        project=project,
        enclave=vault_enclave,
        act=act_claim,
        method=method,
        path=path,
        latency_ms=int(latency_ms),
        resolution_mechanism=resolution_mechanism,
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
