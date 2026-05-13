"""Identity resolution: RFC 8693 token exchange, vaulted credential lookup, or pass-through.

In addition to the three-tier resolution chain, this module enforces vault-side
guardrails required by the RFC: ``auth_time`` freshness for human callers (RFC
Section 3C "MFA Inheritance & Freshness"), pool-detection that fingerprints returned
credentials and warns / denies on cross-user reuse (RFC Section 3C "Prohibition of
Pooling"), and a "Binding Event" structured audit record on every successful
vault read.
"""

import asyncio
import base64
import functools
import hashlib
import inspect
import json
import threading
import time
from typing import Any

import boto3
import httpx
from kubernetes_asyncio import client as k8s_client
from kubernetes_asyncio import config as k8s_config

from .config import Settings
from .exchange_cache import ExchangeCache, default_cache as _default_exchange_cache
from .logging import get_logger
from .token_exchange import exchange_token

logger = get_logger(__name__)

TRUSTED_USERINFO_HEADER = "x-userinfo"

# Process-local pool-observation table: credential fingerprint -> set of subs that
# have been issued that exact credential. RFC Section 3C strictly prohibits assigning the
# same downstream credential to more than one AmSC user.
_pool_lock = threading.Lock()
_pool_observations: dict[str, set[str]] = {}

_kube_init_lock = asyncio.Lock()
_kube_initialized = False
_kube_api_client: Any | None = None
_kube_v1_api: Any | None = None


async def _get_kube_v1_api() -> Any:
    """Initialize and cache the in-cluster Kubernetes API client once per process."""
    global _kube_initialized, _kube_api_client, _kube_v1_api

    if _kube_v1_api is not None:
        return _kube_v1_api

    async with _kube_init_lock:
        if _kube_v1_api is not None:
            return _kube_v1_api
        if not _kube_initialized:
            maybe_awaitable = k8s_config.load_incluster_config()
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable
            _kube_initialized = True
        _kube_api_client = k8s_client.ApiClient()
        _kube_v1_api = k8s_client.CoreV1Api(_kube_api_client)
        return _kube_v1_api


@functools.lru_cache(maxsize=4)
def _get_secrets_manager_client(region_name: str):
    """Cache AWS Secrets Manager clients by region to avoid rebuilding them per request."""
    return boto3.client("secretsmanager", region_name=region_name)


def _decode_jwt_payload(authorization: str | None) -> dict[str, Any] | None:
    """Return the decoded JWT payload from a Bearer header — *without* signature verification.

    Signature verification is performed at the platform edge (Kong-OIDC plugin) for inbound
    requests; rig consumes the already-validated token. Local re-verification (JWKS) is
    available via :mod:`rig.jwt_validator` when configured. This helper merely decodes the
    claims so rig can inject mandatory traceability and authorization-context headers and
    enforce vault-side freshness checks.
    """
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    segments = parts[1].split(".")
    if len(segments) < 2:
        return None
    try:
        payload = segments[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def _extract_subject(authorization: str | None) -> str | None:
    """Extract the 'sub' claim from a Bearer JWT without signature verification."""
    payload = _decode_jwt_payload(authorization)
    return payload.get("sub") if payload else None


def _extract_jti(authorization: str | None) -> str | None:
    """Extract the 'jti' (JWT ID) claim — the ephemeral session identifier (RFC Section 2D, ZT-REQ-09)."""
    payload = _decode_jwt_payload(authorization)
    return payload.get("jti") if payload else None


def _extract_project_context(authorization: str | None) -> str | None:
    """Extract the 'amsc_project_context' claim used for cross-checking the X-Project header (ZT-REQ-04)."""
    payload = _decode_jwt_payload(authorization)
    return payload.get("amsc_project_context") if payload else None


def _extract_auth_time(authorization: str | None) -> int | None:
    """Extract the 'auth_time' claim (epoch seconds) — used by facilities enforcing session freshness."""
    payload = _decode_jwt_payload(authorization)
    if not payload:
        return None
    value = payload.get("auth_time")
    if isinstance(value, (int, float)):
        return int(value)
    return None


def _extract_amr(authorization: str | None) -> list[str]:
    """Return the 'amr' claim as a list of strings (empty when absent or malformed)."""
    payload = _decode_jwt_payload(authorization)
    if not payload:
        return []
    raw = payload.get("amr")
    if isinstance(raw, list):
        return [str(v) for v in raw]
    if isinstance(raw, str):
        return [raw]
    return []


def _extract_acr(authorization: str | None) -> str | None:
    """Extract the 'acr' (assurance level) claim."""
    payload = _decode_jwt_payload(authorization)
    if not payload:
        return None
    value = payload.get("acr")
    return str(value) if value is not None else None


def _extract_idp(authorization: str | None) -> str | None:
    """Extract a best-effort upstream IdP indicator.

    Real-world IdPs use different claim names — Globus emits ``idp``, OneLogin /
    PingAM emit ``idp_id``, Keycloak emits ``identity_provider``. We try them in
    order and return the first match.
    """
    payload = _decode_jwt_payload(authorization)
    if not payload:
        return None
    for key in ("idp", "idp_id", "identity_provider"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _extract_act(authorization: str | None) -> str | None:
    """Extract the JWT ``act`` claim and return a stable string representation."""
    payload = _decode_jwt_payload(authorization)
    if not payload or "act" not in payload:
        return None
    value = payload["act"]
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _extract_subject_from_userinfo(userinfo_header: str | None) -> str | None:
    """Extract the trusted user subject from Kong's base64-encoded X-Userinfo header."""
    if not userinfo_header:
        return None
    try:
        padding = 4 - (len(userinfo_header) % 4)
        if padding < 4:
            userinfo_header += "=" * padding
        decoded = base64.b64decode(userinfo_header).decode("utf-8")
        data = json.loads(decoded)
        return data.get("sub")
    except Exception:
        logger.exception("Failed to parse trusted X-Userinfo header")
        return None


def _check_auth_freshness(
    authorization: str | None,
    max_age_seconds: int | None,
) -> tuple[bool, str | None]:
    """Reject a vault read when the JWT's ``auth_time`` is older than ``max_age_seconds``.

    Returns ``(ok, reason)``. ``reason`` is a stable code suitable for audit logs.
    Always passes when ``max_age_seconds`` is None (default).
    """
    if max_age_seconds is None:
        return True, None
    payload = _decode_jwt_payload(authorization)
    auth_time = payload.get("auth_time") if payload else None
    if not isinstance(auth_time, (int, float)):
        return False, "auth_time_missing"
    age = time.time() - float(auth_time)
    if age > max_age_seconds:
        return False, "auth_time_too_old"
    return True, None


def _credential_fingerprint(authorization: str) -> str:
    """SHA-256 fingerprint of a credential string, suitable for audit + pool detection."""
    return hashlib.sha256(authorization.encode("utf-8")).hexdigest()


def _record_pool_observation(
    fingerprint: str,
    sub: str,
    table_max: int,
) -> int:
    """Note that ``sub`` was issued the credential ``fingerprint``; return the distinct-sub count."""
    with _pool_lock:
        observers = _pool_observations.get(fingerprint)
        if observers is None:
            if len(_pool_observations) >= table_max:
                # Bound memory: drop an arbitrary entry rather than growing unbounded.
                _pool_observations.pop(next(iter(_pool_observations)))
            observers = set()
            _pool_observations[fingerprint] = observers
        observers.add(sub)
        return len(observers)


def _emit_binding_event(
    *,
    user: str,
    project: str,
    facility: str,
    fingerprint: str,
    backend: str,
) -> None:
    """RFC Section 3C "Binding Event": one structured record per successful vault read."""
    logger.info(
        "rig.vault.binding",
        extra={
            "audit": True,
            "event": "vault_binding",
            "user": user,
            "project": project,
            "facility": facility,
            "credential_fingerprint": fingerprint,
            "vault_backend": backend,
            "timestamp": time.time(),
        },
    )


async def resolve_identity(
    authorization: str | None,
    facility: str,
    project: str | None,
    http_client: httpx.AsyncClient,
    settings: Settings,
    user_identity: str | None = None,
    exchange_cache: ExchangeCache | None = None,
) -> tuple[str | None, str]:
    """Resolve upstream Authorization header via token exchange, vault lookup, or pass-through.

    Returns ``(authorization, mechanism)`` where ``mechanism`` is one of:

    * ``"exchange"`` — RFC 8693 token-exchange swapped the inbound bearer for a
      facility-local access token (Tier 2 success path).
    * ``"vault"`` — A vault lookup returned a stored facility credential
      (Tier 3 success path; also reached as a Tier-2-downgrade after exchange failure).
    * ``"passthrough"`` — Neither path resolved; the original bearer is forwarded
      unchanged (Tier 1, or Tier-2/3 fallback after both attempts failed).
    * ``"none"`` — No bearer header was present at all.

    The mechanism is reported back to the proxy so it can label the upstream
    request with ``X-AmSC-Exchange-Status`` and emit accurate audit records.
    """
    facility_config = settings.facilities.get(facility)
    cache = exchange_cache if exchange_cache is not None else _default_exchange_cache
    vault_enclave = facility_config.vault_enclave if facility_config else None

    # Tier 2 — RFC 8693 token exchange takes priority (e.g. Globus → SENSE-O).
    if facility_config and facility_config.token_exchange and authorization:
        sub_for_cache = user_identity if user_identity is not None else _extract_subject(authorization)
        result = await exchange_token(
            authorization,
            facility_config.token_exchange,
            http_client,
            sub=sub_for_cache,
            facility=facility,
            cache=cache,
        )
        if result is not None:
            logger.info("Token exchange resolved upstream authorization", extra={"facility": facility})
            return result, "exchange"
        logger.warning(
            "Token exchange failed, attempting Tier-3 vault downgrade",
            extra={"facility": facility},
        )

    # Tier 3 — vault lookup. Reached either as the primary path (no token_exchange
    # configured) or as a downgrade after a Tier-2 exchange failure.
    if settings.vault_backend:
        user = user_identity if user_identity is not None else _extract_subject(authorization)
        if user and project:
            ok, reason = _check_auth_freshness(authorization, settings.vault_max_auth_age_seconds)
            if not ok:
                logger.warning(
                    "Vault read denied: auth_time freshness check failed",
                    extra={"facility": facility, "user": user, "project": project, "reason": reason},
                )
            else:
                result = await _vault_lookup(user, project, facility, settings, enclave=vault_enclave)
                if result is not None:
                    fingerprint = _credential_fingerprint(result)
                    if settings.vault_pool_detect:
                        observers = _record_pool_observation(fingerprint, user, settings.vault_pool_table_max)
                        if observers > 1:
                            logger.warning(
                                "Vault pool detection: credential fingerprint shared across multiple subs",
                                extra={
                                    "facility": facility,
                                    "user": user,
                                    "project": project,
                                    "credential_fingerprint": fingerprint,
                                    "distinct_subs": observers,
                                },
                            )
                            if settings.vault_pool_deny:
                                logger.error(
                                    "Vault pool detection: denying request (vault_pool_deny=True)",
                                    extra={"facility": facility, "user": user, "project": project},
                                )
                                return authorization, ("passthrough" if authorization else "none")
                    _emit_binding_event(
                        user=user,
                        project=project,
                        facility=facility,
                        fingerprint=fingerprint,
                        backend=settings.vault_backend,
                    )
                    return result, "vault"
                logger.warning(
                    "Vault lookup failed, falling back to pass-through",
                    extra={"facility": facility, "vault_backend": settings.vault_backend},
                )
        elif not user:
            logger.warning("Cannot resolve vault credential: no user identity in token", extra={"facility": facility})
        elif not project:
            logger.warning("Cannot resolve vault credential: no project specified (X-Project header)", extra={"facility": facility})

    return authorization, ("passthrough" if authorization else "none")


async def _vault_lookup(
    user: str,
    project: str,
    facility: str,
    settings: Settings,
    enclave: str | None = None,
) -> str | None:
    """Dispatch to the configured vault backend (kube, aws, or docker)."""
    if settings.vault_backend == "kube":
        return await _vault_kube(user, project, facility, settings, enclave=enclave)
    elif settings.vault_backend == "aws":
        return await _vault_aws(user, project, facility, settings, enclave=enclave)
    elif settings.vault_backend == "docker":
        return await _vault_docker(user, project, facility, settings, enclave=enclave)
    else:
        logger.error("Unknown vault_backend: %s", settings.vault_backend)
        return None


def _vault_locator(settings: Settings, enclave: str | None) -> tuple[str, str, str]:
    """Resolve the effective ``(secret_prefix, kube_namespace, aws_region)`` for a vault lookup."""
    secret_prefix = settings.vault_secret_prefix
    kube_namespace = settings.vault_kube_namespace
    aws_region = settings.vault_aws_region
    if enclave:
        secret_prefix = settings.vault_secret_prefix_by_enclave.get(enclave, secret_prefix)
        kube_namespace = settings.vault_kube_namespace_by_enclave.get(enclave, kube_namespace)
        aws_region = settings.vault_aws_region_by_enclave.get(enclave, aws_region)
    return secret_prefix, kube_namespace, aws_region


async def _vault_kube(
    user: str,
    project: str,
    facility: str,
    settings: Settings,
    enclave: str | None = None,
) -> str | None:
    """Read a facility credential from a Kubernetes Secret."""
    secret_prefix, kube_namespace, _ = _vault_locator(settings, enclave)
    secret_name = f"{secret_prefix}-{user}-{project}-{facility}"
    try:
        v1 = await _get_kube_v1_api()
        secret = await v1.read_namespaced_secret(secret_name, kube_namespace)
        if secret.data and "token" in secret.data:
            token = base64.b64decode(secret.data["token"]).decode()
            logger.debug("Read token from kube secret %s", secret_name)
            return f"Bearer {token}" if not token.startswith("Bearer ") else token
        logger.warning("Kube secret %s has no 'token' key", secret_name)
    except Exception:
        logger.exception("Kube secret lookup failed for %s", secret_name)
    return None


async def _vault_aws(
    user: str,
    project: str,
    facility: str,
    settings: Settings,
    enclave: str | None = None,
) -> str | None:
    """Read a facility credential from AWS Secrets Manager."""
    secret_prefix, _, aws_region = _vault_locator(settings, enclave)
    secret_id = f"{secret_prefix}/{user}/{project}/{facility}"
    try:
        loop = asyncio.get_running_loop()
        sm = _get_secrets_manager_client(aws_region)
        resp = await loop.run_in_executor(
            None,
            functools.partial(sm.get_secret_value, SecretId=secret_id),
        )
        secret_string = resp.get("SecretString", "")
        if secret_string:
            try:
                data = json.loads(secret_string)
                token = data.get("token", secret_string)
            except json.JSONDecodeError:
                token = secret_string
            return f"Bearer {token}" if not token.startswith("Bearer ") else token
    except Exception:
        logger.exception("AWS Secrets Manager lookup failed for %s", secret_id)
    return None


async def _vault_docker(
    user: str,
    project: str,
    facility: str,
    settings: Settings,
    enclave: str | None = None,
) -> str | None:
    """Read a facility credential from the in-config docker_credentials map (local testing only)."""
    project_map = settings.docker_credentials.get(user, {}).get(project, {})
    token = project_map.get(facility)
    if token is None and enclave:
        enclave_map = project_map.get(enclave)
        if isinstance(enclave_map, dict):
            token = enclave_map.get(facility)
    if token:
        logger.debug("Read token from docker credentials for user=%s project=%s facility=%s", user, project, facility)
        return f"Bearer {token}" if not token.startswith("Bearer ") else token
    logger.warning(
        "No docker credential found",
        extra={"user": user, "project": project, "facility": facility},
    )
    return None
