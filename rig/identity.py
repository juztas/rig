"""Two-tier identity resolution: pass-through or vaulted credential lookup."""

import asyncio
import base64
import functools
import json
from typing import Any

import boto3
import httpx
from kubernetes_asyncio import client as k8s_client
from kubernetes_asyncio import config as k8s_config

from .config import Settings
from .logging import get_logger

logger = get_logger(__name__)

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
            await k8s_config.load_incluster_config()
            _kube_initialized = True
        _kube_api_client = k8s_client.ApiClient()
        _kube_v1_api = k8s_client.CoreV1Api(_kube_api_client)
        return _kube_v1_api


@functools.lru_cache(maxsize=4)
def _get_secrets_manager_client(region_name: str):
    """Cache AWS Secrets Manager clients by region to avoid rebuilding them per request."""
    return boto3.client("secretsmanager", region_name=region_name)


def _extract_subject(authorization: str | None) -> str | None:
    """Extract the 'sub' claim from a Bearer JWT without signature verification."""
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
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("sub")
    except Exception:
        return None


async def resolve_identity(
    authorization: str | None,
    facility: str,
    project: str | None,
    http_client: httpx.AsyncClient,
    settings: Settings,
    user_identity: str | None = None,
) -> str | None:
    """Resolve upstream Authorization header via vault lookup or pass-through."""
    if settings.vault_backend:
        user = user_identity if user_identity is not None else _extract_subject(authorization)
        if user and project:
            result = await _vault_lookup(user, project, facility, settings)
            if result is not None:
                return result
            logger.warning("Vault lookup failed, falling back to pass-through", extra={"facility": facility, "vault_backend": settings.vault_backend})
        elif not user:
            logger.warning("Cannot resolve vault credential: no user identity in token", extra={"facility": facility})
        elif not project:
            logger.warning("Cannot resolve vault credential: no project specified (X-Project header)", extra={"facility": facility})

    return authorization


async def _vault_lookup(
    user: str,
    project: str,
    facility: str,
    settings: Settings,
) -> str | None:
    """Dispatch to the configured vault backend (kube or aws)."""
    if settings.vault_backend == "kube":
        return await _vault_kube(user, project, facility, settings)
    elif settings.vault_backend == "aws":
        return await _vault_aws(user, project, facility, settings)
    else:
        logger.error("Unknown vault_backend: %s", settings.vault_backend)
        return None


async def _vault_kube(
    user: str,
    project: str,
    facility: str,
    settings: Settings,
) -> str | None:
    """Read a facility credential from a Kubernetes Secret."""
    secret_name = f"{settings.vault_secret_prefix}-{user}-{project}-{facility}"
    try:
        v1 = await _get_kube_v1_api()
        secret = await v1.read_namespaced_secret(secret_name, settings.vault_kube_namespace)
        if secret.data and "token" in secret.data:
            token = base64.b64decode(secret.data["token"]).decode()
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
) -> str | None:
    """Read a facility credential from AWS Secrets Manager."""
    secret_id = f"{settings.vault_secret_prefix}/{user}/{project}/{facility}"
    try:
        loop = asyncio.get_running_loop()
        sm = _get_secrets_manager_client(settings.vault_aws_region)
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
