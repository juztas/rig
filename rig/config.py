"""Pydantic-settings configuration loader with YAML file and environment variable support."""

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_REF_RE = re.compile(r"^\$\{([A-Z0-9_]+)(?::-([^}]*))?\}$")


class TokenExchangeConfig(BaseModel):
    """RFC 8693 token-exchange parameters for a facility that uses a different identity provider."""

    auth_endpoint: str
    client_id: str
    client_secret: str = ""
    # Issuer URI embedded in the incoming subject_token (Globus → https://auth.globus.org)
    subject_issuer: str = "https://auth.globus.org"
    # When False, the exchange POST is performed via a one-off ``httpx.AsyncClient``
    # with TLS verification disabled. Use only for local dev / self-signed facility
    # IdPs — production deployments must keep this True.
    verify_tls: bool = True
    # Bounds the synchronous edge-exchange budget per RFC Section 3B Path A. Default 5s.
    timeout_seconds: float = 5.0
    # ``audience`` parameter on the RFC 8693 form body. When None, falls back to
    # ``client_id`` for backward compatibility. Set explicitly when the facility's
    # IdP wants the resource server's URL rather than the client identifier.
    audience: str | None = None
    # ``scope`` parameter requested in the RFC 8693 form body. Lets rig pin the
    # downstream token to a narrow capability set instead of relying on the
    # facility IdP's default scope policy.
    requested_scope: str | None = None
    # If a returned (JWT) access token contains any of these scopes, rig treats
    # the exchange as a security violation and signals failure to the caller —
    # which forces a Tier-3 vault downgrade. Use to refuse over-broad grants
    # such as ``all`` or ``admin``.
    forbidden_scopes: list[str] = []
    # Cache TTL for exchanged tokens. ``None`` means derive from the access
    # token's ``exp`` claim minus ``cache_skew_seconds``; a positive integer
    # forces a fixed lifetime (used when the token is opaque or has no exp).
    cache_ttl_seconds: int | None = None
    # Skew subtracted from the access token's ``exp`` when deriving cache TTL,
    # so a request that hits the cache can never surface an already-expired
    # token to the upstream facility.
    cache_skew_seconds: int = 30


class JWTValidationConfig(BaseModel):
    """JWKS-backed inbound JWT validation, off by default.

    Disabled by default so that local development (e.g., the docker smoke test
    which uses unsigned ``alg=none`` tokens) keeps working. Enable in production
    to add a defense-in-depth check on top of Kong's edge validation.
    """

    enabled: bool = False
    jwks_url: str = ""
    issuer: str = ""
    audience: list[str] = []
    leeway_seconds: int = 30
    cache_ttl_seconds: int = 3600
    algorithms: list[str] = ["RS256", "ES256", "RS384", "RS512", "ES384", "ES512"]


class FacilityConfig(BaseModel):
    """Upstream facility connection parameters."""

    base_url: str
    timeout: float = 60.0
    # When set, RIG exchanges the caller's Bearer token via RFC 8693 before proxying.
    token_exchange: TokenExchangeConfig | None = None
    # Explicit RIG integration tier for this facility (1=native OIDC pass-through,
    # 2=RFC 8693 token exchange, 3=vaulted credentials). Optional — when None, rig
    # infers it: token_exchange present -> 2; else (if global vault_backend is set) -> 3;
    # else -> 1. Set explicitly to surface the contract clearly in logs and admin tooling.
    tier: int | None = None


def resolve_tier(facility: "FacilityConfig", vault_backend: str) -> int:
    """Infer the integration tier for a facility when not set explicitly.

    1 = native OIDC pass-through (Tier 1, RFC Section 3A)
    2 = RFC 8693 token exchange (Tier 2, RFC Section 3B)
    3 = vaulted credentials (Tier 3, RFC Section 3C)
    """
    if facility.tier is not None:
        return facility.tier
    if facility.token_exchange is not None:
        return 2
    if vault_backend:
        return 3
    return 1


class Settings(BaseSettings):
    """RIG application settings, loaded from YAML then overridden by RIG_* env vars."""

    model_config = SettingsConfigDict(env_prefix="RIG_")

    facilities: dict[str, FacilityConfig] = {}

    max_connections: int = 1000
    max_keepalive_connections: int = 100
    default_timeout: float = 60.0

    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    log_level: str = "INFO"

    vault_backend: str = ""  # "kube", "aws", or "docker" — empty disables vault lookup
    vault_kube_namespace: str = "default"
    vault_aws_region: str = "us-east-1"
    vault_secret_prefix: str = "rig-creds"  # k8s: {prefix}-{user}-{project}-{facility}, AWS: {prefix}/{user}/{project}/{facility}
    # docker backend: flat credential map for local testing — user -> project -> facility -> token
    docker_credentials: dict[str, dict[str, dict[str, str]]] = {}
    policy_engine_url: str = ""

    # Maximum allowed age (seconds) of the inbound JWT's ``auth_time`` claim before
    # rig will perform a vault read. ``None`` (default) disables the check. RFC Section 3C
    # "MFA Inheritance & Freshness" — accessing high-value legacy keys requires a
    # recent proof of presence ("sudo mode" semantics for the vault).
    vault_max_auth_age_seconds: int | None = None

    # When True, rig fingerprints every credential returned by the vault and warns
    # if the same fingerprint is observed for more than one distinct user — RFC Section 3C
    # "Prohibition of Pooling". Set ``vault_pool_deny`` to additionally reject the
    # request when pooling is detected (default is warn-only).
    vault_pool_detect: bool = True
    vault_pool_deny: bool = False
    # Bound on the in-process fingerprint observation table.
    vault_pool_table_max: int = 1024

    # IP allowlist for service-token (non-MFA) callers — RFC Section 3C "Compensating
    # Controls". When non-empty, any inbound bearer whose ``amr`` claim does not
    # contain a recognized MFA value AND whose ingress IP falls outside this CIDR
    # list is rejected with 403. An empty list disables enforcement.
    service_account_allowed_cidrs: list[str] = []
    service_account_mfa_amr_values: list[str] = ["mfa", "otp", "hwk", "fpt", "hwk-pin"]

    # JWKS-backed inbound JWT validation. Off by default.
    jwt_validation: JWTValidationConfig = JWTValidationConfig()

    # Token revocation (RFC Section 2F). Both checks are off when the corresponding
    # field is empty / None. When both are set, Redis is consulted first (low
    # latency) and DNSBL is the cross-facility fallback / kill switch.
    revocation_redis_url: str | None = None
    revocation_redis_key_prefix: str = "rig:blocklist:"
    # Connection budget for the Redis blocklist check. The check fails open when
    # the budget is exceeded — revocation is defense-in-depth on top of token
    # expiry, so a sluggish Redis must not break the request path.
    revocation_redis_timeout_seconds: float = 0.5
    revocation_dnsbl_zone: str = ""
    # In-process LRU TTL cache for DNSBL lookups. RFC Section 2F mandates a 60s
    # zone TTL; matching that here gives at-most-one-minute global propagation.
    revocation_dnsbl_ttl_seconds: int = 60
    revocation_dnsbl_cache_max: int = 4096

    # Differentiated 401 challenge. When ``auth_redirect_login_url`` is set and
    # the caller signals ``Accept: text/html``, rig responds with a 302 redirect
    # to the configured login flow instead of a JSON 401. CLI / SDK callers
    # always receive JSON 401 — with ``challenge_uri`` populated when
    # ``auth_device_flow_uri`` is configured.
    auth_redirect_login_url: str = ""
    auth_device_flow_uri: str = ""

    # Static bearer token for the admin endpoints (POST /admin/blocklist, etc).
    # Empty (default) disables the routes entirely. Operators can rotate this
    # via the RIG_ADMIN_API_TOKEN env var without restarting other components.
    admin_api_token: str = ""


def _load_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a YAML file, returning an empty dict if the file does not exist."""
    if path.is_file():
        with open(path) as f:
            return _expand_env_refs(yaml.safe_load(f) or {})
    return {}


def _expand_env_refs(value: Any) -> Any:
    """Recursively expand `${ENV_VAR}` or `${ENV_VAR:-default}` string values."""
    if isinstance(value, dict):
        return {k: _expand_env_refs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_refs(v) for v in value]
    if isinstance(value, str):
        match = _ENV_REF_RE.match(value)
        if match:
            env_name, default = match.groups()
            return os.environ.get(env_name, default or "")
    return value


def load_settings() -> Settings:
    """Load settings from the YAML config file specified by RIG_CONFIG_PATH."""
    config_path = Path(os.environ.get("RIG_CONFIG_PATH", "config.yaml"))
    yaml_data = _load_yaml(config_path)
    return Settings(**yaml_data)


settings = load_settings()
