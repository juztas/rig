"""Pydantic-settings configuration loader with YAML file and environment variable support."""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class FacilityConfig(BaseModel):
    """Upstream facility connection parameters."""

    base_url: str
    timeout: float = 60.0


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

    vault_backend: str = ""  # "kube" or "aws" — empty disables vault lookup
    vault_kube_namespace: str = "default"
    vault_aws_region: str = "us-east-1"
    vault_secret_prefix: str = "rig-creds"  # k8s: {prefix}-{user}-{project}-{facility}, AWS: {prefix}/{user}/{project}/{facility}
    policy_engine_url: str = ""


def _load_yaml(path: Path) -> dict[str, Any]:
    """Read and parse a YAML file, returning an empty dict if the file does not exist."""
    if path.is_file():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_settings() -> Settings:
    """Load settings from the YAML config file specified by RIG_CONFIG_PATH."""
    config_path = Path(os.environ.get("RIG_CONFIG_PATH", "config.yaml"))
    yaml_data = _load_yaml(config_path)
    return Settings(**yaml_data)


settings = load_settings()
