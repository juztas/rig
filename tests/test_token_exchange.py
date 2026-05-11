"""Minimal tests for SENSE-O RFC 8693 token exchange."""

import json
import os

import httpx
import pytest

import rig.config as config_mod
from rig.config import FacilityConfig, Settings, TokenExchangeConfig
from rig.identity import resolve_identity
from rig.token_exchange import _strip_bearer, exchange_token

SENSE_AUTH = "https://sense-o-east.es.net:8543/realms/StackV/protocol/openid-connect/token"


def _test_subject_token() -> str:
    return os.environ["RIG_TEST_SUBJECT_TOKEN"]


@pytest.fixture(autouse=True)
def _default_test_subject_token_env(monkeypatch):
    monkeypatch.setenv("RIG_TEST_SUBJECT_TOKEN", os.environ.get("RIG_TEST_SUBJECT_TOKEN", "test-globus-token"))

_EXCHANGE_CFG = TokenExchangeConfig(
    auth_endpoint=SENSE_AUTH,
    client_id="test-client-id",
    client_secret="test-client-secret",
    subject_issuer="https://auth.globus.org",
    verify_tls=True,  # Mock transport does not need TLS verify disabled.
)


# ---------------------------------------------------------------------------
# _strip_bearer
# ---------------------------------------------------------------------------

def test_strip_bearer_extracts_token():
    token = _test_subject_token()
    assert _strip_bearer(f"Bearer {token}") == token


def test_strip_bearer_case_insensitive():
    assert _strip_bearer(f"bearer abc123") == "abc123"


def test_strip_bearer_returns_none_for_non_bearer():
    assert _strip_bearer("Basic dXNlcjpwYXNz") is None
    assert _strip_bearer("") is None


# ---------------------------------------------------------------------------
# exchange_token — happy path (mocked transport)
# ---------------------------------------------------------------------------

class _MockTransport(httpx.AsyncBaseTransport):
    """Returns a pre-canned JSON response for any request."""

    def __init__(self, status: int, body: dict):
        self._status = status
        self._body = json.dumps(body).encode()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=self._status,
            headers={"content-type": "application/json"},
            content=self._body,
            request=request,
        )


@pytest.mark.asyncio
async def test_exchange_token_returns_bearer_on_success():
    transport = _MockTransport(200, {"access_token": "sense-o-access-token-xyz"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await exchange_token(f"Bearer {_test_subject_token()}", _EXCHANGE_CFG, client)
    assert result == "Bearer sense-o-access-token-xyz"


@pytest.mark.asyncio
async def test_exchange_token_sends_correct_form_body():
    captured: list[httpx.Request] = []

    class CapturingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured.append(request)
            body = {"access_token": "tok"}
            return httpx.Response(200, headers={"content-type": "application/json"}, content=json.dumps(body).encode(), request=request)

    async with httpx.AsyncClient(transport=CapturingTransport()) as client:
        await exchange_token(f"Bearer {_test_subject_token()}", _EXCHANGE_CFG, client)

    assert len(captured) == 1
    req = captured[0]
    assert req.url == SENSE_AUTH
    body = req.content.decode()
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" in body
    assert _test_subject_token() in body
    assert "subject_issuer=https%3A%2F%2Fauth.globus.org" in body
    assert "client_id=test-client-id" in body
    assert "client_secret=test-client-secret" in body


@pytest.mark.asyncio
async def test_exchange_token_returns_none_on_http_error():
    transport = _MockTransport(401, {"error": "invalid_token", "error_description": "Token rejected"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await exchange_token(f"Bearer {_test_subject_token()}", _EXCHANGE_CFG, client)
    assert result is None


@pytest.mark.asyncio
async def test_exchange_token_returns_none_on_missing_access_token():
    transport = _MockTransport(200, {"token_type": "bearer"})  # no access_token key
    async with httpx.AsyncClient(transport=transport) as client:
        result = await exchange_token(f"Bearer {_test_subject_token()}", _EXCHANGE_CFG, client)
    assert result is None


@pytest.mark.asyncio
async def test_exchange_token_returns_none_for_non_bearer_header():
    transport = _MockTransport(200, {"access_token": "should-not-reach"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await exchange_token("Basic dXNlcjpwYXNz", _EXCHANGE_CFG, client)
    assert result is None


# ---------------------------------------------------------------------------
# resolve_identity integration — token exchange path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_identity_uses_token_exchange_for_orchestrator():
    """When a facility has token_exchange config, resolve_identity should exchange the token."""
    settings = Settings(
        facilities={
            "orchestrator": FacilityConfig(
                base_url="https://sense-o-east.es.net:8543/api",
                token_exchange=_EXCHANGE_CFG,
            )
        }
    )

    transport = _MockTransport(200, {"access_token": "sense-o-token-abc"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await resolve_identity(
            f"Bearer {_test_subject_token()}",
            "orchestrator",
            None,
            client,
            settings,
        )
    assert result == ("Bearer sense-o-token-abc", "exchange")


@pytest.mark.asyncio
async def test_resolve_identity_passes_through_when_no_exchange_config():
    """Facilities without token_exchange config keep their original authorization."""
    settings = Settings(
        facilities={"nersc": FacilityConfig(base_url="https://api.iri.nersc.gov")}
    )
    transport = _MockTransport(200, {"access_token": "should-not-be-called"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await resolve_identity("Bearer original-token", "nersc", None, client, settings)
    assert result == ("Bearer original-token", "passthrough")


def test_load_settings_expands_env_refs(tmp_path, monkeypatch):
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
facilities:
  orchestrator:
    base_url: "https://sense-o-east.es.net:8543"
    token_exchange:
      auth_endpoint: "https://sense-o-east.es.net:8543/realms/StackV/protocol/openid-connect/token"
      client_id: "${RIG_ORCHESTRATOR_CLIENT_ID}"
      client_secret: "${RIG_ORCHESTRATOR_CLIENT_SECRET:-fallback-secret}"
"""
    )
    monkeypatch.setenv("RIG_CONFIG_PATH", str(config_file))
    monkeypatch.setenv("RIG_ORCHESTRATOR_CLIENT_ID", "env-client-id")
    monkeypatch.delenv("RIG_ORCHESTRATOR_CLIENT_SECRET", raising=False)

    settings = config_mod.load_settings()

    token_exchange = settings.facilities["orchestrator"].token_exchange
    assert token_exchange is not None
    assert token_exchange.client_id == "env-client-id"
    assert token_exchange.client_secret == "fallback-secret"


def test_subject_token_reads_from_env(monkeypatch):
    monkeypatch.setenv("RIG_TEST_SUBJECT_TOKEN", "env-test-token")
    assert _test_subject_token() == "env-test-token"
