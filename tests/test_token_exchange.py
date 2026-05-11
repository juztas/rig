"""Minimal tests for SENSE-O RFC 8693 token exchange."""

import json

import httpx
import pytest

from rig.config import FacilityConfig, Settings, TokenExchangeConfig
from rig.identity import resolve_identity
from rig.token_exchange import _strip_bearer, exchange_token

SENSE_AUTH = "https://sense-o-east.es.net:8543/realms/StackV/protocol/openid-connect/token"
GLOBUS_TOKEN = "AgPrKp1DVv9j0KW9jYe9oP2Bxk2NWkD9Oo6QGnXXQd4eOq8eOqfmC4aBEqdDQmYmQe7jVvX6dkYxQVuJlVrX7CwgGYk"

_EXCHANGE_CFG = TokenExchangeConfig(
    auth_endpoint=SENSE_AUTH,
    client_id="Portal",
    client_secret="",
    subject_issuer="https://auth.globus.org",
    verify_tls=True,  # Mock transport does not need TLS verify disabled.
)


# ---------------------------------------------------------------------------
# _strip_bearer
# ---------------------------------------------------------------------------

def test_strip_bearer_extracts_token():
    assert _strip_bearer(f"Bearer {GLOBUS_TOKEN}") == GLOBUS_TOKEN


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
        result = await exchange_token(f"Bearer {GLOBUS_TOKEN}", _EXCHANGE_CFG, client)
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
        await exchange_token(f"Bearer {GLOBUS_TOKEN}", _EXCHANGE_CFG, client)

    assert len(captured) == 1
    req = captured[0]
    assert req.url == SENSE_AUTH
    body = req.content.decode()
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" in body
    assert GLOBUS_TOKEN in body
    assert "subject_issuer=https%3A%2F%2Fauth.globus.org" in body
    assert "client_id=Portal" in body


@pytest.mark.asyncio
async def test_exchange_token_returns_none_on_http_error():
    transport = _MockTransport(401, {"error": "invalid_token", "error_description": "Token rejected"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await exchange_token(f"Bearer {GLOBUS_TOKEN}", _EXCHANGE_CFG, client)
    assert result is None


@pytest.mark.asyncio
async def test_exchange_token_returns_none_on_missing_access_token():
    transport = _MockTransport(200, {"token_type": "bearer"})  # no access_token key
    async with httpx.AsyncClient(transport=transport) as client:
        result = await exchange_token(f"Bearer {GLOBUS_TOKEN}", _EXCHANGE_CFG, client)
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
            f"Bearer {GLOBUS_TOKEN}",
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
        facilities={"nersc": FacilityConfig(base_url="https://api.iri.nersc.gov/api/v1")}
    )
    transport = _MockTransport(200, {"access_token": "should-not-be-called"})
    async with httpx.AsyncClient(transport=transport) as client:
        result = await resolve_identity("Bearer original-token", "nersc", None, client, settings)
    assert result == ("Bearer original-token", "passthrough")
