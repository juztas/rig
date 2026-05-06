from types import SimpleNamespace

import httpx
import pytest
from starlette.datastructures import Headers

import rig.app as app_mod
import rig.identity as identity_mod
import rig.proxy as proxy_mod
from rig.config import FacilityConfig, Settings
from rig.headers import filter_request_headers, filter_response_headers
from rig.identity import _extract_subject, resolve_identity
from rig.policy import is_allowed
from rig.app import app


def test_hop_by_hop_stripped_from_request():
    headers = Headers(
        {
            "connection": "keep-alive",
            "keep-alive": "5",
            "authorization": "Bearer x",
            "x-custom": "val",
        }
    )
    out = filter_request_headers(headers, request_id="rid-1")
    assert "connection" not in out
    assert "keep-alive" not in out
    assert out["authorization"] == "Bearer x"
    assert out["x-custom"] == "val"
    assert out["x-request-id"] == "rid-1"


def test_host_stripped_from_request():
    headers = Headers({"host": "rig.example.com", "accept": "application/json"})
    out = filter_request_headers(headers, request_id="rid-2")
    assert "host" not in out
    assert out["accept"] == "application/json"


def test_hop_by_hop_stripped_from_response():
    headers = Headers(
        {
            "transfer-encoding": "chunked",
            "content-type": "application/json",
            "connection": "keep-alive",
        }
    )
    out = filter_response_headers(headers)
    assert "transfer-encoding" not in out
    assert "connection" not in out
    assert out["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_pass_through_token():
    settings = Settings(facilities={})
    async with httpx.AsyncClient() as client:
        result = await resolve_identity("Bearer abc123", "nersc", "myproject", client, settings)
    assert result == "Bearer abc123"


@pytest.mark.asyncio
async def test_no_auth_passes_none():
    settings = Settings(facilities={})
    async with httpx.AsyncClient() as client:
        result = await resolve_identity(None, "nersc", None, client, settings)
    assert result is None


@pytest.mark.asyncio
async def test_resolve_identity_uses_precomputed_subject():
    settings = Settings(facilities={}, vault_backend="kube")
    async with httpx.AsyncClient() as client:
        result = await resolve_identity(
            "Bearer abc123",
            "nersc",
            "myproject",
            client,
            settings,
            user_identity="cached-user",
        )
    assert result == "Bearer abc123"


@pytest.mark.asyncio
async def test_kube_client_initialized_once(monkeypatch):
    calls = {"load": 0, "api_client": 0, "core_v1": 0}

    class FakeApiClient:
        pass

    class FakeCoreV1Api:
        def __init__(self, api_client):
            self.api_client = api_client

    def fake_load_incluster_config():
        calls["load"] += 1

    def fake_api_client():
        calls["api_client"] += 1
        return FakeApiClient()

    def fake_core_v1_api(api_client):
        calls["core_v1"] += 1
        return FakeCoreV1Api(api_client)

    monkeypatch.setattr(identity_mod, "_kube_initialized", False)
    monkeypatch.setattr(identity_mod, "_kube_api_client", None)
    monkeypatch.setattr(identity_mod, "_kube_v1_api", None)
    monkeypatch.setattr(identity_mod.k8s_config, "load_incluster_config", fake_load_incluster_config)
    monkeypatch.setattr(identity_mod.k8s_client, "ApiClient", fake_api_client)
    monkeypatch.setattr(identity_mod.k8s_client, "CoreV1Api", fake_core_v1_api)

    first = await identity_mod._get_kube_v1_api()
    second = await identity_mod._get_kube_v1_api()

    assert first is second
    assert calls == {"load": 1, "api_client": 1, "core_v1": 1}


def test_extract_subject_from_jwt():
    import base64
    import json

    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user42"}).encode()).rstrip(b"=").decode()
    token = f"Bearer header.{payload}.sig"
    assert _extract_subject(token) == "user42"


@pytest.mark.asyncio
async def test_policy_stub_allows_all():
    settings = Settings(facilities={})
    async with httpx.AsyncClient() as client:
        assert await is_allowed("user1", "nersc", "/compute/jobs", "GET", client, settings) is True


def test_settings_defaults():
    settings = Settings(facilities={})
    assert settings.max_connections == 1000
    assert settings.max_keepalive_connections == 100
    assert settings.default_timeout == 60.0
    assert settings.vault_backend == ""
    assert settings.policy_engine_url == ""


class FakeUpstreamResponse:
    def __init__(self, *, status_code: int = 200, headers: dict[str, str] | None = None, body: bytes = b"{}"):
        self.status_code = status_code
        self.headers = headers or {"content-type": "application/json"}
        self._body = body
        self.closed = False

    async def aiter_raw(self):
        yield self._body

    async def aclose(self):
        self.closed = True


class RecordingHttpClient:
    def __init__(self, response: FakeUpstreamResponse):
        self.response = response
        self.is_closed = False
        self.request_args = None
        self.sent_request = None

    def build_request(self, **kwargs):
        self.request_args = kwargs
        return SimpleNamespace(**kwargs, extensions={})

    async def send(self, request, stream=True):
        self.sent_request = request
        return self.response


@pytest.fixture
async def test_client(monkeypatch):
    test_settings = Settings(
        facilities={
            "test-facility": FacilityConfig(base_url="https://upstream.example/api/"),
        }
    )

    monkeypatch.setattr(app_mod, "settings", test_settings)
    monkeypatch.setattr(proxy_mod, "settings", test_settings)

    app.state.http_client = SimpleNamespace(is_closed=False)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        yield client, app, proxy_mod


@pytest.mark.asyncio
async def test_health_endpoint(test_client):
    client, _, _ = test_client
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_ready_endpoint_requires_initialized_client(test_client):
    client, app, _ = test_client
    delattr(app.state, "http_client")
    response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["reason"] == "http client not initialized"


@pytest.mark.asyncio
async def test_ready_endpoint_returns_facilities(test_client):
    client, app, _ = test_client
    app.state.http_client = SimpleNamespace(is_closed=False)
    response = await client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "facilities": ["test-facility"]}


@pytest.mark.asyncio
async def test_unknown_facility_returns_404(test_client):
    client, _, _ = test_client
    response = await client.get("/nonexistent/some/path")
    assert response.status_code == 404
    assert "Unknown facility" in response.json()["error"]


@pytest.mark.asyncio
async def test_proxy_preserves_duplicate_query_params_and_resolved_auth(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse(body=b'{"proxied": true}')
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client
    seen = {"extract_calls": 0, "user_identity": None}

    def fake_extract_subject(authorization):
        seen["extract_calls"] += 1
        return "user-123"

    async def fake_resolve_identity(*args, **kwargs):
        seen["user_identity"] = kwargs.get("user_identity")
        return "Bearer resolved"

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "_extract_subject", fake_extract_subject)
    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get(
        "/test-facility/echo?a=1&a=2&b=3",
        headers={"authorization": "Bearer original", "x-project": "demo"},
    )

    assert response.status_code == 200
    assert response.json() == {"proxied": True}
    assert recording_client.request_args["url"] == "https://upstream.example/api/echo"
    assert recording_client.request_args["params"] == [("a", "1"), ("a", "2"), ("b", "3")]
    assert recording_client.request_args["timeout"] == httpx.Timeout(60.0, connect=10.0)
    assert recording_client.request_args["headers"]["authorization"] == "Bearer resolved"
    assert "x-request-id" in recording_client.request_args["headers"]
    assert seen["extract_calls"] == 1
    assert seen["user_identity"] == "user-123"
    assert upstream.closed is True


@pytest.mark.asyncio
async def test_proxy_uses_facility_specific_timeout(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    timeout_settings = Settings(
        facilities={"test-facility": FacilityConfig(base_url="https://upstream.example/api/", timeout=12.5)}
    )
    monkeypatch.setattr(app_mod, "settings", timeout_settings)
    monkeypatch.setattr(proxy_mod, "settings", timeout_settings)

    upstream = FakeUpstreamResponse(body=b'{"proxied": true}')
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return "Bearer resolved"

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/echo")

    assert response.status_code == 200
    assert recording_client.request_args["timeout"] == httpx.Timeout(12.5, connect=10.0)


@pytest.mark.asyncio
async def test_proxy_denies_when_policy_rejects(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_is_allowed(*args, **kwargs):
        return False

    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/secure")
    assert response.status_code == 403
    assert response.json() == {"error": "Forbidden by policy"}
