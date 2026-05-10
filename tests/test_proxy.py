from types import SimpleNamespace

import httpx
import pytest
from starlette.datastructures import Headers

import rig.app as app_mod
import rig.identity as identity_mod
import rig.proxy as proxy_mod
from rig.config import FacilityConfig, Settings
from rig.headers import filter_request_headers, filter_response_headers
from rig.identity import _extract_subject, _extract_subject_from_userinfo, resolve_identity
from rig.policy import is_allowed
from rig.app import app
from rig.proxy import _merge_forwarded_prefix


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


def test_merge_forwarded_prefix_appends_facility():
    assert _merge_forwarded_prefix(None, "esnet-east") == "/esnet-east"
    assert _merge_forwarded_prefix("/proxy", "esnet-east") == "/proxy/esnet-east"


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
    assert result == ("Bearer abc123", "passthrough")


@pytest.mark.asyncio
async def test_no_auth_passes_none():
    settings = Settings(facilities={})
    async with httpx.AsyncClient() as client:
        result = await resolve_identity(None, "nersc", None, client, settings)
    assert result == (None, "none")


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
    # vault is configured but the kube secret lookup fails (no in-cluster config in tests),
    # so resolve_identity falls through to pass-through.
    assert result == ("Bearer abc123", "passthrough")


@pytest.mark.asyncio
async def test_kube_client_initialized_once(monkeypatch):
    calls = {"load": 0, "api_client": 0, "core_v1": 0}

    class FakeApiClient:
        pass

    class FakeCoreV1Api:
        def __init__(self, api_client):
            self.api_client = api_client

    async def fake_load_incluster_config():
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


def test_extract_subject_from_userinfo():
    import base64
    import json

    payload = base64.b64encode(json.dumps({"sub": "userinfo-user"}).encode()).decode()
    assert _extract_subject_from_userinfo(payload) == "userinfo-user"


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
    assert response.json() == {
        "status": "ready",
        "facilities": [{"name": "test-facility", "tier": 1}],
    }


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
        return ("Bearer resolved", "passthrough")

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
    assert recording_client.request_args["headers"]["x-forwarded-host"] == "test"
    assert recording_client.request_args["headers"]["x-forwarded-proto"] == "http"
    assert recording_client.request_args["headers"]["x-forwarded-prefix"] == "/test-facility"
    assert "x-request-id" in recording_client.request_args["headers"]
    assert seen["extract_calls"] == 1
    assert seen["user_identity"] == "user-123"
    assert upstream.closed is True


@pytest.mark.asyncio
async def test_proxy_prefers_trusted_userinfo_header(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse(body=b'{"proxied": true}')
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client
    seen = {"jwt_extract_calls": 0, "userinfo_extract_calls": 0, "user_identity": None}

    def fake_extract_subject_from_userinfo(userinfo):
        seen["userinfo_extract_calls"] += 1
        return "trusted-user"

    def fake_extract_subject(authorization):
        seen["jwt_extract_calls"] += 1
        return "jwt-user"

    async def fake_resolve_identity(*args, **kwargs):
        seen["user_identity"] = kwargs.get("user_identity")
        return ("Bearer resolved", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "_extract_subject_from_userinfo", fake_extract_subject_from_userinfo)
    monkeypatch.setattr(proxy_mod, "_extract_subject", fake_extract_subject)
    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get(
        "/test-facility/echo",
        headers={
            "authorization": "Bearer opaque-token",
            "x-project": "demo",
            "x-userinfo": "encoded-userinfo",
        },
    )

    assert response.status_code == 200
    assert seen["userinfo_extract_calls"] == 1
    assert seen["jwt_extract_calls"] == 0
    assert seen["user_identity"] == "trusted-user"
    assert recording_client.request_args["headers"]["x-forwarded-prefix"] == "/test-facility"


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
        return ("Bearer resolved", "passthrough")

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


# --- tier inference -----------------------------------------------------

def test_resolve_tier_explicit_overrides_inference():
    from rig.config import resolve_tier
    fc = FacilityConfig(base_url="https://x", tier=2)
    assert resolve_tier(fc, vault_backend="docker") == 2  # explicit wins


def test_resolve_tier_token_exchange_implies_tier2():
    from rig.config import resolve_tier, TokenExchangeConfig
    fc = FacilityConfig(
        base_url="https://x",
        token_exchange=TokenExchangeConfig(auth_endpoint="https://idp/token", client_id="c"),
    )
    assert resolve_tier(fc, vault_backend="") == 2


def test_resolve_tier_vault_backend_implies_tier3():
    from rig.config import resolve_tier
    fc = FacilityConfig(base_url="https://x")
    assert resolve_tier(fc, vault_backend="docker") == 3


def test_resolve_tier_default_is_tier1():
    from rig.config import resolve_tier
    fc = FacilityConfig(base_url="https://x")
    assert resolve_tier(fc, vault_backend="") == 1


# --- project-context cross-check -----------------------------------------

def _bearer_with_claims(**claims):
    """Build a Bearer header whose payload base64-decodes to ``claims`` (no signature)."""
    import base64 as b64
    import json as j
    header = b64.urlsafe_b64encode(j.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    payload = b64.urlsafe_b64encode(j.dumps(claims).encode()).rstrip(b"=").decode()
    return f"Bearer {header}.{payload}.sig"


@pytest.mark.asyncio
async def test_project_mismatch_returns_403(test_client):
    client, app, _ = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())
    auth = _bearer_with_claims(sub="user-1", amsc_project_context="proj-claim")
    response = await client.get(
        "/test-facility/anything",
        headers={"authorization": auth, "x-project": "proj-header"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["header_project"] == "proj-header"
    assert body["claim_project"] == "proj-claim"


@pytest.mark.asyncio
async def test_project_match_passes(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer resolved", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    auth = _bearer_with_claims(sub="user-1", amsc_project_context="agree", jti="jti-1")
    response = await client.get(
        "/test-facility/anything",
        headers={"authorization": auth, "x-project": "agree"},
    )
    assert response.status_code == 200


# --- tier-3 missing-project rejection -----------------------------------

@pytest.fixture
async def tier3_client(monkeypatch):
    """Test client with a single tier-3 (vault-backed) facility."""
    test_settings = Settings(
        facilities={"vaulted": FacilityConfig(base_url="https://upstream.example/api/")},
        vault_backend="docker",
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
async def test_tier3_missing_project_returns_400(tier3_client):
    client, app, _ = tier3_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())
    auth = _bearer_with_claims(sub="user-1")  # no amsc_project_context
    response = await client.get("/vaulted/anything", headers={"authorization": auth})
    assert response.status_code == 400
    body = response.json()
    assert "Tier-3" in body["error"]
    assert body["facility"] == "vaulted"


@pytest.mark.asyncio
async def test_tier3_with_project_in_header_passes(tier3_client, monkeypatch):
    client, app, proxy_mod = tier3_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer resolved", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    auth = _bearer_with_claims(sub="user-1")
    response = await client.get(
        "/vaulted/anything",
        headers={"authorization": auth, "x-project": "p1"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_tier1_missing_project_still_passes(test_client, monkeypatch):
    """Tier-1 (no vault, no token exchange) must NOT require X-Project."""
    client, app, proxy_mod = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer resolved", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/anything")  # no headers at all
    assert response.status_code == 200


# --- X-AmSC-* header injection ------------------------------------------

@pytest.mark.asyncio
async def test_xamsc_traceability_headers_injected_upstream(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer resolved", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    auth = _bearer_with_claims(sub="auid-42", jti="jti-7", amsc_project_context="genesis")
    response = await client.get(
        "/test-facility/echo",
        headers={"authorization": auth, "x-project": "genesis"},
    )
    assert response.status_code == 200
    upstream_headers = recording_client.request_args["headers"]
    assert upstream_headers["x-amsc-user"] == "auid-42"
    assert upstream_headers["x-amsc-project"] == "genesis"
    assert upstream_headers.get("x-amsc-trace-id"), "trace-id must be set"


# --- structured audit log -----------------------------------------------

@pytest.mark.asyncio
async def test_audit_log_emits_canonical_fields_on_allow(test_client, monkeypatch, caplog):
    client, app, proxy_mod = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse(status_code=200))

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer resolved", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    caplog.set_level("INFO", logger="rig.proxy")
    auth = _bearer_with_claims(sub="auid-42", jti="jti-7")
    await client.get(
        "/test-facility/echo",
        headers={"authorization": auth, "x-project": "p1"},
    )

    audit_records = [r for r in caplog.records if getattr(r, "audit", False)]
    assert len(audit_records) == 1
    rec = audit_records[0]
    assert rec.decision == "allow"
    assert rec.status == 200
    assert rec.facility == "test-facility"
    assert rec.tier == 1
    assert rec.sub == "auid-42"
    assert rec.jti == "jti-7"
    assert rec.project == "p1"


@pytest.mark.asyncio
async def test_audit_log_emits_deny_on_project_mismatch(test_client, caplog):
    client, app, _ = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())
    caplog.set_level("INFO", logger="rig.proxy")
    auth = _bearer_with_claims(sub="user-1", amsc_project_context="claim", jti="j-mm")
    await client.get(
        "/test-facility/anything",
        headers={"authorization": auth, "x-project": "header"},
    )
    audit = [r for r in caplog.records if getattr(r, "audit", False)]
    assert len(audit) == 1
    assert audit[0].decision == "deny"
    assert audit[0].status == 403
    assert audit[0].reason == "project_mismatch"
    assert audit[0].sub == "user-1"
    assert audit[0].jti == "j-mm"


# --- configurable token-exchange timeout --------------------------------

@pytest.mark.asyncio
async def test_token_exchange_uses_configured_timeout(monkeypatch):
    """`exchange_token` must enforce the per-facility `timeout_seconds` instead of the
    shared httpx client default — RFC Section 3B Path A circuit breaker."""
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token

    captured = {}

    class FakeResp:
        status_code = 200
        text = ""

        def json(self):
            return {"access_token": "swapped"}

    class FakeClient:
        async def post(self, url, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            return FakeResp()

    cfg = TokenExchangeConfig(
        auth_endpoint="https://idp.example/token",
        client_id="client",
        timeout_seconds=2.5,
    )

    result = await exchange_token("Bearer abc", cfg, FakeClient())
    assert result == "Bearer swapped"
    timeout = captured["timeout"]
    # httpx.Timeout(2.5, connect=...) — the read budget should match the configured value
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.read == 2.5


@pytest.mark.asyncio
async def test_token_exchange_returns_none_on_timeout():
    """A timeout during exchange must return None so resolve_identity can downgrade."""
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token

    class FakeClient:
        async def post(self, *args, **kwargs):
            raise httpx.TimeoutException("read timeout")

    cfg = TokenExchangeConfig(
        auth_endpoint="https://slow.example/token",
        client_id="client",
        timeout_seconds=0.1,
    )
    result = await exchange_token("Bearer abc", cfg, FakeClient())
    assert result is None


# --- X-AmSC-Exchange-Status upstream header -----------------------------

@pytest.mark.asyncio
async def test_exchange_status_header_completed_after_exchange(test_client, monkeypatch):
    """When resolve_identity reports mechanism='exchange', proxy injects
    X-AmSC-Exchange-Status: Completed."""
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer exchanged", "exchange")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    auth = _bearer_with_claims(sub="user-1")
    response = await client.get("/test-facility/path", headers={"authorization": auth, "x-project": "p1"})
    assert response.status_code == 200
    assert recording_client.request_args["headers"]["x-amsc-exchange-status"] == "Completed"


@pytest.mark.asyncio
async def test_exchange_status_header_vaulted_after_vault_hit(test_client, monkeypatch):
    """When resolve_identity reports mechanism='vault', the marker is 'Vaulted'."""
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer vaulted", "vault")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    auth = _bearer_with_claims(sub="user-1")
    response = await client.get("/test-facility/path", headers={"authorization": auth, "x-project": "p1"})
    assert response.status_code == 200
    assert recording_client.request_args["headers"]["x-amsc-exchange-status"] == "Vaulted"


@pytest.mark.asyncio
async def test_no_exchange_status_header_on_passthrough(test_client, monkeypatch):
    """Pass-through (Tier 1) must NOT set X-AmSC-Exchange-Status — there was no swap."""
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer original", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/path")
    assert response.status_code == 200
    assert "x-amsc-exchange-status" not in recording_client.request_args["headers"]


# --- Tier-3 downgrade on exchange failure -------------------------------

@pytest.mark.asyncio
async def test_resolve_identity_downgrades_to_vault_when_exchange_fails(monkeypatch):
    """resolve_identity must try vault next when token-exchange returns None and a
    vault backend is configured (RFC Section 3B 'Tier-3 Downgrade')."""
    from rig.config import FacilityConfig, Settings, TokenExchangeConfig
    from rig.identity import resolve_identity

    test_settings = Settings(
        facilities={
            "f": FacilityConfig(
                base_url="https://x",
                token_exchange=TokenExchangeConfig(auth_endpoint="https://idp/token", client_id="c"),
            ),
        },
        vault_backend="docker",
        docker_credentials={"u": {"p": {"f": "vault-token"}}},
    )

    async def fake_exchange_token(*args, **kwargs):
        return None  # simulate Path A failure

    monkeypatch.setattr("rig.identity.exchange_token", fake_exchange_token)

    async with httpx.AsyncClient() as http_client:
        result = await resolve_identity("Bearer in", "f", "p", http_client, test_settings, user_identity="u")
    assert result == ("Bearer vault-token", "vault")


@pytest.mark.asyncio
async def test_resolve_identity_passthrough_when_exchange_and_vault_both_fail(monkeypatch):
    """When both Tier-2 and Tier-3 fail, resolve_identity returns the original auth + passthrough."""
    from rig.config import FacilityConfig, Settings, TokenExchangeConfig
    from rig.identity import resolve_identity

    test_settings = Settings(
        facilities={
            "f": FacilityConfig(
                base_url="https://x",
                token_exchange=TokenExchangeConfig(auth_endpoint="https://idp/token", client_id="c"),
            ),
        },
        vault_backend="docker",
        docker_credentials={},  # no creds at all -> vault miss
    )

    async def fake_exchange_token(*args, **kwargs):
        return None

    monkeypatch.setattr("rig.identity.exchange_token", fake_exchange_token)

    async with httpx.AsyncClient() as http_client:
        result = await resolve_identity(
            "Bearer original", "f", "p", http_client, test_settings, user_identity="u"
        )
    assert result == ("Bearer original", "passthrough")


# --- JWKS-backed JWT validation -----------------------------------------

def test_jwt_validator_disabled_by_default_returns_valid():
    """The validator must short-circuit to valid when disabled, no matter the input."""
    from rig.config import JWTValidationConfig
    from rig.jwt_validator import JWTValidator

    v = JWTValidator(JWTValidationConfig())  # enabled defaults to False
    valid, reason = v.validate("Bearer total-garbage")
    assert valid is True
    assert reason is None


def test_jwt_validator_rejects_missing_when_enabled():
    from rig.config import JWTValidationConfig
    from rig.jwt_validator import JWTValidator

    v = JWTValidator(JWTValidationConfig(enabled=True, jwks_url="https://idp/jwks.json"))
    valid, reason = v.validate(None)
    assert valid is False
    assert reason == "missing_authorization"


def test_jwt_validator_rejects_non_bearer_when_enabled():
    from rig.config import JWTValidationConfig
    from rig.jwt_validator import JWTValidator

    v = JWTValidator(JWTValidationConfig(enabled=True, jwks_url="https://idp/jwks.json"))
    valid, reason = v.validate("Basic dXNlcjpwYXNz")
    assert valid is False
    assert reason == "not_bearer"


@pytest.mark.asyncio
async def test_proxy_returns_401_when_jwt_validation_enabled_and_token_invalid(monkeypatch):
    """When jwt_validation is enabled and the validator says invalid, proxy returns 401."""
    from rig.config import FacilityConfig, JWTValidationConfig, Settings

    test_settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        jwt_validation=JWTValidationConfig(enabled=True, jwks_url="https://idp/jwks.json"),
    )
    monkeypatch.setattr(app_mod, "settings", test_settings)
    monkeypatch.setattr(proxy_mod, "settings", test_settings)

    class FakeValidator:
        def validate(self, authorization):
            return (False, "token_expired")

    app.state.http_client = SimpleNamespace(is_closed=False)
    app.state.jwt_validator = FakeValidator()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/f/anything",
            headers={"authorization": "Bearer expired"},
        )
    assert response.status_code == 401
    body = response.json()
    assert body["reason"] == "token_expired"


@pytest.mark.asyncio
async def test_proxy_skips_jwt_validation_when_disabled(test_client, monkeypatch):
    """Default config has jwt_validation disabled — request must proceed normally."""
    client, app, proxy_mod = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    class StrictValidator:
        """If proxy ever calls .validate when disabled, this would fail the assert."""
        def validate(self, authorization):
            raise AssertionError("validator should not be invoked when disabled")

    app.state.jwt_validator = StrictValidator()

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/path")
    assert response.status_code == 200


# --- Exchange-token cache --------------------------------------------------------------

@pytest.mark.asyncio
async def test_exchange_cache_hit_skips_post():
    from rig.config import TokenExchangeConfig
    from rig.exchange_cache import ExchangeCache
    from rig.token_exchange import exchange_token

    cache = ExchangeCache()
    await cache.set(sub="u1", facility="f1", requested_scope=None, authorization="Bearer cached", ttl_seconds=60)

    class FailIfCalled:
        async def post(self, *args, **kwargs):
            raise AssertionError("cache hit must avoid network I/O")

    cfg = TokenExchangeConfig(auth_endpoint="https://idp/token", client_id="c")
    out = await exchange_token("Bearer in", cfg, FailIfCalled(), sub="u1", facility="f1", cache=cache)
    assert out == "Bearer cached"


@pytest.mark.asyncio
async def test_exchange_cache_miss_then_populates():
    from rig.config import TokenExchangeConfig
    from rig.exchange_cache import ExchangeCache
    from rig.token_exchange import exchange_token

    cache = ExchangeCache()

    class FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"access_token": "newly-minted"}

    class FakeClient:
        def __init__(self):
            self.calls = 0
        async def post(self, *args, **kwargs):
            self.calls += 1
            return FakeResp()

    cfg = TokenExchangeConfig(
        auth_endpoint="https://idp/token", client_id="c",
        cache_ttl_seconds=300,
    )
    fake = FakeClient()
    out = await exchange_token("Bearer in", cfg, fake, sub="u1", facility="f1", cache=cache)
    assert out == "Bearer newly-minted"
    assert fake.calls == 1
    out2 = await exchange_token("Bearer in", cfg, fake, sub="u1", facility="f1", cache=cache)
    assert out2 == "Bearer newly-minted"
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_exchange_cache_evicts_after_ttl():
    import asyncio as _asyncio
    from rig.exchange_cache import ExchangeCache
    cache = ExchangeCache()
    await cache.set("u", "f", None, "Bearer x", ttl_seconds=0.01)
    await _asyncio.sleep(0.02)
    assert await cache.get("u", "f", None) is None


# --- verify_tls=False uses a one-off client --------------------------------------------

@pytest.mark.asyncio
async def test_exchange_uses_oneoff_client_when_verify_tls_false(monkeypatch):
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token
    import rig.token_exchange as token_exchange_mod

    captured = {}

    class FakeOneOff:
        def __init__(self, *args, **kwargs):
            captured["init_kwargs"] = kwargs
        async def __aenter__(self):
            return self
        async def __aexit__(self, *exc):
            return False
        async def post(self, *args, **kwargs):
            captured["post_called"] = True
            class R:
                status_code = 200
                text = ""
                def json(self):
                    return {"access_token": "via-oneoff"}
            return R()

    monkeypatch.setattr(token_exchange_mod.httpx, "AsyncClient", FakeOneOff)
    cfg = TokenExchangeConfig(auth_endpoint="https://idp/token", client_id="c", verify_tls=False)

    class ShouldNotBeCalled:
        async def post(self, *args, **kwargs):
            raise AssertionError("the shared client must NOT be used when verify_tls=False")

    out = await exchange_token("Bearer in", cfg, ShouldNotBeCalled())
    assert out == "Bearer via-oneoff"
    assert captured["post_called"]
    assert captured["init_kwargs"]["verify"] is False


# --- audience override + requested_scope -----------------------------------------------

@pytest.mark.asyncio
async def test_exchange_audience_override_used_when_set():
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token

    captured = {}

    class FakeClient:
        async def post(self, url, **kwargs):
            captured["data"] = dict(kwargs.get("data", {}))
            class R:
                status_code = 200
                text = ""
                def json(self):
                    return {"access_token": "ok"}
            return R()

    cfg = TokenExchangeConfig(
        auth_endpoint="https://idp/token",
        client_id="my-client",
        audience="https://api.facility.example",
    )
    await exchange_token("Bearer in", cfg, FakeClient())
    assert captured["data"]["audience"] == "https://api.facility.example"


@pytest.mark.asyncio
async def test_exchange_audience_defaults_to_client_id():
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token

    captured = {}

    class FakeClient:
        async def post(self, url, **kwargs):
            captured["data"] = dict(kwargs.get("data", {}))
            class R:
                status_code = 200
                text = ""
                def json(self):
                    return {"access_token": "ok"}
            return R()

    cfg = TokenExchangeConfig(auth_endpoint="https://idp/token", client_id="my-client")
    await exchange_token("Bearer in", cfg, FakeClient())
    assert captured["data"]["audience"] == "my-client"


@pytest.mark.asyncio
async def test_exchange_requested_scope_added_to_form_body():
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token

    captured = {}

    class FakeClient:
        async def post(self, url, **kwargs):
            captured["data"] = dict(kwargs.get("data", {}))
            class R:
                status_code = 200
                text = ""
                def json(self):
                    return {"access_token": "ok"}
            return R()

    cfg = TokenExchangeConfig(
        auth_endpoint="https://idp/token",
        client_id="c",
        requested_scope="compute:submit storage:read",
    )
    await exchange_token("Bearer in", cfg, FakeClient())
    assert captured["data"]["scope"] == "compute:submit storage:read"


# --- forbidden_scopes refuses over-broad downstream tokens -----------------------------

@pytest.mark.asyncio
async def test_exchange_returns_none_when_forbidden_scope_granted():
    import base64
    import json as j
    from rig.config import TokenExchangeConfig
    from rig.token_exchange import exchange_token

    payload = base64.urlsafe_b64encode(j.dumps({"scope": "compute:execute all"}).encode()).rstrip(b"=").decode()
    fake_jwt = f"eyJhbGciOiJub25lIn0.{payload}.sig"

    class FakeClient:
        async def post(self, *args, **kwargs):
            class R:
                status_code = 200
                text = ""
                def json(self):
                    return {"access_token": fake_jwt}
            return R()

    cfg = TokenExchangeConfig(
        auth_endpoint="https://idp/token", client_id="c",
        forbidden_scopes=["all", "admin"],
    )
    out = await exchange_token("Bearer in", cfg, FakeClient())
    assert out is None


# --- Vault auth_time freshness window --------------------------------------------------

@pytest.mark.asyncio
async def test_vault_denied_when_auth_time_too_old():
    import base64
    import json as j
    import time as t
    from rig.config import FacilityConfig, Settings
    from rig.identity import resolve_identity

    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        vault_backend="docker",
        docker_credentials={"u": {"p": {"f": "Bearer fresh"}}},
        vault_max_auth_age_seconds=60,
    )
    stale_payload = base64.urlsafe_b64encode(
        j.dumps({"sub": "u", "auth_time": int(t.time()) - 3600}).encode()
    ).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{stale_payload}.sig"

    async with httpx.AsyncClient() as http_client:
        _, mech = await resolve_identity(auth, "f", "p", http_client, settings, user_identity="u")
    assert mech == "passthrough"


@pytest.mark.asyncio
async def test_vault_allowed_when_auth_time_fresh():
    import base64
    import json as j
    import time as t
    from rig.config import FacilityConfig, Settings
    from rig.identity import resolve_identity

    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        vault_backend="docker",
        docker_credentials={"u": {"p": {"f": "fresh"}}},
        vault_max_auth_age_seconds=3600,
    )
    fresh_payload = base64.urlsafe_b64encode(
        j.dumps({"sub": "u", "auth_time": int(t.time())}).encode()
    ).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{fresh_payload}.sig"

    async with httpx.AsyncClient() as http_client:
        _, mech = await resolve_identity(auth, "f", "p", http_client, settings, user_identity="u")
    assert mech == "vault"


# --- Pool detection --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vault_pool_detection_warns_on_cross_user_reuse(caplog):
    from rig.config import FacilityConfig, Settings
    from rig.identity import resolve_identity, _pool_observations

    _pool_observations.clear()
    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        vault_backend="docker",
        docker_credentials={
            "userA": {"p": {"f": "shared-token"}},
            "userB": {"p": {"f": "shared-token"}},
        },
        vault_pool_detect=True,
    )

    caplog.set_level("WARNING", logger="rig.identity")
    async with httpx.AsyncClient() as http_client:
        await resolve_identity("Bearer x", "f", "p", http_client, settings, user_identity="userA")
        await resolve_identity("Bearer x", "f", "p", http_client, settings, user_identity="userB")

    msgs = [r.getMessage() for r in caplog.records]
    assert any("pool detection" in m.lower() for m in msgs)


@pytest.mark.asyncio
async def test_vault_pool_deny_returns_passthrough():
    from rig.config import FacilityConfig, Settings
    from rig.identity import resolve_identity, _pool_observations

    _pool_observations.clear()
    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        vault_backend="docker",
        docker_credentials={
            "userA": {"p": {"f": "shared-token"}},
            "userB": {"p": {"f": "shared-token"}},
        },
        vault_pool_detect=True,
        vault_pool_deny=True,
    )
    async with httpx.AsyncClient() as http_client:
        await resolve_identity("Bearer x", "f", "p", http_client, settings, user_identity="userA")
        _, mech = await resolve_identity("Bearer x", "f", "p", http_client, settings, user_identity="userB")
    assert mech == "passthrough"


# --- Binding event audit log -----------------------------------------------------------

@pytest.mark.asyncio
async def test_binding_event_emitted_on_vault_hit(caplog):
    from rig.config import FacilityConfig, Settings
    from rig.identity import resolve_identity, _pool_observations

    _pool_observations.clear()
    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        vault_backend="docker",
        docker_credentials={"u": {"p": {"f": "Bearer t"}}},
    )
    caplog.set_level("INFO", logger="rig.identity")
    async with httpx.AsyncClient() as http_client:
        await resolve_identity("Bearer in", "f", "p", http_client, settings, user_identity="u")

    binding_records = [r for r in caplog.records if getattr(r, "event", None) == "vault_binding"]
    assert len(binding_records) == 1
    rec = binding_records[0]
    assert rec.user == "u"
    assert rec.project == "p"
    assert rec.facility == "f"
    assert rec.vault_backend == "docker"
    assert isinstance(rec.credential_fingerprint, str) and len(rec.credential_fingerprint) == 64


# --- IP allowlist for non-MFA service tokens -------------------------------------------

def test_is_service_token_no_amr_is_service():
    from rig.proxy import _is_service_token
    assert _is_service_token("Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.x", ["mfa"]) is True


def test_is_service_token_with_mfa_amr_is_not_service():
    import base64, json as j
    from rig.proxy import _is_service_token
    payload = base64.urlsafe_b64encode(j.dumps({"sub": "u1", "amr": ["mfa", "pwd"]}).encode()).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{payload}.sig"
    assert _is_service_token(auth, ["mfa", "otp", "hwk"]) is False


def test_ip_in_allowlist_matches_v4_v6_and_misses():
    from rig.proxy import _ip_in_allowlist
    assert _ip_in_allowlist("10.0.0.5", ["10.0.0.0/8"]) is True
    assert _ip_in_allowlist("192.168.1.1", ["10.0.0.0/8"]) is False
    assert _ip_in_allowlist("::1", ["::1/128"]) is True
    assert _ip_in_allowlist(None, ["10.0.0.0/8"]) is False
    assert _ip_in_allowlist("not-an-ip", ["10.0.0.0/8"]) is False


@pytest.mark.asyncio
async def test_proxy_denies_service_token_outside_allowlist(monkeypatch):
    from rig.config import FacilityConfig, Settings

    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        service_account_allowed_cidrs=["10.0.0.0/8"],
    )
    monkeypatch.setattr(app_mod, "settings", settings)
    monkeypatch.setattr(proxy_mod, "settings", settings)
    app.state.http_client = SimpleNamespace(is_closed=False)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/f/anything",
            headers={
                "authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdmMifQ.x",
                "x-forwarded-for": "203.0.113.7",
            },
        )
    assert response.status_code == 403
    assert "CIDR allowlist" in response.json()["error"]


@pytest.mark.asyncio
async def test_proxy_allows_service_token_inside_allowlist(monkeypatch):
    from rig.config import FacilityConfig, Settings

    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        service_account_allowed_cidrs=["10.0.0.0/8"],
    )
    monkeypatch.setattr(app_mod, "settings", settings)
    monkeypatch.setattr(proxy_mod, "settings", settings)
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/f/anything",
            headers={
                "authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdmMifQ.x",
                "x-forwarded-for": "10.1.2.3",
            },
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_proxy_allows_mfa_token_outside_allowlist(monkeypatch):
    """Tokens carrying a recognized MFA `amr` value are NOT subject to the IP allowlist."""
    import base64, json as j
    from rig.config import FacilityConfig, Settings

    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        service_account_allowed_cidrs=["10.0.0.0/8"],
    )
    monkeypatch.setattr(app_mod, "settings", settings)
    monkeypatch.setattr(proxy_mod, "settings", settings)
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    payload = base64.urlsafe_b64encode(j.dumps({"sub": "u1", "amr": ["mfa"]}).encode()).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{payload}.sig"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/f/anything",
            headers={"authorization": auth, "x-forwarded-for": "203.0.113.7"},
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_proxy_no_enforcement_when_cidr_list_empty(monkeypatch):
    """Empty allowlist disables enforcement entirely (default behavior)."""
    from rig.config import FacilityConfig, Settings

    settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        service_account_allowed_cidrs=[],
    )
    monkeypatch.setattr(app_mod, "settings", settings)
    monkeypatch.setattr(proxy_mod, "settings", settings)
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/f/anything",
            headers={
                "authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdmMifQ.x",
                "x-forwarded-for": "203.0.113.7",
            },
        )
    assert response.status_code == 200


# --- Forwarded auth-context headers (auth_time / amr / acr / idp) ---------------------

def test_extract_auth_time_returns_int():
    import base64, json as j
    from rig.identity import _extract_auth_time

    payload = base64.urlsafe_b64encode(j.dumps({"auth_time": 1700000000}).encode()).rstrip(b"=").decode()
    assert _extract_auth_time(f"Bearer h.{payload}.s") == 1700000000


def test_extract_amr_normalizes_to_list():
    import base64, json as j
    from rig.identity import _extract_amr

    p1 = base64.urlsafe_b64encode(j.dumps({"amr": ["mfa", "pwd"]}).encode()).rstrip(b"=").decode()
    assert _extract_amr(f"Bearer h.{p1}.s") == ["mfa", "pwd"]
    p2 = base64.urlsafe_b64encode(j.dumps({"amr": "mfa"}).encode()).rstrip(b"=").decode()
    assert _extract_amr(f"Bearer h.{p2}.s") == ["mfa"]
    assert _extract_amr(None) == []


def test_extract_acr_and_idp():
    import base64, json as j
    from rig.identity import _extract_acr, _extract_idp

    p = base64.urlsafe_b64encode(
        j.dumps({"acr": "nist-aal2", "idp_id": "globus"}).encode()
    ).rstrip(b"=").decode()
    auth = f"Bearer h.{p}.s"
    assert _extract_acr(auth) == "nist-aal2"
    assert _extract_idp(auth) == "globus"


@pytest.mark.asyncio
async def test_proxy_forwards_auth_context_headers(test_client, monkeypatch):
    """When the inbound JWT carries auth_time/amr/acr/idp, the proxy forwards them."""
    import base64, json as j
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    payload = base64.urlsafe_b64encode(
        j.dumps(
            {
                "sub": "u",
                "auth_time": 1700000000,
                "amr": ["mfa", "pwd"],
                "acr": "nist-aal2",
                "idp": "globus",
            }
        ).encode()
    ).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{payload}.sig"

    response = await client.get("/test-facility/path", headers={"authorization": auth})
    assert response.status_code == 200
    h = recording_client.request_args["headers"]
    assert h["x-amsc-auth-time"] == "1700000000"
    assert h["x-amsc-amr"] == "mfa,pwd"
    assert h["x-amsc-acr"] == "nist-aal2"
    assert h["x-amsc-idp"] == "globus"


@pytest.mark.asyncio
async def test_proxy_omits_auth_context_headers_when_claims_absent(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/path")  # no Authorization at all
    assert response.status_code == 200
    h = recording_client.request_args["headers"]
    for unwanted in ("x-amsc-auth-time", "x-amsc-amr", "x-amsc-acr", "x-amsc-idp"):
        assert unwanted not in h


# --- /ready tier enrichment + /metrics --------------------------------------------------

@pytest.mark.asyncio
async def test_ready_payload_includes_tier_per_facility(test_client):
    client, _, _ = test_client
    response = await client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert isinstance(body["facilities"], list)
    assert {"name": "test-facility", "tier": 1} in body["facilities"]


@pytest.mark.asyncio
async def test_metrics_emits_per_facility_tier_gauge(test_client, monkeypatch):
    """The /metrics endpoint emits a Prometheus-format gauge per facility."""
    from rig.config import FacilityConfig, Settings, TokenExchangeConfig
    settings_with_two = Settings(
        facilities={
            "passthrough-fac": FacilityConfig(base_url="https://x"),
            "exchange-fac": FacilityConfig(
                base_url="https://y",
                token_exchange=TokenExchangeConfig(auth_endpoint="https://idp", client_id="c"),
            ),
        }
    )
    monkeypatch.setattr(app_mod, "settings", settings_with_two)
    monkeypatch.setattr(proxy_mod, "settings", settings_with_two)

    client, _, _ = test_client
    response = await client.get("/metrics")
    assert response.status_code == 200
    body = response.text
    assert "# HELP rig_facility_tier" in body
    assert "# TYPE rig_facility_tier gauge" in body
    assert 'rig_facility_tier{facility="passthrough-fac"} 1' in body
    assert 'rig_facility_tier{facility="exchange-fac"} 2' in body


# --- Revocation: Redis blocklist + DNSBL -----------------------------------------------

@pytest.mark.asyncio
async def test_revocation_redis_hit_returns_revoked():
    from rig.revocation import RevocationChecker

    checker = RevocationChecker(redis_url="redis://stub/0")

    class StubRedis:
        async def exists(self, key):
            assert key == "rig:blocklist:abc"
            return 1

    checker._redis_client = StubRedis()
    revoked, source = await checker.is_revoked("abc")
    assert revoked is True
    assert source == "redis"


@pytest.mark.asyncio
async def test_revocation_redis_unreachable_fails_open():
    from rig.revocation import RevocationChecker

    checker = RevocationChecker(redis_url="redis://stub/0")

    class StubRedis:
        async def exists(self, key):
            raise RuntimeError("redis down")

    checker._redis_client = StubRedis()
    revoked, source = await checker.is_revoked("abc")
    assert revoked is False  # Fail open
    assert source is None


@pytest.mark.asyncio
async def test_revocation_dnsbl_hit_returns_revoked(monkeypatch):
    from rig.revocation import RevocationChecker

    checker = RevocationChecker(dnsbl_zone="revoked.example.com")

    async def fake_resolve(name, rdtype):
        return ["txt-record"]

    import dns.asyncresolver
    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)
    revoked, source = await checker.is_revoked("xyz")
    assert revoked is True
    assert source == "dnsbl"


@pytest.mark.asyncio
async def test_revocation_dnsbl_nxdomain_returns_clean(monkeypatch):
    from rig.revocation import RevocationChecker

    checker = RevocationChecker(dnsbl_zone="revoked.example.com")

    import dns.asyncresolver
    import dns.resolver

    async def fake_resolve(name, rdtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)
    revoked, source = await checker.is_revoked("xyz")
    assert revoked is False
    assert source is None


@pytest.mark.asyncio
async def test_revocation_dnsbl_caches_result(monkeypatch):
    """A second lookup for the same jti must not re-issue the DNS query within the TTL."""
    from rig.revocation import RevocationChecker

    checker = RevocationChecker(dnsbl_zone="revoked.example.com", dnsbl_ttl_seconds=60)
    counter = {"calls": 0}

    async def fake_resolve(name, rdtype):
        counter["calls"] += 1
        return ["x"]

    import dns.asyncresolver
    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)

    await checker.is_revoked("same-jti")
    await checker.is_revoked("same-jti")
    assert counter["calls"] == 1


@pytest.mark.asyncio
async def test_revocation_disabled_returns_clean():
    from rig.revocation import RevocationChecker

    checker = RevocationChecker()  # both knobs empty
    assert checker.enabled is False
    revoked, source = await checker.is_revoked("anything")
    assert revoked is False
    assert source is None


@pytest.mark.asyncio
async def test_proxy_returns_401_on_revoked_jti(test_client, monkeypatch):
    """When the revocation checker says revoked, proxy denies with 401 + audit reason."""
    client, app, proxy_mod = test_client

    class FakeChecker:
        enabled = True
        async def is_revoked(self, jti):
            return (True, "redis")

    app.state.revocation_checker = FakeChecker()

    import base64, json as j
    payload = base64.urlsafe_b64encode(j.dumps({"sub": "u", "jti": "j-bad"}).encode()).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{payload}.sig"

    response = await client.get("/test-facility/path", headers={"authorization": auth})
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "Token revoked"
    # New shape uses _challenge_401 which encodes the source into ``reason``.
    assert body["reason"] == "revoked:redis"


@pytest.mark.asyncio
async def test_proxy_skips_revocation_when_disabled(test_client, monkeypatch):
    client, app, proxy_mod = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    class StrictChecker:
        enabled = False
        async def is_revoked(self, jti):
            raise AssertionError("checker must not be invoked when disabled")

    app.state.revocation_checker = StrictChecker()

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/path", headers={"authorization": "Bearer x"})
    assert response.status_code == 200


# --- NetworkPolicy structural test ----------------------------------------------------

def test_networkpolicy_yaml_parses_and_has_default_deny():
    """The shipped k8s/networkpolicy.yaml must define a default-deny + service-specific allow."""
    import os
    import yaml

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "k8s", "networkpolicy.yaml")) as f:
        docs = list(yaml.safe_load_all(f))

    by_name = {d["metadata"]["name"]: d for d in docs}
    assert "default-deny" in by_name
    deny = by_name["default-deny"]
    assert deny["spec"]["podSelector"] == {}
    assert set(deny["spec"]["policyTypes"]) == {"Ingress", "Egress"}

    assert "allow-rig-ingress" in by_name
    ing = by_name["allow-rig-ingress"]
    assert ing["spec"]["podSelector"]["matchLabels"]["app"] == "rig"
    ports = ing["spec"]["ingress"][0]["ports"]
    assert any(p["port"] == 8000 and p["protocol"] == "TCP" for p in ports)

    assert "allow-rig-egress" in by_name
    egr = by_name["allow-rig-egress"]
    assert egr["spec"]["podSelector"]["matchLabels"]["app"] == "rig"


# --- Differentiated 401 challenge ------------------------------------------------------

@pytest.mark.asyncio
async def test_challenge_401_html_browser_redirects_when_login_url_set(test_client, monkeypatch):
    from rig.config import FacilityConfig, JWTValidationConfig, Settings

    settings_w_redirect = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        jwt_validation=JWTValidationConfig(enabled=True, jwks_url="https://idp/jwks.json"),
        auth_redirect_login_url="https://login.example/oidc",
    )
    monkeypatch.setattr(app_mod, "settings", settings_w_redirect)
    monkeypatch.setattr(proxy_mod, "settings", settings_w_redirect)
    app.state.http_client = SimpleNamespace(is_closed=False)

    class FakeValidator:
        def validate(self, authorization):
            return (False, "token_expired")

    app.state.jwt_validator = FakeValidator()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        # Tell httpx not to follow redirects so we observe the 302 directly.
        client.follow_redirects = False
        response = await client.get(
            "/f/anything",
            headers={"authorization": "Bearer expired", "accept": "text/html,application/xhtml+xml"},
        )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://login.example/oidc")
    assert "return_to=/f/anything" in location
    assert response.headers["x-amsc-auth-challenge"] == "token_expired"


@pytest.mark.asyncio
async def test_challenge_401_cli_includes_device_flow_uri(test_client, monkeypatch):
    from rig.config import FacilityConfig, JWTValidationConfig, Settings

    settings_w_device = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        jwt_validation=JWTValidationConfig(enabled=True, jwks_url="https://idp/jwks.json"),
        auth_device_flow_uri="https://login.example/device",
    )
    monkeypatch.setattr(app_mod, "settings", settings_w_device)
    monkeypatch.setattr(proxy_mod, "settings", settings_w_device)
    app.state.http_client = SimpleNamespace(is_closed=False)

    class FakeValidator:
        def validate(self, authorization):
            return (False, "token_expired")

    app.state.jwt_validator = FakeValidator()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/f/anything",
            headers={"authorization": "Bearer expired", "accept": "application/json"},
        )
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "Invalid bearer token"
    assert body["reason"] == "token_expired"
    assert body["challenge_uri"] == "https://login.example/device"


@pytest.mark.asyncio
async def test_challenge_401_no_config_falls_back_to_plain_json(test_client, monkeypatch):
    from rig.config import FacilityConfig, JWTValidationConfig, Settings

    settings_bare = Settings(
        facilities={"f": FacilityConfig(base_url="https://upstream.example/api/")},
        jwt_validation=JWTValidationConfig(enabled=True, jwks_url="https://idp/jwks.json"),
    )
    monkeypatch.setattr(app_mod, "settings", settings_bare)
    monkeypatch.setattr(proxy_mod, "settings", settings_bare)
    app.state.http_client = SimpleNamespace(is_closed=False)

    class FakeValidator:
        def validate(self, authorization):
            return (False, "token_expired")

    app.state.jwt_validator = FakeValidator()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        # Browser-style Accept but no redirect URL configured -> should still 401 JSON.
        response = await client.get(
            "/f/anything",
            headers={"authorization": "Bearer expired", "accept": "text/html"},
        )
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "Invalid bearer token"
    assert body["reason"] == "token_expired"
    assert "challenge_uri" not in body


# --- Admin blocklist endpoint (#33) ----------------------------------------------------

@pytest.fixture
async def admin_client(monkeypatch):
    from rig.config import FacilityConfig, Settings
    from rig.revocation import RevocationChecker

    test_settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        admin_api_token="s3cret-admin-token",
    )
    monkeypatch.setattr(app_mod, "settings", test_settings)
    monkeypatch.setattr(proxy_mod, "settings", test_settings)
    # Also patch the admin module's settings — it imports a snapshot at module-load.
    import rig.admin as admin_mod
    monkeypatch.setattr(admin_mod, "settings", test_settings)
    app.state.http_client = SimpleNamespace(is_closed=False)

    class FakeChecker:
        can_write = True
        enabled = True
        last = None

        async def block(self, jti, *, ttl_seconds, reason):
            self.last = (jti, ttl_seconds, reason)
            return True

    app.state.revocation_checker = FakeChecker()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_admin_blocklist_add_authorized(admin_client):
    response = await admin_client.post(
        "/admin/blocklist",
        json={"jti": "j-bad", "ttl_seconds": 7200, "reason": "anomaly"},
        headers={"authorization": "Bearer s3cret-admin-token"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["jti"] == "j-bad"
    assert body["ttl_seconds"] == 7200
    assert body["reason"] == "anomaly"
    assert app.state.revocation_checker.last == ("j-bad", 7200, "anomaly")


@pytest.mark.asyncio
async def test_admin_blocklist_rejects_missing_token(admin_client):
    response = await admin_client.post(
        "/admin/blocklist",
        json={"jti": "j"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_blocklist_rejects_wrong_token(admin_client):
    response = await admin_client.post(
        "/admin/blocklist",
        json={"jti": "j"},
        headers={"authorization": "Bearer wrong"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_blocklist_disabled_returns_404(monkeypatch):
    from rig.config import FacilityConfig, Settings

    test_settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        admin_api_token="",  # disabled
    )
    monkeypatch.setattr(app_mod, "settings", test_settings)
    import rig.admin as admin_mod
    monkeypatch.setattr(admin_mod, "settings", test_settings)
    app.state.http_client = SimpleNamespace(is_closed=False)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/admin/blocklist",
            json={"jti": "j"},
            headers={"authorization": "Bearer anything"},
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_admin_blocklist_returns_503_when_redis_unavailable(monkeypatch):
    from rig.config import FacilityConfig, Settings

    test_settings = Settings(
        facilities={"f": FacilityConfig(base_url="https://x")},
        admin_api_token="t",
    )
    monkeypatch.setattr(app_mod, "settings", test_settings)
    import rig.admin as admin_mod
    monkeypatch.setattr(admin_mod, "settings", test_settings)
    app.state.http_client = SimpleNamespace(is_closed=False)

    class FakeChecker:
        can_write = False
        enabled = False
        async def block(self, *args, **kwargs):
            return False

    app.state.revocation_checker = FakeChecker()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/admin/blocklist",
            json={"jti": "j"},
            headers={"authorization": "Bearer t"},
        )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_revocation_checker_block_writes_to_redis():
    """RevocationChecker.block must SETEX the configured key with the TTL."""
    from rig.revocation import RevocationChecker

    checker = RevocationChecker(redis_url="redis://stub/0")

    class StubRedis:
        def __init__(self):
            self.calls = []
        async def setex(self, key, ttl, value):
            self.calls.append((key, ttl, value))
            return True

    stub = StubRedis()
    checker._redis_client = stub
    ok = await checker.block("j-1", ttl_seconds=60, reason="anomaly")
    assert ok is True
    assert stub.calls == [("rig:blocklist:j-1", 60, b"anomaly")]


# --- OpenTelemetry span propagation (#23) ----------------------------------------------

_OTEL_PROVIDER = None  # set lazily; the OTel API forbids replacing a provider once set.


@pytest.fixture
def otel_memory_exporter():
    """Register a fresh in-memory exporter on the singleton TracerProvider.

    OpenTelemetry refuses to replace an installed TracerProvider — and the
    module-level ``_tracer = trace.get_tracer(...)`` in ``rig.tracing`` is a
    ProxyTracer that resolves to the configured provider lazily — so we set
    the SDK provider exactly once and just attach a per-test exporter.
    """
    global _OTEL_PROVIDER
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    if _OTEL_PROVIDER is None:
        _OTEL_PROVIDER = TracerProvider()
        trace.set_tracer_provider(_OTEL_PROVIDER)
    exporter = InMemorySpanExporter()
    _OTEL_PROVIDER.add_span_processor(SimpleSpanProcessor(exporter))
    yield exporter
    exporter.clear()


@pytest.mark.asyncio
async def test_proxy_emits_otel_span_with_audit_attributes(test_client, monkeypatch, otel_memory_exporter):
    client, app, proxy_mod_local = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod_local, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod_local, "is_allowed", fake_is_allowed)

    import base64, json as j
    payload = base64.urlsafe_b64encode(j.dumps({"sub": "auid-9", "jti": "jti-9"}).encode()).rstrip(b"=").decode()
    auth = f"Bearer eyJhbGciOiJub25lIn0.{payload}.sig"

    response = await client.get(
        "/test-facility/some/path",
        headers={"authorization": auth, "x-project": "demo"},
    )
    assert response.status_code == 200

    spans = otel_memory_exporter.get_finished_spans()
    rig_spans = [s for s in spans if s.name == "rig.proxy"]
    assert len(rig_spans) == 1
    attrs = dict(rig_spans[0].attributes)
    assert attrs["rig.facility"] == "test-facility"
    assert attrs["rig.tier"] == 1
    assert attrs["rig.sub"] == "auid-9"
    assert attrs["rig.jti"] == "jti-9"
    assert attrs["rig.project"] == "demo"
    assert attrs["rig.decision"] == "allow"
    assert attrs["rig.status"] == 200
    assert attrs["rig.resolution_mechanism"] == "passthrough"
    assert attrs["http.method"] == "GET"


@pytest.mark.asyncio
async def test_proxy_continues_inbound_traceparent(test_client, monkeypatch, otel_memory_exporter):
    """An inbound traceparent must seed the rig span as a child."""
    client, app, proxy_mod_local = test_client
    app.state.http_client = RecordingHttpClient(FakeUpstreamResponse())

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod_local, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod_local, "is_allowed", fake_is_allowed)

    parent_trace_id = "12345678901234567890123456789012"
    parent_span_id = "1234567890123456"
    traceparent = f"00-{parent_trace_id}-{parent_span_id}-01"

    response = await client.get(
        "/test-facility/path",
        headers={"traceparent": traceparent},
    )
    assert response.status_code == 200

    spans = otel_memory_exporter.get_finished_spans()
    rig_spans = [s for s in spans if s.name == "rig.proxy"]
    assert len(rig_spans) == 1
    span = rig_spans[0]
    # The trace_id is preserved across the parent boundary; the span_id is rig's own.
    assert format(span.context.trace_id, "032x") == parent_trace_id
    assert format(span.parent.span_id, "016x") == parent_span_id


@pytest.mark.asyncio
async def test_proxy_injects_traceparent_into_upstream(test_client, monkeypatch, otel_memory_exporter):
    """The upstream request must carry a fresh traceparent header for the facility's tracing."""
    client, app, proxy_mod_local = test_client
    upstream = FakeUpstreamResponse()
    recording_client = RecordingHttpClient(upstream)
    app.state.http_client = recording_client

    async def fake_resolve_identity(*args, **kwargs):
        return ("Bearer x", "passthrough")

    async def fake_is_allowed(*args, **kwargs):
        return True

    monkeypatch.setattr(proxy_mod_local, "resolve_identity", fake_resolve_identity)
    monkeypatch.setattr(proxy_mod_local, "is_allowed", fake_is_allowed)

    response = await client.get("/test-facility/path")
    assert response.status_code == 200
    upstream_headers = recording_client.request_args["headers"]
    assert "traceparent" in upstream_headers
    assert upstream_headers["traceparent"].startswith("00-")

