# RIG - Resource Integration Gateway

Stateless, horizontally-scalable reverse proxy and identity broker for IRI Facility APIs.

```
Client --> Kong (OIDC/Globus) --> Load Balancer --> RIG (N replicas) --> Facility APIs
```

RIG is **not** an IRI implementation. It is a wildcard proxy that accepts any path, resolves
credentials for the target facility, and streams the request/response without inspecting
the payload. Every instance is stateless; scale by adding replicas.

## Quick Start

```bash
cd rig
uv sync
RIG_CONFIG_PATH=config.yaml uv run rig
```

```bash
# liveness
curl http://localhost:8000/health

# readiness (lists configured facilities)
curl http://localhost:8000/ready

# proxy a request to NERSC
curl http://localhost:8000/nersc/api/v1/facility \
  -H "Authorization: Bearer <token>" \
  -H "X-Project: m3795"
```

## Architecture

```
rig/
  app.py             FastAPI startup; /health /ready /metrics;
                     OpenAPI security schemes (BearerAuth + ProjectHeader);
                     wires JWTValidator + RevocationChecker into app.state
  proxy.py           Wildcard route /{facility}/{path:path};
                     OTel span wrapper; project-mismatch / tier-3 fail-closed;
                     IP-allowlist gate; upstream header injection;
                     differentiated 401 (HTML 302 vs JSON challenge)
  admin.py           /admin/blocklist — push a jti to the revocation blocklist
  identity.py        resolve_identity() chain: exchange → vault → passthrough;
                     auth_time freshness; pool-detection fingerprint; binding-event audit;
                     vault backends (kube / aws / docker)
  token_exchange.py  RFC 8693 POST with per-call timeout, configurable audience,
                     requested_scope, forbidden_scopes guard, per-call verify_tls
  exchange_cache.py  Per-process LRU TTL cache for exchanged tokens
                     (key: sub + facility + scope; TTL = exp − skew)
  revocation.py      RevocationChecker — Redis blocklist + DNSBL fallback
                     (fail-open; admin block() write path)
  jwt_validator.py   JWKS-backed inbound JWT validation (OFF by default)
  tracing.py         OpenTelemetry context propagation + canonical rig.* attrs
  policy.py          Optional external policy-engine HTTP hook
  config.py          pydantic-settings YAML loader; FacilityConfig +
                     TokenExchangeConfig + JWTValidationConfig + resolve_tier()
  headers.py         Hop-by-hop header filtering
  logging.py         Structured JSON logging surfacing every extra= field
```

See [`docs/rig-components.png`](docs/rig-components.png) for a module / dependency
diagram and [`docs/rig-sequence.png`](docs/rig-sequence.png) for the full
request-flow sequence.

### Request Pipeline

Every proxied request flows through these gates, in order. Most are opt-in and
no-op when the corresponding configuration knob is absent.

1. **OTel span start** — open a `rig.proxy` span; continue any inbound
   `traceparent` so this span becomes a child of the caller's.
2. **Resolve facility** — look up `{facility}` in the configured map and infer
   its `tier` (1 = pass-through, 2 = token-exchange, 3 = vault). Returns 404 if
   unknown.
3. **Bearer normalisation** — if `Authorization` is absent but `X-Access-Token`
   is set (Kong-OIDC consumed the inbound bearer), promote it.
4. **JWT validation (optional)** — when `jwt_validation.enabled = true`, verify
   signature / iss / aud / exp via JWKS. On failure return 401 (or 302 redirect
   for HTML callers if `auth_redirect_login_url` is set).
5. **Revocation check (optional)** — when Redis or DNSBL is configured, look up
   the JWT's `jti`. Revoked → 401. Both checks fail open on backend errors.
6. **IP allowlist (optional)** — when `service_account_allowed_cidrs` is set,
   tokens with no recognised MFA `amr` value must originate from an allowed
   CIDR or get a 403.
7. **Project-context cross-check** — `X-Project` header vs the JWT's
   `amsc_project_context` claim. Disagreement → 403. For Tier-3 facilities the
   project is required; missing → 400.
8. **Identity resolution** — `exchange → vault → passthrough` chain (see
   [Identity Resolution](#identity-resolution)).
9. **Policy check (optional)** — call the configured external policy engine.
   Denied → 403.
10. **Header build** — strip hop-by-hop; preserve `X-Forwarded-*`; inject
    `X-AmSC-Trace-Id / -User / -Project`, plus `X-AmSC-Auth-Time / -Amr / -Acr /
    -Idp` when the JWT carries those claims, plus `X-AmSC-Exchange-Status`
    (Completed / Vaulted) when the identity resolver swapped the bearer.
    Re-inject the outbound `traceparent`.
11. **Stream to upstream** — full method / path / query / headers / body
    streamed via the shared `httpx.AsyncClient` (HTTP/2, connection pooled).
    Body is never buffered, never inspected.
12. **Stream response back** — preserve upstream status / headers / body;
    append `X-Request-Id` and `X-Upstream-Latency-Ms`.
13. **Audit log** — single `rig.audit` line per request with `decision`,
    `status`, `facility`, `tier`, `sub`, `jti`, `project`, `method`, `path`,
    `latency_ms`, `resolution_mechanism`, `trace_id`, `span_id`.

### Statelessness

RIG stores **nothing** between requests:

- No session state
- No tokens in memory
- No request affinity
- No facility state

All external state (credentials, policy decisions) is resolved per-request from
Kubernetes Secrets, AWS Secrets Manager, or external services.

---

## Configuration

Settings are loaded in this priority order:

1. **Environment variables** (prefix `RIG_`, e.g. `RIG_LOG_LEVEL=DEBUG`)
2. **YAML config file** (path set by `RIG_CONFIG_PATH`, default: `config.yaml`)
3. **Built-in defaults**

### config.yaml

```yaml
facilities:
  nersc:
    base_url: "https://api.iri.nersc.gov"
    timeout: 60
  esnet-east:
    base_url: "https://iri-dev.ppg.es.net"
    timeout: 60
  esnet-west:
    base_url: "https://esnet-west.sdn-sense.net"
    timeout: 60
  alcf:
    base_url: "https://api.alcf.anl.gov"
    timeout: 60

max_connections: 1000
max_keepalive_connections: 100
default_timeout: 60
log_level: "INFO"
host: "0.0.0.0"
port: 8000
workers: 4
```

### All Settings

| Setting | Env var | Default | Description |
|---------|---------|---------|-------------|
| `facilities` | `RIG_FACILITIES` (JSON) | `{}` | Map of facility name to `{base_url, timeout}` |
| `max_connections` | `RIG_MAX_CONNECTIONS` | `1000` | Max concurrent upstream connections per worker |
| `max_keepalive_connections` | `RIG_MAX_KEEPALIVE_CONNECTIONS` | `100` | Keep-alive pool size per worker |
| `default_timeout` | `RIG_DEFAULT_TIMEOUT` | `60` | Default upstream request timeout (seconds) |
| `host` | `RIG_HOST` | `0.0.0.0` | Bind address |
| `port` | `RIG_PORT` | `8000` | Bind port |
| `workers` | `RIG_WORKERS` | `4` | Number of uvicorn worker processes |
| `log_level` | `RIG_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `vault_backend` | `RIG_VAULT_BACKEND` | `""` | Vault backend: `docker`, `kube`, or `aws` |
| `docker_credentials` | `RIG_DOCKER_CREDENTIALS` (JSON) | `{}` | Local test credential map: `user -> project -> facility -> token` |
| `vault_kube_namespace` | `RIG_VAULT_KUBE_NAMESPACE` | `default` | Kubernetes namespace for secret lookup |
| `vault_aws_region` | `RIG_VAULT_AWS_REGION` | `us-east-1` | AWS region for Secrets Manager |
| `vault_secret_prefix` | `RIG_VAULT_SECRET_PREFIX` | `rig-creds` | Prefix for secret names |
| `policy_engine_url` | `RIG_POLICY_ENGINE_URL` | `""` | External policy engine URL (OPA/Cedar) |

---

## Identity Resolution

RIG resolves credentials in two tiers, evaluated in order. The first tier that
returns a token wins; if all tiers fail, the original `Authorization` header is
passed through unchanged.

### Tier 1 -- Pass-through (default)

The incoming `Authorization` header is forwarded to the upstream facility as-is.
This works when the client already holds a token the facility accepts (e.g., the
same Globus token accepted by both Kong and the IRI endpoint).

No configuration required. This is the default when no vault backend is set.

### Tier 2 -- Vaulted Credentials

Pre-stored, per-user, per-project, per-facility credentials retrieved from a
local Docker config file, Kubernetes Secrets, or AWS Secrets Manager. This is
for facilities that do not support federated tokens and require locally
provisioned credentials.

When RIG runs behind Kong, it first extracts user identity from Kong's trusted
`X-Userinfo` header and uses that header's `sub` claim for vault lookup. If
`X-Userinfo` is absent, RIG falls back to extracting `sub` from a Bearer JWT in
the `Authorization` header (decoded without verification -- Kong has already
verified the token). The project is read from the `X-Project` request header.

Both **user** and **project** must be present for vault lookup to proceed. If
either is missing, RIG logs a warning and falls back to pass-through.

#### Storing Tokens in a Local Docker Config File

Enable with:

```yaml
vault_backend: docker
```

This backend is intended for local testing only. Define credentials in your
`config.yaml` or a separate file such as `config.docker.yaml`, then run RIG
with `RIG_CONFIG_PATH=config.docker.yaml`.

The credential map is:

```text
docker_credentials.{user}.{project}.{facility} = "<bearer-token>"
```

- `user` must match the trusted `sub` claim from Kong's `X-Userinfo` header.
- If Kong is not in front of RIG, `user` falls back to the JWT `sub` claim in
  the incoming `Authorization` header.
- `project` must match the incoming `X-Project` header.
- `facility` must be one of your configured facilities, for example `nersc`,
  `esnet-east`, `esnet-west`, or `alcf`.

Example:

```yaml
facilities:
  nersc:
    base_url: "https://api.iri.nersc.gov"
    timeout: 60
  esnet-east:
    base_url: "https://iri-dev.ppg.es.net"
    timeout: 60
  esnet-west:
    base_url: "https://esnet-west.sdn-sense.net"
    timeout: 60
  alcf:
    base_url: "https://api.alcf.anl.gov"
    timeout: 60

vault_backend: docker
docker_credentials:
  alice:
    m3795:
      nersc: "alice_nersc_token"
      esnet-east: "alice_esnet_east_token"
      esnet-west: "alice_esnet_west_token"
      alcf: "alice_alcf_token"
  bob:
    irisandbox:
      nersc: "bob_nersc_token"
      esnet-east: "bob_esnet_east_token"
      esnet-west: "bob_esnet_west_token"
      alcf: "bob_alcf_token"
```

With that config:

- Requests from JWT subject `alice` with `X-Project: m3795` use Alice's facility token.
- Requests from JWT subject `bob` with `X-Project: irisandbox` use Bob's facility token.
- If a matching user, project, or facility entry is missing, RIG falls back to
  pass-through and forwards the original `Authorization` header.

#### Storing Tokens in Kubernetes Secrets

Enable with:

```bash
RIG_VAULT_BACKEND=kube
RIG_VAULT_KUBE_NAMESPACE=rig          # namespace where secrets live
RIG_VAULT_SECRET_PREFIX=rig-creds     # default
```

**Secret naming convention:**

```
{prefix}-{user}-{project}-{facility}
```

Example: user `alice`, project `m3795`, facility `nersc`:

```
rig-creds-alice-m3795-nersc
```

**Secret format:**

The secret must contain a key named `token` whose value is the bearer token
for that user/project/facility combination.

```bash
# Create a secret for user alice, project m3795, at NERSC
kubectl create secret generic rig-creds-alice-m3795-nersc \
  --namespace=rig \
  --from-literal=token="eyJhbGciOiJSUzI1NiIs..."
```

Or as a YAML manifest:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rig-creds-alice-m3795-nersc
  namespace: rig
type: Opaque
data:
  token: ZXlKaGJHY2lPaUpTVXpJMU5pSXMuLi4=    # base64-encoded token
```

**Multiple facilities for the same user/project:**

```bash
kubectl create secret generic rig-creds-alice-m3795-nersc \
  --namespace=rig --from-literal=token="<nersc-token>"

kubectl create secret generic rig-creds-alice-m3795-alcf \
  --namespace=rig --from-literal=token="<alcf-token>"

kubectl create secret generic rig-creds-alice-m3795-esnet-east \
  --namespace=rig --from-literal=token="<esnet-east-token>"
```

**RBAC requirements:**

The RIG service account must have `get` permission on secrets in the configured
namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: rig-secret-reader
  namespace: rig
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rig-secret-reader-binding
  namespace: rig
subjects:
  - kind: ServiceAccount
    name: rig
    namespace: rig
roleRef:
  kind: Role
  name: rig-secret-reader
  apiGroup: rbac.authorization.k8s.io
```

#### Storing Tokens in AWS Secrets Manager

Enable with:

```bash
RIG_VAULT_BACKEND=aws
RIG_VAULT_AWS_REGION=us-east-1        # default
RIG_VAULT_SECRET_PREFIX=rig-creds     # default
```

**Secret naming convention:**

```
{prefix}/{user}/{project}/{facility}
```

Example: user `alice`, project `m3795`, facility `nersc`:

```
rig-creds/alice/m3795/nersc
```

**Secret format -- plain string:**

Store the bare token as the secret value:

```bash
aws secretsmanager create-secret \
  --name "rig-creds/alice/m3795/nersc" \
  --secret-string "eyJhbGciOiJSUzI1NiIs..." \
  --region us-east-1
```

**Secret format -- JSON:**

Alternatively, store a JSON object with a `token` key:

```bash
aws secretsmanager create-secret \
  --name "rig-creds/alice/m3795/nersc" \
  --secret-string '{"token": "eyJhbGciOiJSUzI1NiIs..."}' \
  --region us-east-1
```

RIG tries to parse the secret as JSON and read the `token` key. If parsing
fails, the raw string is used as the token.

**Updating an existing secret:**

```bash
aws secretsmanager put-secret-value \
  --secret-id "rig-creds/alice/m3795/nersc" \
  --secret-string "eyJuZXd0b2tlbiI6..." \
  --region us-east-1
```

**IAM requirements:**

The RIG execution role (ECS task role, EC2 instance profile, or IRSA role) must
have `secretsmanager:GetSecretValue` on the relevant secret ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:rig-creds/*"
    }
  ]
}
```

#### Vault Lookup Flow Summary

```
Incoming request
  |
  +-- Extract user from JWT sub claim
  +-- Extract project from X-Project header
  |
  +-- user or project missing? --> WARN, fall back to pass-through
  |
  +-- vault_backend == "kube"?
  |     |
  |     +-- Read k8s secret: {prefix}-{user}-{project}-{facility}
  |     +-- Return secret.data["token"]
  |
  +-- vault_backend == "aws"?
        |
        +-- Read AWS secret: {prefix}/{user}/{project}/{facility}
        +-- Parse as JSON {"token": "..."} or use raw string
        +-- Return token
```

---

## API Surface

### Proxy Route

```
{GET,HEAD,OPTIONS,POST,PUT,DELETE,PATCH} /{facility}/{path:path}
```

All methods, all paths. RIG does not inspect or validate the downstream path --
it forwards whatever the client sends. Callers must provide the full upstream API
path after the facility segment, for example `/api/v1/facility` or
`/api/v2/compute/jobs`.

**Required headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes (for authenticated endpoints) | Bearer token, forwarded upstream |
| `X-Project` | For Tier 2 vault lookup | Project identifier for credential resolution |

**Examples:**

```bash
# List facility metadata at NERSC
curl http://rig:8000/nersc/api/v1/facility \
  -H "Authorization: Bearer <token>"

# Submit a job at ESnet-East with project context
curl -X POST http://rig:8000/esnet-east/api/v1/compute/job/perlmutter \
  -H "Authorization: Bearer <token>" \
  -H "X-Project: m3795" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-job", "script": "#!/bin/bash\necho hello"}'

# List files at ALCF
curl http://rig:8000/alcf/api/v1/filesystem/ls/theta?path=/home/alice \
  -H "Authorization: Bearer <token>"
```

### Health Endpoints

```
GET /health    --> {"status": "ok"}                    (liveness probe)
GET /ready     --> {"status": "ready", "facilities": [...]}  (readiness probe)
```

---

## Observability

### Structured JSON Logging

All log output is single-line JSON to stdout:

```json
{
  "timestamp": "2026-04-30 14:22:01,234",
  "level": "INFO",
  "logger": "rig.proxy",
  "message": "Proxied request",
  "request_id": "a1b2c3d4-...",
  "facility": "nersc",
  "path": "api/v1/facility",
  "method": "GET",
  "status": 200,
  "latency_ms": 142
}
```

### Request Tracing

- **X-Request-ID**: Extracted from the incoming request (set by Kong/LB) or
  generated as a UUID. Propagated to the upstream and included in the response.
- **traceparent**: If present in the incoming request, forwarded to the upstream
  (W3C Trace Context).
- **x-upstream-latency-ms**: Added to every response, measuring the time from
  sending the upstream request to receiving the first byte.

### Error Responses

| Upstream condition | RIG status | Body |
|---|---|---|
| Unknown facility | 404 | `{"error": "Unknown facility: ...", "known_facilities": [...]}` |
| Policy denied | 403 | `{"error": "Forbidden by policy"}` |
| Connection refused / DNS failure | 502 | `{"error": "Cannot connect to upstream"}` |
| Timeout | 504 | `{"error": "Upstream timeout"}` |
| Other upstream error | 502 | `{"error": "Upstream error"}` |

---

## Deployment

### Docker

```bash
docker build -t rig:latest .
docker run -p 8000:8000 \
  -e RIG_VAULT_BACKEND=kube \
  -e RIG_VAULT_KUBE_NAMESPACE=rig \
  -e RIG_LOG_LEVEL=INFO \
  rig:latest
```

The `Dockerfile` uses `python:3.13-slim` and runs uvicorn with 4 workers by
default. Override worker count with `RIG_WORKERS` or the `WEB_CONCURRENCY`
environment variable.

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rig
  namespace: rig
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rig
  template:
    metadata:
      labels:
        app: rig
    spec:
      serviceAccountName: rig
      containers:
        - name: rig
          image: rig:latest
          ports:
            - containerPort: 8000
          env:
            - name: RIG_VAULT_BACKEND
              value: "kube"
            - name: RIG_VAULT_KUBE_NAMESPACE
              value: "rig"
            - name: RIG_LOG_LEVEL
              value: "INFO"
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: rig
  namespace: rig
spec:
  selector:
    app: rig
  ports:
    - port: 8000
      targetPort: 8000
```

### Kong Integration

Add RIG as an upstream service in your Kong configuration:

```yaml
services:
  - name: rig-service
    url: http://rig.rig.svc.cluster.local:8000
    routes:
      - name: rig-route
        paths:
          - /rig
        strip_path: false
    plugins:
      - name: openid-connect
        config:
          bearer_only: "yes"
          # ... OIDC config
```

### Scaling

RIG scales linearly with replicas. Each instance is fully independent:

- 1 replica = baseline throughput
- 10 replicas = 10x throughput
- 100 replicas = burst capacity

No code changes, shared memory, or sticky sessions required. If one instance
dies mid-request, only that single request is affected.

Within each replica, uvicorn runs N worker processes (default 4), each with its
own async event loop and `httpx.AsyncClient` connection pool. Each worker
handles thousands of concurrent connections via asyncio.

---

## Development

```bash
# Install with dev dependencies
uv sync --all-extras

# Run tests
uv run python -m pytest tests/ -v

# Run locally
RIG_CONFIG_PATH=config.yaml uv run rig
```

### Tests

Tests use `httpx.ASGITransport` to test through the full ASGI stack without
starting a server, plus a lightweight fake upstream client to validate proxy
request construction and streaming behavior.

```bash
uv run python -m pytest tests/ -v
```

### Kubernetes Smoke Test

The manifests in [k8s/smoke](/Users/jbalcas/work/amsc/rig/k8s/smoke) deploy a
mock upstream, a single-replica RIG instance, and a smoke-test Job that checks
`/health`, `/ready`, and one proxied request.

```bash
docker build -t rig:latest .
kubectl apply -f k8s/smoke/namespace.yaml
kubectl apply -f k8s/smoke/rig-configmap.yaml -f k8s/smoke/upstream.yaml -f k8s/smoke/rig.yaml
kubectl apply -f k8s/smoke/smoke-job.yaml
kubectl logs -n rig-smoke job/rig-smoke-test
```
