#!/usr/bin/env bash
# Smoke test for the rig docker vault backend.
# Brings up rig + echo upstream via docker-compose, verifies that:
#   - health/ready/404 baseline works
#   - a known user (jbalcas) gets their incoming Bearer JWT replaced with the vaulted token
#   - an unknown user falls through to pass-through (original token reaches upstream)
set -euo pipefail

cd "$(dirname "$0")"

RIG="http://localhost:8000"

# Unsigned JWT with sub=jbalcas (matches docker_credentials in config.yaml)
JWT_JBALCAS="Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJqYmFsY2FzIiwiaXNzIjoicmlnLXNtb2tlIiwiZXhwIjo0MTAyNDQ0ODAwfQ."
# Unsigned JWT with sub=stranger (not in docker_credentials -> pass-through)
JWT_STRANGER="Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzdHJhbmdlciIsImlzcyI6InJpZy1zbW9rZSIsImV4cCI6NDEwMjQ0NDgwMH0."

cleanup() {
  echo "=== docker compose down ==="
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== docker compose up (build) ==="
docker compose up -d --build

echo "=== waiting for rig /health ==="
for i in $(seq 1 60); do
  if curl -fsS "$RIG/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "=== /health ==="
health="$(curl -fsS "$RIG/health")"
echo "$health"
echo "$health" | grep -q '"status":"ok"'

echo "=== /ready ==="
ready="$(curl -fsS "$RIG/ready")"
echo "$ready"
echo "$ready" | grep -q '"status":"ready"'
echo "$ready" | grep -q '"echo"'

echo "=== unknown facility -> 404 ==="
code="$(curl -o /dev/null -w '%{http_code}' -sS "$RIG/rig/nonexistent/test")"
echo "status=$code"
test "$code" = "404"

echo "=== known user (jbalcas/smoke) -> token rewritten to smoke-vault-token ==="
resp="$(curl -sS -w '\n%{http_code}' \
  -H "Authorization: $JWT_JBALCAS" \
  -H 'X-Project: smoke' \
  "$RIG/rig/echo/some/path?x=1")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"
echo "status=$code"
echo "$body"
test "$code" = "200"
# echo upstream returns the request as JSON, including the rewritten Authorization header
echo "$body" | grep -q '"authorization": "Bearer smoke-vault-token"'
echo "$body" | grep -q '"path": "/some/path"'

echo "=== unknown user (stranger) -> pass-through (original JWT reaches upstream) ==="
resp="$(curl -sS -w '\n%{http_code}' \
  -H "Authorization: $JWT_STRANGER" \
  -H 'X-Project: smoke' \
  "$RIG/rig/echo/another")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"
echo "status=$code"
test "$code" = "200"
echo "$body" | grep -qF "\"authorization\": \"$JWT_STRANGER\""

echo "=== known user but missing X-Project -> pass-through ==="
resp="$(curl -sS -w '\n%{http_code}' \
  -H "Authorization: $JWT_JBALCAS" \
  "$RIG/rig/echo/no-project")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"
echo "status=$code"
test "$code" = "200"
# Without X-Project, vault lookup is skipped -> original JWT passes through
echo "$body" | grep -qF "\"authorization\": \"$JWT_JBALCAS\""

echo "=== known user, wrong project -> pass-through ==="
resp="$(curl -sS -w '\n%{http_code}' \
  -H "Authorization: $JWT_JBALCAS" \
  -H 'X-Project: not-smoke' \
  "$RIG/rig/echo/wrong-proj")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"
echo "status=$code"
test "$code" = "200"
# vault lookup returns None -> falls through to original JWT
echo "$body" | grep -qF "\"authorization\": \"$JWT_JBALCAS\""

echo "=== proxy injects x-request-id and x-upstream-latency-ms ==="
hdrs="$(curl -sS -D - -o /dev/null \
  -H "Authorization: $JWT_JBALCAS" \
  -H 'X-Project: smoke' \
  "$RIG/rig/echo/headers-check")"
echo "$hdrs" | grep -i -q '^x-request-id:'
echo "$hdrs" | grep -i -q '^x-upstream-latency-ms:'

echo
echo "ALL CHECKS PASSED"
