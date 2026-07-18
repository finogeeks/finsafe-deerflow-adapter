#!/usr/bin/env bash
# Verify the FinSAFE sidecar starts and responds (standalone, no DeerFlow).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/docker"

TOKEN="${FINSAFE_TOKEN:-dev-change-me}"
BASE_URL="${FINSAFE_BASE_URL:-http://127.0.0.1:18080}"

echo "==> Starting FinSAFE sidecar..."
docker compose up -d

echo "==> Waiting for readiness at ${BASE_URL}..."
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE_URL}/v1/executions/does-not-exist" || true)
  if [[ "$code" == "404" ]]; then
    echo "OK: daemon ready (HTTP ${code})"
    exit 0
  fi
  sleep 2
done

echo "FAIL: daemon did not become ready within 120s (last HTTP ${code:-none})"
docker compose logs --tail=50
exit 1
