#!/usr/bin/env bash
# FinSAFE provider smoke: unit tests + optional live integration against sidecar.
#
# Usage:
#   ./scripts/smoke.sh              # unit + integration (sidecar must be up)
#   ./scripts/smoke.sh --quick      # unit tests only
#   ./scripts/smoke.sh --sidecar    # start docker sidecar, then run all tests
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
QUICK=0
START_SIDECAR=0
DEER_FLOW_BACKEND="${DEER_FLOW_BACKEND:-${ROOT}/../deer-flow/backend}"

for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --sidecar) START_SIDECAR=1 ;;
    -h|--help)
      sed -n '2,9p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ "${START_SIDECAR}" -eq 1 ]]; then
  echo "==> Starting FinSAFE sidecar (docker compose)"
  (cd "${ROOT}/docker" && docker compose up -d)
  export FINSAFE_BASE_URL="${FINSAFE_BASE_URL:-http://127.0.0.1:18080}"
  export FINSAFE_TOKEN="${FINSAFE_TOKEN:-dev-change-me}"
  "${ROOT}/scripts/verify-sidecar.sh"
fi

if [[ ! -d "${DEER_FLOW_BACKEND}" ]]; then
  echo "ERROR: DeerFlow backend not found at ${DEER_FLOW_BACKEND}" >&2
  echo "Set DEER_FLOW_BACKEND to a checkout with uv and deerflow-harness." >&2
  exit 1
fi

echo "==> Unit tests (mocked)"
cd "${DEER_FLOW_BACKEND}"
uv sync --extra finsafe >/dev/null
uv run pytest "${ROOT}/tests/test_policy.py" "${ROOT}/tests/test_provider.py" -q

if [[ "${QUICK}" -eq 1 ]]; then
  echo "==> Skipping live integration (--quick)"
  exit 0
fi

export FINSAFE_BASE_URL="${FINSAFE_BASE_URL:-http://127.0.0.1:18080}"
export FINSAFE_TOKEN="${FINSAFE_TOKEN:-dev-change-me}"

echo "==> Live integration (provider → daemon → cell)"
uv run pytest "${ROOT}/tests/test_integration.py" -m integration -v

echo "==> FinSAFE provider smoke passed"
