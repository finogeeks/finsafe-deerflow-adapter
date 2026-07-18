# DeerFlow Docker + FinSAFE wiring

This file describes how to run DeerFlow with the FinSAFE sidecar using files
from `finsafe-deerflow-provider/examples/deer-flow/`.

Full guide: [docs/INTEGRATION.md](../../docs/INTEGRATION.md)

## Files to copy into `deer-flow/docker/`

| Source (this repo) | Destination |
|--------------------|-------------|
| `docker-compose.finsafe.yaml` | `deer-flow/docker/docker-compose.finsafe.yaml` |
| `finsafe-daemon.yaml` | `deer-flow/docker/finsafe-daemon.yaml` |

Also merge `config-sandbox-finsafe.yaml` into your project-root `config.yaml`.

## One-time setup

1. **Install provider** in `deer-flow/backend` (see [INTEGRATION.md §3](../../docs/INTEGRATION.md#3-安装-provider)).

2. **Configure sandbox** — copy `examples/deer-flow/config-sandbox-finsafe.yaml` into `config.yaml`.

3. **Align tokens** — the same secret must appear in three places:

   | Location | Key |
   |----------|-----|
   | `config.yaml` | `sandbox.token` or `$FINSAFE_TOKEN` |
   | `docker/finsafe-daemon.yaml` | `auth.bearer_token` |
   | shell / `.env` | `FINSAFE_TOKEN` (injected into gateway by overlay) |

4. **Build gateway with FinSAFE extra** (requires `git` in `backend/Dockerfile` builder — see INTEGRATION.md §6.3):

   ```bash
   cd deer-flow/backend && uv lock
   cd ../docker
   touch ../.env
   export DEER_FLOW_HOME=../backend/.deer-flow DEER_FLOW_CONFIG_PATH=../config.yaml \
     DEER_FLOW_EXTENSIONS_CONFIG_PATH=../extensions_config.json DEER_FLOW_REPO_ROOT=.. \
     FINSAFE_TOKEN=dev-change-me UV_EXTRAS=finsafe
   docker compose -p deer-flow -f docker-compose.yaml -f docker-compose.finsafe.yaml build gateway frontend
   ```

5. **Start stack**:

   ```bash
   docker compose -p deer-flow -f docker-compose.yaml -f docker-compose.finsafe.yaml \
     up -d --no-build redis finsafe-saas gateway frontend nginx
   ```

Browser entry: `http://localhost:2026` (or `$PORT`).

## Verify

**Sidecar readiness** (404 = up):

```bash
docker exec deer-flow-gateway sh -c \
  'curl -s -o /dev/null -w "%{http_code}" \
   -H "Authorization: Bearer dev-change-me" \
   http://finsafe-saas:8080/v1/executions/does-not-exist'
```

**Real cells enabled**:

```bash
docker logs deer-flow-finsafe-saas 2>&1 | grep -E 'mock='
# expect: mock=false
```

**Provider smoke** (from finsafe-deerflow-provider checkout):

```bash
cd finsafe-deerflow-provider
DEER_FLOW_BACKEND=/path/to/deer-flow/backend ./scripts/smoke.sh --quick
DEER_FLOW_BACKEND=/path/to/deer-flow/backend ./scripts/smoke.sh
```

## Restart after config changes

| Changed | Restart |
|---------|---------|
| `config.yaml` sandbox section | `gateway` |
| `finsafe-daemon.yaml` (incl. `host_capabilities`) | `finsafe-saas` |

```bash
docker compose -p deer-flow -f docker-compose.yaml -f docker-compose.finsafe.yaml up -d --no-deps gateway
docker compose -p deer-flow -f docker-compose.yaml -f docker-compose.finsafe.yaml up -d --no-deps finsafe-saas
```

## Security

- Production: `network_mode: deny`, rotate `FINSAFE_TOKEN`, `mock_cells: false`.
- Allowlist egress: set `host_capabilities.allowlist_supported: true` in `finsafe-daemon.yaml` **and** `network_mode: allowlist` in sandbox config; do not use `proxy_profiles` (S1 executor does not support `network.mode=proxy`).
- See [finsafe-security-guide.md](../../docs/finsafe-security-guide.md) for permission fields and test cases.

## Upstream DeerFlow footprint

These three wiring files are the only DeerFlow-repo additions required for
FinSAFE integration. Provider logic lives in the separate
`finsafe-deerflow-provider` package — no DeerFlow core code changes.
