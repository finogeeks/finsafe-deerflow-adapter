# finsafe-deerflow-adapter

FinSAFE SaaS sandbox provider for [DeerFlow](https://github.com/bytedance/deer-flow).

Repository: `https://github.com/finogeeks/finsafe-deerflow-adapter`

DeerFlow loads sandbox backends via `config.yaml` → `sandbox.use`. This package
implements `FinsafeSandboxProvider` so agent tools run in FinSAFE-isolated cells.

**No DeerFlow core code changes** — install this package and configure `sandbox.use`.

## Architecture

```
FinSAFE daemon (ghcr.io/geeksfino/finsafe-saas)   ← docker/ in this repo
        ↑ HTTP
finsafe-deerflow-adapter (this package)
        ↑ sandbox.use
DeerFlow gateway
```

## Install

Installed from GitHub (no PyPI publish required); `deerflow-harness` resolves from PyPI.

```bash
pip install "git+https://github.com/finogeeks/finsafe-deerflow-adapter.git@v0.1.0"
```

Into the DeerFlow gateway environment (uv):

```bash
cd deer-flow/backend
uv add "git+https://github.com/finogeeks/finsafe-deerflow-adapter.git@v0.1.0"
```

Or declare it in `deer-flow/backend/pyproject.toml` so `uv sync --extra finsafe` works:

```toml
[project.optional-dependencies]
finsafe = ["finsafe-deerflow-adapter"]

[tool.uv.sources]
finsafe-deerflow-adapter = { git = "https://github.com/finogeeks/finsafe-deerflow-adapter", tag = "v0.1.0" }
```

Then `cd deer-flow/backend && uv sync --extra finsafe`.

Docker: build the gateway image with `--build-arg UV_EXTRAS=finsafe` once the
source above is declared.

## DeerFlow config

```yaml
sandbox:
  use: finsafe_deerflow_adapter:FinsafeSandboxProvider
  base_url: $FINSAFE_BASE_URL
  token: $FINSAFE_TOKEN
  tenant_id: acme
  user_id: app-user
  policy_id: deerflow-sandbox
  host_profile: linux-desktop-isolated
  network_mode: deny
  memory_max: "2G"
  pids_max: "512"
  cpu_max: "200000 100000"
```

Restart gateway after changing `sandbox.use`.

## Start FinSAFE sidecar

**Standalone** (customer infra):

```bash
cd docker && docker compose up -d
export FINSAFE_BASE_URL=http://127.0.0.1:18080 FINSAFE_TOKEN=dev-change-me
../scripts/verify-sidecar.sh
```

**With DeerFlow**: use `deer-flow/docker/docker-compose.finsafe.yaml` overlay — see
`deer-flow/docker/FINSAFE.md`.

## Tests

Unit tests need `deerflow-harness` importable. Easiest is to run them through a
DeerFlow backend venv (which already has harness):

```bash
chmod +x scripts/*.sh
./scripts/smoke.sh --quick          # unit tests only (via DeerFlow venv)
./scripts/smoke.sh --sidecar        # start sidecar + unit + integration
```

`smoke.sh` uses `DEER_FLOW_BACKEND` (default `../deer-flow/backend`) to locate the
uv environment. A standalone `pip install deerflow-harness` venv also works.

## Documentation

| Doc | Content |
|-----|---------|
| [docs/finsafe-policy.md](docs/finsafe-policy.md) | Policy matrix (EN) |
| [docs/finsafe-security-guide.md](docs/finsafe-security-guide.md) | Security config & test cases (中文) |

## DeerFlow repo footprint

DeerFlow keeps only three wiring files: `docker-compose.finsafe.yaml`, `finsafe-daemon.yaml`, `FINSAFE.md`.
