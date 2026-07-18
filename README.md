# finsafe-deerflow-provider

FinSAFE SaaS sandbox provider for [DeerFlow](https://github.com/bytedance/deer-flow).

Repository: `https://github.com/finogeeks/finsafe-deerflow-provider`

DeerFlow loads sandbox backends via `config.yaml` → `sandbox.use`. This package
implements `FinsafeSandboxProvider` so agent tools run in FinSAFE-isolated cells.

**No DeerFlow core code changes** — install this package and configure `sandbox.use`.

## Architecture

```
FinSAFE daemon (ghcr.io/geeksfino/finsafe-saas)   ← docker/ in this repo
        ↑ HTTP
finsafe-deerflow-provider (this package)
        ↑ sandbox.use
DeerFlow gateway
```

## Install

### From GitHub (standalone / non-workspace)

**`deerflow-harness` is not on PyPI at 2.x** (the published 0.0.1 release is stale),
so a standalone install must also pull `deerflow-harness` from the DeerFlow repo:

```bash
pip install \
  "deerflow-harness @ git+https://github.com/bytedance/deer-flow.git@c9b6131f8fc4beb186632556ea3d589488edc90f#subdirectory=backend/packages/harness" \
  "git+https://github.com/finogeeks/finsafe-deerflow-provider.git@v0.2.2"
```

The provider declares `deerflow-harness>=2.1.0` as a plain dependency so the
consumer environment chooses the source. In a standalone venv that source is the
git URL above; inside the DeerFlow backend workspace it is the local workspace
package (see below).

### Into the DeerFlow backend workspace (uv)

In the DeerFlow monorepo, `deerflow-harness` is already provided as a workspace
package by `deer-flow/backend`. Simply add the provider from git and keep
`deerflow-harness` on its workspace source:

```bash
cd deer-flow/backend
uv add "git+https://github.com/finogeeks/finsafe-deerflow-provider.git@v0.2.2"
```

Or declare it in `deer-flow/backend/pyproject.toml` so `uv sync --extra finsafe` works:

```toml
[project.optional-dependencies]
finsafe = ["finsafe-deerflow-provider"]

[tool.uv.sources]
deerflow-harness = { workspace = true }
finsafe-deerflow-provider = { git = "https://github.com/finogeeks/finsafe-deerflow-provider", tag = "v0.2.2" }
```

Then `cd deer-flow/backend && uv sync --extra finsafe`.

Docker: build the gateway image with `--build-arg UV_EXTRAS=finsafe` once the
source above is declared.

**Harness pin:** validate against `deerflow-harness` 2.1.0 (commit `c9b6131f` on
`bytedance/deer-flow` `main`). Bump the `>=` floor in `pyproject.toml` when you
validate against a newer DeerFlow release.

## DeerFlow config

```yaml
sandbox:
  use: finsafe_deerflow_provider:FinsafeSandboxProvider
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
uv environment. After `pip install` from GitHub, a venv with the provider alone also works.

## Documentation

| Doc | Content |
|-----|---------|
| [docs/finsafe-policy.md](docs/finsafe-policy.md) | Policy matrix (EN) |
| [docs/finsafe-security-guide.md](docs/finsafe-security-guide.md) | Security config & test cases (中文) |

## DeerFlow repo footprint

DeerFlow keeps only three wiring files: `docker-compose.finsafe.yaml`, `finsafe-daemon.yaml`, `FINSAFE.md`.
