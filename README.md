# finsafe-deerflow-provider

FinSAFE SaaS sandbox provider for [DeerFlow](https://github.com/bytedance/deer-flow).

Repository: `https://github.com/finogeeks/finsafe-deerflow-provider`

DeerFlow loads sandbox backends via `config.yaml` → `sandbox.use`. This package
implements `FinsafeSandboxProvider` so agent tools run in FinSAFE-isolated cells.

**No DeerFlow core code changes** — install this package and configure `sandbox.use`.

## Quick start

**Start here:** [docs/INTEGRATION.md](docs/INTEGRATION.md) — end-to-end integration,
sandbox permissions, Compose wiring, and acceptance tests.

```bash
# 1. Install into DeerFlow backend (v0.2.2)
cd deer-flow/backend
# add finsafe extra + git source to pyproject.toml (see INTEGRATION.md)
uv sync --extra finsafe

# 2. Configure config.yaml (copy from examples/deer-flow/config-sandbox-finsafe.yaml)

# 3. Start sidecar + DeerFlow (copy examples/deer-flow/* to deer-flow/docker/)
```

## Architecture

```
FinSAFE daemon (ghcr.io/geeksfino/finsafe-saas)   ← docker/ or examples/deer-flow/
        ↑ HTTP
finsafe-deerflow-provider (this package)
        ↑ sandbox.use
DeerFlow gateway
```

## Install (summary)

Provider **v0.2.2** declares `deerflow-harness>=2.1.0` as a plain dependency — the
consumer environment chooses the source (workspace in DeerFlow backend, git URL in
standalone venv). Details: [INTEGRATION.md §3](docs/INTEGRATION.md#3-安装-provider).

```toml
# deer-flow/backend/pyproject.toml
[project.optional-dependencies]
finsafe = ["finsafe-deerflow-provider"]

[tool.uv.sources]
deerflow-harness = { workspace = true }
finsafe-deerflow-provider = { git = "https://github.com/finogeeks/finsafe-deerflow-provider", tag = "v0.2.2" }
```

Docker gateway build: `UV_EXTRAS=finsafe`.

## DeerFlow config (production minimum)

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

Full template with all tunable fields:
[examples/deer-flow/config-sandbox-finsafe.yaml](examples/deer-flow/config-sandbox-finsafe.yaml).

Restart gateway after changing `sandbox.use`.

## Documentation

| Doc | Content |
|-----|---------|
| **[docs/INTEGRATION.md](docs/INTEGRATION.md)** | **主集成指南**（安装、配置、权限、验收） |
| [docs/finsafe-security-guide.md](docs/finsafe-security-guide.md) | 沙箱权限字段表、配置模板、测试用例（中文） |
| [docs/finsafe-policy.md](docs/finsafe-policy.md) | 策略栈与 JSON policy 参考（英文） |
| [examples/deer-flow/FINSAFE.md](examples/deer-flow/FINSAFE.md) | DeerFlow Docker Compose 接线 |

## Tests

```bash
chmod +x scripts/*.sh
DEER_FLOW_BACKEND=/path/to/deer-flow/backend ./scripts/smoke.sh --quick   # unit only
DEER_FLOW_BACKEND=/path/to/deer-flow/backend ./scripts/smoke.sh --sidecar  # + integration
```

## DeerFlow repo footprint

Copy into `deer-flow/docker/` from [examples/deer-flow/](examples/deer-flow/):

- `docker-compose.finsafe.yaml`
- `finsafe-daemon.yaml`
- (optional) `FINSAFE.md` for operators

No other DeerFlow core changes required.
