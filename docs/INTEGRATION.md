# DeerFlow × FinSAFE 集成指南

本文档是 **客户集成的主入口**：从安装 provider、启动 FinSAFE sidecar、配置 DeerFlow `config.yaml`，到验收测试的完整流程。

| 文档 | 用途 |
|------|------|
| **本文** | 端到端集成步骤 |
| [finsafe-security-guide.md](finsafe-security-guide.md) | 沙箱权限完整字段表、生产/开发模板、手动与自动化测试用例 |
| [finsafe-policy.md](finsafe-policy.md) | 策略栈架构与 JSON 策略参考（英文） |
| [../examples/deer-flow/FINSAFE.md](../examples/deer-flow/FINSAFE.md) | DeerFlow Docker Compose 接线说明 |
| [../examples/deer-flow/config-sandbox-finsafe.yaml](../examples/deer-flow/config-sandbox-finsafe.yaml) | 可复制到 `config.yaml` 的 `sandbox:` 模板 |

Provider 版本：**v0.2.2**（`https://github.com/finogeeks/finsafe-deerflow-provider`）

---

## 1. 架构

```text
浏览器 / IM → DeerFlow Gateway
                 ↓ sandbox.use
         finsafe-deerflow-provider
                 ↓ HTTP (Phase X sessions)
         finsafe-server-http (sidecar)
                 ↓ bubblewrap + Landlock + cgroup
         linux-desktop-isolated cell (uid 1000)
```

**无需修改 DeerFlow 核心代码**：安装 Python 包并配置 `sandbox.use` 即可。

安全能力分三层（详见 [finsafe-security-guide.md §1](finsafe-security-guide.md#1-安全能力分层测什么)）：

1. **DeerFlow SandboxAudit** — bash 命令审计（block / warn / pass）
2. **`config.yaml` → `sandbox.*`** — 网络、cgroup、文件系统策略（客户主要配置面）
3. **FinSAFE 编译器内置** — deny-read、seccomp、bwrap 命名空间

---

## 2. 前置条件

| 组件 | 要求 |
|------|------|
| DeerFlow | `2.1.0+`（harness workspace） |
| Python | `>=3.12` |
| FinSAFE sidecar | Docker；Linux 宿主机需支持 bubblewrap + cgroup v2 |
| Sidecar 镜像 | `ghcr.io/geeksfino/finsafe-saas:v0.9.16`（可 pin 其他 tag） |

Sidecar 容器需 **`privileged: true`** 与 **`cgroup: host`**（见 `docker/docker-compose.yaml`）。

---

## 3. 安装 provider

### 3.1 DeerFlow backend workspace（推荐）

在 `deer-flow/backend/pyproject.toml` 中声明：

```toml
[project.optional-dependencies]
finsafe = ["finsafe-deerflow-provider"]

[tool.uv.sources]
deerflow-harness = { workspace = true }
finsafe-deerflow-provider = { git = "https://github.com/finogeeks/finsafe-deerflow-provider", tag = "v0.2.2" }
```

```bash
cd deer-flow/backend
uv sync --extra finsafe
```

Docker 构建 gateway 时传入：

```bash
UV_EXTRAS=finsafe docker compose ... build gateway
```

### 3.2 独立 venv（非 workspace）

PyPI 上的 `deerflow-harness` 0.0.1 已过时，需同时从 DeerFlow 仓库安装 harness：

```bash
pip install \
  "deerflow-harness @ git+https://github.com/bytedance/deer-flow.git@c9b6131f8fc4beb186632556ea3d589488edc90f#subdirectory=backend/packages/harness" \
  "git+https://github.com/finogeeks/finsafe-deerflow-provider.git@v0.2.2"
```

---

## 4. 配置 DeerFlow

将 [examples/deer-flow/config-sandbox-finsafe.yaml](../examples/deer-flow/config-sandbox-finsafe.yaml) 中的 `sandbox:` 段合并进项目根目录 `config.yaml`（替换默认的 `LocalSandboxProvider`）。

**生产最小配置：**

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
  bash_command_timeout: 600
```

修改 `config.yaml` 后 **重启 gateway**。

### 4.1 三处配置必须一致

| 项 | `config.yaml` | `finsafe-daemon.yaml` | Compose / 环境变量 |
|----|---------------|----------------------|-------------------|
| API 令牌 | `sandbox.token` 或 `$FINSAFE_TOKEN` | `auth.bearer_token` | gateway 的 `FINSAFE_TOKEN` |
| 租户 | `sandbox.tenant_id` | `auth.tenant_id` | — |
| 默认用户 | `sandbox.user_id` | `auth.user_id` | — |
| Sidecar 地址 | `sandbox.base_url` 或 `$FINSAFE_BASE_URL` | — | `FINSAFE_BASE_URL=http://finsafe-saas:8080`（Compose 内） |

已登录用户会以 DeerFlow 用户 id 覆盖 `sandbox.user_id`；每个 `(user_id, thread_id)` 拥有独立 FinSAFE session。

---

## 5. 沙箱权限怎么设

客户主要通过 **`config.yaml` → `sandbox:`** 控制 cell 姿态。Sidecar 用 **`finsafe-daemon.yaml`** 控制是否启用真实 cell 与宿主机资源预算。

### 5.1 推荐默认值（生产）

| 类别 | 字段 | 推荐值 | 说明 |
|------|------|--------|------|
| 隔离 profile | `host_profile` | `linux-desktop-isolated` | bwrap + Landlock + cgroup |
| 网络 | `network_mode` | **`deny`** | 禁止 cell 出网；生产不要用 `host` |
| 内存 | `memory_max` | `"2G"` | 单 cell cgroup 上限；用 `G`/`M`，勿用 `GiB` |
| 进程数 | `pids_max` | `"512"` | 单 cell 进程上限 |
| CPU | `cpu_max` | `"200000 100000"` | cgroup v2，约 2 核 |
| Shell 超时 | `bash_command_timeout` | `600` | 秒；同步写入 cell `timeout_ms` |
| Sidecar | `executor.mock_cells` | **`false`** | `true` 无真实隔离 |

**两层内存：**

| 层级 | 配置位置 | 典型值 |
|------|----------|--------|
| 单 cell | `sandbox.memory_max` | `2G` |
| 整 daemon | `host_profiles.linux-desktop-isolated.memory_max` | `8G` |

### 5.2 网络模式

| `network_mode` | cell 出网 | 官方 `finsafe-saas` |
|----------------|-----------|---------------------|
| **`deny`** | 禁止 | **支持（推荐）** |
| `host` | 共享 sidecar Docker 网络 | 支持（仅开发） |
| `allowlist` | 白名单 + egress proxy | **不支持** |
| `proxy` | 经代理出网 | 需企业版/自建 |

需要 Agent 访问公网时，优先使用 DeerFlow **`web_search` / `web_fetch` 等工具**（在 gateway 侧执行），而不是放宽 cell 网络。

### 5.3 文件系统策略（高级）

Provider 每次 tool 调用向 finsafe-server 提交 JSON policy。以下字段可在 `sandbox:` 中覆盖（默认见 [finsafe-policy.md §3](finsafe-policy.md#3-per-execution-json-assembled-by-finsafesandboxprovider)）：

| 字段 | 默认 | 用途 |
|------|------|------|
| `filesystem_read_only_paths` | `/usr`, `/bin`, … | cell 内只读 rootfs（保证 `/bin/sh` 可 exec） |
| `filesystem_read_write_paths` | `[/dev/null]` | shell 重定向 |
| `filesystem_deny_read_paths` | `[]` | 追加自定义 deny-read |
| `filesystem_deny_write_globs` | `[]` | 追加禁止写入 glob |
| `filesystem_skip_default_deny_read` | `false` | **`true` 关闭 FinSAFE 内置 deny-read（不推荐生产）** |
| `policy_extensions` | `{}` | 合并 FinSAFE HighLevelPolicyV1 扩展字段 |

**Session 工作区 rw** 由 finsafe-server 按 session 目录自动注入，**不要**在 policy 里写 guest `/workspace`。

### 5.4 工具路径与隔离边界

| DeerFlow 工具 | 是否走 FinSAFE cell |
|---------------|---------------------|
| `bash`, `ls`, `glob`, `grep` | **是** |
| `read_file`, `write_file` | **否**（daemon session 文件 API） |

因此验收时要分别测试 bash 路径与 read_file 路径。详见 [finsafe-security-guide.md §1.1](finsafe-security-guide.md#11-工具路径与隔离边界重要)。

### 5.5 开发 vs 生产

| 场景 | `network_mode` | 说明 |
|------|------------------|------|
| 生产 / 验收 | `deny` | 见 [finsafe-security-guide.md §4.1](finsafe-security-guide.md#41-生产--验收严格) |
| 内网开发 | `host` | 隔离较弱；上线前改回 `deny` |

完整字段表与调优对照：[finsafe-security-guide.md §3](finsafe-security-guide.md#3-可配置安全项完整清单)。

---

## 6. 启动 FinSAFE sidecar

### 6.1 独立验证（不含 DeerFlow）

```bash
cd finsafe-deerflow-provider/docker
docker compose up -d
export FINSAFE_BASE_URL=http://127.0.0.1:18080 FINSAFE_TOKEN=dev-change-me
../scripts/verify-sidecar.sh
```

就绪探针：带 Bearer token 访问 `/v1/executions/does-not-exist` 返回 **HTTP 404** 表示 daemon 已启动。

### 6.2 与 DeerFlow Compose 一起运行

1. 将 [examples/deer-flow/](../examples/deer-flow/) 下三个文件复制到 `deer-flow/docker/`：

   ```bash
   cp examples/deer-flow/docker-compose.finsafe.yaml  /path/to/deer-flow/docker/
   cp examples/deer-flow/finsafe-daemon.yaml          /path/to/deer-flow/docker/
   # FINSAFE.md 供运维阅读，可选复制
   ```

2. 在 `config.yaml` 启用 FinSAFE sandbox（§4）。

3. 构建并启动：

   ```bash
   cd /path/to/deer-flow/docker
   export FINSAFE_TOKEN=dev-change-me   # 生产请轮换
   UV_EXTRAS=finsafe docker compose -p deer-flow \
     -f docker-compose.yaml \
     -f docker-compose.finsafe.yaml \
     build gateway
   docker compose -p deer-flow \
     -f docker-compose.yaml \
     -f docker-compose.finsafe.yaml \
     up -d
   ```

详细接线见 [examples/deer-flow/FINSAFE.md](../examples/deer-flow/FINSAFE.md)。

---

## 7. 验收测试

### 7.1 Provider 冒烟（改配置后推荐）

```bash
cd finsafe-deerflow-provider
chmod +x scripts/*.sh
DEER_FLOW_BACKEND=/path/to/deer-flow/backend ./scripts/smoke.sh --quick
```

26 项单元测试（mocked，无需 sidecar）。

### 7.2 集成测试（需 sidecar）

```bash
# 先启动 sidecar（§6.1 或 §6.2）
DEER_FLOW_BACKEND=/path/to/deer-flow/backend ./scripts/smoke.sh --sidecar
# 或 sidecar 已运行时：
./scripts/smoke.sh
```

覆盖：daemon 就绪、cell uid=1000、workspace 读写、network deny、shadow deny 等。

### 7.3 聊天窗口手动验收

在 `http://<主机>:2026` 让 Agent 执行 bash：`echo SANITY-OK && id -u` → 期望 uid **1000**。

完整用例编号（TC-MAN-*、TC-ISO-* 等）：[finsafe-security-guide.md §5](finsafe-security-guide.md#5-测试用例)。

### 7.4 日志检查

```bash
docker logs deer-flow-gateway 2>&1 | grep -iE 'FinSAFE|SandboxAudit|Created FinSAFE sandbox'
docker logs deer-flow-finsafe-saas 2>&1 | grep -E 'mock='
# 期望 mock=false
```

---

## 8. 生产 checklist

- [ ] `network_mode: deny`
- [ ] `mock_cells: false`；sidecar 日志 `mock=false`
- [ ] 轮换 `bearer_token` / `FINSAFE_TOKEN`（勿用 `dev-change-me`）
- [ ] `memory_max` 与 `host_profiles.*.memory_max` 使用 `G`/`M` 后缀
- [ ] `./scripts/smoke.sh --quick` 与 `./scripts/smoke.sh` 通过
- [ ] 手动 TC-MAN-01（uid 1000）与 TC-NET-01（network deny）通过

---

## 9. 常见问题

### `uv sync --extra finsafe` 报 deerflow-harness 来源冲突

Provider v0.2.2 已将 harness 改为普通依赖 `deerflow-harness>=2.1.0`。请保持：

```toml
[tool.uv.sources]
deerflow-harness = { workspace = true }
```

不要将 harness 与 provider 同时 pin 到不同 git URL。

### `network_mode: allowlist` admission 失败

官方 `ghcr.io/geeksfino/finsafe-saas` 不含 egress-proxy。请使用 `deny`，或部署支持 allowlist 的 FinSAFE 企业构建。

### Agent bash 报 exit 127

通常 `filesystem_read_only_paths` 过窄，cell 无法 exec `/bin/sh`。恢复默认 rootfs 只读集。

### 改 sandbox 配置不生效

`sandbox` 属于 DeerFlow **重启生效** 字段；修改 `config.yaml` 后重启 gateway。修改 `finsafe-daemon.yaml` 后重启 `finsafe-saas`。

---

## 10. 文档与示例文件索引

```text
finsafe-deerflow-provider/
├── README.md                          # 安装摘要
├── docs/
│   ├── INTEGRATION.md                 # 本文
│   ├── finsafe-security-guide.md      # 权限字段 + 测试用例（中文）
│   └── finsafe-policy.md              # 策略参考（英文）
├── docker/
│   ├── docker-compose.yaml            # 独立 sidecar
│   └── finsafe-daemon.yaml            # daemon 模板
├── examples/deer-flow/
│   ├── FINSAFE.md                     # DeerFlow Compose 接线
│   ├── docker-compose.finsafe.yaml    # Compose overlay
│   ├── finsafe-daemon.yaml            # 与 docker/ 同步的 daemon 模板
│   └── config-sandbox-finsafe.yaml    # config.yaml sandbox 段模板
└── scripts/
    ├── smoke.sh                       # 冒烟测试
    └── verify-sidecar.sh              # sidecar 就绪探针
```
