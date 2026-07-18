# FinSAFE × DeerFlow — complete security policy

This document is the **reference policy** for DeerFlow deployments that use
`FinsafeSandboxProvider` with the `finsafe-saas` sidecar. It maps three layers:

1. **DeerFlow `config.yaml`** — operator-tunable cell posture (network, cgroup, timeouts)
2. **`FinsafeSandboxProvider`** — per-execution JSON policy sent to finsafe-server
3. **FinSAFE compiler defaults** — built-in deny-read, bubblewrap, Landlock (not repeated in YAML)

For compose wiring and smoke tests see [FINSAFE.md](FINSAFE.md).

**Operator guide (中文):** [finsafe-security-guide.md](finsafe-security-guide.md) —
configuration templates, manual test cases, and automated smoke/chat E2E steps.

---

## Policy stack (what runs where)

```
Chat UI → bash / file tools
    ↓
DeerFlow SandboxAuditMiddleware     command block / warn / pass
    ↓
FinsafeSandboxProvider              network + cgroup + Landlock baseline JSON
    ↓
finsafe-server-http                 session workspace bind, admission, broker pool
    ↓
linux-desktop-isolated cell         bwrap namespaces + Landlock + cgroup v2 + uid 1000
    ↓
FinSAFE built-in deny-read          .ssh, .env, /etc/shadow, docker.sock, …
```

---

## 1. Recommended `config.yaml` (DeerFlow)

Copy into `config.yaml` when enabling Option 5 in `config.example.yaml`:

```yaml
sandbox:
  use: finsafe_deerflow_provider:FinsafeSandboxProvider

  # ── Sidecar connectivity (must match docker-compose.finsafe.yaml + daemon) ──
  base_url: $FINSAFE_BASE_URL          # http://finsafe-saas:8080 in compose
  token: $FINSAFE_TOKEN                # must match docker/finsafe-daemon.yaml auth.bearer_token
  tenant_id: acme
  user_id: app-user                    # fallback FinSAFE identity; per-login users override

  # ── Cell posture ──
  policy_id: deerflow-sandbox
  host_profile: linux-desktop-isolated # strict Linux: bwrap + Landlock + cgroup
  network_mode: deny                   # recommended — no cell egress

  # ── Per-cell cgroup limits (kernel memparse: "2G" not "2GiB") ──
  memory_max: "2G"
  pids_max: "512"
  cpu_max: "200000 100000"             # ~2 CPUs on cgroup v2

  # ── DeerFlow tool limits (apply before / after cell) ──
  bash_command_timeout: 600            # seconds; foreground bash in a turn
  bash_output_max_chars: 20000
  read_file_output_max_chars: 50000
  ls_output_max_chars: 20000
```

### `network_mode` options

| Mode | Cell egress | Stock `finsafe-saas` image |
|------|-------------|----------------------------|
| **`deny`** | No outbound connections | **Supported** (recommended) |
| `host` | Shares sidecar Docker network | Supported (weakest — avoid in prod) |
| `allowlist` | Only listed host:ports via egress proxy | **Not supported** (`policy_router_unavailable_capability`) |

### Identity

- **`tenant_id` / `user_id`** in config are defaults for unauthenticated paths.
- In normal DeerFlow usage, **each logged-in user** gets their own FinSAFE sessions
  (`user_id` = DeerFlow auth user id); threads are isolated by `(user_id, thread_id)`.
- Daemon `auth.user_id` / `auth.tenant_id` in `finsafe-daemon.yaml` must be consistent
  with the tokens and tenant you expect for API admission.

---

## 2. Recommended `docker/finsafe-daemon.yaml` (sidecar)

```yaml
schema_version: 1

server:
  bind: "0.0.0.0:8080"

auth:
  bearer_token: "change-me-in-production"   # ↔ FINSAFE_TOKEN / sandbox.token
  user_id: "app-user"
  tenant_id: "acme"

storage:
  runtime_root: "/var/lib/finsafe"

executor:
  finsafe_cli: "/usr/local/bin/finsafe"
  mock_cells: false                         # real bwrap cells (required for isolation)

sessions:
  reaper_interval_secs: 60                  # TTL sweep for idle workspace sessions

# Broker pool defaults (max_brokers=32, idle_ttl=600s) — do not omit entirely;
# upstream panics on all-zero resident defaults without `resident: {}`.
resident: {}

host_profiles:
  linux-desktop-isolated:
  # Host-level budget ceiling for all cells on this daemon (not per-cell).
  # Per-cell limit is sandbox.memory_max in config.yaml (default 2G).
    memory_max: "8G"
```

**Two-level memory model:**

| Layer | Key | Typical value | Meaning |
|-------|-----|---------------|---------|
| Per cell | `sandbox.memory_max` | `2G` | cgroup limit inside each bwrap cell |
| Per daemon | `host_profiles.*.memory_max` | `8G` | scheduler won't admit cells if host budget exhausted |

Use **`G` / `M`** suffixes (memparse). **`GiB` / `MiB` are rejected** by cgroup writes.

---

## 3. Per-execution JSON (assembled by `FinsafeSandboxProvider`)

Every `bash` / file tool call submits a payload equivalent to the defaults below.
All `policy` fields are overridable via `config.yaml` → `sandbox:` (see
`config.example.yaml` Option 5 and `sandbox_config.py`). Assembly lives in
`finsafe_policy.build_high_level_policy()`.

```json
{
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
  "network": {
    "mode": "deny"
  }
}
```

**Workspace write access** is **not** listed in `filesystem` — finsafe-server injects the
session workspace host directory as an rw bind + Landlock rw entry (`inject_workspace_bind`).
DeerFlow passes the session `workspace_path` as `work_dir` (never guest `/workspace`).

### Why these filesystem paths?

| Path set | Purpose |
|----------|---------|
| `read_only_paths` (rootfs) | Allow `exec /bin/sh`, dynamic linker, distro libs under Landlock |
| `read_write_paths: [/dev/null]` | Shell redirects (`2>/dev/null`) without widening rw binds |
| Injected session dir | Agent workspace (`/mnt/user-data/…` inside DeerFlow virtual paths) |

---

## 4. FinSAFE built-in defaults (compiler — not in DeerFlow YAML)

Shipped in FinSAFE `sandbox-defaults.yaml` and merged at compile time for
`linux-desktop-isolated`:

**Deny-read (representative):**

| Category | Examples |
|----------|----------|
| System secrets | `/etc/shadow`, `/etc/gshadow` |
| Under writable workspace | `.env`, `.env.local`, `.env.production` |
| User credential dirs | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker/config.json`, `~/.netrc` |
| Container sockets | `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `~/.docker/run/docker.sock` |

**Isolation mechanics (`linux-desktop-isolated`):**

- bubblewrap: user/mount/network namespaces, ro-bind rootfs
- Landlock: path rules from compiled policy + injected workspace
- cgroup v2: memory / pids / cpu from `resources`
- Process uid **1000** inside cell (non-root broker)

---

## 5. DeerFlow `SandboxAuditMiddleware` (pre-cell)

Before a command reaches FinSAFE, DeerFlow classifies `bash` invocations:

| Verdict | Action |
|---------|--------|
| `block` | Tool returns error (`rm -rf /`, pipe-to-sh, `cat /etc/shadow`, `LD_PRELOAD=`, …) |
| `warn` | Executes but appends medium-risk warning to tool output |
| `pass` | Executes; logs `[SandboxAudit] {"verdict":"pass",…}` |

This is **orthogonal** to FinSAFE — both layers should be enabled.

---

## 6. Production checklist

- [ ] `network_mode: deny` (or audited `host` only in dev)
- [ ] `mock_cells: false` in daemon; sidecar logs show `mock=false`
- [ ] Rotate `bearer_token` / `FINSAFE_TOKEN` (not `dev-change-me`)
- [ ] `memory_max` / `host_profiles.*.memory_max` use `G` suffixes
- [ ] Sidecar: `privileged: true`, `cgroup: host`, `FINSAFE_HELPER_ALLOWED_CGROUP_ROOT`
- [ ] Run `./scripts/smoke.sh` and `./scripts/smoke.sh`
- [ ] Verify logs: `Created FinSAFE sandbox`, `[SandboxAudit]`, `exec-*/succeeded`

---

## 7. Tuning guide

| Goal | Knob |
|------|------|
| Stricter network | Keep `deny`; never use `host` in prod |
| More cell RAM | Raise `sandbox.memory_max` (e.g. `4G`) and daemon `host_profiles` ceiling |
| Longer agent shell | Raise `bash_command_timeout` and/or `resources.timeout_ms` (via timeout on execute) |
| Allow HTTPS egress | Requires FinSAFE egress-proxy build + `network_mode: allowlist` (not in stock image) |
| Weaker audit only | **Do not** disable FinSAFE; adjust SandboxAudit rules in harness if needed |

---

## 8. Verify policy in logs

```bash
# Gateway: sandbox lifecycle + audit + FinSAFE HTTP
docker logs deer-flow-gateway 2>&1 | grep -iE 'FinSAFE|SandboxAudit|finsafe-saas'

# Sidecar: real cells enabled
docker logs deer-flow-finsafe-saas 2>&1 | grep mock=
```

Expected for a successful bash tool call:

1. `[SandboxAudit] … "verdict": "pass"`
2. `POST http://finsafe-saas:8080/v1/sessions/…/executions`
3. `Created FinSAFE sandbox … (session=…)`
4. Tool output contains expected cell uid (`1000`) when running `id -u`
