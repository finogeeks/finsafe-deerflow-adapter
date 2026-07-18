"""Default values for FinSAFE sandbox configuration.

All keys are read from ``sandbox:`` in DeerFlow ``config.yaml`` via ``getattr``
in the provider (``SandboxConfig`` uses ``extra="allow"``). No DeerFlow core
changes are required to add FinSAFE-specific fields.
"""

from __future__ import annotations

DEFAULT_BASE_URL = "http://finsafe-saas:8080"
DEFAULT_POLICY_ID = "deerflow-sandbox"
DEFAULT_HOST_PROFILE = "linux-desktop-isolated"
DEFAULT_TENANT_ID = "acme"
DEFAULT_NETWORK_MODE = "deny"
DEFAULT_MEMORY_MAX = "2G"
DEFAULT_PIDS_MAX = "512"
DEFAULT_CPU_MAX = "200000 100000"
DEFAULT_AGENT_ID = "deerflow"
DEFAULT_EXECUTION_MODE = "short-lived"
DEFAULT_SESSION_MODE = "workspace"
DEFAULT_HTTP_TIMEOUT_SECONDS = 120.0
DEFAULT_EXECUTION_POLL_INTERVAL_SECONDS = 0.1
DEFAULT_GUEST_WORKSPACE_PATH = "/workspace"
DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS = 30
DEFAULT_DOWNLOAD_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_CAPTURE_DIRECTORY = ".deerflow-capture"
DEFAULT_EXECUTION_ID_PREFIX = "exec-deerflow"
DEFAULT_REQUEST_ID_PREFIX = "req-deerflow"
DEFAULT_LIST_DIR_TIMEOUT_SECONDS = 30
DEFAULT_SEARCH_TIMEOUT_SECONDS = 60
DEFAULT_BASH_COMMAND_TIMEOUT_SECONDS = 600

DEFAULT_FILESYSTEM_READ_ONLY_PATHS: tuple[str, ...] = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
)
DEFAULT_FILESYSTEM_READ_WRITE_PATHS: tuple[str, ...] = ("/dev/null",)

DEFAULT_BOOTSTRAP_DIRECTORIES: tuple[str, ...] = (
    "mnt/user-data/workspace",
    "mnt/user-data/uploads",
    "mnt/user-data/outputs",
    "mnt/acp-workspace",
    "mnt/skills",
)

FINSAFE_NETWORK_MODES: frozenset[str] = frozenset({"deny", "host", "allowlist", "proxy"})
