"""Shared test helpers for provider tests."""

from __future__ import annotations

from unittest.mock import MagicMock

# All FinSAFE-specific sandbox.* keys the provider reads via getattr. Mirrors the
# config surface documented in examples/deer-flow/config-sandbox-finsafe.yaml.
FINSAFE_SANDBOX_ATTRS = (
    "token",
    "base_url",
    "tenant_id",
    "user_id",
    "policy_id",
    "host_profile",
    "network_mode",
    "network_allowlist",
    "network_proxy_profile",
    "network_tls_terminate",
    "network_start_internal_proxy",
    "network_inject_identity",
    "network_content_audit",
    "network_parent_proxy_url",
    "network_parent_proxy_no_proxy",
    "network_parent_proxy_required",
    "memory_max",
    "pids_max",
    "cpu_max",
    "filesystem_read_only_paths",
    "filesystem_read_write_paths",
    "filesystem_deny_read_paths",
    "filesystem_deny_write_globs",
    "filesystem_skip_default_deny_read",
    "syscalls",
    "identity_use_user_namespace",
    "policy_extensions",
    "agent_id",
    "execution_mode",
    "session_mode",
    "http_timeout_seconds",
    "execution_poll_interval_seconds",
    "execution_id_prefix",
    "request_id_prefix",
    "guest_workspace_path",
    "bootstrap_timeout_seconds",
    "bootstrap_directories",
    "capture_directory",
    "download_max_bytes",
    "list_dir_timeout_seconds",
    "search_timeout_seconds",
    "bash_command_timeout",
)


def make_mock_sandbox_config(**overrides):
    """Build a MagicMock app config whose ``.sandbox`` exposes FinSAFE attrs.

    Every FinSAFE attr defaults to ``None`` so the provider falls back to
    ``defaults.py``; pass overrides to exercise specific config values.
    """
    cfg = MagicMock()
    cfg.sandbox.use = "finsafe_deerflow_provider:FinsafeSandboxProvider"
    for name in FINSAFE_SANDBOX_ATTRS:
        setattr(cfg.sandbox, name, None)
    for key, value in overrides.items():
        setattr(cfg.sandbox, key, value)
    return cfg
