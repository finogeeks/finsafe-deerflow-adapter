"""Unit tests for ``FinsafeSandboxProvider._load_config`` over the full sandbox
configuration surface.

Covers every attribute declared in ``_helpers.FINSAFE_SANDBOX_ATTRS``: that
each is read from ``config.yaml``'s ``sandbox:`` block, that defaults from
``defaults.py`` apply when unset, and that ``FINSAFE_BASE_URL`` /
``FINSAFE_TOKEN`` env vars fill in the connectivity pair.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from _helpers import make_mock_sandbox_config as _mock_sandbox_config
from finsafe_deerflow_provider import defaults as D
from finsafe_deerflow_provider.provider import FinsafeSandboxProvider


def _provider_with(config=None, env: dict[str, str] | None = None):
    """Build a provider with a mocked app config and env, return (provider, cfg)."""
    # Always pin FINSAFE_BASE_URL so the host shell env cannot leak into defaults
    # tests; callers that want to exercise the env fallback pass it explicitly.
    full_env = {"FINSAFE_TOKEN": "tok", "FINSAFE_BASE_URL": ""}
    full_env.update(env or {})
    with patch("finsafe_deerflow_provider.provider.get_app_config", return_value=_mock_sandbox_config(**(config or {}))):
        with patch.dict("os.environ", full_env, clear=False):
            provider = FinsafeSandboxProvider()
    return provider


# ── Connectivity & identity defaults ──────────────────────────────────────────


def test_defaults_connectivity_and_identity() -> None:
    provider = _provider_with()
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["base_url"] == D.DEFAULT_BASE_URL
    assert cfg["token"] == "tok"  # from env
    assert cfg["tenant_id"] == D.DEFAULT_TENANT_ID
    assert cfg["policy_id"] == D.DEFAULT_POLICY_ID
    assert cfg["host_profile"] == D.DEFAULT_HOST_PROFILE


def test_user_id_not_stored_in_config() -> None:
    # user_id is resolved per-acquire from get_effective_user_id(), not held in
    # _config, so the provider config dict must not carry a stale user_id.
    provider = _provider_with()
    try:
        assert "user_id" not in provider._config
    finally:
        provider.shutdown()


# ── Network defaults ───────────────────────────────────────────────────────────


def test_defaults_network() -> None:
    provider = _provider_with()
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["network_mode"] == D.DEFAULT_NETWORK_MODE
    assert cfg["network_allowlist"] == []
    assert cfg["network_proxy_profile"] is None
    assert cfg["network_tls_terminate"] is None
    assert cfg["network_start_internal_proxy"] is None
    assert cfg["network_inject_identity"] is None
    assert cfg["network_content_audit"] is None
    assert cfg["network_parent_proxy_url"] is None
    assert cfg["network_parent_proxy_no_proxy"] == []
    assert cfg["network_parent_proxy_required"] is None


def test_load_config_reads_all_network_attrs() -> None:
    provider = _provider_with(
        config=dict(
            network_mode="allowlist",
            network_allowlist=["api.example.com:443"],
            network_proxy_profile="corp-egress",
            network_tls_terminate=True,
            network_start_internal_proxy=True,
            network_inject_identity=True,
            network_content_audit=True,
            network_parent_proxy_url="http://proxy:3128",
            network_parent_proxy_no_proxy=[".internal"],
            network_parent_proxy_required=True,
        )
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["network_mode"] == "allowlist"
    assert cfg["network_allowlist"] == ["api.example.com:443"]
    assert cfg["network_proxy_profile"] == "corp-egress"
    assert cfg["network_tls_terminate"] is True
    assert cfg["network_start_internal_proxy"] is True
    assert cfg["network_inject_identity"] is True
    assert cfg["network_content_audit"] is True
    assert cfg["network_parent_proxy_url"] == "http://proxy:3128"
    assert cfg["network_parent_proxy_no_proxy"] == [".internal"]
    assert cfg["network_parent_proxy_required"] is True


# ── Resources defaults ─────────────────────────────────────────────────────────


def test_defaults_resources() -> None:
    provider = _provider_with()
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["memory_max"] == D.DEFAULT_MEMORY_MAX
    assert cfg["pids_max"] == D.DEFAULT_PIDS_MAX
    assert cfg["cpu_max"] == D.DEFAULT_CPU_MAX


def test_load_config_reads_resources() -> None:
    provider = _provider_with(
        config=dict(memory_max="4G", pids_max="128", cpu_max="100000 100000")
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["memory_max"] == "4G"
    assert cfg["pids_max"] == "128"
    assert cfg["cpu_max"] == "100000 100000"


# ── Filesystem defaults ───────────────────────────────────────────────────────


def test_defaults_filesystem() -> None:
    provider = _provider_with()
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["filesystem_read_only_paths"] is None
    assert cfg["filesystem_read_write_paths"] is None
    assert cfg["filesystem_deny_read_paths"] == []
    assert cfg["filesystem_deny_write_globs"] == []
    assert cfg["filesystem_skip_default_deny_read"] is None


def test_load_config_reads_filesystem_attrs() -> None:
    provider = _provider_with(
        config=dict(
            filesystem_read_only_paths=["/usr", "/bin"],
            filesystem_read_write_paths=["/dev/null"],
            filesystem_deny_read_paths=["/etc/hostname"],
        )
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["filesystem_read_only_paths"] == ["/usr", "/bin"]
    assert cfg["filesystem_read_write_paths"] == ["/dev/null"]
    assert cfg["filesystem_deny_read_paths"] == ["/etc/hostname"]


# ── Syscalls / identity / extensions ──────────────────────────────────────────


def test_defaults_syscalls_identity_extensions() -> None:
    provider = _provider_with()
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["syscalls"] is None
    assert cfg["identity_use_user_namespace"] is None
    assert cfg["policy_extensions"] == {}


def test_load_config_reads_syscalls_identity_extensions() -> None:
    provider = _provider_with(
        config=dict(
            syscalls="no_network",
            identity_use_user_namespace=True,
            policy_extensions={"environment": {"passthrough": ["PATH"]}},
        )
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["syscalls"] == "no_network"
    assert cfg["identity_use_user_namespace"] is True
    assert cfg["policy_extensions"] == {"environment": {"passthrough": ["PATH"]}}


# ── Execution / session tuning defaults ──────────────────────────────────────


def test_defaults_execution_tuning() -> None:
    provider = _provider_with()
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["agent_id"] == D.DEFAULT_AGENT_ID
    assert cfg["execution_mode"] == D.DEFAULT_EXECUTION_MODE
    assert cfg["session_mode"] == D.DEFAULT_SESSION_MODE
    assert cfg["http_timeout_seconds"] == D.DEFAULT_HTTP_TIMEOUT_SECONDS
    assert cfg["execution_poll_interval_seconds"] == D.DEFAULT_EXECUTION_POLL_INTERVAL_SECONDS
    assert cfg["guest_workspace_path"] == D.DEFAULT_GUEST_WORKSPACE_PATH
    assert cfg["bootstrap_timeout_seconds"] == D.DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS
    assert cfg["download_max_bytes"] == D.DEFAULT_DOWNLOAD_MAX_BYTES
    assert cfg["capture_directory"] == D.DEFAULT_CAPTURE_DIRECTORY
    assert cfg["execution_id_prefix"] == D.DEFAULT_EXECUTION_ID_PREFIX
    assert cfg["request_id_prefix"] == D.DEFAULT_REQUEST_ID_PREFIX
    assert cfg["list_dir_timeout_seconds"] == D.DEFAULT_LIST_DIR_TIMEOUT_SECONDS
    assert cfg["search_timeout_seconds"] == D.DEFAULT_SEARCH_TIMEOUT_SECONDS
    assert cfg["bash_command_timeout"] == D.DEFAULT_BASH_COMMAND_TIMEOUT_SECONDS


def test_load_config_reads_execution_tuning() -> None:
    provider = _provider_with(
        config=dict(
            agent_id="custom-agent",
            execution_mode="resident",
            session_mode="workspace",
            http_timeout_seconds=30.0,
            execution_poll_interval_seconds=0.5,
            guest_workspace_path="/custom-workspace",
            bootstrap_timeout_seconds=10,
            download_max_bytes=1024,
            bootstrap_directories=["mnt/a"],
            capture_directory="custom-cap",
            execution_id_prefix="exec-custom",
            request_id_prefix="req-custom",
            list_dir_timeout_seconds=5,
            search_timeout_seconds=15,
            bash_command_timeout=42,
        )
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["agent_id"] == "custom-agent"
    assert cfg["execution_mode"] == "resident"
    assert cfg["session_mode"] == "workspace"
    assert cfg["http_timeout_seconds"] == 30.0
    assert cfg["execution_poll_interval_seconds"] == 0.5
    assert cfg["guest_workspace_path"] == "/custom-workspace"
    assert cfg["bootstrap_timeout_seconds"] == 10
    assert cfg["download_max_bytes"] == 1024
    assert cfg["bootstrap_directories"] == ["mnt/a"]
    assert cfg["capture_directory"] == "custom-cap"
    assert cfg["execution_id_prefix"] == "exec-custom"
    assert cfg["request_id_prefix"] == "req-custom"
    assert cfg["list_dir_timeout_seconds"] == 5
    assert cfg["search_timeout_seconds"] == 15
    assert cfg["bash_command_timeout"] == 42


# ── Env fallback for connectivity ─────────────────────────────────────────────


def test_env_base_url_and_token_fallback() -> None:
    provider = _provider_with(
        env={"FINSAFE_TOKEN": "env-tok", "FINSAFE_BASE_URL": "http://finsafe:8080"}
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["token"] == "env-tok"
    assert cfg["base_url"] == "http://finsafe:8080"


def test_sandbox_config_overrides_env_base_url() -> None:
    provider = _provider_with(
        config=dict(base_url="http://configured:8080"),
        env={"FINSAFE_BASE_URL": "http://env:8080", "FINSAFE_TOKEN": "tok"},
    )
    try:
        cfg = provider._config
    finally:
        provider.shutdown()
    assert cfg["base_url"] == "http://configured:8080"


def test_missing_token_warns_but_does_not_crash() -> None:
    provider = _provider_with(env={"FINSAFE_TOKEN": ""})
    try:
        # token stays empty; provider logs a warning but still constructs.
        assert provider._config["token"] == ""
    finally:
        provider.shutdown()


# ── base_url trailing slash normalization ─────────────────────────────────────


def test_base_url_trailing_slash_stripped() -> None:
    provider = _provider_with(
        config=dict(base_url="http://finsafe:8080/"),
        env={"FINSAFE_TOKEN": "tok"},
    )
    try:
        assert provider._config["base_url"] == "http://finsafe:8080"
    finally:
        provider.shutdown()
