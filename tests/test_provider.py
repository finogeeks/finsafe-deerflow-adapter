"""Unit tests for FinsafeSandbox path mapping and provider wiring."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from _helpers import make_mock_sandbox_config as _mock_sandbox_config
from finsafe_deerflow_adapter.defaults import (
    DEFAULT_CPU_MAX,
    DEFAULT_FILESYSTEM_READ_ONLY_PATHS,
    DEFAULT_FILESYSTEM_READ_WRITE_PATHS,
    DEFAULT_MEMORY_MAX,
    DEFAULT_NETWORK_MODE,
    DEFAULT_PIDS_MAX,
)
from finsafe_deerflow_adapter.provider import FinsafeSandboxProvider
from finsafe_deerflow_adapter.sandbox import FinsafeSandbox


def _sandbox(**kwargs) -> FinsafeSandbox:
    client = MagicMock()
    defaults = {
        "sandbox_id": "sb1",
        "session_id": "sess-1",
        "workspace_path": "/var/lib/finsafe/sessions/sess-1",
        "client": client,
        "policy_factory": lambda timeout_ms=None: {"schema_version": 1},
        "tenant_id": "acme",
        "user_id": "u1",
        "policy_id": "deerflow-sandbox",
        "host_profile": "linux-desktop-isolated",
    }
    defaults.update(kwargs)
    return FinsafeSandbox(**defaults)


def test_resolve_virtual_user_data_path() -> None:
    sb = _sandbox()
    assert sb._resolve_path("/mnt/user-data/workspace/a.txt") == "mnt/user-data/workspace/a.txt"


def test_resolve_acp_workspace_path() -> None:
    sb = _sandbox()
    assert sb._resolve_path("/mnt/acp-workspace/out.md") == "mnt/acp-workspace/out.md"


def test_reject_path_traversal() -> None:
    sb = _sandbox()
    with pytest.raises(PermissionError):
        sb._resolve_path("/mnt/user-data/../etc/passwd")


def test_build_execution_payload_uses_session_host_workdir() -> None:
    client = MagicMock()
    client.new_execution_ids.return_value = ("exec-1", "req-1")
    sb = _sandbox(client=client)
    payload = sb._build_execution_payload(["echo", "hi"])
    assert payload["request"]["request"]["work_dir"] == "/var/lib/finsafe/sessions/sess-1"
    assert payload["request"]["identity"]["agent_id"] == "deerflow"
    assert payload["request"]["request"]["mode"] == "short-lived"
    assert payload["policy"].get("filesystem", {}) == {}


def test_build_execution_payload_respects_runtime_config() -> None:
    client = MagicMock()
    client.new_execution_ids.return_value = ("exec-1", "req-1")
    sb = _sandbox(
        client=client,
        runtime_config={"agent_id": "custom-agent", "execution_mode": "resident"},
    )
    payload = sb._build_execution_payload(["echo", "hi"])
    assert payload["request"]["identity"]["agent_id"] == "custom-agent"
    assert payload["request"]["request"]["mode"] == "resident"


def test_execute_command_bootstraps_without_deadlock() -> None:
    client = MagicMock()
    client.new_execution_ids.return_value = ("exec-1", "req-1")
    client.submit_session_execution.return_value = {"admission": {"admitted": True, "execution_id": "exec-1"}}
    client.wait_execution.return_value = {"status": "succeeded"}

    downloads: list[bytes] = [
        b"BOOTSTRAP_OK\n",
        b"0\n",
        b"hello\n",
        b"0\n",
    ]
    client.download_session_file.side_effect = lambda *_: downloads.pop(0)

    sb = _sandbox(client=client)
    result = sb.execute_command("echo hello")
    assert result == "hello\n"
    assert client.submit_session_execution.call_count == 2


@patch("finsafe_deerflow_adapter.provider.get_app_config")
def test_provider_loads_env_token(mock_get_config) -> None:
    mock_get_config.return_value = _mock_sandbox_config()

    with patch.dict("os.environ", {"FINSAFE_TOKEN": "tok", "FINSAFE_BASE_URL": "http://finsafe:8080"}):
        provider = FinsafeSandboxProvider()
    assert provider._config["token"] == "tok"
    assert provider._config["base_url"] == "http://finsafe:8080"
    provider.shutdown()


@patch("finsafe_deerflow_adapter.provider.get_app_config")
def test_policy_factory_default_shape(mock_get_config) -> None:
    mock_get_config.return_value = _mock_sandbox_config()

    with patch.dict("os.environ", {"FINSAFE_TOKEN": "tok"}):
        provider = FinsafeSandboxProvider()
    try:
        policy = provider._policy_factory()()
    finally:
        provider.shutdown()

    assert policy["schema_version"] == 1
    assert policy["policy_id"] == "deerflow-sandbox"
    assert policy["network"] == {"mode": DEFAULT_NETWORK_MODE}
    assert policy["resources"]["memory_max"] == DEFAULT_MEMORY_MAX
    assert policy["resources"]["pids_max"] == DEFAULT_PIDS_MAX
    assert policy["resources"]["cpu_max"] == DEFAULT_CPU_MAX
    assert policy["filesystem"]["read_only_paths"] == list(DEFAULT_FILESYSTEM_READ_ONLY_PATHS)
    assert policy["filesystem"]["read_write_paths"] == list(DEFAULT_FILESYSTEM_READ_WRITE_PATHS)


@patch("finsafe_deerflow_adapter.provider.get_app_config")
def test_provider_reset_deletes_sessions(mock_get_config) -> None:
    mock_get_config.return_value = _mock_sandbox_config()

    with patch.dict("os.environ", {"FINSAFE_TOKEN": "tok"}):
        provider = FinsafeSandboxProvider()
    try:
        sandbox = FinsafeSandbox(
            "sb-reset",
            session_id="sess-reset",
            workspace_path="/var/lib/finsafe/sessions/sess-reset",
            client=provider._client,
            policy_factory=provider._policy_factory(),
            tenant_id="acme",
            user_id="u1",
            policy_id="deerflow-sandbox",
            host_profile="linux-desktop-isolated",
        )
        provider._sandboxes["sb-reset"] = sandbox
        provider._client.delete_session = MagicMock()
        provider.reset()
        provider._client.delete_session.assert_called_once_with("sess-reset")
    finally:
        provider.shutdown()


@patch("finsafe_deerflow_adapter.provider.get_app_config")
def test_execute_command_uses_default_timeout(mock_get_config) -> None:
    mock_get_config.return_value = _mock_sandbox_config()

    with patch.dict("os.environ", {"FINSAFE_TOKEN": "tok"}):
        provider = FinsafeSandboxProvider()
    try:
        sb = FinsafeSandbox(
            "sb-timeout",
            session_id="sess-timeout",
            workspace_path="/var/lib/finsafe/sessions/sess-timeout",
            client=MagicMock(),
            policy_factory=provider._policy_factory(),
            tenant_id="acme",
            user_id="u1",
            policy_id="deerflow-sandbox",
            host_profile="linux-desktop-isolated",
            runtime_config={"bash_command_timeout": 42},
        )
        sb._bootstrapped = True
        sb._run_shell = MagicMock(return_value="ok")
        sb.execute_command("echo hi")
        sb._run_shell.assert_called_once()
        assert sb._run_shell.call_args.kwargs["timeout"] == 42.0
    finally:
        provider.shutdown()


@patch("finsafe_deerflow_adapter.provider.get_app_config")
def test_policy_factory_reads_filesystem_from_config(mock_get_config) -> None:
    mock_get_config.return_value = _mock_sandbox_config(
        filesystem_read_only_paths=["/usr", "/bin"],
        filesystem_read_write_paths=["/dev/null"],
        filesystem_deny_read_paths=["/mnt/user-data/workspace/private"],
    )

    with patch.dict("os.environ", {"FINSAFE_TOKEN": "tok"}):
        provider = FinsafeSandboxProvider()
    try:
        policy = provider._policy_factory()()
    finally:
        provider.shutdown()

    assert policy["filesystem"]["read_only_paths"] == ["/usr", "/bin"]
    assert policy["filesystem"]["deny_read_paths"] == ["/mnt/user-data/workspace/private"]
