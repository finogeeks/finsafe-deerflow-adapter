"""Unit tests for FinSAFE policy assembly from sandbox config."""

from __future__ import annotations

import pytest
from finsafe_deerflow_provider.defaults import (
    DEFAULT_FILESYSTEM_READ_ONLY_PATHS,
    DEFAULT_FILESYSTEM_READ_WRITE_PATHS,
)
from finsafe_deerflow_provider.policy import (
    FinsafePolicyConfigError,
    build_bootstrap_script,
    build_high_level_policy,
    validate_policy_config,
)


def _base_cfg(**overrides):
    cfg = {
        "policy_id": "deerflow-sandbox",
        "network_mode": "deny",
        "network_allowlist": [],
        "memory_max": "2G",
        "pids_max": "512",
        "cpu_max": "200000 100000",
        "filesystem_read_only_paths": None,
        "filesystem_read_write_paths": None,
        "filesystem_deny_read_paths": [],
        "filesystem_deny_write_globs": [],
        "filesystem_skip_default_deny_read": False,
        "network_proxy_profile": None,
        "network_tls_terminate": False,
        "network_start_internal_proxy": False,
        "network_inject_identity": False,
        "network_content_audit": False,
        "network_parent_proxy_url": None,
        "network_parent_proxy_no_proxy": [],
        "network_parent_proxy_required": False,
        "syscalls": None,
        "identity_use_user_namespace": None,
        "policy_extensions": {},
        "capture_directory": ".deerflow-capture",
        "bootstrap_directories": None,
    }
    cfg.update(overrides)
    return cfg


def test_build_policy_defaults() -> None:
    policy = build_high_level_policy(_base_cfg())
    assert policy["filesystem"]["read_only_paths"] == list(DEFAULT_FILESYSTEM_READ_ONLY_PATHS)
    assert policy["filesystem"]["read_write_paths"] == list(DEFAULT_FILESYSTEM_READ_WRITE_PATHS)
    assert policy["network"] == {"mode": "deny"}


def test_build_policy_custom_filesystem() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            filesystem_read_only_paths=["/usr", "/bin"],
            filesystem_read_write_paths=["/dev/null"],
            filesystem_deny_read_paths=["/mnt/user-data/workspace/secret.txt"],
            filesystem_deny_write_globs=["**/*.key"],
            filesystem_skip_default_deny_read=True,
        )
    )
    fs = policy["filesystem"]
    assert fs["read_only_paths"] == ["/usr", "/bin"]
    assert fs["deny_read_paths"] == ["/mnt/user-data/workspace/secret.txt"]
    assert fs["deny_write_globs"] == ["**/*.key"]
    assert fs["skip_default_deny_read"] is True


def test_build_policy_allowlist_network() -> None:
    policy = build_high_level_policy(
        _base_cfg(network_mode="allowlist", network_allowlist=["api.example.com:443"])
    )
    assert policy["network"] == {
        "mode": "allowlist",
        "allowlist": ["api.example.com:443"],
    }


def test_build_policy_proxy_network() -> None:
    policy = build_high_level_policy(
        _base_cfg(network_mode="proxy", network_proxy_profile="corp-egress")
    )
    assert policy["network"] == {"mode": "proxy", "proxy_profile": "corp-egress"}


def test_build_policy_timeout_ms() -> None:
    policy = build_high_level_policy(_base_cfg(), timeout_ms=600_000)
    assert policy["resources"]["timeout_ms"] == 600_000


def test_build_policy_extensions_merge() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            syscalls="no_network",
            identity_use_user_namespace=True,
            policy_extensions={
                "environment": {"passthrough": ["PATH", "LANG"]},
            },
        )
    )
    assert policy["syscalls"] == "no_network"
    assert policy["identity"] == {"use_user_namespace": True}
    assert policy["environment"] == {"passthrough": ["PATH", "LANG"]}


def test_validate_rejects_empty_read_only_paths() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="read_only_paths"):
        validate_policy_config(_base_cfg(filesystem_read_only_paths=[]))


def test_validate_rejects_invalid_network_mode() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="network_mode"):
        validate_policy_config(_base_cfg(network_mode="wide-open"))


def test_validate_rejects_allowlist_without_entries() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="network_allowlist"):
        validate_policy_config(_base_cfg(network_mode="allowlist", network_allowlist=[]))


def test_build_bootstrap_script_quotes_paths() -> None:
    script = build_bootstrap_script(
        {
            "bootstrap_directories": ["mnt/my dir", "mnt/user-data/workspace"],
            "capture_directory": ".deerflow-capture",
        }
    )
    assert "mkdir -p" in script
    assert "'mnt/my dir'" in script or '"mnt/my dir"' in script
    assert "BOOTSTRAP_OK" in script
