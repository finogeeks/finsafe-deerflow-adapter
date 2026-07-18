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
        )
    )
    fs = policy["filesystem"]
    assert fs["read_only_paths"] == ["/usr", "/bin"]
    assert fs["deny_read_paths"] == ["/mnt/user-data/workspace/secret.txt"]
    # wrapper-YAML-only fields must not leak into the HighLevel policy JSON
    assert "deny_write_globs" not in fs
    assert "skip_default_deny_read" not in fs


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


def test_validate_rejects_non_string_memory_max() -> None:
    # provider requires a string; an int would bypass the suffix check and
    # also break the JSON payload shape.
    with pytest.raises(FinsafePolicyConfigError, match="non-empty string"):
        validate_policy_config(_base_cfg(memory_max=2048))


def test_validate_rejects_binary_memory_suffix() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="binary suffixes"):
        validate_policy_config(_base_cfg(memory_max="2GiB"))


def test_validate_rejects_binary_memory_suffix_case_insensitive() -> None:
    # finsafe-scheduler parses memory case-insensitively, so a lowercase
    # `2gib` admits and then the cell exits with code 3 — the provider must
    # reject it regardless of case.
    for bad in ("2gib", "2GIB", "2GiB", "512mib", "1kib", "8tib"):
        with pytest.raises(FinsafePolicyConfigError, match="binary suffixes"):
            validate_policy_config(_base_cfg(memory_max=bad))


def test_validate_accepts_decimal_memory_suffix() -> None:
    validate_policy_config(_base_cfg(memory_max="2G"))
    validate_policy_config(_base_cfg(memory_max="512M"))
    validate_policy_config(_base_cfg(memory_max="512MB"))
    validate_policy_config(_base_cfg(memory_max="1024"))


def test_validate_rejects_syscalls_object_form() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="syscalls must be one of"):
        validate_policy_config(_base_cfg(syscalls={"allow": []}))


def test_validate_accepts_syscalls_string_profiles() -> None:
    validate_policy_config(_base_cfg(syscalls="default"))
    validate_policy_config(_base_cfg(syscalls="no_network"))


def test_validate_rejects_skip_default_deny_read() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="wrapper-YAML field"):
        validate_policy_config(_base_cfg(filesystem_skip_default_deny_read=True))


def test_validate_rejects_deny_write_globs() -> None:
    with pytest.raises(FinsafePolicyConfigError, match="wrapper-YAML field"):
        validate_policy_config(_base_cfg(filesystem_deny_write_globs=["**/*.key"]))


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


# ── Network advanced flags ────────────────────────────────────────────────────


def test_build_policy_network_flags_emit_when_true() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            network_tls_terminate=True,
            network_start_internal_proxy=True,
            network_inject_identity=True,
            network_content_audit=True,
        )
    )
    net = policy["network"]
    assert net["mode"] == "deny"
    assert net["tls_terminate"] is True
    assert net["start_internal_proxy"] is True
    assert net["inject_identity"] is True
    assert net["content_audit"] is True


def test_build_policy_network_flags_omitted_when_false() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            network_tls_terminate=False,
            network_start_internal_proxy=False,
            network_inject_identity=False,
            network_content_audit=False,
        )
    )
    net = policy["network"]
    assert net == {"mode": "deny"}


def test_build_policy_network_flags_omitted_when_unset() -> None:
    policy = build_high_level_policy(_base_cfg())
    assert policy["network"] == {"mode": "deny"}


def test_build_policy_parent_proxy_url_only() -> None:
    policy = build_high_level_policy(
        _base_cfg(network_parent_proxy_url="http://proxy:3128")
    )
    assert policy["network"]["parent_proxy"] == {"url": "http://proxy:3128"}


def test_build_policy_parent_proxy_full() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            network_parent_proxy_url="http://proxy:3128",
            network_parent_proxy_no_proxy=["example.com", ".internal"],
            network_parent_proxy_required=True,
        )
    )
    assert policy["network"]["parent_proxy"] == {
        "url": "http://proxy:3128",
        "no_proxy": ["example.com", ".internal"],
        "required": True,
    }


def test_build_policy_parent_proxy_required_without_url_is_noop() -> None:
    # `required` only rides on parent_proxy, which is only emitted when url is set.
    policy = build_high_level_policy(_base_cfg(network_parent_proxy_required=True))
    assert "parent_proxy" not in policy["network"]


def test_build_policy_allowlist_carries_flags() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            network_mode="allowlist",
            network_allowlist=["api.example.com:443"],
            network_tls_terminate=True,
            network_inject_identity=True,
        )
    )
    net = policy["network"]
    assert net["mode"] == "allowlist"
    assert net["allowlist"] == ["api.example.com:443"]
    assert net["tls_terminate"] is True
    assert net["inject_identity"] is True


def test_build_policy_proxy_carries_profile_and_flags() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            network_mode="proxy",
            network_proxy_profile="corp-egress",
            network_start_internal_proxy=True,
            network_content_audit=True,
        )
    )
    net = policy["network"]
    assert net["mode"] == "proxy"
    assert net["proxy_profile"] == "corp-egress"
    assert net["start_internal_proxy"] is True
    assert net["content_audit"] is True


# ── Resources & identity ─────────────────────────────────────────────────────


def test_build_policy_resources_passthrough() -> None:
    policy = build_high_level_policy(
        _base_cfg(memory_max="4G", pids_max="128", cpu_max="100000 100000")
    )
    assert policy["resources"] == {
        "memory_max": "4G",
        "pids_max": "128",
        "cpu_max": "100000 100000",
    }


def test_build_policy_policy_id_passthrough() -> None:
    policy = build_high_level_policy(_base_cfg(policy_id="custom-policy"))
    assert policy["policy_id"] == "custom-policy"


def test_build_policy_identity_true() -> None:
    policy = build_high_level_policy(_base_cfg(identity_use_user_namespace=True))
    assert policy["identity"] == {"use_user_namespace": True}


def test_build_policy_identity_false() -> None:
    policy = build_high_level_policy(_base_cfg(identity_use_user_namespace=False))
    assert policy["identity"] == {"use_user_namespace": False}


def test_build_policy_identity_absent() -> None:
    policy = build_high_level_policy(_base_cfg())
    assert "identity" not in policy


def test_build_policy_syscalls_default_string() -> None:
    policy = build_high_level_policy(_base_cfg(syscalls="default"))
    assert policy["syscalls"] == "default"


def test_build_policy_syscalls_no_network_string() -> None:
    policy = build_high_level_policy(_base_cfg(syscalls="no_network"))
    assert policy["syscalls"] == "no_network"


def test_build_policy_syscalls_absent() -> None:
    policy = build_high_level_policy(_base_cfg())
    assert "syscalls" not in policy


# ── policy_extensions merge semantics ─────────────────────────────────────────


def test_build_policy_extensions_environment() -> None:
    policy = build_high_level_policy(
        _base_cfg(policy_extensions={"environment": {"passthrough": ["PATH", "LANG"]}})
    )
    assert policy["environment"] == {"passthrough": ["PATH", "LANG"]}


def test_build_policy_extensions_artifacts() -> None:
    policy = build_high_level_policy(
        _base_cfg(
            policy_extensions={"artifacts": {"collect": ["mnt/user-data/outputs"]}}
        )
    )
    assert policy["artifacts"] == {"collect": ["mnt/user-data/outputs"]}


def test_build_policy_extensions_approval() -> None:
    policy = build_high_level_policy(
        _base_cfg(policy_extensions={"approval": {"execution_mode": "auto"}})
    )
    assert policy["approval"] == {"execution_mode": "auto"}


def test_build_policy_extensions_shallow_merges_into_existing_network_dict() -> None:
    # network already exists as a dict; a dict extension shallow-merges one
    # level (top-level keys combine, nested dicts are replaced, not deep-merged).
    policy = build_high_level_policy(
        _base_cfg(
            network_mode="deny",
            network_tls_terminate=True,
            policy_extensions={"network": {"l7_rules": []}},
        )
    )
    net = policy["network"]
    assert net["mode"] == "deny"
    assert net["tls_terminate"] is True
    assert net["l7_rules"] == []


def test_build_policy_extensions_non_dict_replaces_scalar() -> None:
    # When the existing value is not a dict, the extension replaces it.
    policy = build_high_level_policy(
        _base_cfg(syscalls="default", policy_extensions={"syscalls": "no_network"})
    )
    assert policy["syscalls"] == "no_network"


def test_build_policy_extensions_shallow_merge_replaces_nested_dict() -> None:
    # Shallow merge: a nested dict under an existing dict key is replaced
    # outright, not recursively merged. Guards against accidentally reading
    # the merge as a deep merge.
    policy = build_high_level_policy(
        _base_cfg(
            network_mode="deny",
            policy_extensions={"network": {"mode": "allowlist", "allowlist": ["x:443"]}},
        )
    )
    net = policy["network"]
    # The extension's `mode` and `allowlist` win; no inheritance from the
    # previously-built `{"mode": "deny"}` network dict.
    assert net == {"mode": "allowlist", "allowlist": ["x:443"]}


def test_build_policy_extensions_empty_is_noop() -> None:
    policy = build_high_level_policy(_base_cfg(policy_extensions={}))
    assert "environment" not in policy
    assert "artifacts" not in policy


# ── bootstrap script ──────────────────────────────────────────────────────────


def test_build_bootstrap_script_defaults_include_capture_dir() -> None:
    script = build_bootstrap_script({})
    assert "mkdir -p" in script
    assert ".deerflow-capture" in script
    assert "BOOTSTRAP_OK" in script


def test_build_bootstrap_script_custom_capture_appended() -> None:
    script = build_bootstrap_script(
        {"bootstrap_directories": ["mnt/a"], "capture_directory": "custom-cap"}
    )
    assert "mnt/a" in script
    assert "custom-cap" in script
    # custom capture dir must be appended even when not in bootstrap_directories
    assert script.count("custom-cap") >= 1


def test_build_bootstrap_script_custom_capture_already_listed_not_duplicated() -> None:
    script = build_bootstrap_script(
        {
            "bootstrap_directories": ["mnt/a", "custom-cap"],
            "capture_directory": "custom-cap",
        }
    )
    assert script.count("custom-cap") == 1
