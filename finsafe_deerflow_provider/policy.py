"""Build FinSAFE HighLevelPolicyV1 payloads from sandbox configuration."""

from __future__ import annotations

import shlex
from typing import Any

from .defaults import (
    DEFAULT_BOOTSTRAP_DIRECTORIES,
    DEFAULT_FILESYSTEM_READ_ONLY_PATHS,
    DEFAULT_FILESYSTEM_READ_WRITE_PATHS,
    FINSAFE_NETWORK_MODES,
)


class FinsafePolicyConfigError(ValueError):
    """Invalid FinSAFE policy settings."""


def _opt_list(value: Any, *, default: tuple[str, ...] | list[str]) -> list[str]:
    if value is None:
        return list(default)
    return list(value)


def _opt_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def validate_policy_config(cfg: dict[str, Any]) -> None:
    """Fail fast on operator mistakes before hitting finsafe-server."""
    network_mode = cfg.get("network_mode")
    if network_mode not in FINSAFE_NETWORK_MODES:
        allowed = ", ".join(sorted(FINSAFE_NETWORK_MODES))
        raise FinsafePolicyConfigError(f"network_mode must be one of: {allowed} (got {network_mode!r})")

    read_only = _opt_list(
        cfg.get("filesystem_read_only_paths"),
        default=DEFAULT_FILESYSTEM_READ_ONLY_PATHS,
    )
    if not read_only:
        raise FinsafePolicyConfigError("filesystem_read_only_paths must not be empty")

    read_write = _opt_list(
        cfg.get("filesystem_read_write_paths"),
        default=DEFAULT_FILESYSTEM_READ_WRITE_PATHS,
    )
    if not read_write:
        raise FinsafePolicyConfigError("filesystem_read_write_paths must not be empty")

    if network_mode == "allowlist" and not list(cfg.get("network_allowlist") or []):
        raise FinsafePolicyConfigError("network_allowlist is required when network_mode is allowlist")

    if network_mode == "proxy" and not cfg.get("network_proxy_profile"):
        raise FinsafePolicyConfigError("network_proxy_profile is required when network_mode is proxy")


def build_high_level_policy(
    cfg: dict[str, Any],
    *,
    timeout_ms: int | None = None,
) -> dict[str, Any]:
    """Assemble FinSAFE ``policy`` object for session execution requests."""
    validate_policy_config(cfg)

    filesystem: dict[str, Any] = {
        "read_only_paths": _opt_list(
            cfg.get("filesystem_read_only_paths"),
            default=DEFAULT_FILESYSTEM_READ_ONLY_PATHS,
        ),
        "read_write_paths": _opt_list(
            cfg.get("filesystem_read_write_paths"),
            default=DEFAULT_FILESYSTEM_READ_WRITE_PATHS,
        ),
    }
    deny_read = list(cfg.get("filesystem_deny_read_paths") or [])
    if deny_read:
        filesystem["deny_read_paths"] = deny_read
    deny_write_globs = list(cfg.get("filesystem_deny_write_globs") or [])
    if deny_write_globs:
        filesystem["deny_write_globs"] = deny_write_globs
    if _opt_bool(cfg.get("filesystem_skip_default_deny_read")):
        filesystem["skip_default_deny_read"] = True

    resources: dict[str, Any] = {
        "memory_max": cfg["memory_max"],
        "pids_max": cfg["pids_max"],
        "cpu_max": cfg["cpu_max"],
    }
    if timeout_ms is not None:
        resources["timeout_ms"] = timeout_ms

    network_mode = cfg["network_mode"]
    network: dict[str, Any] = {"mode": network_mode}
    if network_mode == "allowlist":
        network["allowlist"] = list(cfg.get("network_allowlist") or [])
    if network_mode == "proxy":
        network["proxy_profile"] = cfg["network_proxy_profile"]
    if _opt_bool(cfg.get("network_tls_terminate")):
        network["tls_terminate"] = True
    if _opt_bool(cfg.get("network_start_internal_proxy")):
        network["start_internal_proxy"] = True
    if _opt_bool(cfg.get("network_inject_identity")):
        network["inject_identity"] = True
    if _opt_bool(cfg.get("network_content_audit")):
        network["content_audit"] = True
    parent_url = cfg.get("network_parent_proxy_url")
    if parent_url:
        parent: dict[str, Any] = {"url": parent_url}
        no_proxy = list(cfg.get("network_parent_proxy_no_proxy") or [])
        if no_proxy:
            parent["no_proxy"] = no_proxy
        if _opt_bool(cfg.get("network_parent_proxy_required")):
            parent["required"] = True
        network["parent_proxy"] = parent

    policy: dict[str, Any] = {
        "schema_version": 1,
        "policy_id": cfg["policy_id"],
        "filesystem": filesystem,
        "resources": resources,
        "network": network,
    }

    syscalls = cfg.get("syscalls")
    if syscalls:
        policy["syscalls"] = syscalls

    if cfg.get("identity_use_user_namespace") is not None:
        policy["identity"] = {"use_user_namespace": bool(cfg["identity_use_user_namespace"])}

    extensions = cfg.get("policy_extensions") or {}
    if extensions:
        for key, value in extensions.items():
            if key in policy and isinstance(policy[key], dict) and isinstance(value, dict):
                policy[key] = {**policy[key], **value}
            else:
                policy[key] = value

    return policy


def build_bootstrap_script(cfg: dict[str, Any]) -> str:
    """Shell script that prepares session-relative workspace directories."""
    dirs = _opt_list(
        cfg.get("bootstrap_directories"),
        default=DEFAULT_BOOTSTRAP_DIRECTORIES,
    )
    capture_dir = cfg.get("capture_directory") or ".deerflow-capture"
    if capture_dir not in dirs:
        dirs = [*dirs, capture_dir]
    quoted = " ".join(shlex.quote(d) for d in dirs)
    return f"set -e; mkdir -p {quoted}; echo BOOTSTRAP_OK"
