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


# SaaS `finsafe-server-http` parses `policy` as `HighLevelPolicyV1`, whose
# `FilesystemIntentV1` only declares `read_only_paths` / `read_write_paths` /
# `deny_read_paths` and whose `SyscallProfileV1` is a `default | no_network`
# enum. The wrapper-YAML-only knobs below are rejected with
# `bad_request_unknown_field` at admission time, so fail fast here instead
# of letting the cell launch die on the server side.
_ALLOWED_SYSCALL_PROFILES = ("default", "no_network")
# `finsafe-scheduler::parse_memory_string` accepts IEC binary suffixes
# (KiB/MiB/GiB/TiB/PiB, case-insensitive) AND decimal-style suffixes
# (K/M/G/B, KB/MB/GB). However the cell launch path (bwrap → cgroup write)
# only honors the non-IEC forms — a `2GiB` policy admits and then the cell
# exits with code 3. Reject IEC binary suffixes (case-insensitively) so
# operators see the mistake before any cell is launched.
_MEMORY_IEC_BINARY_SUFFIXES = ("kib", "mib", "gib", "tib", "pib")


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

    _validate_memory_max(cfg.get("memory_max"))
    _validate_syscalls(cfg.get("syscalls"))
    _validate_wrapper_only_filesystem_fields(cfg)


def _validate_memory_max(value: Any) -> None:
    """Reject ``memory_max`` forms that the SaaS cell launch path cannot honor.

    ``finsafe-scheduler::parse_memory_string`` accepts IEC binary suffixes
    (``KiB``/``MiB``/``GiB``/…, case-insensitive) but the bwrap → cgroup write
    path does not — a ``2GiB`` value admits and then the cell exits with code
    3. Reject IEC binary suffixes case-insensitively; other invalid forms
    (e.g. ``"2X"``) are left for the scheduler to reject, since the accepted
    surface there is intentionally broad (``K``/``M``/``G``/``B``/``KB``/…).
    """
    if not isinstance(value, str) or not value.strip():
        raise FinsafePolicyConfigError(f"memory_max must be a non-empty string (got {value!r})")
    raw = value.strip().lower()
    for suffix in _MEMORY_IEC_BINARY_SUFFIXES:
        if raw.endswith(suffix):
            raise FinsafePolicyConfigError(
                f"memory_max does not accept IEC binary suffixes such as {suffix.upper()!r} "
                f"(got {value!r}); use forms like '2G', '512M', '512MB', or plain bytes "
                "(the cell launch path rejects KiB/MiB/GiB even though the scheduler "
                "accepts them, case-insensitively)"
            )


def _validate_syscalls(value: Any) -> None:
    """Reject wrapper-YAML syscall object forms.

    `HighLevelPolicyV1.syscalls` is a `default | no_network` enum serialized as
    a string; object forms like `{'allow': [...]}` are wrapper-YAML-only and
    produce `bad_request_unknown_field` at admission.
    """
    if value is None:
        return
    if not isinstance(value, str) or value not in _ALLOWED_SYSCALL_PROFILES:
        raise FinsafePolicyConfigError(
            "syscalls must be one of: 'default', 'no_network' (got %r); "
            "object forms such as {'allow': [...]} are wrapper-YAML only and "
            "are rejected by the SaaS HighLevelPolicyV1 router" % (value,)
        )


def _validate_wrapper_only_filesystem_fields(cfg: dict[str, Any]) -> None:
    """Reject filesystem knobs that the HighLevelPolicyV1 schema does not carry.

    `skip_default_deny_read` and `deny_write_globs` exist only on the wrapper
    YAML `FilesystemIntentV1`; the SaaS HTTP path rejects them with
    `bad_request_unknown_field`. Surface the mistake here with a pointer to
    the supported alternatives.
    """
    if cfg.get("filesystem_skip_default_deny_read"):
        raise FinsafePolicyConfigError(
            "filesystem_skip_default_deny_read is a wrapper-YAML field and is "
            "rejected by the SaaS HighLevelPolicyV1 router; the FinSAFE built-in "
            "deny-read is always merged in deny mode and cannot be disabled via "
            "this provider"
        )
    if list(cfg.get("filesystem_deny_write_globs") or []):
        raise FinsafePolicyConfigError(
            "filesystem_deny_write_globs is a wrapper-YAML field and is rejected "
            "by the SaaS HighLevelPolicyV1 router; HighLevelPolicyV1 has no "
            "write-glob deny knob (deny_read_paths is read-only, not a write "
            "replacement). To block writes to sensitive paths, scope them out "
            "of filesystem_read_write_paths, or surface a custom rule via "
            "policy_extensions"
        )


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
        # Shallow one-level merge: when both the existing value and the
        # extension value are dicts, merge the top level only (nested dicts
        # are replaced, not recursively merged). Non-dict extensions replace
        # the existing value outright.
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
