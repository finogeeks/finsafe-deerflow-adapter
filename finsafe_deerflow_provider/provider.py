"""``FinsafeSandboxProvider`` — DeerFlow sandbox provider for FinSAFE SaaS."""

from __future__ import annotations

import atexit
import hashlib
import logging
import os
import threading
import uuid
from collections.abc import Callable
from typing import Any

from deerflow.config import get_app_config
from deerflow.runtime.user_context import get_effective_user_id
from deerflow.sandbox.sandbox import Sandbox
from deerflow.sandbox.sandbox_provider import SandboxProvider

from .defaults import (
    DEFAULT_AGENT_ID,
    DEFAULT_BASE_URL,
    DEFAULT_BASH_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS,
    DEFAULT_CAPTURE_DIRECTORY,
    DEFAULT_CPU_MAX,
    DEFAULT_DOWNLOAD_MAX_BYTES,
    DEFAULT_EXECUTION_ID_PREFIX,
    DEFAULT_EXECUTION_MODE,
    DEFAULT_EXECUTION_POLL_INTERVAL_SECONDS,
    DEFAULT_GUEST_WORKSPACE_PATH,
    DEFAULT_HOST_PROFILE,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_LIST_DIR_TIMEOUT_SECONDS,
    DEFAULT_MEMORY_MAX,
    DEFAULT_NETWORK_MODE,
    DEFAULT_PIDS_MAX,
    DEFAULT_POLICY_ID,
    DEFAULT_REQUEST_ID_PREFIX,
    DEFAULT_SEARCH_TIMEOUT_SECONDS,
    DEFAULT_SESSION_MODE,
    DEFAULT_TENANT_ID,
)
from .http import FinsafeHttpClient, FinsafeHttpError
from .policy import build_high_level_policy
from .sandbox import FinsafeSandbox

logger = logging.getLogger(__name__)


# Filesystem knobs that exist on the wrapper YAML `FilesystemIntentV1` but
# are rejected by the SaaS `HighLevelPolicyV1` router. The provider still
# reads them (so config.yaml does not error on parse), but `build_high_level_policy`
# refuses to emit them; surface a warning here so operators notice the no-op.
_WRAPPER_ONLY_FILESYSTEM_FIELDS = (
    "filesystem_skip_default_deny_read",
    "filesystem_deny_write_globs",
)


def _warn_wrapper_only_filesystem_fields(cfg: dict[str, Any]) -> None:
    for name in _WRAPPER_ONLY_FILESYSTEM_FIELDS:
        value = cfg.get(name)
        if name == "filesystem_deny_write_globs":
            if not list(value or []):
                continue
        elif value is None:
            continue
        logger.warning(
            "FinsafeSandboxProvider: %s is set in sandbox config but is a "
            "wrapper-YAML-only field rejected by the SaaS HighLevelPolicyV1 "
            "router; it will be ignored at policy build time",
            name,
        )


class FinsafeSandboxProvider(SandboxProvider):
    """Sandbox provider backed by finsafe-server-http Phase X workspace sessions."""

    uses_thread_data_mounts = False
    needs_upload_permission_adjustment = True

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sandboxes: dict[str, FinsafeSandbox] = {}
        self._thread_sessions: dict[tuple[str, str], str] = {}
        self._thread_locks: dict[tuple[str, str], threading.Lock] = {}
        self._shutdown_called = False
        self._config = self._load_config()
        self._client = FinsafeHttpClient(
            self._config["base_url"],
            self._config["token"],
            timeout=self._config["http_timeout_seconds"],
            poll_interval=self._config["execution_poll_interval_seconds"],
            execution_id_prefix=self._config["execution_id_prefix"],
            request_id_prefix=self._config["request_id_prefix"],
        )
        atexit.register(self.shutdown)

    @staticmethod
    def _load_config() -> dict[str, Any]:
        sandbox_config = get_app_config().sandbox

        def _opt(name: str, default: Any = None) -> Any:
            return getattr(sandbox_config, name, default)

        base_url = _opt("base_url") or os.environ.get("FINSAFE_BASE_URL") or DEFAULT_BASE_URL
        token = _opt("token") or os.environ.get("FINSAFE_TOKEN")
        if not token:
            logger.warning(
                "FinsafeSandboxProvider: no token configured "
                "(set sandbox.token in config.yaml or FINSAFE_TOKEN env var)"
            )

        cfg = {
            "base_url": str(base_url).rstrip("/"),
            "token": token or "",
            "tenant_id": _opt("tenant_id") or DEFAULT_TENANT_ID,
            "policy_id": _opt("policy_id") or DEFAULT_POLICY_ID,
            "host_profile": _opt("host_profile") or DEFAULT_HOST_PROFILE,
            "network_mode": _opt("network_mode") or DEFAULT_NETWORK_MODE,
            "network_allowlist": list(_opt("network_allowlist") or []),
            "network_proxy_profile": _opt("network_proxy_profile"),
            "network_tls_terminate": _opt("network_tls_terminate"),
            "network_start_internal_proxy": _opt("network_start_internal_proxy"),
            "network_inject_identity": _opt("network_inject_identity"),
            "network_content_audit": _opt("network_content_audit"),
            "network_parent_proxy_url": _opt("network_parent_proxy_url"),
            "network_parent_proxy_no_proxy": list(_opt("network_parent_proxy_no_proxy") or []),
            "network_parent_proxy_required": _opt("network_parent_proxy_required"),
            "memory_max": _opt("memory_max") or DEFAULT_MEMORY_MAX,
            "pids_max": _opt("pids_max") or DEFAULT_PIDS_MAX,
            "cpu_max": _opt("cpu_max") or DEFAULT_CPU_MAX,
            "filesystem_read_only_paths": _opt("filesystem_read_only_paths"),
            "filesystem_read_write_paths": _opt("filesystem_read_write_paths"),
            "filesystem_deny_read_paths": list(_opt("filesystem_deny_read_paths") or []),
            "filesystem_deny_write_globs": list(_opt("filesystem_deny_write_globs") or []),
            "filesystem_skip_default_deny_read": _opt("filesystem_skip_default_deny_read"),
            "syscalls": _opt("syscalls"),
            "identity_use_user_namespace": _opt("identity_use_user_namespace"),
            "policy_extensions": dict(_opt("policy_extensions") or {}),
            "agent_id": _opt("agent_id") or DEFAULT_AGENT_ID,
            "execution_mode": _opt("execution_mode") or DEFAULT_EXECUTION_MODE,
            "session_mode": _opt("session_mode") or DEFAULT_SESSION_MODE,
            "http_timeout_seconds": float(_opt("http_timeout_seconds") or DEFAULT_HTTP_TIMEOUT_SECONDS),
            "execution_poll_interval_seconds": float(
                _opt("execution_poll_interval_seconds") or DEFAULT_EXECUTION_POLL_INTERVAL_SECONDS
            ),
            "guest_workspace_path": _opt("guest_workspace_path") or DEFAULT_GUEST_WORKSPACE_PATH,
            "bootstrap_timeout_seconds": int(
                _opt("bootstrap_timeout_seconds") or DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS
            ),
            "download_max_bytes": int(_opt("download_max_bytes") or DEFAULT_DOWNLOAD_MAX_BYTES),
            "bootstrap_directories": _opt("bootstrap_directories"),
            "capture_directory": _opt("capture_directory") or DEFAULT_CAPTURE_DIRECTORY,
            "execution_id_prefix": _opt("execution_id_prefix") or DEFAULT_EXECUTION_ID_PREFIX,
            "request_id_prefix": _opt("request_id_prefix") or DEFAULT_REQUEST_ID_PREFIX,
            "list_dir_timeout_seconds": int(_opt("list_dir_timeout_seconds") or DEFAULT_LIST_DIR_TIMEOUT_SECONDS),
            "search_timeout_seconds": int(_opt("search_timeout_seconds") or DEFAULT_SEARCH_TIMEOUT_SECONDS),
            "bash_command_timeout": int(
                _opt("bash_command_timeout") or DEFAULT_BASH_COMMAND_TIMEOUT_SECONDS
            ),
        }

        _warn_wrapper_only_filesystem_fields(cfg)
        return cfg

    def _policy_factory(self, *, timeout_ms: int | None = None) -> Callable[..., dict[str, Any]]:
        cfg = self._config

        def _build(timeout_ms: int | None = None) -> dict[str, Any]:
            return build_high_level_policy(cfg, timeout_ms=timeout_ms)

        return lambda timeout_ms=timeout_ms: _build(timeout_ms)

    @staticmethod
    def _thread_key(thread_id: str, user_id: str) -> tuple[str, str]:
        return (user_id, thread_id)

    @staticmethod
    def _sandbox_id(thread_id: str, user_id: str) -> str:
        return hashlib.sha256(f"{user_id}:{thread_id}".encode()).hexdigest()[:12]

    def _get_thread_lock(self, thread_id: str, user_id: str) -> threading.Lock:
        key = self._thread_key(thread_id, user_id)
        with self._lock:
            lock = self._thread_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._thread_locks[key] = lock
            return lock

    def acquire(self, thread_id: str | None = None, *, user_id: str | None = None) -> str:
        effective_user = user_id or get_effective_user_id()
        if thread_id:
            with self._get_thread_lock(thread_id, effective_user):
                return self._acquire_for_thread(thread_id, user_id=effective_user)
        return self._create_ephemeral(user_id=effective_user)

    async def acquire_async(self, thread_id: str | None = None, *, user_id: str | None = None) -> str:
        import asyncio

        return await asyncio.to_thread(self.acquire, thread_id, user_id=user_id)

    def _acquire_for_thread(self, thread_id: str, *, user_id: str) -> str:
        key = self._thread_key(thread_id, user_id)
        with self._lock:
            existing = self._thread_sessions.get(key)
            if existing and existing in self._sandboxes:
                return existing
        return self._create_for_thread(thread_id, user_id=user_id)

    def _create_for_thread(self, thread_id: str, *, user_id: str) -> str:
        sandbox_id = self._sandbox_id(thread_id, user_id)
        sandbox = self._create_session_sandbox(sandbox_id, user_id=user_id)
        with self._lock:
            self._sandboxes[sandbox_id] = sandbox
            self._thread_sessions[self._thread_key(thread_id, user_id)] = sandbox_id
        logger.info(
            "Created FinSAFE sandbox %s (session=%s) for user/thread %s/%s",
            sandbox_id,
            sandbox.session_id,
            user_id,
            thread_id,
        )
        return sandbox_id

    def _create_ephemeral(self, *, user_id: str) -> str:
        sandbox_id = str(uuid.uuid4())[:12]
        sandbox = self._create_session_sandbox(sandbox_id, user_id=user_id)
        with self._lock:
            self._sandboxes[sandbox_id] = sandbox
        return sandbox_id

    def _create_session_sandbox(self, sandbox_id: str, *, user_id: str) -> FinsafeSandbox:
        if not self._config["token"]:
            raise FinsafeHttpError("FinSAFE token is not configured (sandbox.token or FINSAFE_TOKEN)")
        created = self._client.create_session(
            tenant_id=self._config["tenant_id"],
            user_id=user_id,
            policy_id=self._config["policy_id"],
            mode=self._config["session_mode"],
        )
        session = created.get("session") or {}
        session_id = session.get("session_id")
        workspace_path = session.get("workspace_path")
        if not session_id or not workspace_path:
            raise FinsafeHttpError(f"unexpected create_session response: {created}")
        policy_factory = self._policy_factory()
        sandbox = FinsafeSandbox(
            sandbox_id,
            session_id=session_id,
            workspace_path=workspace_path,
            client=self._client,
            policy_factory=policy_factory,
            tenant_id=self._config["tenant_id"],
            user_id=user_id,
            policy_id=self._config["policy_id"],
            host_profile=self._config["host_profile"],
            runtime_config=self._config,
        )
        sandbox._ensure_bootstrapped()
        return sandbox

    def get(self, sandbox_id: str) -> Sandbox | None:
        with self._lock:
            return self._sandboxes.get(sandbox_id)

    def release(self, sandbox_id: str) -> None:
        with self._lock:
            known = sandbox_id in self._sandboxes
        if known:
            logger.info("Released FinSAFE sandbox %s (session kept warm for reuse)", sandbox_id)

    def reset(self) -> None:
        with self._lock:
            sandboxes = list(self._sandboxes.values())
            self._sandboxes.clear()
            self._thread_sessions.clear()
            self._thread_locks.clear()
        for sandbox in sandboxes:
            try:
                self._client.delete_session(sandbox.session_id)
            except Exception as e:
                logger.warning(
                    "Failed to delete FinSAFE session %s during reset: %s",
                    sandbox.session_id,
                    e,
                )
            sandbox.close()

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown_called:
                return
            self._shutdown_called = True
            sandboxes = list(self._sandboxes.values())
            self._sandboxes.clear()
            self._thread_sessions.clear()

        for sandbox in sandboxes:
            try:
                self._client.delete_session(sandbox.session_id)
            except Exception as e:
                logger.warning(
                    "Failed to delete FinSAFE session %s during shutdown: %s",
                    sandbox.session_id,
                    e,
                )
            sandbox.close()
        self._client.close()
