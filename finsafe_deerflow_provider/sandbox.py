"""``FinsafeSandbox`` — DeerFlow :class:`Sandbox` backed by FinSAFE Phase X sessions."""

from __future__ import annotations

import logging
import re
import shlex
import threading
import uuid
from typing import TYPE_CHECKING, Any

from deerflow.config.paths import VIRTUAL_PATH_PREFIX
from deerflow.sandbox.sandbox import Sandbox, _validate_extra_env
from deerflow.sandbox.search import GrepMatch, path_matches, should_ignore_path, truncate_line

# DeerFlow virtual roots that appear as absolute paths inside bash command
# strings. The harness rewrites these for local sandboxes; a remote provider
# must do the equivalent so commands, ``cd`` prefixes, and file-tool writes all
# resolve to the same physical location inside the FinSAFE cell.
_ACP_WORKSPACE_VIRTUAL_PREFIX = "/mnt/acp-workspace"
_SKILLS_VIRTUAL_PREFIX = "/mnt/skills"
_VIRTUAL_COMMAND_PREFIXES: tuple[str, ...] = (
    VIRTUAL_PATH_PREFIX,
    _ACP_WORKSPACE_VIRTUAL_PREFIX,
    _SKILLS_VIRTUAL_PREFIX,
)

from .defaults import (
    DEFAULT_AGENT_ID,
    DEFAULT_BASH_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS,
    DEFAULT_CAPTURE_DIRECTORY,
    DEFAULT_DOWNLOAD_MAX_BYTES,
    DEFAULT_EXECUTION_MODE,
    DEFAULT_GUEST_WORKSPACE_PATH,
    DEFAULT_LIST_DIR_TIMEOUT_SECONDS,
    DEFAULT_SEARCH_TIMEOUT_SECONDS,
)
from .policy import build_bootstrap_script

if TYPE_CHECKING:
    from .http import FinsafeHttpClient

logger = logging.getLogger(__name__)

_DEFAULT_RUNTIME_CONFIG: dict[str, Any] = {
    "agent_id": DEFAULT_AGENT_ID,
    "execution_mode": DEFAULT_EXECUTION_MODE,
    "guest_workspace_path": DEFAULT_GUEST_WORKSPACE_PATH,
    "bootstrap_timeout_seconds": DEFAULT_BOOTSTRAP_TIMEOUT_SECONDS,
    "download_max_bytes": DEFAULT_DOWNLOAD_MAX_BYTES,
    "capture_directory": DEFAULT_CAPTURE_DIRECTORY,
    "list_dir_timeout_seconds": DEFAULT_LIST_DIR_TIMEOUT_SECONDS,
    "search_timeout_seconds": DEFAULT_SEARCH_TIMEOUT_SECONDS,
    "bash_command_timeout": DEFAULT_BASH_COMMAND_TIMEOUT_SECONDS,
}


class FinsafeSandbox(Sandbox):
    """Adapter that runs tool operations via finsafe-server session cells."""

    def __init__(
        self,
        sandbox_id: str,
        *,
        session_id: str,
        workspace_path: str,
        client: FinsafeHttpClient,
        policy_factory,
        tenant_id: str,
        user_id: str,
        policy_id: str,
        host_profile: str,
        runtime_config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(sandbox_id)
        self._session_id = session_id
        self._workspace_path = workspace_path
        self._client = client
        self._policy_factory = policy_factory
        self._tenant_id = tenant_id
        self._user_id = user_id
        self._policy_id = policy_id
        self._host_profile = host_profile
        self._runtime = {**_DEFAULT_RUNTIME_CONFIG, **(runtime_config or {})}
        self._guest_workspace_path = str(self._runtime["guest_workspace_path"]).rstrip("/")
        self._capture_dir = str(self._runtime["capture_directory"])
        self._download_max_bytes = int(self._runtime["download_max_bytes"])
        self._bootstrap_timeout = int(self._runtime["bootstrap_timeout_seconds"])
        self._list_dir_timeout = float(self._runtime["list_dir_timeout_seconds"])
        self._search_timeout = float(self._runtime["search_timeout_seconds"])
        self._default_command_timeout = float(self._runtime["bash_command_timeout"])
        self._lock = threading.Lock()
        self._bootstrap_lock = threading.Lock()
        self._closed = False
        self._bootstrapped = False

        # Precompute virtual-path rewrites for bash commands. The cell work_dir
        # is ``workspace_path``; DeerFlow virtual roots live under it as
        # ``{workspace_path}/mnt/...`` (bootstrap creates them). The negative
        # lookahead mirrors the harness rewriter so a virtual root does not match
        # a sibling that merely shares its prefix (``/mnt/user-data-backup``).
        ws = self._workspace_path.rstrip("/")
        self._cell_workspace_root = ws
        self._command_path_rewrites: list[tuple[re.Pattern[str], str]] = [
            (
                re.compile(rf"{re.escape(prefix)}(?=/|$|[^\w./-])"),
                f"{ws}/{prefix.lstrip('/')}",
            )
            for prefix in _VIRTUAL_COMMAND_PREFIXES
        ]
        # Reverse map (cell absolute path -> virtual path) so command output does
        # not leak the host session directory back to the agent.
        self._output_path_masks: list[tuple[str, str]] = [
            (f"{ws}/{prefix.lstrip('/')}", prefix) for prefix in _VIRTUAL_COMMAND_PREFIXES
        ]

    @property
    def session_id(self) -> str:
        return self._session_id

    def close(self) -> None:
        with self._lock:
            self._closed = True

    @property
    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    @staticmethod
    def _guard_traversal(path: str) -> str:
        if not path:
            raise ValueError("path must be a non-empty string")
        normalized = path.replace("\\", "/")
        for segment in normalized.split("/"):
            if segment == "..":
                raise PermissionError(f"Access denied: path traversal detected in '{path}'")
        return normalized

    def _resolve_path(self, path: str) -> str:
        normalized = self._guard_traversal(path)
        if normalized == VIRTUAL_PATH_PREFIX or normalized.startswith(f"{VIRTUAL_PATH_PREFIX}/"):
            tail = normalized[len(VIRTUAL_PATH_PREFIX) :].lstrip("/")
            return f"mnt/user-data/{tail}".rstrip("/") if tail else "mnt/user-data"
        if normalized == "/mnt/acp-workspace" or normalized.startswith("/mnt/acp-workspace/"):
            tail = normalized[len("/mnt/acp-workspace") :].lstrip("/")
            return f"mnt/acp-workspace/{tail}".rstrip("/") if tail else "mnt/acp-workspace"
        if normalized == "/mnt/skills" or normalized.startswith("/mnt/skills/"):
            tail = normalized[len("/mnt/skills") :].lstrip("/")
            return f"mnt/skills/{tail}".rstrip("/") if tail else "mnt/skills"
        if normalized.startswith("/"):
            raise PermissionError(f"Access denied: path '{path}' is outside the sandbox workspace")
        return normalized

    def _virtualize_path(self, rel_path: str) -> str:
        rel = rel_path.replace("\\", "/").lstrip("/")
        if rel == "mnt/user-data" or rel.startswith("mnt/user-data/"):
            tail = rel[len("mnt/user-data") :].lstrip("/")
            return f"{VIRTUAL_PATH_PREFIX}/{tail}".rstrip("/") if tail else VIRTUAL_PATH_PREFIX
        if rel == "mnt/acp-workspace" or rel.startswith("mnt/acp-workspace/"):
            tail = rel[len("mnt/acp-workspace") :].lstrip("/")
            return f"/mnt/acp-workspace/{tail}".rstrip("/") if tail else "/mnt/acp-workspace"
        if rel == "mnt/skills" or rel.startswith("mnt/skills/"):
            tail = rel[len("mnt/skills") :].lstrip("/")
            return f"/mnt/skills/{tail}".rstrip("/") if tail else "/mnt/skills"
        return f"/{rel}"

    def _rel_from_cell_path(self, raw_path: str) -> str:
        rel = raw_path.strip().replace("\\", "/")
        for prefix in (self._workspace_path.rstrip("/"), self._guest_workspace_path):
            stem = f"{prefix}/"
            if rel.startswith(stem):
                rel = rel[len(stem) :]
                break
        return rel.lstrip("/")

    def _rewrite_command_paths(self, command: str) -> str:
        """Rewrite DeerFlow virtual roots to cell-absolute paths.

        The harness prepends ``cd /mnt/user-data/workspace;`` for remote
        providers and agents routinely pass absolute ``/mnt/user-data/...``
        paths, but the cell only exposes those trees under ``work_dir``
        (``{workspace_path}/mnt/...``). Rewriting keeps ``bash`` aligned with
        ``read_file``/``write_file`` (which resolve to the same location).
        """
        result = command
        for pattern, replacement in self._command_path_rewrites:
            result = pattern.sub(lambda _m, repl=replacement: repl, result)
        return result

    def _mask_output_paths(self, output: str) -> str:
        """Reverse of :meth:`_rewrite_command_paths` for command output."""
        result = output
        for cell_abs, virtual in self._output_path_masks:
            result = result.replace(cell_abs, virtual)
        # Bare session workspace root (e.g. ``pwd``) -> default workspace path.
        result = result.replace(self._cell_workspace_root, f"{VIRTUAL_PATH_PREFIX}/workspace")
        return result

    def _ensure_bootstrapped(self) -> None:
        if self._bootstrapped:
            return
        with self._bootstrap_lock:
            if self._bootstrapped:
                return
            if self.is_closed:
                raise RuntimeError("sandbox has been closed")
            result = self._run_shell(
                build_bootstrap_script(self._runtime),
                timeout=self._bootstrap_timeout,
                _bootstrap=False,
            )
            if "BOOTSTRAP_OK" not in result:
                logger.warning("FinSAFE bootstrap may have failed: %s", result[:500])
            self._bootstrapped = True

    def _build_execution_payload(self, command: list[str], *, timeout_ms: int | None = None) -> dict:
        execution_id, request_id = self._client.new_execution_ids()
        policy = self._policy_factory(timeout_ms=timeout_ms)
        return {
            "policy": policy,
            "request": {
                "schema_version": 1,
                "identity": {
                    "tenant_id": self._tenant_id,
                    "user_id": self._user_id,
                    "execution_id": execution_id,
                    "request_id": request_id,
                    "session_id": self._session_id,
                    "agent_id": self._runtime["agent_id"],
                },
                "policy_id": self._policy_id,
                "host_profile": self._host_profile,
                "request": {
                    "mode": self._runtime["execution_mode"],
                    "command": command,
                    "work_dir": self._workspace_path,
                },
            },
        }

    def _submit_and_wait(self, command: list[str], *, timeout: float | None = None) -> None:
        timeout_ms = int(timeout * 1000) if timeout is not None else None
        payload = self._build_execution_payload(command, timeout_ms=timeout_ms)
        submitted = self._client.submit_session_execution(self._session_id, payload)
        admission = submitted.get("admission") or {}
        if not admission.get("admitted"):
            reason = admission.get("reason") or submitted
            raise RuntimeError(f"FinSAFE admission denied: {reason}")
        execution_id = admission.get("execution_id")
        if not execution_id:
            raise RuntimeError("FinSAFE admission missing execution_id")
        self._client.wait_execution(execution_id, timeout=timeout)

    def _run_shell(
        self,
        script: str,
        *,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
        _bootstrap: bool = True,
    ) -> str:
        _validate_extra_env(env)
        if _bootstrap:
            self._ensure_bootstrapped()
        capture_id = uuid.uuid4().hex
        out_rel = f"{self._capture_dir}/{capture_id}.out"
        exit_rel = f"{self._capture_dir}/{capture_id}.exit"
        env_prefix = ""
        if env:
            exports = " ".join(f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in env.items())
            env_prefix = f"export {exports}; "
        wrapped = f"mkdir -p {shlex.quote(self._capture_dir)}; {env_prefix}({script}) >{shlex.quote(out_rel)} 2>&1; echo $? >{shlex.quote(exit_rel)}"
        self._submit_and_wait(["/bin/sh", "-lc", wrapped], timeout=timeout)
        try:
            output = self._client.download_session_file(self._session_id, out_rel).decode("utf-8", errors="replace")
            exit_code = self._client.download_session_file(self._session_id, exit_rel).decode("utf-8", errors="replace").strip()
        except Exception as e:
            return f"Error: failed to read command output: {e}"
        if exit_code not in ("0", ""):
            if output:
                return output
            return f"Command exited with code {exit_code or 'unknown'}"
        return output if output else "(no output)"

    def execute_command(
        self,
        command: str,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> str:
        if self.is_closed:
            return "Error: sandbox has been closed"
        effective_timeout = self._default_command_timeout if timeout is None else timeout
        try:
            rewritten = self._rewrite_command_paths(command)
            output = self._run_shell(rewritten, env=env, timeout=effective_timeout)
            return self._mask_output_paths(output)
        except Exception as e:
            logger.error("FinSAFE execute_command failed for sandbox %s: %s", self.id, e)
            return f"Error: {e}"

    def read_file(self, path: str) -> str:
        rel = self._resolve_path(path)
        try:
            data = self._client.download_session_file(self._session_id, rel)
        except Exception as e:
            return f"Error: {e}"
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return f"Error: file '{path}' is not valid UTF-8 text"

    def download_file(self, path: str) -> bytes:
        rel = self._resolve_path(path)
        data = self._client.download_session_file(self._session_id, rel)
        if len(data) > self._download_max_bytes:
            raise OSError(f"file '{path}' exceeds download size cap ({self._download_max_bytes} bytes)")
        return data

    def write_file(self, path: str, content: str, append: bool = False) -> None:
        rel = self._resolve_path(path)
        if append:
            try:
                existing = self._client.download_session_file(self._session_id, rel)
            except Exception:
                existing = b""
            payload = existing + content.encode("utf-8")
        else:
            payload = content.encode("utf-8")
        self._client.upload_session_file(self._session_id, rel, payload)

    def update_file(self, path: str, content: bytes) -> None:
        rel = self._resolve_path(path)
        self._client.upload_session_file(self._session_id, rel, content)

    def list_dir(self, path: str, max_depth: int = 2) -> list[str]:
        resolved = self._resolve_path(path)
        depth = max(1, int(max_depth))
        script = f"find {shlex.quote(resolved)} -mindepth 1 -maxdepth {depth} -printf '%y\\t%p\\n' 2>/dev/null || true"
        output = self._run_shell(script, timeout=self._list_dir_timeout)
        entries: list[str] = []
        for line in output.splitlines():
            if not line.strip() or line.startswith("Error:"):
                continue
            try:
                kind, raw_path = line.split("\t", 1)
            except ValueError:
                continue
            rel = self._rel_from_cell_path(raw_path.strip())
            if not rel or should_ignore_path(rel):
                continue
            virtual = self._virtualize_path(rel)
            if kind == "d":
                entries.append(virtual.rstrip("/") + "/")
            else:
                entries.append(virtual)
        return sorted(entries)

    def glob(
        self,
        path: str,
        pattern: str,
        *,
        include_dirs: bool = False,
        max_results: int = 200,
    ) -> tuple[list[str], bool]:
        root = self._resolve_path(path)
        type_flag = "" if include_dirs else "-type f"
        script = f"find {shlex.quote(root)} {type_flag} -name {shlex.quote(pattern)} -print 2>/dev/null | head -n {max_results + 1}"
        output = self._run_shell(script, timeout=self._search_timeout)
        matches: list[str] = []
        truncated = False
        for line in output.splitlines():
            if not line.strip() or line.startswith("Error:"):
                continue
            rel = self._rel_from_cell_path(line.strip())
            if should_ignore_path(rel):
                continue
            virtual = self._virtualize_path(rel)
            if not path_matches(pattern, virtual):
                continue
            matches.append(virtual)
            if len(matches) > max_results:
                truncated = True
                matches = matches[:max_results]
                break
        return matches, truncated

    def grep(
        self,
        path: str,
        pattern: str,
        *,
        glob: str | None = None,
        literal: bool = False,
        case_sensitive: bool = False,
        max_results: int = 100,
    ) -> tuple[list[GrepMatch], bool]:
        root = self._resolve_path(path)
        grep_flags = "-Hn"
        if not case_sensitive:
            grep_flags += "i"
        if literal:
            grep_flags += "F"
        else:
            grep_flags += "E"
        glob_clause = f"--include={shlex.quote(glob)} " if glob else ""
        script = f"grep -r {grep_flags} {glob_clause}{shlex.quote(pattern)} {shlex.quote(root)} 2>/dev/null | head -n {max_results + 1} || true"
        output = self._run_shell(script, timeout=self._search_timeout)
        matches: list[GrepMatch] = []
        truncated = False
        for line in output.splitlines():
            if not line.strip() or line.startswith("Error:"):
                continue
            try:
                raw_path, line_no, content = line.split(":", 2)
            except ValueError:
                continue
            rel = self._rel_from_cell_path(raw_path.strip())
            if should_ignore_path(rel):
                continue
            virtual = self._virtualize_path(rel)
            try:
                number = int(line_no)
            except ValueError:
                continue
            matches.append(GrepMatch(path=virtual, line_number=number, line=truncate_line(content)))
            if len(matches) > max_results:
                truncated = True
                matches = matches[:max_results]
                break
        return matches, truncated
