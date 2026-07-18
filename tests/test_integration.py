"""Live integration tests (requires a running finsafe-saas sidecar).

Run from a DeerFlow backend venv with the adapter installed::

    export FINSAFE_BASE_URL=http://127.0.0.1:18080
    export FINSAFE_TOKEN=dev-change-me
    cd deer-flow/backend && uv sync --extra finsafe
    uv run pytest /path/to/finsafe-deerflow-adapter/tests/test_integration.py -m integration -v

Or use ``scripts/smoke.sh`` from this repository.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import patch

import httpx
import pytest
from _helpers import make_mock_sandbox_config as _mock_sandbox_config

pytestmark = pytest.mark.integration


def _daemon_reachable() -> bool:
    base = os.environ.get("FINSAFE_BASE_URL", "").rstrip("/")
    token = os.environ.get("FINSAFE_TOKEN", "")
    if not base or not token:
        return False
    try:
        response = httpx.get(
            f"{base}/v1/executions/does-not-exist",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
    except httpx.HTTPError:
        return False
    return response.status_code == 404


@pytest.fixture(scope="module")
def require_finsafe_daemon():
    if not _daemon_reachable():
        pytest.skip(
            "FinSAFE daemon not reachable (set FINSAFE_BASE_URL + FINSAFE_TOKEN "
            "and start docker compose in finsafe-deerflow-adapter/docker)"
        )


@pytest.fixture
def finsafe_provider(require_finsafe_daemon):
    from finsafe_deerflow_adapter import FinsafeSandboxProvider

    with patch("finsafe_deerflow_adapter.provider.get_app_config", return_value=_mock_sandbox_config()):
        provider = FinsafeSandboxProvider()
    yield provider
    provider.shutdown()


@pytest.fixture
def sandbox(finsafe_provider):
    thread_id = f"pytest-{uuid.uuid4().hex[:12]}"
    sandbox_id = finsafe_provider.acquire(thread_id, user_id="finsafe-smoke")
    sb = finsafe_provider.get(sandbox_id)
    assert sb is not None
    yield sb
    finsafe_provider.release(sandbox_id)


def test_daemon_readiness(require_finsafe_daemon) -> None:
    base = os.environ["FINSAFE_BASE_URL"].rstrip("/")
    token = os.environ["FINSAFE_TOKEN"]
    response = httpx.get(
        f"{base}/v1/executions/does-not-exist",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5.0,
    )
    assert response.status_code == 404


def test_execute_command_identity(sandbox) -> None:
    output = sandbox.execute_command("echo smoke-ok && id -u")
    assert "smoke-ok" in output
    assert "1000" in output
    assert not output.startswith("Error:")


def test_write_read_append(sandbox) -> None:
    path = "/mnt/user-data/workspace/smoke.txt"
    sandbox.write_file(path, "line1\n")
    assert sandbox.read_file(path) == "line1\n"
    sandbox.write_file(path, "line2\n", append=True)
    assert sandbox.read_file(path) == "line1\nline2\n"


def test_list_glob_grep(sandbox) -> None:
    sandbox.write_file("/mnt/user-data/workspace/notes.md", "finsafe smoke marker\n")
    entries = sandbox.list_dir("/mnt/user-data/workspace")
    assert "/mnt/user-data/workspace/notes.md" in entries
    matches, truncated = sandbox.glob("/mnt/user-data/workspace", "*.md")
    assert "/mnt/user-data/workspace/notes.md" in matches
    assert not truncated
    grep_hits, grep_truncated = sandbox.grep("/mnt/user-data/workspace", "finsafe")
    assert grep_hits and grep_hits[0].path.endswith("notes.md")
    assert not grep_truncated


def test_network_denied(sandbox) -> None:
    output = sandbox.execute_command(
        "curl -sm3 http://1.1.1.1 >/dev/null 2>&1 && echo NETWORK-OPEN || echo NETWORK-BLOCKED"
    )
    assert "NETWORK-BLOCKED" in output


def test_sensitive_read_denied(sandbox) -> None:
    output = sandbox.execute_command("cat /etc/shadow 2>&1 || true")
    assert "Permission denied" in output or "denied" in output.lower()


def test_cell_toolbox_python(sandbox) -> None:
    output = sandbox.execute_command("python3 -c \"print(40 + 2)\"")
    assert "42" in output
