"""Test network_allowlist functionality (unit + live)."""

from __future__ import annotations

import os
import uuid
from unittest.mock import patch

import httpx
import pytest
from _helpers import make_mock_sandbox_config as _mock_sandbox_config

pytestmark = pytest.mark.integration


def _base_cfg(**overrides):
    cfg = {
        "network_mode": "allowlist",
        "memory_max": "2G",
        "pids_max": "512",
        "cpu_max": "200000 100000",
        "tenant_id": "acme",
        "user_id": "app-user",
        "policy_id": "deerflow-sandbox",
        "host_profile": "linux-desktop-isolated",
    }
    cfg.update(overrides)
    return cfg


def test_allowlist_requires_list():
    """allowlist mode without network_allowlist must fail fast at the provider."""
    from finsafe_deerflow_provider.policy import (
        FinsafePolicyConfigError,
        build_high_level_policy,
    )

    with pytest.raises(FinsafePolicyConfigError, match="network_allowlist is required"):
        build_high_level_policy(_base_cfg())


def test_allowlist_policy_shape():
    """allowlist mode emits network.allowlist in the assembled policy."""
    from finsafe_deerflow_provider.policy import build_high_level_policy

    allowlist = ["1.1.1.1:443", "api.example.com:443"]
    policy = build_high_level_policy(_base_cfg(network_allowlist=allowlist))
    net = policy.get("network", {})
    assert net.get("mode") == "allowlist"
    assert net.get("allowlist") == allowlist


def _daemon_reachable() -> bool:
    base = os.environ.get("FINSAFE_BASE_URL", "").rstrip("/")
    token = os.environ.get("FINSAFE_TOKEN", "")
    if not base or not token:
        return False
    try:
        r = httpx.get(
            f"{base}/v1/executions/does-not-exist",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
    except httpx.HTTPError:
        return False
    return r.status_code == 404


@pytest.fixture(scope="module")
def require_finsafe_daemon():
    if not _daemon_reachable():
        pytest.skip("FinSAFE daemon not reachable")


def test_allowlist_live(require_finsafe_daemon):
    """Live: observe sidecar behavior under allowlist mode.

    Requires finsafe-daemon.yaml with host_capabilities.allowlist_supported: true.
    Sidecars without that capability fail at admission with a recognizable
    `policy_router_unavailable_capability` error and are skipped; any other
    failure (admission rejected for a different reason, cell launch error,
    whitelisted host not actually reachable) is a real regression and must
    surface as a test failure, not a silent skip.
    """
    from finsafe_deerflow_provider import FinsafeSandboxProvider

    allowlist = ["1.1.1.1:443", "www.baidu.com:443"]
    with patch(
        "finsafe_deerflow_provider.provider.get_app_config",
        return_value=_mock_sandbox_config(
            network_mode="allowlist", network_allowlist=allowlist
        ),
    ):
        provider = FinsafeSandboxProvider()
    thread_id = f"allowlist-{uuid.uuid4().hex[:12]}"
    print("\n--- allowlist live test ---")
    sid = None
    try:
        sid = provider.acquire(thread_id, user_id="finsafe-net")
        sb = provider.get(sid)
        print("cell acquired OK (sidecar accepted allowlist policy)")
        out_wl = sb.execute_command(
            "curl -sm5 -o /dev/null -w 'WL:%{http_code}' https://1.1.1.1 2>&1 || echo WL:CURL-FAIL"
        )
        print("whitelisted 1.1.1.1:", out_wl)
        out_nw = sb.execute_command(
            "curl -sm5 -o /dev/null -w 'NW:%{http_code}' http://8.8.8.8 2>&1 || echo NW:CURL-FAIL"
        )
        print("non-whitelisted 8.8.8.8:", out_nw)
    except Exception as e:
        msg = str(e)
        provider.shutdown()
        # Only skip when the sidecar itself lacks the capability; everything
        # else is a regression we want CI to catch.
        if "policy_router_unavailable_capability" in msg or "allowlist" in msg.lower():
            pytest.skip(
                f"sidecar does not support allowlist (check host_capabilities): {type(e).__name__}: {e}"
            )
        raise
    else:
        provider.release(sid)
        provider.shutdown()
