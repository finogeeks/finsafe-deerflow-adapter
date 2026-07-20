"""Test network_allowlist functionality (unit + live)."""

from __future__ import annotations

import os
import re
import uuid
from unittest.mock import patch

import httpx
import pytest
from _helpers import make_mock_sandbox_config as _mock_sandbox_config

pytestmark = pytest.mark.integration

_HTTP_CODE = re.compile(r":(\d{3})$")


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


def _http_status(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            match = _HTTP_CODE.search(line.strip())
            if match:
                return int(match.group(1))
    return None


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
    """Live: allowlist cell reaches whitelisted HTTPS via loopback relay (finsafe#138+).

    Requires finsafe-daemon.yaml with host_capabilities.allowlist_supported: true
    and sidecar ghcr.io/geeksfino/finsafe-saas:v0.9.20 rebuilt after finsafe#138.
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
        if "policy_router_unavailable_capability" in msg:
            pytest.skip(
                f"sidecar does not support allowlist (check host_capabilities): {type(e).__name__}: {e}"
            )
        raise
    else:
        assert "Unsupported proxy scheme" not in out_wl, (
            "sidecar image predates finsafe#138 loopback relay — "
            "docker compose pull finsafe-saas (v0.9.20+)"
        )
        assert "WL:CURL-FAIL" not in out_wl, f"whitelisted host unreachable: {out_wl}"
        wl_status = _http_status(out_wl, "WL:")
        assert wl_status is not None and 200 <= wl_status < 400, (
            f"expected WL:2xx/3xx for whitelisted host, got: {out_wl!r}"
        )

        nw_status = _http_status(out_nw, "NW:")
        assert "NW:CURL-FAIL" in out_nw or nw_status is None or nw_status >= 400, (
            f"non-whitelisted host should not succeed: {out_nw!r}"
        )

        provider.release(sid)
        provider.shutdown()
