"""FinSAFE SaaS sandbox provider for DeerFlow.

Install this package, then point DeerFlow at it::

    sandbox:
      use: finsafe_deerflow_adapter:FinsafeSandboxProvider
      base_url: $FINSAFE_BASE_URL
      token: $FINSAFE_TOKEN
      tenant_id: acme
      user_id: app-user
      policy_id: deerflow-sandbox
      host_profile: linux-desktop-isolated
      network_mode: deny

Start the FinSAFE sidecar separately (see ``docker/`` in this repo or
``docker/docker-compose.finsafe.yaml`` in the DeerFlow overlay).

Policy reference: ``docs/finsafe-policy.md`` (copy from DeerFlow docker docs).
"""

from .provider import FinsafeSandboxProvider
from .sandbox import FinsafeSandbox

__all__ = [
    "FinsafeSandbox",
    "FinsafeSandboxProvider",
]
