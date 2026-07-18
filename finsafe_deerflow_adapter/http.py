"""Thin synchronous HTTP client for finsafe-server-http (Phase X sessions)."""

from __future__ import annotations

import time
import uuid
from typing import Any
from urllib.parse import quote

import httpx

from .defaults import (
    DEFAULT_EXECUTION_ID_PREFIX,
    DEFAULT_EXECUTION_POLL_INTERVAL_SECONDS,
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    DEFAULT_REQUEST_ID_PREFIX,
)

_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled", "denied"})


class FinsafeHttpError(RuntimeError):
    """Raised when the FinSAFE API returns a non-success response."""


class FinsafeHttpClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        poll_interval: float = DEFAULT_EXECUTION_POLL_INTERVAL_SECONDS,
        execution_id_prefix: str = DEFAULT_EXECUTION_ID_PREFIX,
        request_id_prefix: str = DEFAULT_REQUEST_ID_PREFIX,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._execution_id_prefix = execution_id_prefix
        self._request_id_prefix = request_id_prefix
        self._client = httpx.Client(
            base_url=self._base_url,
            headers=self._headers,
            timeout=self._timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: bytes | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        response = self._client.request(
            method,
            path,
            json=json_body,
            content=content,
            timeout=timeout or self._timeout,
        )
        if response.status_code >= 400:
            detail = response.text.strip() or response.reason_phrase
            raise FinsafeHttpError(f"{method} {path} -> {response.status_code}: {detail}")
        return response

    def create_session(
        self,
        *,
        tenant_id: str,
        user_id: str,
        policy_id: str,
        mode: str = "workspace",
    ) -> dict[str, Any]:
        body = {
            "schema_version": 1,
            "identity": {"tenant_id": tenant_id, "user_id": user_id},
            "policy_id": policy_id,
            "mode": mode,
        }
        return self._request("POST", "/v1/sessions", json_body=body).json()

    def delete_session(self, session_id: str) -> None:
        self._request("DELETE", f"/v1/sessions/{session_id}")

    def list_session_files(self, session_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/sessions/{session_id}/files").json()

    def upload_session_file(self, session_id: str, rel_path: str, data: bytes) -> None:
        encoded = quote(rel_path.lstrip("/"), safe="")
        self._request(
            "POST",
            f"/v1/sessions/{session_id}/files/{encoded}",
            content=data,
        )

    def download_session_file(self, session_id: str, rel_path: str) -> bytes:
        encoded = quote(rel_path.lstrip("/"), safe="")
        return self._request("GET", f"/v1/sessions/{session_id}/files/{encoded}").content

    def submit_session_execution(self, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/sessions/{session_id}/executions",
            json_body=payload,
        ).json()

    def get_execution(self, execution_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/executions/{execution_id}").json()

    def wait_execution(
        self,
        execution_id: str,
        *,
        poll_interval: float | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        interval = self._poll_interval if poll_interval is None else poll_interval
        deadline = time.monotonic() + (timeout or self._timeout)
        while time.monotonic() < deadline:
            record = self.get_execution(execution_id)
            status = record.get("status")
            if status in _TERMINAL_STATUSES:
                if status != "succeeded":
                    raise FinsafeHttpError(f"execution {execution_id} ended as {status}")
                return record
            time.sleep(interval)
        raise TimeoutError(f"execution {execution_id} did not finish within {timeout or self._timeout}s")

    def new_execution_ids(self) -> tuple[str, str]:
        suffix = uuid.uuid4().hex[:12]
        return (f"{self._execution_id_prefix}-{suffix}", f"{self._request_id_prefix}-{suffix}")
