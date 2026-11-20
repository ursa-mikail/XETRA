"""
CrowdStrike Falcon adapter — shaped to the Falcon REST API
(https://falcon.crowdstrike.com/documentation, Hosts & Real Time
Response scopes). Requires an OAuth2 client ID/secret with
`hosts:read` and `real-time-response:write` scopes.
"""
from __future__ import annotations
import os
import time
from typing import Any

from .base import EDRAdapter, CoverageReport

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class CrowdStrikeAdapter(EDRAdapter):
    name = "crowdstrike"

    def __init__(self, base_url: str | None = None, client_id: str | None = None,
                 client_secret: str | None = None, expected_total_hosts: int | None = None):
        self.base_url = base_url or os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")
        self.client_id = client_id or os.environ.get("FALCON_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("FALCON_CLIENT_SECRET", "")
        self.expected_total_hosts = expected_total_hosts  # from your CMDB, not Falcon itself
        self._token = None
        self._token_expiry = 0.0

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret and requests is not None)

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry:
            return self._token
        resp = requests.post(
            f"{self.base_url}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + body.get("expires_in", 1799) - 60
        return self._token

    def get_coverage_report(self) -> CoverageReport:
        if not self.is_configured():
            raise RuntimeError("CrowdStrikeAdapter not configured. Set FALCON_CLIENT_ID/FALCON_CLIENT_SECRET.")
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        resp = requests.get(f"{self.base_url}/devices/queries/devices/v1",
                             headers=headers, params={"limit": 5000}, timeout=30)
        resp.raise_for_status()
        covered_ids = resp.json().get("resources", [])
        covered = len(covered_ids)
        total = self.expected_total_hosts or covered  # without a CMDB figure, we can only report what Falcon sees
        pct = round((covered / total) * 100, 2) if total else 0.0
        return CoverageReport(
            total_hosts=total, covered_hosts=covered, coverage_pct=pct,
            uncovered_host_ids=[] if total == covered else ["<diff CMDB vs Falcon inventory to populate>"],
            detail={"falcon_device_count": covered},
        )

    def isolate_host(self, host_id: str) -> bool:
        if not self.is_configured():
            raise RuntimeError("CrowdStrikeAdapter not configured.")
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        resp = requests.post(
            f"{self.base_url}/devices/entities/devices-actions/v2",
            headers=headers, params={"action_name": "contain"},
            json={"ids": [host_id]}, timeout=30,
        )
        resp.raise_for_status()
        return resp.status_code == 202
