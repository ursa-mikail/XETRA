"""
Microsoft Sentinel adapter — shaped to the Log Analytics Query API
(https://learn.microsoft.com/azure/azure-monitor/logs/api/overview),
run via KQL against your Sentinel workspace.

Setup: set SENTINEL_WORKSPACE_ID + an Azure AD app token (AZURE_TOKEN),
map attack_id -> KQL query in config.yaml under siem.sentinel.query_map.
"""
from __future__ import annotations
import os
from typing import Any

from .base import SIEMAdapter, AlertCheckResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class SentinelAdapter(SIEMAdapter):
    name = "sentinel"

    def __init__(self, workspace_id: str | None = None, token: str | None = None,
                 query_map: dict[str, str] | None = None):
        self.workspace_id = workspace_id or os.environ.get("SENTINEL_WORKSPACE_ID", "")
        self.token = token or os.environ.get("AZURE_TOKEN", "")
        self.query_map = query_map or {}

    def is_configured(self) -> bool:
        return bool(self.workspace_id and self.token and requests is not None)

    def check_alert(self, attack_id: str, time_window_minutes: int = 30) -> AlertCheckResult:
        if not self.is_configured():
            raise RuntimeError(
                "SentinelAdapter not configured. Set SENTINEL_WORKSPACE_ID "
                "and AZURE_TOKEN, and provide a KQL query_map entry."
            )
        kql = self.query_map.get(attack_id)
        if not kql:
            raise ValueError(f"No KQL query mapped for {attack_id}.")

        full_query = f"{kql} | where TimeGenerated > ago({time_window_minutes}m)"
        resp = requests.post(
            f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"query": full_query}, timeout=30,
        )
        resp.raise_for_status()
        tables = resp.json().get("tables", [{}])
        rows = tables[0].get("rows", []) if tables else []
        return AlertCheckResult(
            technique_id=attack_id, alert_found=len(rows) > 0, alert_count=len(rows),
            query_used=full_query, detail={"rows": rows[:5]},
        )
