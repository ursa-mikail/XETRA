"""
Palo Alto Cortex XSOAR adapter — shaped to the XSOAR REST API
(/playbook/{playbookId}/run style incident-triggered playbooks).

Setup: set XSOAR_BASE_URL + XSOAR_API_KEY, map playbook_id -> XSOAR
playbook name in config.yaml under soar.xsoar.playbook_map.
"""
from __future__ import annotations
import os
from typing import Any

from .base import SOARAdapter, PlaybookResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class XSOARAdapter(SOARAdapter):
    name = "xsoar"

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 playbook_map: dict[str, str] | None = None):
        self.base_url = base_url or os.environ.get("XSOAR_BASE_URL", "")
        self.api_key = api_key or os.environ.get("XSOAR_API_KEY", "")
        self.playbook_map = playbook_map or {}

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and requests is not None)

    def trigger_playbook(self, playbook_id: str, context: dict[str, Any]) -> PlaybookResult:
        if not self.is_configured():
            raise RuntimeError("XSOARAdapter not configured. Set XSOAR_BASE_URL and XSOAR_API_KEY.")
        xsoar_name = self.playbook_map.get(playbook_id)
        if not xsoar_name:
            raise ValueError(f"No XSOAR playbook mapped for {playbook_id}.")

        resp = requests.post(
            f"{self.base_url}/incident", headers={"Authorization": self.api_key},
            json={"name": f"XETRA-{playbook_id}", "playbookId": xsoar_name,
                  "customFields": context}, timeout=30,
        )
        resp.raise_for_status()
        return PlaybookResult(
            playbook_id=playbook_id, triggered=True, status="pending",
            detail={"xsoar_incident": resp.json()},
        )
