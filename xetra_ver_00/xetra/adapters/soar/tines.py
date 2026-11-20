"""
Tines adapter — shaped to Tines's webhook-trigger model
(https://www.tines.com/docs/, Story webhook actions). Each playbook is a
Tines Story you build; XETRA just POSTs the webhook with context and
polls Tines's Story Run API for completion status.
"""
from __future__ import annotations
import os
from typing import Any

from .base import SOARAdapter, PlaybookResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class TinesAdapter(SOARAdapter):
    name = "tines"

    def __init__(self, webhook_map: dict[str, str] | None = None, tenant_url: str | None = None,
                 api_token: str | None = None):
        self.webhook_map = webhook_map or {}
        self.tenant_url = tenant_url or os.environ.get("TINES_TENANT_URL", "")
        self.api_token = api_token or os.environ.get("TINES_API_TOKEN", "")

    def is_configured(self) -> bool:
        return bool(self.webhook_map and requests is not None)

    def trigger_playbook(self, playbook_id: str, context: dict[str, Any]) -> PlaybookResult:
        if not self.is_configured():
            raise RuntimeError(
                "TinesAdapter not configured. Build the Story in Tines, "
                "add its webhook URL to soar.tines.webhook_map[playbook_id] "
                "in config.yaml."
            )
        url = self.webhook_map.get(playbook_id)
        if not url:
            raise ValueError(f"No Tines webhook mapped for playbook {playbook_id}.")

        resp = requests.post(url, json=context, timeout=30)
        resp.raise_for_status()
        return PlaybookResult(
            playbook_id=playbook_id,
            triggered=True,
            status="pending",  # Tines Stories run async; check Story Run API for final status
            detail={"webhook_status_code": resp.status_code},
        )
