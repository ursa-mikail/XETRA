"""
SafeBreach adapter — shaped to the SafeBreach Public API
(https://developer.safebreach.com/ — /api/data/v1/test and
/api/data/v1/simulation endpoints). Requires an authorized SafeBreach
account and simulator deployment; SafeBreach's platform owns all attack
logic, selected by "moves"/attack IDs you map to ATT&CK IDs.

Setup: set SAFEBREACH_BASE_URL and SAFEBREACH_API_KEY, map attack_id ->
SafeBreach move/attack ID in config.yaml under scope.safebreach_move_map.
"""
from __future__ import annotations
import os
from typing import Any

from .base import BASAdapter, ScenarioResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class SafeBreachAdapter(BASAdapter):
    name = "safebreach"

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = base_url or os.environ.get("SAFEBREACH_BASE_URL", "")
        self.api_key = api_key or os.environ.get("SAFEBREACH_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and requests is not None)

    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        if not self.is_configured():
            raise RuntimeError(
                "SafeBreachAdapter not configured. Set SAFEBREACH_BASE_URL "
                "and SAFEBREACH_API_KEY, and map this technique in "
                "scope['safebreach_move_map']."
            )
        move_id = scope.get("safebreach_move_map", {}).get(attack_id)
        if not move_id:
            raise ValueError(f"No SafeBreach move mapped for {attack_id}.")

        started = self._now()
        headers = {"x-apitoken": self.api_key}
        run = requests.post(f"{self.base_url}/api/data/v1/simulation",
                             headers=headers, json={"moveId": move_id}, timeout=30)
        run.raise_for_status()
        payload = run.json()
        outcome = _map_sb_outcome(payload.get("status", "unknown"))
        return ScenarioResult(
            technique_id=attack_id, scenario_ref=f"safebreach::move={move_id}",
            started_at=started, finished_at=self._now(), executed=True,
            outcome=outcome, detail=payload,
        )


def _map_sb_outcome(v: str) -> str:
    return {"prevented": "blocked", "detected": "detected_only", "missed": "undetected"}.get(v.lower(), "error")
