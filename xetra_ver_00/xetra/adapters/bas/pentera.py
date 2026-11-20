"""
Pentera adapter — shaped to Pentera's RankedVC API
(https://kb.pentera.io/ — Pentera exposes a REST API for triggering
"Action" runs within a licensed, scoped Pentera node). This stub asks
Pentera to execute the action mapped to an ATT&CK ID in your Pentera
console and polls for its verdict; Pentera's platform owns all
emulation logic.

Setup:
  1. License Pentera, deploy a Pentera node against your authorized scope.
  2. In the Pentera console, note the Action ID for each ATT&CK technique
     you want XETRA to validate.
  3. Set PENTERA_BASE_URL and PENTERA_API_KEY; map attack_id -> action_id
     in config.yaml under scope.pentera_action_map.
"""
from __future__ import annotations
import os
from typing import Any

from .base import BASAdapter, ScenarioResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class PenteraAdapter(BASAdapter):
    name = "pentera"

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = base_url or os.environ.get("PENTERA_BASE_URL", "")
        self.api_key = api_key or os.environ.get("PENTERA_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and requests is not None)

    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        if not self.is_configured():
            raise RuntimeError(
                "PenteraAdapter not configured. Set PENTERA_BASE_URL and "
                "PENTERA_API_KEY, and map this technique in "
                "scope['pentera_action_map']."
            )
        action_id = scope.get("pentera_action_map", {}).get(attack_id)
        if not action_id:
            raise ValueError(f"No Pentera action mapped for {attack_id}.")

        started = self._now()
        headers = {"Authorization": f"Bearer {self.api_key}"}
        run = requests.post(f"{self.base_url}/api/v1/actions/{action_id}/execute",
                             headers=headers, timeout=30)
        run.raise_for_status()
        exec_id = run.json().get("executionId")

        verdict = requests.get(f"{self.base_url}/api/v1/executions/{exec_id}/verdict",
                                headers=headers, timeout=30)
        verdict.raise_for_status()
        payload = verdict.json()
        outcome = _map_pentera_outcome(payload.get("verdict", "unknown"))
        return ScenarioResult(
            technique_id=attack_id, scenario_ref=f"pentera::action={action_id}::exec={exec_id}",
            started_at=started, finished_at=self._now(), executed=True,
            outcome=outcome, detail=payload,
        )


def _map_pentera_outcome(v: str) -> str:
    return {"blocked": "blocked", "alerted": "detected_only", "succeeded": "undetected"}.get(v.lower(), "error")
