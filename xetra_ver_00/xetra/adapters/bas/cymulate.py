"""
Cymulate adapter — shaped to the Cymulate API
(https://api.cymulate.com/ — /v1/attack-simulations endpoints).
Requires a licensed Cymulate tenant and pre-built "attack" templates;
Cymulate's platform owns all attack logic.

Setup: set CYMULATE_BASE_URL and CYMULATE_API_KEY, map attack_id ->
Cymulate attack-template ID in config.yaml under scope.cymulate_attack_map.
"""
from __future__ import annotations
import os
from typing import Any

from .base import BASAdapter, ScenarioResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class CymulateAdapter(BASAdapter):
    name = "cymulate"

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = base_url or os.environ.get("CYMULATE_BASE_URL", "https://api.cymulate.com")
        self.api_key = api_key or os.environ.get("CYMULATE_API_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.api_key and requests is not None)

    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        if not self.is_configured():
            raise RuntimeError(
                "CymulateAdapter not configured. Set CYMULATE_API_KEY, "
                "and map this technique in scope['cymulate_attack_map']."
            )
        template_id = scope.get("cymulate_attack_map", {}).get(attack_id)
        if not template_id:
            raise ValueError(f"No Cymulate attack template mapped for {attack_id}.")

        started = self._now()
        headers = {"x-token": self.api_key}
        run = requests.post(f"{self.base_url}/v1/attack-simulations/{template_id}/run",
                             headers=headers, timeout=30)
        run.raise_for_status()
        payload = run.json()
        outcome = _map_cym_outcome(payload.get("result", "unknown"))
        return ScenarioResult(
            technique_id=attack_id, scenario_ref=f"cymulate::template={template_id}",
            started_at=started, finished_at=self._now(), executed=True,
            outcome=outcome, detail=payload,
        )


def _map_cym_outcome(v: str) -> str:
    return {"blocked": "blocked", "detected": "detected_only", "not detected": "undetected"}.get(v.lower(), "error")
