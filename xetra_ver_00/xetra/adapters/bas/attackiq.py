"""
AttackIQ adapter — shaped to AttackIQ's public REST API
(https://docs.attackiq.com/ — Assessment / Test / Result endpoints).

This is a *stub*: the request/response shape matches AttackIQ's documented
API, but it requires your own API token and an Assessment already built
in your AttackIQ tenant (AttackIQ's platform owns the actual scenario
logic — this file only asks it to run and polls for a result). It raises
clearly if credentials are missing rather than silently doing nothing or
falling back to attack logic of its own. There is none here to fall back
to.

Setup:
  1. License AttackIQ (they offer a free Community Edition tier).
  2. Build an Assessment in their console scoped to your authorized
     targets, mapped to the ATT&CK technique IDs in ttp_library/artex_ttps.yaml.
  3. Set ATTACKIQ_API_TOKEN and ATTACKIQ_BASE_URL in your environment or
     config/config.yaml.
"""

from __future__ import annotations
import os
from typing import Any

from .base import BASAdapter, ScenarioResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class AttackIQAdapter(BASAdapter):
    name = "attackiq"

    def __init__(self, base_url: str | None = None, api_token: str | None = None):
        self.base_url = base_url or os.environ.get("ATTACKIQ_BASE_URL", "")
        self.api_token = api_token or os.environ.get("ATTACKIQ_API_TOKEN", "")

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_token and requests is not None)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.api_token}", "Content-Type": "application/json"}

    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        if not self.is_configured():
            raise RuntimeError(
                "AttackIQAdapter not configured. Set ATTACKIQ_BASE_URL and "
                "ATTACKIQ_API_TOKEN, and ensure `requests` is installed. "
                "XETRA will not simulate a live result on your behalf — "
                "use MockBASAdapter for development instead."
            )
        started = self._now()

        # AttackIQ assessments are run by assessment ID, not raw ATT&CK ID;
        # scope must map attack_id -> the assessment/test you built for it.
        assessment_id = scope.get("attackiq_assessment_map", {}).get(attack_id)
        if not assessment_id:
            raise ValueError(
                f"No AttackIQ assessment mapped for {attack_id}. "
                f"Add it to scope['attackiq_assessment_map'] in your config."
            )

        run_resp = requests.post(
            f"{self.base_url}/v1/assessments/{assessment_id}/run/",
            headers=self._headers(),
            timeout=30,
        )
        run_resp.raise_for_status()
        run_id = run_resp.json().get("id")

        result_resp = requests.get(
            f"{self.base_url}/v1/assessments/{assessment_id}/runs/{run_id}/results/",
            headers=self._headers(),
            timeout=30,
        )
        result_resp.raise_for_status()
        payload = result_resp.json()

        outcome = _map_attackiq_outcome(payload.get("outcome", "unknown"))
        finished = self._now()
        return ScenarioResult(
            technique_id=attack_id,
            scenario_ref=f"attackiq::assessment={assessment_id}::run={run_id}",
            started_at=started,
            finished_at=finished,
            executed=True,
            outcome=outcome,
            detail=payload,
        )


def _map_attackiq_outcome(aiq_outcome: str) -> str:
    table = {
        "prevented": "blocked",
        "detected": "detected_only",
        "missed": "undetected",
    }
    return table.get(aiq_outcome.lower(), "error")
