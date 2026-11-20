"""
Mock BAS adapter. Default adapter when no vendor is configured.

Simulates scenario execution deterministically so the orchestrator,
HUNT loop, and evidence packaging can be developed, tested, and demoed
with zero external dependencies and zero risk. Swap in a real adapter
(attackiq.py, etc.) only once you've licensed that platform and defined
an authorized scope.
"""

from __future__ import annotations
import random
from typing import Any

from .base import BASAdapter, ScenarioResult


class MockBASAdapter(BASAdapter):
    name = "mock"

    def __init__(self, seed: int | None = 42):
        self._rng = random.Random(seed)

    def is_configured(self) -> bool:
        return True  # mock is always "ready"

    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        started = self._now()
        # Deterministic-but-varied simulated outcome, biased toward "blocked"
        # to represent a maturing program; real results come from your
        # licensed platform once wired in.
        outcome = self._rng.choices(
            ["blocked", "detected_only", "undetected"],
            weights=[0.6, 0.3, 0.1],
        )[0]
        finished = self._now()
        return ScenarioResult(
            technique_id=attack_id,
            scenario_ref=f"mock-scenario::{attack_id}",
            started_at=started,
            finished_at=finished,
            executed=True,
            outcome=outcome,
            detail={"note": "MOCK RESULT — not a real test. Configure a live adapter for real evidence.", "scope": scope},
        )
