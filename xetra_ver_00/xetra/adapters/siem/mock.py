"""Mock SIEM adapter — deterministic simulated alert lookups."""
from __future__ import annotations
import random
from .base import SIEMAdapter, AlertCheckResult


class MockSIEMAdapter(SIEMAdapter):
    name = "mock"

    def __init__(self, seed: int | None = 7):
        self._rng = random.Random(seed)

    def is_configured(self) -> bool:
        return True

    def check_alert(self, attack_id: str, time_window_minutes: int = 30) -> AlertCheckResult:
        found = self._rng.random() < 0.75
        return AlertCheckResult(
            technique_id=attack_id,
            alert_found=found,
            alert_count=self._rng.randint(1, 4) if found else 0,
            query_used=f"mock-query for {attack_id} (last {time_window_minutes}m)",
            detail={"note": "MOCK RESULT — configure a live SIEM adapter for real evidence."},
        )
