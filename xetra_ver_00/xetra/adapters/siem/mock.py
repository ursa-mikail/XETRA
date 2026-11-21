"""Mock SIEM adapter — deterministic simulated alert lookups."""
from __future__ import annotations
from .base import SIEMAdapter, AlertCheckResult
from ..bas.mock import _bucket


class MockSIEMAdapter(SIEMAdapter):
    name = "mock"

    def __init__(self, seed: int | None = None):
        self.fixed: set[str] = set()

    def is_configured(self) -> bool:
        return True

    def check_alert(self, attack_id: str, time_window_minutes: int = 30) -> AlertCheckResult:
        found = attack_id in self.fixed or _bucket("siem:" + attack_id) < 0.92
        return AlertCheckResult(
            technique_id=attack_id, alert_found=found,
            alert_count=1 + int(_bucket("n:" + attack_id) * 3) if found else 0,
            query_used=f"simulated query for {attack_id} (last {time_window_minutes}m)",
            detail={"note": "SIMULATED RESULT — configure a live SIEM for real evidence."},
        )
