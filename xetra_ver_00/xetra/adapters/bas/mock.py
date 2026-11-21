"""
Mock BAS adapter. Default when no vendor is configured.

Outcomes are a pure function of the technique ID (hash), so the same
technique gives the same answer every run — a demo you can reason about.
A technique a human has marked fixed (dashboard → Fix list → "Approve",
mock mode only) flips to "blocked", so you can watch the full
find → decide → retest → verified loop without any real system.
"""
from __future__ import annotations
import hashlib
import os
import time
from typing import Any

from .base import BASAdapter, ScenarioResult


def _bucket(key: str) -> float:
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF


class MockBASAdapter(BASAdapter):
    name = "mock"

    def __init__(self, seed: int | None = None):
        self.fixed: set[str] = set()   # injected by the orchestrator from the state store

    def is_configured(self) -> bool:
        return True

    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        started = self._now()
        # Simulated work time so a run is watchable (progress, Stop). Set XETRA_MOCK_DELAY_MS=0 for instant.
        time.sleep(int(os.environ.get("XETRA_MOCK_DELAY_MS", "25")) / 1000)
        if attack_id in self.fixed:
            outcome = "blocked"
        else:
            b = _bucket("bas:" + attack_id)
            outcome = "blocked" if b < 0.62 else "detected_only" if b < 0.90 else "undetected"
        return ScenarioResult(
            technique_id=attack_id, scenario_ref=f"mock-scenario::{attack_id}",
            started_at=started, finished_at=self._now(), executed=True, outcome=outcome,
            detail={"note": "SIMULATED RESULT — not a real test."},
        )
