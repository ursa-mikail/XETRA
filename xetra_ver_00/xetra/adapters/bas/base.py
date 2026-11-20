"""
Breach-and-Attack-Simulation adapter interface.

A BAS adapter's only job: given an ATT&CK technique ID and an authorized
scope, ask a *licensed* platform to run the safe emulation module it
already owns for that technique, and return whether it ran and what
happened. XETRA never implements technique-level exploitation logic —
that logic lives inside the licensed BAS product, which is built,
tested, and supported specifically to run it safely against your own
environment within scope you define.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ScenarioResult:
    technique_id: str
    scenario_ref: str
    started_at: str
    finished_at: str
    executed: bool
    outcome: str  # "blocked" | "detected_only" | "undetected" | "error"
    detail: dict[str, Any] = field(default_factory=dict)


class BASAdapter(ABC):
    """Implement this against a specific vendor's API to go live."""

    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True only if real credentials/scope are present."""

    @abstractmethod
    def run_technique(self, attack_id: str, scope: dict[str, Any]) -> ScenarioResult:
        """Request the vendor platform run its scenario for attack_id."""

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
