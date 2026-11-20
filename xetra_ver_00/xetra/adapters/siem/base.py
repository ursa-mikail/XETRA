"""SIEM adapter interface — confirms a technique produced an alert."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class AlertCheckResult:
    technique_id: str
    alert_found: bool
    alert_count: int
    query_used: str
    detail: dict[str, Any]


class SIEMAdapter(ABC):
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def check_alert(self, attack_id: str, time_window_minutes: int = 30) -> AlertCheckResult: ...
