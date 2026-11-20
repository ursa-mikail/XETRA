"""SOAR adapter interface — triggers a RESPOND playbook, returns outcome."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class PlaybookResult:
    playbook_id: str
    triggered: bool
    status: str  # "completed" | "pending" | "failed"
    detail: dict[str, Any]


class SOARAdapter(ABC):
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def trigger_playbook(self, playbook_id: str, context: dict[str, Any]) -> PlaybookResult: ...
