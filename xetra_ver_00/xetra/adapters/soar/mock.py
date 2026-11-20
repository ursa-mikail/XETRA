"""Mock SOAR adapter."""
from __future__ import annotations
from .base import SOARAdapter, PlaybookResult


class MockSOARAdapter(SOARAdapter):
    name = "mock"

    def is_configured(self) -> bool:
        return True

    def trigger_playbook(self, playbook_id: str, context: dict) -> PlaybookResult:
        return PlaybookResult(
            playbook_id=playbook_id,
            triggered=True,
            status="completed",
            detail={"note": "MOCK — simulated playbook run.", "context": context},
        )
