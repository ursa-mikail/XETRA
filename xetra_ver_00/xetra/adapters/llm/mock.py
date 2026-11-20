"""Mock LLM adapter — deterministic templated text, zero API calls."""
from __future__ import annotations
from typing import Any
from .base import LLMAdapter, DraftText


class MockLLMAdapter(LLMAdapter):
    name = "mock"

    def is_configured(self) -> bool:
        return True

    def summarize_cycle(self, cycle_summary: dict[str, Any]) -> DraftText:
        s = cycle_summary
        text = (
            f"[MOCK SUMMARY] This cycle tested {s.get('techniques_tested', '?')} techniques "
            f"and found {s.get('gaps_found', '?')} gaps. "
            f"{s.get('recoveries_validated', '?')} were confirmed remediated; "
            f"{s.get('recoveries_still_gapped', '?')} remain open and need attention. "
            f"Configure a live LLM adapter for a real narrative summary."
        )
        return DraftText(text=text, provider="mock", model="mock-template-v1")

    def draft_remediation_note(self, finding: dict[str, Any]) -> DraftText:
        text = (
            f"[MOCK DRAFT] Technique {finding.get('technique_id')} in the "
            f"{finding.get('stratum')} stratum was not fully caught during validation. "
            f"Review the control responsible for this technique and confirm remediation "
            f"before closing. This is a template; configure a live LLM adapter for a "
            f"context-aware draft."
        )
        return DraftText(text=text, provider="mock", model="mock-template-v1")
