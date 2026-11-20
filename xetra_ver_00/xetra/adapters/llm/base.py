"""
LLM adapter interface — the ONE place in XETRA an LLM may appear, and
only for text generation that a human reviews before it's acted on.

Hard boundary, enforced by design, not just convention:
  - LLM output is NEVER passed to HUNT (what to test), HARDEN (what to
    change), RESPOND (what playbook to trigger), or RECOVER (what to
    re-validate). Those decisions come only from the TTP library and
    your adapters' factual results.
  - LLM output only ever lands in ATTEST's evidence package as an
    `analyst_summary` field, clearly labeled as LLM-drafted, advisory,
    and requiring human sign-off before use in a filing or remediation.
  - No LLM call can trigger an action. There is no code path from any
    method on this interface back into RespondAgent, HardenAgent, or
    any adapter that mutates state.
This is the structural inverse of ARTEX's own LLM usage: ARTEX's LLM
calls choose the next attack step; XETRA's LLM calls only ever draft
a sentence a human then reads.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class DraftText:
    text: str
    provider: str
    model: str
    advisory_only: bool = True  # always True; present so it's impossible to miss in a dump


class LLMAdapter(ABC):
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def summarize_cycle(self, cycle_summary: dict[str, Any]) -> DraftText:
        """Plain-English executive summary of one HUNT/HARDEN/RESPOND/RECOVER cycle."""

    @abstractmethod
    def draft_remediation_note(self, finding: dict[str, Any]) -> DraftText:
        """Draft (not finalize) a ticket description for one gap finding."""
