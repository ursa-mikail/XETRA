"""
Anthropic Claude adapter — shaped to the public Messages API
(https://docs.anthropic.com/en/api/messages).

Used ONLY for summarize_cycle / draft_remediation_note (see base.py for
the hard boundary: text out, never actions). Every call sends factual,
already-computed XETRA data (counts, technique IDs, stratum names) —
never raw target/credential data — and is logged for audit.

Setup:
  export ANTHROPIC_API_KEY=sk-ant-...
  llm:
    provider: anthropic
    options:
      model: "<see https://docs.anthropic.com/en/docs/about-claude/models for current model IDs>"
"""
from __future__ import annotations
import os
from typing import Any

from .base import LLMAdapter, DraftText

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None

_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class AnthropicLLMAdapter(LLMAdapter):
    name = "anthropic"

    def __init__(self, api_key: str | None = None, model: str | None = None, max_tokens: int = 500):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        # Deliberately no hardcoded default here — model IDs change; the
        # operator must choose a current one from Anthropic's docs and
        # set it explicitly, rather than XETRA silently assuming a
        # possibly-stale or possibly-wrong model string.
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "")
        self.max_tokens = max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and self.model and requests is not None)

    def _call(self, prompt: str) -> str:
        if not self.is_configured():
            raise RuntimeError(
                "AnthropicLLMAdapter not configured. Set ANTHROPIC_API_KEY and "
                "llm.options.model (a current model ID from Anthropic's docs)."
            )
        resp = requests.post(
            _API_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": _API_VERSION,
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": self.max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        blocks = resp.json().get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")

    def summarize_cycle(self, cycle_summary: dict[str, Any]) -> DraftText:
        prompt = (
            "You are drafting an advisory, human-reviewed executive summary of a "
            "security-control validation cycle (XETRA). Summarize these factual "
            "results in 3-4 plain-English sentences for a non-technical exec. "
            "Do not recommend specific remediation steps beyond noting that gaps "
            f"need review. Data: {cycle_summary}"
        )
        text = self._call(prompt)
        return DraftText(text=text, provider=self.name, model=self.model)

    def draft_remediation_note(self, finding: dict[str, Any]) -> DraftText:
        prompt = (
            "Draft a one-paragraph remediation-ticket description (advisory only, "
            "a human will edit/approve it) for this control-validation gap. State "
            "what was tested, what the expected control was, and that it wasn't "
            f"confirmed. Do not invent root cause. Data: {finding}"
        )
        text = self._call(prompt)
        return DraftText(text=text, provider=self.name, model=self.model)
