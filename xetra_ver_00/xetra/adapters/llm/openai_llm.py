"""
OpenAI adapter — shaped to the public Chat Completions API
(https://platform.openai.com/docs/api-reference/chat).

Same hard boundary as anthropic_llm.py: text out, never actions.

Setup:
  export OPENAI_API_KEY=sk-...
  llm:
    provider: openai
    options:
      model: "<a current model ID from https://platform.openai.com/docs/models>"
"""
from __future__ import annotations
import os
from typing import Any

from .base import LLMAdapter, DraftText

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None

_API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAILLMAdapter(LLMAdapter):
    name = "openai"

    def __init__(self, api_key: str | None = None, model: str | None = None, max_tokens: int = 500):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("OPENAI_MODEL", "")
        self.max_tokens = max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and self.model and requests is not None)

    def _call(self, prompt: str) -> str:
        if not self.is_configured():
            raise RuntimeError(
                "OpenAILLMAdapter not configured. Set OPENAI_API_KEY and "
                "llm.options.model (a current model ID from OpenAI's docs)."
            )
        resp = requests.post(
            _API_URL,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "max_tokens": self.max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        choices = resp.json().get("choices", [])
        return choices[0]["message"]["content"] if choices else ""

    def summarize_cycle(self, cycle_summary: dict[str, Any]) -> DraftText:
        prompt = (
            "Summarize this security-control validation cycle's factual results in "
            "3-4 plain-English sentences for a non-technical exec. Advisory only — "
            f"a human reviews before use. Data: {cycle_summary}"
        )
        text = self._call(prompt)
        return DraftText(text=text, provider=self.name, model=self.model)

    def draft_remediation_note(self, finding: dict[str, Any]) -> DraftText:
        prompt = (
            "Draft a one-paragraph remediation-ticket description (advisory only) "
            f"for this control-validation gap. Data: {finding}"
        )
        text = self._call(prompt)
        return DraftText(text=text, provider=self.name, model=self.model)
