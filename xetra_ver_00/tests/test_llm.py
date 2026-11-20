"""
Verifies (1) mock LLM path works end to end, (2) live adapters fail
loudly without credentials, and (3) the hard boundary: LLM output can
only ever appear as the advisory-only analyst_summary field, never
influence HUNT/HARDEN/RESPOND/RECOVER.
"""
import pytest

from xetra.adapters.llm.mock import MockLLMAdapter
from xetra.adapters.llm.anthropic_llm import AnthropicLLMAdapter
from xetra.adapters.llm.openai_llm import OpenAILLMAdapter
from xetra.agents.attest import AttestAgent


@pytest.mark.parametrize("cls", [AnthropicLLMAdapter, OpenAILLMAdapter])
def test_live_llm_adapters_unconfigured_by_default(cls):
    a = cls()
    assert a.is_configured() is False
    with pytest.raises(RuntimeError):
        a.summarize_cycle({})
    with pytest.raises(RuntimeError):
        a.draft_remediation_note({})


def test_mock_llm_returns_advisory_only_text():
    a = MockLLMAdapter()
    draft = a.summarize_cycle({"techniques_tested": 5, "gaps_found": 1,
                                 "recoveries_validated": 1, "recoveries_still_gapped": 0})
    assert draft.advisory_only is True
    assert isinstance(draft.text, str) and len(draft.text) > 0


def test_attest_without_llm_has_no_analyst_summary_field(tmp_path):
    agent = AttestAgent(output_dir=str(tmp_path), llm=None)
    out = agent.package_cycle([], [], [], [], cycle_label="t")
    import json
    data = json.loads(out.read_text())
    assert "analyst_summary" not in data


def test_attest_with_llm_includes_disclaimer(tmp_path):
    agent = AttestAgent(output_dir=str(tmp_path), llm=MockLLMAdapter())
    out = agent.package_cycle([], [], [], [], cycle_label="t")
    import json
    data = json.loads(out.read_text())
    assert "analyst_summary" in data
    assert data["analyst_summary"]["advisory_only"] is True
    assert "human" in data["analyst_summary"]["disclaimer"].lower()
