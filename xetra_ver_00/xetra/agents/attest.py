"""
ATTEST — turns a complete HUNT/HARDEN/RESPOND/RECOVER cycle into a
certification-ready evidence package, cross-walked to the control
frameworks in docs/CONTROL_MAPPING.md (SOC2 / ISO 27001 / PCI DSS v4.0 /
NIST CSF 2.0 / FedRAMP / NYDFS 23 NYCRR 500 / NY MTL).

This is the one place in XETRA where output is a document, not an
action — by design, consequential sign-off (accepting residual risk,
closing a finding) stays with a named human.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hunt import HuntFinding
from .harden import RemediationItem
from .respond import ResponseRecord
from .recover import RecoveryRecord
from ..adapters.llm.base import LLMAdapter


class AttestAgent:
    def __init__(self, output_dir: str = "evidence_output", llm: LLMAdapter | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Optional — see adapters/llm/base.py for the hard boundary this
        # is held to: text only, advisory only, human-reviewed only.
        self.llm = llm

    def package_cycle(
        self,
        findings: list[HuntFinding],
        remediations: list[RemediationItem],
        responses: list[ResponseRecord],
        recoveries: list[RecoveryRecord],
        cycle_label: str = "cycle",
        adapter_modes: dict[str, str] | None = None,
    ) -> Path:
        timestamp = datetime.now(timezone.utc).isoformat()
        adapter_modes = adapter_modes or {}
        # The single most important flag in this file. If ANY of the four
        # CORE categories (bas/siem/soar/edr) is mock, this cycle produced
        # no real evidence of control effectiveness. LLM is deliberately
        # excluded from this check: "none" is its normal, fully-supported
        # default (LLM is an optional advisory add-on, not a validation
        # source — see adapters/llm/base.py) and must never make an
        # otherwise-fully-live cycle incorrectly report as mock.
        _CORE_CATEGORIES = ("bas", "siem", "soar", "edr")
        core_modes = {k: v for k, v in adapter_modes.items() if k in _CORE_CATEGORIES}
        is_live = bool(core_modes) and all(v not in ("mock", "none") for v in core_modes.values())
        package: dict[str, Any] = {
            "program": "XETRA",
            "generated_at": timestamp,
            "cycle_label": cycle_label,
            "mock_mode": not is_live,
            "mock_mode_warning": (
                None if is_live else
                "AT LEAST ONE ADAPTER IS RUNNING IN MOCK MODE. This cycle's "
                "results are simulated, not real validation evidence. Do not "
                "submit this package to an auditor or treat any 'blocked'/"
                "'detected_only' outcome below as a real control confirmation. "
                "See adapter_modes for which categories are mock vs. live."
            ),
            "adapter_modes": adapter_modes,
            "summary": {
                "techniques_tested": len(findings),
                "gaps_found": sum(1 for f in findings if f.gap),
                "gaps_remediated_pending_human_approval": len(remediations),
                "responses_triggered": len(responses),
                "recoveries_validated": sum(1 for r in recoveries if not r.still_gapped),
                "recoveries_still_gapped": sum(1 for r in recoveries if r.still_gapped),
            },
            "findings": [asdict(f) for f in findings],
            "remediations": [asdict(r) for r in remediations],
            "responses": [r.__dict__ for r in responses],
            "recoveries": [r.__dict__ for r in recoveries],
            "note": (
                "This package is machine-generated evidence of a XETRA "
                "validation cycle. It is an input to your audit evidence "
                "package (see docs/CONTROL_MAPPING.md), not a substitute "
                "for auditor review or management sign-off."
            ),
        }

        if self.llm is not None:
            draft = self.llm.summarize_cycle(package["summary"])
            package["analyst_summary"] = {
                "text": draft.text,
                "provider": draft.provider,
                "model": draft.model,
                "advisory_only": draft.advisory_only,
                "disclaimer": (
                    "LLM-drafted. Not a factual source — every number here is "
                    "copied from the 'summary' block above, computed by XETRA's "
                    "agents, not the LLM. A human must review this text before "
                    "it is used in any filing, report, or remediation record."
                ),
            }
        out_path = self.output_dir / f"xetra-attest-{cycle_label}-{timestamp.replace(':', '')}.json"
        out_path.write_text(json.dumps(package, indent=2, default=str))
        return out_path
