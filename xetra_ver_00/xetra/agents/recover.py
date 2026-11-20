"""
RECOVER — the inverse of ARTEX's collection/exfil agents.

After RESPOND contains an issue, RECOVER validates restoration: that the
affected host/service is back to a known-good state, and re-runs HUNT
against just that technique to confirm the gap is actually closed before
declaring the cycle complete.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from ..adapters.edr.base import EDRAdapter
from .hunt import HuntAgent, HuntFinding


@dataclass
class RecoveryRecord:
    technique_id: str
    re_validated: bool
    still_gapped: bool
    detail: dict[str, Any]


class RecoverAgent:
    def __init__(self, hunt_agent: HuntAgent, edr: EDRAdapter | None = None):
        self.hunt_agent = hunt_agent
        self.edr = edr

    def confirm_host_isolated(self, host_id: str) -> bool:
        if self.edr is None:
            return True  # nothing to confirm if no EDR configured
        return self.edr.isolate_host(host_id)

    def re_validate(self, original_finding: HuntFinding, ttp: dict, scope: dict) -> RecoveryRecord:
        retest = self.hunt_agent.run_one(ttp, scope)
        matching = [r for r in retest if r.technique_id == original_finding.technique_id]
        still_gapped = any(r.gap for r in matching)
        return RecoveryRecord(
            technique_id=original_finding.technique_id,
            re_validated=True,
            still_gapped=still_gapped,
            detail={"retest_results": [r.__dict__ for r in matching]},
        )
