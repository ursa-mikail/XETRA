"""
RECOVER — the inverse of ARTEX's collection/exfil agents.

Re-runs HUNT against each gapped technique to confirm whether the gap is
actually closed. It reports what it saw; it never declares success on its
own authority.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from .hunt import HuntAgent, HuntFinding


@dataclass
class RecoveryRecord:
    technique_id: str
    re_validated: bool
    still_gapped: bool
    detail: dict[str, Any]


class RecoverAgent:
    def __init__(self, hunt_agent: HuntAgent, edr=None):
        self.hunt_agent = hunt_agent
        self.edr = edr

    def re_validate(self, original: HuntFinding, scope: dict) -> RecoveryRecord:
        retest = self.hunt_agent.run_technique(original.technique_id, original.stratum, scope)
        return RecoveryRecord(
            technique_id=original.technique_id,
            re_validated=retest.status != "not_tested",
            still_gapped=retest.status != "caught",
            detail={"retest": retest.__dict__},
        )
