"""
RESPOND — the inverse of ARTEX's lateral-movement/C2 agents.

Triggers a named SOAR playbook for each confirmed gap.

Safety: with a LIVE SOAR, playbooks like "isolate network segment" are real.
So against a live SOAR, RESPOND does nothing until a human switches
"Allow real containment playbooks" on (dashboard → Controls). Until then it
records exactly what it WOULD have triggered, so you can review it first.
Against the simulated SOAR it always runs (nothing real can happen).
"""
from __future__ import annotations
from dataclasses import dataclass

from ..adapters.soar.base import SOARAdapter
from .hunt import HuntFinding


@dataclass
class ResponseRecord:
    technique_id: str
    playbook_id: str
    triggered: bool
    status: str


PLAYBOOK_MAP = {
    "infra_network": "isolate-network-segment",
    "service": "revoke-api-key-rollback-deploy",
    "system": "force-krbtgt-reset-isolate-host",
    "protocol": "rotate-idp-signing-key-invalidate-sessions",
    "algorithm": "emergency-key-rotation-rehash",
    "software": "revoke-signing-key-halt-pipeline",
    "hardware": "physical-isolation-reflash",
}


class RespondAgent:
    def __init__(self, soar: SOARAdapter, allow_live: bool = False):
        self.soar = soar
        self.allow = allow_live or soar.name == "mock"

    def respond_to_gaps(self, findings: list[HuntFinding]) -> list[ResponseRecord]:
        records = []
        for f in findings:
            if f.status != "gap":
                continue
            playbook_id = PLAYBOOK_MAP.get(f.stratum, "generic-contain-and-notify")
            if not self.allow:
                records.append(ResponseRecord(f.technique_id, playbook_id, False, "held_awaiting_human_enable"))
                continue
            try:
                result = self.soar.trigger_playbook(playbook_id, context={
                    "technique_id": f.technique_id, "stratum": f.stratum, "finding": f.detail})
                records.append(ResponseRecord(f.technique_id, playbook_id, result.triggered, result.status))
            except Exception as e:
                records.append(ResponseRecord(f.technique_id, playbook_id, False, f"failed: {e}"))
        return records
