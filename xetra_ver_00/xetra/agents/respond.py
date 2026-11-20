"""
RESPOND — the inverse of ARTEX's lateral-movement/C2 agents.

Turns a HUNT gap (or a live SIEM/EDR alert, in production use) into a
triggered SOAR playbook: isolate, revoke, rotate, block. RESPOND reports
what it triggered and its completion status; it does not itself decide
*whether* to respond in production — that decision is governed by your
SOAR platform's own approval gates, which you configure.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from ..adapters.soar.base import SOARAdapter
from .hunt import HuntFinding


@dataclass
class ResponseRecord:
    technique_id: str
    playbook_id: str
    triggered: bool
    status: str


_PLAYBOOK_MAP = {
    "infra_network": "isolate-network-segment",
    "service": "revoke-api-key-rollback-deploy",
    "system": "force-krbtgt-reset-isolate-host",
    "protocol": "rotate-idp-signing-key-invalidate-sessions",
    "algorithm": "emergency-key-rotation-rehash",
    "software": "revoke-signing-key-halt-pipeline",
    "hardware": "physical-isolation-reflash",
}


class RespondAgent:
    def __init__(self, soar: SOARAdapter):
        self.soar = soar

    def respond_to_gaps(self, findings: list[HuntFinding]) -> list[ResponseRecord]:
        records = []
        for f in findings:
            if not f.gap:
                continue
            playbook_id = _PLAYBOOK_MAP.get(f.stratum, "generic-contain-and-notify")
            result = self.soar.trigger_playbook(playbook_id, context={
                "technique_id": f.technique_id, "stratum": f.stratum, "finding": f.detail,
            })
            records.append(ResponseRecord(
                technique_id=f.technique_id, playbook_id=playbook_id,
                triggered=result.triggered, status=result.status,
            ))
        return records
