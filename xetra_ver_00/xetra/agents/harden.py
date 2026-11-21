"""
HARDEN — the inverse of ARTEX's persistence/privesc agents.

Turns HUNT's gaps into tracked remediation work. HARDEN never changes
production config on its own authority: every item needs a named human to
approve it in the dashboard (Fix list), and that decision is recorded.
"""
from __future__ import annotations
from dataclasses import dataclass
from .hunt import HuntFinding


@dataclass
class RemediationItem:
    technique_id: str
    stratum: str
    recommended_action: str
    requires_human_approval: bool = True


REMEDIATION_HINTS = {
    "infra_network": "Review perimeter/IAM config drift against the CIS benchmark; close the exposed admin plane.",
    "service": "Add or confirm an input-validation + authorization gate in CI (SAST/DAST) for the affected endpoint class.",
    "system": "Close the AD attack path (PingCastle/BloodHound finding) or extend EDR coverage to the uncovered host.",
    "protocol": "Enforce signing/relay protections (SAML signature validation, SMB signing) for the affected flow.",
    "algorithm": "Rotate or replace the deprecated crypto primitive or key; re-hash the affected credential store.",
    "software": "Patch or rebuild from a signed artifact; add a regression test covering the missed class.",
    "hardware": "Re-flash from verified firmware source or escalate to physical replacement.",
}


def hint_for(stratum: str) -> str:
    return REMEDIATION_HINTS.get(stratum, "Review the finding and remediate.")


class HardenAgent:
    def process(self, findings: list[HuntFinding]) -> list[RemediationItem]:
        return [RemediationItem(f.technique_id, f.stratum, hint_for(f.stratum))
                for f in findings if f.status == "gap"]
