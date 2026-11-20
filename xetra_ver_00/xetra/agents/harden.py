"""
HARDEN — the inverse of ARTEX's persistence/privesc agents.

Takes HUNT's gaps and turns them into tracked remediation work. HARDEN
never auto-changes production config on its own authority — it opens
the ticket/PR and, if a ticketing integration is configured, files it;
a human approves the merge. This mirrors the program requirement (see
README) that consequential changes stay with accountable people.
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


_REMEDIATION_HINTS = {
    "infra_network": "Review perimeter/IAM config drift against CIS benchmark; close exposed admin plane.",
    "service": "Add/confirm input-validation + authz gate in CI (SAST/DAST) for the affected endpoint class.",
    "system": "Close AD attack path (PingCastle/BloodHound finding) or extend EDR coverage to gap host.",
    "protocol": "Enforce signing/relay protections (SAML signature validation, SMB signing) for the affected flow.",
    "algorithm": "Rotate/replace deprecated crypto primitive or key; re-hash affected credential store.",
    "software": "Patch/rebuild from signed artifact; add regression test covering the missed class.",
    "hardware": "Re-flash from verified firmware source or escalate to physical replacement.",
}


class HardenAgent:
    def process(self, findings: list[HuntFinding]) -> list[RemediationItem]:
        items = []
        for f in findings:
            if f.gap:
                items.append(RemediationItem(
                    technique_id=f.technique_id,
                    stratum=f.stratum,
                    recommended_action=_REMEDIATION_HINTS.get(f.stratum, "Review finding and remediate."),
                ))
        return items
