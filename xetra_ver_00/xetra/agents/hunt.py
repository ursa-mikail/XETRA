"""
HUNT — the inverse of ARTEX's recon/exploit agents.

For every technique in the TTP library, HUNT asks the configured BAS
adapter to run the vendor's own safe emulation scenario, then asks the
SIEM adapter whether it alerted. The result is the ground truth XETRA
builds every other decision on.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

from ..adapters.bas.base import BASAdapter
from ..adapters.siem.base import SIEMAdapter


@dataclass
class HuntFinding:
    technique_id: str
    stratum: str
    bas_outcome: str
    siem_alerted: bool
    gap: bool  # True if the technique ran and was NOT caught
    detail: dict[str, Any]


class HuntAgent:
    def __init__(self, bas: BASAdapter, siem: SIEMAdapter):
        self.bas = bas
        self.siem = siem

    def run_one(self, ttp: dict, scope: dict) -> list[HuntFinding]:
        findings = []
        for attack_id in ttp["attack_ids"]:
            bas_result = self.bas.run_technique(attack_id, scope)
            siem_result = self.siem.check_alert(attack_id)
            gap = bas_result.outcome in ("undetected", "error") or not siem_result.alert_found
            findings.append(HuntFinding(
                technique_id=attack_id,
                stratum=ttp["stratum"],
                bas_outcome=bas_result.outcome,
                siem_alerted=siem_result.alert_found,
                gap=gap,
                detail={"bas": asdict(bas_result), "siem": asdict(siem_result)},
            ))
        return findings

    def run_all(self, ttp_library: list[dict], scope: dict) -> list[HuntFinding]:
        out: list[HuntFinding] = []
        for ttp in ttp_library:
            out.extend(self.run_one(ttp, scope))
        return out
