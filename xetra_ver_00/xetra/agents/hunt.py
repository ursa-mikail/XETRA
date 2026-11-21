"""
HUNT — the inverse of ARTEX's recon/exploit agents.

For every technique, ask the BAS adapter to run the vendor's own safe
emulation scenario, then ask the SIEM whether it alerted.

Each finding has one of three statuses — and the difference matters for
evidence:
  caught      the technique ran and your controls blocked or alerted on it
  gap         the technique ran and nothing caught it            (real finding)
  not_tested  XETRA could not run it (missing mapping, vendor error)
              This is NOT a pass and NOT a gap: it is "unknown". It is never
              counted as coverage, and never triggers containment.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Callable

from ..adapters.bas.base import BASAdapter
from ..adapters.siem.base import SIEMAdapter


class RunCancelled(Exception):
    pass


@dataclass
class HuntFinding:
    technique_id: str
    stratum: str
    bas_outcome: str
    siem_alerted: bool
    gap: bool            # True only for status == "gap"
    detail: dict[str, Any]
    status: str = "caught"   # caught | gap | not_tested


class HuntAgent:
    def __init__(self, bas: BASAdapter, siem: SIEMAdapter):
        self.bas = bas
        self.siem = siem

    def run_technique(self, attack_id: str, stratum: str, scope: dict) -> HuntFinding:
        try:
            bas_result = self.bas.run_technique(attack_id, scope)
            siem_result = self.siem.check_alert(attack_id)
        except Exception as e:  # one broken mapping must not sink the whole run
            return HuntFinding(attack_id, stratum, "error", False, False,
                               {"error": f"{type(e).__name__}: {e}"}, status="not_tested")
        if bas_result.outcome == "error":
            return HuntFinding(attack_id, stratum, "error", siem_result.alert_found, False,
                               {"bas": asdict(bas_result), "siem": asdict(siem_result)}, status="not_tested")
        gap = bas_result.outcome == "undetected" or not siem_result.alert_found
        return HuntFinding(attack_id, stratum, bas_result.outcome, siem_result.alert_found, gap,
                           {"bas": asdict(bas_result), "siem": asdict(siem_result)},
                           status="gap" if gap else "caught")

    def run_one(self, ttp: dict, scope: dict) -> list[HuntFinding]:
        return [self.run_technique(a, ttp["stratum"], scope) for a in ttp["attack_ids"]]

    def run_all(self, ttp_library: list[dict], scope: dict,
                on_result: Callable[[HuntFinding, int, int], None] | None = None,
                should_cancel: Callable[[], bool] | None = None) -> list[HuntFinding]:
        total = sum(len(t["attack_ids"]) for t in ttp_library)
        out: list[HuntFinding] = []
        for ttp in ttp_library:
            for attack_id in ttp["attack_ids"]:
                if should_cancel and should_cancel():
                    raise RunCancelled()
                f = self.run_technique(attack_id, ttp["stratum"], scope)
                out.append(f)
                if on_result:
                    on_result(f, len(out), total)
        return out
