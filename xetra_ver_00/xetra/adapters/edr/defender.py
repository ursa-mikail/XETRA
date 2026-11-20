"""
Microsoft Defender for Endpoint adapter — shaped to the Microsoft
Defender for Endpoint API (/api/machines, /api/machines/{id}/isolate).

Setup: set DEFENDER_TOKEN (Azure AD app token with Machine.Isolate +
Machine.Read.All) and optionally DEFENDER_EXPECTED_TOTAL_HOSTS from
your CMDB.
"""
from __future__ import annotations
import os
from typing import Any

from .base import EDRAdapter, CoverageReport

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class DefenderAdapter(EDRAdapter):
    name = "defender"

    def __init__(self, token: str | None = None, expected_total_hosts: int | None = None):
        self.token = token or os.environ.get("DEFENDER_TOKEN", "")
        self.expected_total_hosts = expected_total_hosts

    def is_configured(self) -> bool:
        return bool(self.token and requests is not None)

    def get_coverage_report(self) -> CoverageReport:
        if not self.is_configured():
            raise RuntimeError("DefenderAdapter not configured. Set DEFENDER_TOKEN.")
        resp = requests.get("https://api.securitycenter.microsoft.com/api/machines",
                             headers={"Authorization": f"Bearer {self.token}"}, timeout=30)
        resp.raise_for_status()
        machines = resp.json().get("value", [])
        covered = len(machines)
        total = self.expected_total_hosts or covered
        pct = round((covered / total) * 100, 2) if total else 0.0
        return CoverageReport(
            total_hosts=total, covered_hosts=covered, coverage_pct=pct,
            uncovered_host_ids=[] if total == covered else ["<diff CMDB vs Defender inventory>"],
            detail={"defender_machine_count": covered},
        )

    def isolate_host(self, host_id: str) -> bool:
        if not self.is_configured():
            raise RuntimeError("DefenderAdapter not configured.")
        resp = requests.post(
            f"https://api.securitycenter.microsoft.com/api/machines/{host_id}/isolate",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"Comment": "XETRA automated containment", "IsolationType": "Full"}, timeout=30,
        )
        resp.raise_for_status()
        return resp.status_code in (200, 201)
