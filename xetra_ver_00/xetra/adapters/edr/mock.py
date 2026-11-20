"""Mock EDR adapter."""
from __future__ import annotations
from .base import EDRAdapter, CoverageReport


class MockEDRAdapter(EDRAdapter):
    name = "mock"

    def is_configured(self) -> bool:
        return True

    def get_coverage_report(self) -> CoverageReport:
        return CoverageReport(
            total_hosts=100, covered_hosts=94, coverage_pct=94.0,
            uncovered_host_ids=["mock-host-07", "mock-host-33", "mock-host-81",
                                 "mock-host-12", "mock-host-55", "mock-host-66"],
            detail={"note": "MOCK — configure a live EDR adapter for real coverage data."},
        )

    def isolate_host(self, host_id: str) -> bool:
        return True  # simulated
