"""EDR adapter interface — used by HARDEN for coverage checks and by
RECOVER for host isolation/re-provision confirmation."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class CoverageReport:
    total_hosts: int
    covered_hosts: int
    coverage_pct: float
    uncovered_host_ids: list[str]
    detail: dict[str, Any]


class EDRAdapter(ABC):
    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def get_coverage_report(self) -> CoverageReport: ...

    @abstractmethod
    def isolate_host(self, host_id: str) -> bool: ...
