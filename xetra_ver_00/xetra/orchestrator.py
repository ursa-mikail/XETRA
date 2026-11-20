"""
XETRA Orchestrator — wires a config into the five agents and runs one
full validation cycle: HUNT -> HARDEN -> RESPOND (on gaps) -> RECOVER
(re-validate) -> ATTEST (package evidence).

Adapter selection defaults to mock everywhere. Nothing here will touch
a real system unless you explicitly configure a live adapter with real
credentials and an authorized scope in config/config.yaml.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Any

import yaml

from .adapters.bas.mock import MockBASAdapter
from .adapters.bas.attackiq import AttackIQAdapter
from .adapters.bas.pentera import PenteraAdapter
from .adapters.bas.safebreach import SafeBreachAdapter
from .adapters.bas.cymulate import CymulateAdapter
from .adapters.siem.mock import MockSIEMAdapter
from .adapters.siem.splunk import SplunkAdapter
from .adapters.siem.sentinel import SentinelAdapter
from .adapters.siem.elastic import ElasticAdapter
from .adapters.soar.mock import MockSOARAdapter
from .adapters.soar.tines import TinesAdapter
from .adapters.soar.xsoar import XSOARAdapter
from .adapters.edr.mock import MockEDRAdapter
from .adapters.edr.crowdstrike import CrowdStrikeAdapter
from .adapters.edr.defender import DefenderAdapter
from .adapters.llm.mock import MockLLMAdapter
from .adapters.llm.anthropic_llm import AnthropicLLMAdapter
from .adapters.llm.openai_llm import OpenAILLMAdapter

from .agents.hunt import HuntAgent
from .agents.harden import HardenAgent
from .agents.respond import RespondAgent
from .agents.recover import RecoverAgent
from .agents.attest import AttestAgent

log = logging.getLogger("xetra")

_BAS_ADAPTERS = {
    "mock": MockBASAdapter, "attackiq": AttackIQAdapter,
    "pentera": PenteraAdapter, "safebreach": SafeBreachAdapter, "cymulate": CymulateAdapter,
}
_SIEM_ADAPTERS = {
    "mock": MockSIEMAdapter, "splunk": SplunkAdapter,
    "sentinel": SentinelAdapter, "elastic": ElasticAdapter,
}
_SOAR_ADAPTERS = {"mock": MockSOARAdapter, "tines": TinesAdapter, "xsoar": XSOARAdapter}
_EDR_ADAPTERS = {"mock": MockEDRAdapter, "crowdstrike": CrowdStrikeAdapter, "defender": DefenderAdapter}
# "none" disables LLM use entirely — ATTEST then emits no analyst_summary
# field at all, which is the default (see config.example.yaml).
_LLM_ADAPTERS = {"mock": MockLLMAdapter, "anthropic": AnthropicLLMAdapter, "openai": OpenAILLMAdapter}


def load_config(path: str) -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f)


def load_ttp_library(path: str) -> list[dict]:
    with open(path) as f:
        return yaml.safe_load(f)


def _build_adapter(kind: str, registry: dict, cfg: dict):
    adapter_cls = registry.get(kind, next(iter(registry.values())))
    if kind == "mock" or adapter_cls is None:
        return registry["mock"]()
    try:
        return adapter_cls(**cfg)
    except TypeError:
        return adapter_cls()


class XetraOrchestrator:
    def __init__(self, config_path: str, ttp_library_paths: list[str] | None = None):
        self.config = load_config(config_path)
        lib_dir = Path(__file__).parent / "ttp_library"
        default_paths = [str(lib_dir / "artex_ttps.yaml")]
        if self.config.get("include_extended_attack_library", True):
            default_paths.append(str(lib_dir / "attack_enterprise.yaml"))
        paths = ttp_library_paths or default_paths

        self.ttp_library: list[dict] = []
        for p in paths:
            self.ttp_library.extend(load_ttp_library(p))

        bas_cfg = self.config.get("bas", {})
        siem_cfg = self.config.get("siem", {})
        soar_cfg = self.config.get("soar", {})
        edr_cfg = self.config.get("edr", {})

        self.bas = _build_adapter(bas_cfg.get("provider", "mock"), _BAS_ADAPTERS, bas_cfg.get("options", {}))
        self.siem = _build_adapter(siem_cfg.get("provider", "mock"), _SIEM_ADAPTERS, siem_cfg.get("options", {}))
        self.soar = _build_adapter(soar_cfg.get("provider", "mock"), _SOAR_ADAPTERS, soar_cfg.get("options", {}))
        self.edr = _build_adapter(edr_cfg.get("provider", "mock"), _EDR_ADAPTERS, edr_cfg.get("options", {}))

        llm_cfg = self.config.get("llm", {})
        llm_provider = llm_cfg.get("provider", "none")
        self.llm = None
        if llm_provider != "none":
            self.llm = _build_adapter(llm_provider, _LLM_ADAPTERS, llm_cfg.get("options", {}))

        self.hunt = HuntAgent(self.bas, self.siem)
        self.harden = HardenAgent()
        self.respond = RespondAgent(self.soar)
        self.recover = RecoverAgent(self.hunt, self.edr)
        self.attest = AttestAgent(self.config.get("evidence_output_dir", "evidence_output"), llm=self.llm)

        log.info("XETRA initialized — BAS=%s SIEM=%s SOAR=%s EDR=%s LLM=%s (mock/none unless configured otherwise)",
                  self.bas.name, self.siem.name, self.soar.name, self.edr.name,
                  self.llm.name if self.llm else "none")

    def run_cycle(self, cycle_label: str = "manual", stratum_filter: str | None = None) -> Path:
        scope = self.config.get("scope", {})
        ttps = self.ttp_library
        if stratum_filter:
            ttps = [t for t in self.ttp_library if t["stratum"] == stratum_filter]
            if not ttps:
                raise ValueError(f"No TTP entries found for stratum '{stratum_filter}'.")
        log.info("HUNT: running %d TTP entries against configured scope%s...",
                  len(ttps), f" (stratum={stratum_filter})" if stratum_filter else "")
        findings = self.hunt.run_all(ttps, scope)

        log.info("HARDEN: processing %d findings (%d gaps)...",
                  len(findings), sum(1 for f in findings if f.gap))
        remediations = self.harden.process(findings)

        log.info("RESPOND: triggering playbooks for gaps...")
        responses = self.respond.respond_to_gaps(findings)

        log.info("RECOVER: re-validating gapped techniques...")
        recoveries = []
        ttp_by_attack_id = {aid: t for t in self.ttp_library for aid in t["attack_ids"]}
        for f in findings:
            if f.gap:
                ttp = ttp_by_attack_id.get(f.technique_id)
                if ttp:
                    recoveries.append(self.recover.re_validate(f, ttp, scope))

        log.info("ATTEST: packaging evidence...")
        adapter_modes = {"bas": self.bas.name, "siem": self.siem.name,
                          "soar": self.soar.name, "edr": self.edr.name,
                          "llm": self.llm.name if self.llm else "none"}
        out_path = self.attest.package_cycle(
            findings, remediations, responses, recoveries, cycle_label,
            adapter_modes=adapter_modes,
        )
        if not all(v not in ("mock", "none") for v in adapter_modes.values()):
            log.warning(
                "MOCK MODE: %s — this cycle is NOT real audit evidence.",
                {k: v for k, v in adapter_modes.items() if v in ("mock", "none")},
            )
        log.info("Cycle complete. Evidence package: %s", out_path)
        return out_path
