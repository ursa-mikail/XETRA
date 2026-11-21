"""
XETRA Orchestrator — wires a config into the five agents and runs one
validation cycle: HUNT -> HARDEN -> RESPOND -> RECOVER -> ATTEST.

A cycle can cover all seven strata or any subset. Either way it only ever
*updates* what it tested: results for strata it did not touch stay exactly
as the last run left them (see core/store.py).

Adapter selection defaults to mock everywhere. Nothing here touches a real
system unless you configure a live adapter with credentials and an
authorized scope.
"""
from __future__ import annotations
import logging
import uuid
from pathlib import Path
from typing import Any, Callable

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

from .agents.hunt import HuntAgent, RunCancelled
from .agents.harden import HardenAgent, hint_for
from .agents.respond import RespondAgent
from .agents.recover import RecoverAgent
from .agents.attest import AttestAgent

from .core.settings import (load_config_file, state_dir_for, evidence_dir_for, SecretsFile)
from .core.store import StateStore
from .providers import STRATUM_IDS

log = logging.getLogger("xetra")

_BAS_ADAPTERS = {"mock": MockBASAdapter, "attackiq": AttackIQAdapter, "pentera": PenteraAdapter,
                 "safebreach": SafeBreachAdapter, "cymulate": CymulateAdapter}
_SIEM_ADAPTERS = {"mock": MockSIEMAdapter, "splunk": SplunkAdapter,
                  "sentinel": SentinelAdapter, "elastic": ElasticAdapter}
_SOAR_ADAPTERS = {"mock": MockSOARAdapter, "tines": TinesAdapter, "xsoar": XSOARAdapter}
_EDR_ADAPTERS = {"mock": MockEDRAdapter, "crowdstrike": CrowdStrikeAdapter, "defender": DefenderAdapter}
_LLM_ADAPTERS = {"mock": MockLLMAdapter, "anthropic": AnthropicLLMAdapter, "openai": OpenAILLMAdapter}

Progress = Callable[[str, dict], None]


def load_config(path: str) -> dict[str, Any]:
    return load_config_file(path)


def load_ttp_library(path: str) -> list[dict]:
    with open(path) as f:
        return yaml.safe_load(f)


def load_all_ttps(include_extended: bool = True) -> list[dict]:
    lib_dir = Path(__file__).parent / "ttp_library"
    out = load_ttp_library(str(lib_dir / "artex_ttps.yaml"))
    if include_extended:
        out += load_ttp_library(str(lib_dir / "attack_enterprise.yaml"))
    return out


def _build_adapter(kind: str, registry: dict, cfg: dict):
    if kind == "mock":
        return registry["mock"]()
    adapter_cls = registry.get(kind)
    if adapter_cls is None:
        raise ValueError(f"Unknown provider '{kind}'. Choose one of: {', '.join(registry)}.")
    try:
        return adapter_cls(**(cfg or {}))
    except TypeError:
        return adapter_cls()


class XetraOrchestrator:
    def __init__(self, config_path: str, ttp_library_paths: list[str] | None = None):
        self.config_path = str(config_path)
        self.config = load_config_file(config_path)
        self.state_dir = state_dir_for(self.config, config_path)
        self.store = StateStore(self.state_dir)
        SecretsFile(self.state_dir / "secrets.env").apply_to_environ()

        if ttp_library_paths:
            self.ttp_library: list[dict] = []
            for p in ttp_library_paths:
                self.ttp_library.extend(load_ttp_library(p))
        else:
            self.ttp_library = load_all_ttps(self.config.get("include_extended_attack_library", True))

        c = self.config
        self.bas = _build_adapter(c["bas"]["provider"], _BAS_ADAPTERS, c["bas"].get("options", {}))
        self.siem = _build_adapter(c["siem"]["provider"], _SIEM_ADAPTERS, c["siem"].get("options", {}))
        self.soar = _build_adapter(c["soar"]["provider"], _SOAR_ADAPTERS, c["soar"].get("options", {}))
        self.edr = _build_adapter(c["edr"]["provider"], _EDR_ADAPTERS, c["edr"].get("options", {}))
        llm_provider = c["llm"].get("provider", "none")
        self.llm = None if llm_provider == "none" else _build_adapter(llm_provider, _LLM_ADAPTERS, c["llm"].get("options", {}))

        fixed = self.store.mock_fixed()
        for a in (self.bas, self.siem):
            if hasattr(a, "fixed"):
                a.fixed = fixed

        self.hunt = HuntAgent(self.bas, self.siem)
        self.harden = HardenAgent()
        self.respond = RespondAgent(self.soar, allow_live=bool(c.get("respond", {}).get("allow_live_playbooks", False)))
        self.recover = RecoverAgent(self.hunt, self.edr)
        self.attest = AttestAgent(str(evidence_dir_for(c, config_path)), llm=self.llm)

    # ------------------------------------------------------------------ run
    def adapter_modes(self) -> dict[str, str]:
        return {"bas": self.bas.name, "siem": self.siem.name, "soar": self.soar.name,
                "edr": self.edr.name, "llm": self.llm.name if self.llm else "none"}

    def select_ttps(self, strata: list[str] | None) -> list[dict]:
        if not strata:
            return list(self.ttp_library)
        bad = [s for s in strata if s not in STRATUM_IDS]
        if bad:
            raise ValueError(f"Unknown stratum {bad}. Valid: {', '.join(STRATUM_IDS)}.")
        ttps = [t for t in self.ttp_library if t["stratum"] in strata]
        if not ttps:
            raise ValueError(f"No techniques are defined for {', '.join(strata)}.")
        return ttps

    def run_cycle(self, cycle_label: str = "manual", stratum_filter: str | None = None,
                  strata: list[str] | None = None, progress: Progress | None = None,
                  should_cancel: Callable[[], bool] | None = None,
                  run_id: str | None = None, trigger: str = "manual") -> Path:
        strata = strata or ([stratum_filter] if stratum_filter else None)
        run_id = run_id or uuid.uuid4().hex[:8]
        emit = progress or (lambda stage, payload: None)
        scope = self.config.get("scope", {})
        ttps = self.select_ttps(strata)
        partial = bool(strata) and set(strata) != set(STRATUM_IDS)
        covered = sorted({t["stratum"] for t in ttps}, key=STRATUM_IDS.index)
        total = sum(len(t["attack_ids"]) for t in ttps)
        modes = self.adapter_modes()
        mode = "live" if all(modes[k] not in ("mock", "none") for k in ("bas", "siem", "soar", "edr")) else "mock"
        ttp_meta = {a: {"ttp_id": t["id"], "expected_control": t.get("expected_control", ""),
                        "description": t.get("description", "")}
                    for t in self.ttp_library for a in t["attack_ids"]}

        self.store.event("run.started", f"Run {run_id} started: {', '.join(covered)} ({total} techniques, {mode}).",
                         run_id=run_id, strata=covered, mode=mode, trigger=trigger)
        emit("start", {"run_id": run_id, "strata": covered, "total": total, "mode": mode})
        started_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        try:
            emit("stage", {"name": "hunt", "state": "running"})
            findings = self.hunt.run_all(
                ttps, scope, should_cancel=should_cancel,
                on_result=lambda f, i, n: emit("technique", {
                    "i": i, "n": n, "technique": f.technique_id, "stratum": f.stratum, "status": f.status}))
            emit("stage", {"name": "hunt", "state": "done"})

            emit("stage", {"name": "harden", "state": "running"})
            remediations = self.harden.process(findings)
            emit("stage", {"name": "harden", "state": "done", "items": len(remediations)})

            if should_cancel and should_cancel():
                raise RunCancelled()
            emit("stage", {"name": "respond", "state": "running"})
            responses = self.respond.respond_to_gaps(findings)
            held = sum(1 for r in responses if r.status == "held_awaiting_human_enable")
            emit("stage", {"name": "respond", "state": "done", "triggered": sum(1 for r in responses if r.triggered), "held": held})

            emit("stage", {"name": "recover", "state": "running"})
            recoveries = []
            for f in findings:
                if f.status == "gap":
                    if should_cancel and should_cancel():
                        raise RunCancelled()
                    recoveries.append(self.recover.re_validate(f, scope))
            emit("stage", {"name": "recover", "state": "done", "retested": len(recoveries)})

            emit("stage", {"name": "attest", "state": "running"})
            extra = {"run_id": run_id, "trigger": trigger, "partial": partial,
                     "strata_covered": covered, "strata_not_covered": [s for s in STRATUM_IDS if s not in covered],
                     "respond_live_playbooks_enabled": self.respond.allow and self.soar.name != "mock"}
            out_path = self.attest.package_cycle(findings, remediations, responses, recoveries, cycle_label,
                                                 adapter_modes=modes, extra=extra)
            emit("stage", {"name": "attest", "state": "done", "file": out_path.name})
        except RunCancelled:
            self.store.event("run.cancelled", f"Run {run_id} stopped by a person before it finished. "
                             "Nothing from this run was saved as results.", level="warn", run_id=run_id)
            self.store.record_run({"run_id": run_id, "label": cycle_label, "started_at": started_at,
                                   "finished_at": self.store_now(), "state": "cancelled", "strata": covered, "mode": mode})
            emit("cancelled", {})
            raise
        except Exception as e:
            self.store.event("run.failed", f"Run {run_id} failed: {e}", level="error", run_id=run_id)
            self.store.record_run({"run_id": run_id, "label": cycle_label, "started_at": started_at,
                                   "finished_at": self.store_now(), "state": "failed", "error": str(e),
                                   "strata": covered, "mode": mode})
            emit("failed", {"error": str(e)})
            raise

        # Persist only after the whole cycle succeeded, so a half-finished run
        # can never leave half-updated posture behind.
        fdicts = [f.__dict__ for f in findings]
        self.store.update_posture(fdicts, run_id, mode, ttp_meta)
        counts = self.store.sync_remediations(fdicts, hint_for, run_id)
        gaps = sum(1 for f in findings if f.status == "gap")
        nt = sum(1 for f in findings if f.status == "not_tested")
        post = self.store.posture()
        all_t = [t for sid in STRATUM_IDS for t in post[sid]["techniques"].values()]
        posture_totals = {"tested": len(all_t), "gaps": sum(t["status"] == "gap" for t in all_t),
                          "caught": sum(t["status"] == "caught" for t in all_t),
                          "not_tested": sum(t["status"] == "not_tested" for t in all_t)}
        summary = {"run_id": run_id, "label": cycle_label, "posture": posture_totals, "started_at": started_at,
                   "finished_at": self.store_now(), "state": "completed", "strata": covered, "mode": mode,
                   "partial": partial, "tested": len(findings), "gaps": gaps, "not_tested": nt,
                   "caught": len(findings) - gaps - nt, "file": out_path.name, "trigger": trigger, **counts}
        self.store.record_run(summary)
        level = "warn" if (gaps or nt) else "info"
        self.store.event("run.finished",
                         f"Run {run_id} finished: {len(findings)} tested, {gaps} gap(s), {nt} not tested."
                         + (" SIMULATED — not audit evidence." if mode == "mock" else ""),
                         level=level, run_id=run_id, **counts)
        emit("done", {"summary": summary})
        return out_path

    @staticmethod
    def store_now() -> str:
        from .core.store import now_iso
        return now_iso()
