"""Behaviour that must never regress: results are never lost, runs are stoppable,
unknown is never reported as pass, and nothing real happens without a human."""
import json
import threading
import time

import pytest

from xetra.core.engine import Engine, Busy, Paused
from xetra.core.settings import load_config_file, save_config_file
from xetra.core.store import StateStore
from xetra.orchestrator import XetraOrchestrator, load_all_ttps
from xetra.agents.hunt import HuntAgent, HuntFinding
from xetra.agents.respond import RespondAgent
from xetra.providers import STRATUM_IDS


def post(cfg):
    o = XetraOrchestrator(cfg)
    return o, o.store.posture()


def test_every_stratum_has_techniques():
    ttps = load_all_ttps(True)
    for s in STRATUM_IDS:
        assert sum(len(t["attack_ids"]) for t in ttps if t["stratum"] == s) >= 6, s
    ids = [t["id"] for t in ttps]
    assert len(ids) == len(set(ids))


def test_first_run_creates_simulated_config(cfg):
    c = load_config_file(cfg)
    assert c["bas"]["provider"] == "mock" and c["llm"]["provider"] == "none"
    assert c["respond"]["allow_live_playbooks"] is False


def test_single_stratum_run_never_erases_the_others(cfg):
    """THE regression: running one stratum used to hide the other six."""
    o = XetraOrchestrator(cfg)
    o.run_cycle("full")
    before = o.store.posture()
    tested_before = {s: len(before[s]["techniques"]) for s in STRATUM_IDS}
    assert all(n > 0 for n in tested_before.values())
    XetraOrchestrator(cfg).run_cycle("one", strata=["hardware"])
    after = XetraOrchestrator(cfg).store.posture()
    assert {s: len(after[s]["techniques"]) for s in STRATUM_IDS} == tested_before
    assert after["service"]["techniques"] == before["service"]["techniques"]   # untouched, byte for byte


def test_partial_run_package_is_labelled_partial(cfg):
    out = XetraOrchestrator(cfg).run_cycle("p", strata=["service", "system"])
    pkg = json.loads(out.read_text())
    assert pkg["partial"] is True and pkg["strata_covered"] == ["service", "system"]
    assert "hardware" in pkg["strata_not_covered"] and pkg["mock_mode"] is True


def test_full_run_is_not_partial(cfg):
    pkg = json.loads(XetraOrchestrator(cfg).run_cycle("f").read_text())
    assert pkg["partial"] is False and pkg["strata_not_covered"] == []


def test_fix_list_human_decision_then_retest_verifies(cfg):
    o = XetraOrchestrator(cfg); o.run_cycle("a")
    items = o.store.remediations()
    assert items and all(i["status"] == "open" for i in items)
    it = items[0]
    with pytest.raises(ValueError):
        o.store.set_remediation_status(it["id"], "approved", "", "")        # needs a name
    with pytest.raises(ValueError):
        o.store.set_remediation_status(it["id"], "risk_accepted", "Dana", "")  # needs a reason
    with pytest.raises(ValueError):
        o.store.set_remediation_status(it["id"], "verified", "Dana", "x")      # only XETRA may verify
    o.store.set_remediation_status(it["id"], "approved", "Dana", "patching")
    o.store.mock_mark_fixed([it["technique_id"]])
    XetraOrchestrator(cfg).run_cycle("retest", strata=[it["stratum"]])
    now = {i["id"]: i for i in o.store.remediations()}[it["id"]]
    assert now["status"] == "verified"
    assert [h["by"] for h in now["history"]] == ["Dana", "xetra"]


def test_not_tested_is_unknown_not_pass_and_triggers_nothing():
    class Boom:
        name = "boom"
        def run_technique(self, *a): raise RuntimeError("no assessment mapped")
    class Siem:
        name = "s"
        def check_alert(self, *a): raise AssertionError("unreached")
    f = HuntAgent(Boom(), Siem()).run_technique("T1", "service", {})
    assert f.status == "not_tested" and f.gap is False
    calls = []
    class Soar:
        name = "live"
        def trigger_playbook(self, *a, **k): calls.append(a)
    assert RespondAgent(Soar(), allow_live=True).respond_to_gaps([f]) == [] and not calls


def test_live_soar_holds_playbooks_until_human_enables():
    class Soar:
        name = "tines"
        def trigger_playbook(self, *a, **k): raise AssertionError("must not run")
    gap = HuntFinding("T1", "system", "undetected", False, True, {}, status="gap")
    rec = RespondAgent(Soar(), allow_live=False).respond_to_gaps([gap])
    assert rec[0].triggered is False and rec[0].status == "held_awaiting_human_enable"


def test_a_broken_llm_does_not_cost_you_the_evidence(cfg):
    c = load_config_file(cfg); c["llm"]["provider"] = "anthropic"; save_config_file(cfg, c)
    out = XetraOrchestrator(cfg).run_cycle("x", strata=["hardware"])
    pkg = json.loads(out.read_text())
    assert "analyst_summary_error" in pkg and pkg["summary"]["techniques_tested"] > 0


# ------------------------------------------------------------------ engine
def wait(engine, timeout=20):
    t0 = time.time()
    while engine.is_running() and time.time() - t0 < timeout:
        time.sleep(0.02)


def test_engine_one_run_at_a_time_and_pause(cfg, monkeypatch):
    monkeypatch.setenv("XETRA_MOCK_DELAY_MS", "30")
    e = Engine(cfg); load_config_file(cfg)
    e.start(["service"])
    with pytest.raises(Busy):
        e.start(["system"])
    e.cancel(); wait(e)
    e.set_paused(True)
    with pytest.raises(Paused):
        e.start()
    e.set_paused(False)
    e.start(["hardware"]); wait(e)
    assert e.job()["state"] == "completed"


def test_stop_saves_nothing_from_the_stopped_run(cfg, monkeypatch):
    monkeypatch.setenv("XETRA_MOCK_DELAY_MS", "40")
    e = Engine(cfg)
    e.start(["system"]); time.sleep(0.3)
    assert e.cancel() is True
    wait(e)
    j = e.job()
    assert j["state"] == "cancelled"
    assert all(not e.store.posture()[s]["techniques"] for s in STRATUM_IDS)
    assert e.store.runs()[-1]["state"] == "cancelled"
    assert any(ev["kind"] == "run.cancelled" for ev in e.store.events())


def test_schedule_validation(cfg):
    e = Engine(cfg)
    with pytest.raises(ValueError):
        e.set_schedule(True, 1)
    v = e.set_schedule(True, 30)
    assert v["enabled"] and v["next_run_at"]
    assert e.set_schedule(False, 30)["next_run_at"] is None


def test_corrupt_state_file_does_not_crash(tmp_path):
    s = StateStore(tmp_path)
    (tmp_path / "posture.json").write_text("{not json")
    assert all(s.posture()[x]["techniques"] == {} for x in STRATUM_IDS)
