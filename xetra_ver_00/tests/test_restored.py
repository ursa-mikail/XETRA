"""Coverage for what v0.1 had (wizard, doctor, orchestrator, server compat, Docker scripts)
and what v0.2 restored on top of the new design (stale, trend, findings, auto-schedule)."""
import json
import os
import stat
import subprocess
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from xetra.core.engine import Engine
from xetra.core.settings import load_config_file, save_config_file
from xetra.core import views
from xetra.doctor import run_doctor
from xetra.init_wizard import run_wizard
from xetra.orchestrator import XetraOrchestrator
from xetra.server import make_handler
from xetra.status import render_status

ROOT = Path(__file__).parent.parent


def test_wizard_non_interactive_writes_valid_all_mock_config(cfg, capsys):
    run_wizard(cfg, non_interactive=True)
    c = yaml.safe_load(open(cfg))
    assert all(c[k]["provider"] == "mock" for k in ("bas", "siem", "soar", "edr")) and c["llm"]["provider"] == "none"
    assert not any(x.status == "FAIL" for x in run_doctor(cfg))


def test_doctor_all_mock_has_no_fail_and_flags_mock(cfg):
    checks = {c.name: c for c in run_doctor(cfg)}
    assert checks["OVERALL MODE"].status == "WARN" and checks["TTP library"].status == "PASS"
    assert not any(c.status == "FAIL" for c in checks.values())


def test_doctor_live_llm_without_key_fails_with_named_variable(cfg):
    c = load_config_file(cfg); c["llm"]["provider"] = "anthropic"; save_config_file(cfg, c)
    llm = {x.name: x for x in run_doctor(cfg)}["llm"]
    assert llm.status == "FAIL" and "ANTHROPIC_API_KEY" in llm.fix


def test_orchestrator_full_cycle_writes_flagged_evidence(cfg):
    out = XetraOrchestrator(cfg).run_cycle("t")
    d = json.loads(out.read_text())
    assert d["program"] == "XETRA" and d["mock_mode"] is True and d["mock_mode_warning"]
    s = d["summary"]
    assert s["techniques_tested"] == s["techniques_caught"] + s["gaps_found"] + s["not_tested"]
    assert set(d["adapter_modes"]) == {"bas", "siem", "soar", "edr", "llm"}


def test_status_shows_all_strata_after_partial_run(cfg):
    XetraOrchestrator(cfg).run_cycle("p", strata=["service"])
    out = render_status(cfg)
    assert out.count("\n") >= 9 and "Service" in out and "never" in out


# ----------------------------------------------------------- server compat
@pytest.fixture
def srv(cfg):
    load_config_file(cfg)
    eng = Engine(cfg)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg, eng))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], eng, cfg
    server.shutdown()


def g(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
        return json.loads(r.read())


def post(port, path, body):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def idle(e):
    while e.is_running():
        time.sleep(0.02)


def test_v01_endpoints_still_work(srv):
    port, eng, _ = srv
    assert g(port, "/api/status")["has_data"] is False
    j = post(port, "/api/trigger", {"stratum": "hardware"}); idle(eng)
    assert g(port, f"/api/job/{j['job_id']}")["status"] == "completed"
    st = g(port, "/api/status")
    assert st["has_data"] and st["summary"]["techniques_tested"] == 6 and st["stale"] is False
    ev = g(port, "/api/evidence"); assert ev["latest"] and len(ev["files"]) == 1
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/evidence/{ev['latest']}") as r:
        assert json.loads(r.read())["program"] == "XETRA"
    assert len(g(port, "/api/history")["history"]) == 1


def test_all_findings_spans_every_tested_stratum(srv):
    port, eng, _ = srv
    post(port, "/api/run", {"strata": ["service", "protocol"]}); idle(eng)
    rows = g(port, "/api/findings")["findings"]
    assert {r["stratum"] for r in rows} == {"service", "protocol"} and all("status" in r for r in rows)


def test_trend_accumulates_whole_posture_not_just_last_run(srv):
    port, eng, _ = srv
    post(port, "/api/run", {}); idle(eng)
    post(port, "/api/run", {"strata": ["hardware"]}); idle(eng)
    t = g(port, "/api/overview")["trend"]
    assert len(t) == 2 and t[1]["tested"] == 134      # a partial run still reports the whole posture


def test_stale_banner_data(srv):
    port, eng, cfg = srv
    post(port, "/api/run", {}); idle(eng)
    c = load_config_file(cfg); c["stale_after_minutes"] = 0.0005; save_config_file(cfg, c)   # ~0.03 s
    time.sleep(0.2)
    ov = g(port, "/api/overview")
    assert ov["stale"]["stale"] is True and all(s["stale"] for s in ov["strata"])
    assert g(port, "/api/status")["stale"] is True


def test_env_schedule_runs_immediately_and_user_choice_wins(cfg):
    e = Engine(cfg)
    e.apply_env_schedule(5)
    assert e.schedule_view()["enabled"] and e._next_run_at <= __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    e.set_schedule(False, 5)                                    # a person switches it off...
    e2 = Engine(cfg); e2.apply_env_schedule(5)                  # ...and a restart must not undo that
    assert e2.schedule_view()["enabled"] is False


def test_evidence_dir_flag(cfg, tmp_path, monkeypatch):
    monkeypatch.setenv("XETRA_EVIDENCE_DIR", str(tmp_path / "elsewhere"))
    out = XetraOrchestrator(cfg).run_cycle("x", strata=["hardware"])
    assert out.parent == tmp_path / "elsewhere"


# --------------------------------------------------------------- docker
def test_docker_files_are_consistent():
    for f in ("up", "down", "clean"):
        p = ROOT / f
        assert p.stat().st_mode & stat.S_IXUSR, f
        assert subprocess.run(["bash", "-n", str(p)]).returncode == 0
    comp = yaml.safe_load((ROOT / "docker" / "docker-compose.yml").read_text())
    svc = comp["services"]["xetra"]
    assert "127.0.0.1:8420:8420" in svc["ports"]
    assert any("XETRA_SCHEDULE_MINUTES=5" == e for e in svc["environment"])
    assert {"xetra-state", "xetra-evidence"} <= set(comp["volumes"])
    df = (ROOT / "Dockerfile").read_text()
    assert "--host\", \"0.0.0.0\"" in df and "--evidence-dir" in df
    assert "/app/.xetra" in " ".join(svc["volumes"]) and "/app/evidence_output" in " ".join(svc["volumes"])
