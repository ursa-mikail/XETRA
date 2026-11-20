import json
import textwrap
from pathlib import Path

from xetra.doctor import run_doctor
from xetra.status import render_status
from xetra.orchestrator import XetraOrchestrator


def _write_mock_config(tmp_path) -> str:
    cfg = textwrap.dedent("""
        bas: {provider: mock, options: {}}
        siem: {provider: mock, options: {}}
        soar: {provider: mock, options: {}}
        edr: {provider: mock, options: {}}
        llm: {provider: none, options: {}}
        evidence_output_dir: "{outdir}"
        include_extended_attack_library: true
        scope: {{authorized_by: "test", environment: "staging", targets: []}}
    """)
    outdir = tmp_path / "evidence"
    path = tmp_path / "config.yaml"
    path.write_text(cfg.format(outdir=str(outdir)))
    return str(path)


def test_doctor_all_mock_has_no_fails_but_has_warns(tmp_path):
    config_path = _write_mock_config(tmp_path)
    checks = run_doctor(config_path)
    assert all(c.status != "FAIL" for c in checks)
    assert any(c.status == "WARN" and "bas" in c.name for c in checks)
    assert any(c.name == "OVERALL MODE" and c.status == "WARN" for c in checks)


def test_doctor_missing_config_fails_with_fix_hint(tmp_path):
    checks = run_doctor(str(tmp_path / "does-not-exist.yaml"))
    assert len(checks) == 1
    assert checks[0].status == "FAIL"
    assert checks[0].fix is not None


def test_status_before_any_run_says_so_clearly(tmp_path):
    config_path = _write_mock_config(tmp_path)
    out = render_status(config_path)
    assert "No cycles have run yet" in out


def test_status_after_run_shows_mock_mode_and_counts(tmp_path):
    config_path = _write_mock_config(tmp_path)
    orch = XetraOrchestrator(config_path)
    orch.run_cycle(cycle_label="test")
    out = render_status(config_path)
    assert "MOCK" in out
    assert "Techniques tested:" in out
