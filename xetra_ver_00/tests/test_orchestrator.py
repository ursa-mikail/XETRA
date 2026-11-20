import os
import tempfile
import textwrap

import pytest

from xetra.orchestrator import XetraOrchestrator


@pytest.fixture
def mock_config_path():
    cfg = textwrap.dedent("""
        bas: {provider: mock, options: {}}
        siem: {provider: mock, options: {}}
        soar: {provider: mock, options: {}}
        edr: {provider: mock, options: {}}
        evidence_output_dir: "{outdir}"
        scope: {{authorized_by: "test", environment: "staging", targets: []}}
    """)
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "evidence")
        path = os.path.join(d, "config.yaml")
        with open(path, "w") as f:
            f.write(cfg.format(outdir=out))
        yield path


def test_orchestrator_initializes_with_mocks(mock_config_path):
    orch = XetraOrchestrator(mock_config_path)
    assert orch.bas.name == "mock"
    assert orch.siem.name == "mock"
    assert orch.soar.name == "mock"
    assert orch.edr.name == "mock"


def test_full_cycle_runs_end_to_end_with_mocks(mock_config_path):
    orch = XetraOrchestrator(mock_config_path)
    out_path = orch.run_cycle(cycle_label="pytest")
    assert out_path.exists()
    content = out_path.read_text()
    assert '"program": "XETRA"' in content
