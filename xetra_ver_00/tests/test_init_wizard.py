from pathlib import Path
import yaml

from xetra.init_wizard import run_wizard
from xetra.doctor import run_doctor


def test_non_interactive_writes_all_mock_config(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    run_wizard(str(cfg_path), non_interactive=True)
    assert cfg_path.exists()
    cfg = yaml.safe_load(cfg_path.read_text())
    assert cfg["bas"]["provider"] == "mock"
    assert cfg["siem"]["provider"] == "mock"
    assert cfg["soar"]["provider"] == "mock"
    assert cfg["edr"]["provider"] == "mock"
    assert cfg["llm"]["provider"] == "none"


def test_non_interactive_config_passes_doctor_with_only_warns(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    run_wizard(str(cfg_path), non_interactive=True)
    checks = run_doctor(str(cfg_path))
    assert all(c.status != "FAIL" for c in checks)
