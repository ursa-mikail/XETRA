import os
import pytest

os.environ["XETRA_MOCK_DELAY_MS"] = "0"
# Make sure a developer's real credentials can never leak into a test run.
for k in list(os.environ):
    if any(k.startswith(p) for p in ("ANTHROPIC_", "OPENAI_", "SPLUNK_", "FALCON_", "ATTACKIQ_", "PENTERA_",
                                     "SAFEBREACH_", "CYMULATE_", "ELASTIC_", "XSOAR_", "TINES_", "DEFENDER_", "SENTINEL_", "AZURE_")):
        os.environ.pop(k)


@pytest.fixture
def cfg(tmp_path):
    return str(tmp_path / "config" / "config.yaml")


@pytest.fixture(autouse=True)
def _restore_environ():
    snap = dict(os.environ)
    yield
    os.environ.clear(); os.environ.update(snap)
