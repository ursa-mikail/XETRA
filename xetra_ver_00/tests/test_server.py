"""End-to-end test of the dashboard server: starts it on an ephemeral
port, hits every endpoint, confirms the path-traversal guard."""
import json
import threading
import time
import urllib.request
import urllib.error

import pytest

from xetra.server import make_handler
from http.server import ThreadingHTTPServer


@pytest.fixture
def running_server(tmp_path):
    evidence_dir = tmp_path / "evidence_output"
    evidence_dir.mkdir()
    sample = {"program": "XETRA", "summary": {"techniques_tested": 1}}
    (evidence_dir / "xetra-attest-test-123.json").write_text(json.dumps(sample))

    handler = make_handler(evidence_dir)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield port
    server.shutdown()


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return r.status, r.read()


def test_dashboard_served_at_root(running_server):
    status, body = _get(running_server, "/")
    assert status == 200
    assert b"<html" in body.lower()


def test_api_evidence_lists_files(running_server):
    status, body = _get(running_server, "/api/evidence")
    data = json.loads(body)
    assert data["latest"] == "xetra-attest-test-123.json"
    assert len(data["files"]) == 1


def test_evidence_file_served(running_server):
    status, body = _get(running_server, "/evidence/xetra-attest-test-123.json")
    data = json.loads(body)
    assert data["program"] == "XETRA"


def test_healthz(running_server):
    status, body = _get(running_server, "/healthz")
    assert json.loads(body)["status"] == "ok"


def test_path_traversal_blocked(running_server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(running_server, "/evidence/../../../etc/passwd")
    assert exc.value.code == 404
