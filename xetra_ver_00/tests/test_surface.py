"""API, security, connection-test and CLI surface."""
import json
import threading
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

import pytest

from xetra.server import make_handler
from xetra.core import connect
from xetra.core.settings import SecretsFile, field_states, load_config_file
from xetra.core.engine import Engine
from xetra.providers import PROVIDERS


@pytest.fixture
def srv(cfg):
    load_config_file(cfg)
    eng = Engine(cfg)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg, eng))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], eng, cfg
    server.shutdown()


def call(port, path, body=None, headers=None, method=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=None if body is None else json.dumps(body).encode(),
                                 headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_dashboard_and_overview(srv):
    port, *_ = srv
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as r:
        assert b"XETRA" in r.read()
    s, ov = call(port, "/api/overview")
    assert s == 200 and ov["mode"] == "mock" and len(ov["strata"]) == 7
    assert ov["next"]["action"] == "run_all"          # a brand-new user is told exactly what to do


def test_run_via_api_then_every_stratum_visible(srv):
    port, eng, _ = srv
    assert call(port, "/api/run", {"strata": ["service"]})[0] == 202
    while eng.is_running(): pass
    call(port, "/api/run", {"strata": ["hardware"]})
    while eng.is_running(): pass
    _, ov = call(port, "/api/overview")
    by = {s["id"]: s for s in ov["strata"]}
    assert by["service"]["tested"] > 0 and by["hardware"]["tested"] > 0 and by["system"]["health"] == "never_run"
    s, d = call(port, "/api/stratum/service")
    assert s == 200 and len(d["rows"]) == by["service"]["defined"]
    assert call(port, "/api/stratum/nope")[0] == 404


def test_busy_returns_409_with_fix(srv, monkeypatch):
    port, eng, _ = srv
    monkeypatch.setenv("XETRA_MOCK_DELAY_MS", "30")
    call(port, "/api/run", {"strata": ["system"]})
    s, body = call(port, "/api/run", {})
    assert s == 409 and body["fix"]
    call(port, "/api/run/stop", {})
    while eng.is_running(): pass


def test_pause_returns_423(srv):
    port, *_ = srv
    call(port, "/api/pause", {"paused": True})
    assert call(port, "/api/run", {})[0] == 423
    call(port, "/api/pause", {"paused": False})


def test_security_guards(srv):
    port, *_ = srv
    assert call(port, "/api/overview", headers={"Host": "evil.example.com"})[0] == 403          # DNS rebinding
    assert call(port, "/api/pause", {"paused": True}, headers={"Origin": "https://evil.example.com"})[0] == 403
    assert call(port, "/api/pause", {"paused": True}, headers={"Content-Type": "text/plain"})[0] == 415  # no no-preflight CSRF
    s, _ = call(port, "/evidence/..%2f..%2fetc%2fpasswd")
    assert s == 404


def test_secrets_are_write_only(srv):
    port, eng, cfg = srv
    assert call(port, "/api/connections/save", {"category": "llm", "provider": "anthropic",
                "values": {"ANTHROPIC_API_KEY": "sk-ant-SECRETVALUE1234"}, "model": "m"})[0] == 200
    _, c = call(port, "/api/config")
    blob = json.dumps(c)
    assert "SECRETVALUE" not in blob and "1234" in blob          # only a masked tail
    f = c["categories"]["llm"]["fields"][0]
    assert f["set"] is True and f["masked"].endswith("1234")
    assert (eng.store.dir / "secrets.env").stat().st_mode & 0o777 == 0o600
    assert "SECRETVALUE" not in "".join(e["message"] for e in eng.store.events(500))   # nor in the audit log
    # unknown env names are refused rather than written
    call(port, "/api/connections/save", {"category": "llm", "provider": "anthropic", "values": {"PATH": "x"}})
    assert "PATH" not in SecretsFile(eng.store.dir / "secrets.env").read()


def test_fix_decision_endpoint_needs_a_name(srv):
    port, eng, _ = srv
    call(port, "/api/run", {})
    while eng.is_running(): pass
    _, f = call(port, "/api/fixes")
    fid = f["fixes"][0]["id"]
    s, body = call(port, f"/api/fixes/{fid}", {"status": "approved", "actor": ""})
    assert s == 400 and "name" in body["error"]
    assert call(port, f"/api/fixes/{fid}", {"status": "approved", "actor": "Dana"})[0] == 200


def test_posture_export_has_all_seven(srv):
    port, *_ = srv
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/posture/export") as r:
        d = json.loads(r.read())
    assert len(d["strata"]) == 7 and d["kind"] == "posture-snapshot"


# -------------------------------------------------------- connection tests
class FakeResp:
    def __init__(self, status, payload=None): self.status_code, self._p = status, payload or {}
    def json(self): return self._p


def test_connection_missing_fields_are_named():
    r = connect.test_connection("llm", "anthropic", {})
    assert r["state"] == "missing" and "API key" in r["message"] and r["fix"]


def test_connection_simulated_needs_nothing():
    assert connect.test_connection("bas", "mock")["state"] == "simulated"
    assert connect.test_connection("llm", "none")["ok"] is True


def test_llm_test_returns_model_list(monkeypatch):
    monkeypatch.setattr(connect.requests, "get", lambda *a, **k: FakeResp(200, {"data": [{"id": "m-1"}, {"id": "m-2"}]}))
    r = connect.test_connection("llm", "anthropic", {"ANTHROPIC_API_KEY": "k"})
    assert r["ok"] and r["verified"] and r["models"] == ["m-1", "m-2"]
    r = connect.test_connection("llm", "anthropic", {"ANTHROPIC_API_KEY": "k"}, model="nope")
    assert r["ok"] is False and "not available" in r["message"] and r["models"]


def test_llm_test_rejected_key_is_plain_english(monkeypatch):
    monkeypatch.setattr(connect.requests, "get", lambda *a, **k: FakeResp(401))
    r = connect.test_connection("llm", "openai", {"OPENAI_API_KEY": "bad"})
    assert r["state"] == "rejected" and "refused" in r["message"] and "platform.openai.com" in r["fix"]


def test_unreachable_is_plain_english(monkeypatch):
    def boom(*a, **k): raise connect.requests.exceptions.ConnectionError()
    monkeypatch.setattr(connect.requests, "get", boom)
    r = connect.test_connection("siem", "splunk", {"SPLUNK_BASE_URL": "https://x", "SPLUNK_TOKEN": "t"})
    assert r["state"] == "unreachable" and "typos" in r["fix"]


def test_vendor_without_safe_check_is_honest_about_it(monkeypatch):
    monkeypatch.setattr(connect.requests, "get", lambda *a, **k: FakeResp(200))
    r = connect.test_connection("bas", "pentera", {"PENTERA_BASE_URL": "https://p", "PENTERA_API_KEY": "k"})
    assert r["ok"] and r["verified"] is False and r["state"] == "reachable"


def test_every_live_provider_declares_fields():
    for cat, provs in PROVIDERS.items():
        for name, p in provs.items():
            assert p["live"] == bool(p["fields"]), (cat, name)


def test_cli_status_and_run(cfg, capsys):
    from xetra.cli import main
    main(["status", "--config", cfg]); assert "No checks have run" in capsys.readouterr().out
    main(["run", "--config", cfg, "--strata", "algorithm,hardware"])
    main(["status", "--config", cfg]); out = capsys.readouterr().out
    assert "Algorithm" in out and "never" in out and "SIMULATED" in out


def test_doctor_flags_live_bas_without_authoriser(cfg):
    from xetra.doctor import run_doctor
    from xetra.core.settings import save_config_file
    c = load_config_file(cfg); c["bas"]["provider"] = "pentera"; save_config_file(cfg, c)
    names = {x.name: x.status for x in run_doctor(cfg)}
    assert names["bas"] == "FAIL" and names["scope authorization"] == "FAIL"
