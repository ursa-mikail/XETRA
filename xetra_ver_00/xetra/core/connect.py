"""
Connection tests — "does this actually work?" in one click, with a plain
answer and a fix, instead of finding out mid-run.

Result shape (always the same, so the UI never has to guess):
  {ok: bool, verified: bool, state: str, message: str, fix: str|None, models: [..]|None}

state:
  simulated   nothing external involved
  missing     required fields not filled in yet
  rejected    the service answered and said the credentials are wrong
  unreachable could not connect (URL typo, VPN, firewall, proxy)
  reachable   service is there; this vendor has no safe read-only check, so
              credentials are proven on the first run (verified=False)
  ok          credentials verified with a harmless read-only call
"""
from __future__ import annotations
import os
from typing import Any

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None

from ..providers import PROVIDERS

TIMEOUT = 12


def _res(ok, state, message, fix=None, verified=False, models=None) -> dict[str, Any]:
    return {"ok": ok, "verified": verified, "state": state, "message": message, "fix": fix, "models": models}


def _get(env: dict[str, str], name: str, default: str = "") -> str:
    return (env.get(name) or os.environ.get(name) or default).strip()


def _http_state(r) -> dict | None:
    """Translate common HTTP failures into plain language."""
    if r.status_code in (401, 403):
        return _res(False, "rejected", f"The service answered but refused these credentials (HTTP {r.status_code}).",
                    "Re-copy the key/token — look for a missing character or an expired or revoked credential — and test again.")
    return None


def test_connection(category: str, provider: str, values: dict[str, str] | None = None,
                    model: str | None = None) -> dict[str, Any]:
    """values: unsaved form values (env-name -> value) so users can test BEFORE saving."""
    values = {k: v for k, v in (values or {}).items() if v}
    spec = PROVIDERS.get(category, {}).get(provider)
    if spec is None:
        return _res(False, "missing", f"Unknown provider '{provider}'.", "Pick a provider from the list.")
    if not spec["live"]:
        return _res(True, "simulated", "Simulated — nothing external to connect to." if provider != "none"
                    else "Off — nothing to connect.", verified=True)
    if requests is None:
        return _res(False, "error", "The 'requests' package is missing.", "Run: pip install requests")

    missing = [f["label"] for f in spec["fields"] if not _get(values, f["env"], f.get("default", ""))]
    if missing:
        return _res(False, "missing", "Still needed: " + ", ".join(missing) + ".",
                    "Fill in the highlighted fields, then press Test again.")

    try:
        fn = _TESTS.get((category, provider)) or _generic
        return fn(values, spec, model)
    except requests.exceptions.SSLError:
        return _res(False, "unreachable", "The connection started but the TLS certificate was not accepted.",
                    "If this is an internal server with a private CA, add the CA to your system trust store.")
    except requests.exceptions.ConnectionError:
        return _res(False, "unreachable", "Could not connect to that address.",
                    "Check the URL for typos, and that this machine can reach it (VPN, firewall, proxy).")
    except requests.exceptions.Timeout:
        return _res(False, "unreachable", f"No answer within {TIMEOUT} seconds.",
                    "Check the URL and your network; the service may be down or blocked.")
    except Exception as e:  # last resort — still a plain sentence, never a stack trace
        return _res(False, "error", f"Unexpected problem: {type(e).__name__}: {e}", "Check the values and try again.")


# --------------------------------------------------------------------- LLMs
def _anthropic(v, spec, model):
    key = _get(v, "ANTHROPIC_API_KEY")
    r = requests.get("https://api.anthropic.com/v1/models?limit=100",
                     headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, timeout=TIMEOUT)
    bad = _http_state(r)
    if bad:
        bad["fix"] = "Create a new key at console.anthropic.com → API keys, paste it here, and test again."
        return bad
    if r.status_code != 200:
        return _res(False, "error", f"Anthropic answered HTTP {r.status_code}.", "Try again in a minute; if it persists check status.anthropic.com.")
    ids = [m["id"] for m in r.json().get("data", [])]
    return _model_result("Claude", ids, model)


def _openai(v, spec, model):
    key = _get(v, "OPENAI_API_KEY")
    r = requests.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT)
    bad = _http_state(r)
    if bad:
        bad["fix"] = "Create a new key at platform.openai.com → API keys, paste it here, and test again."
        return bad
    if r.status_code != 200:
        return _res(False, "error", f"OpenAI answered HTTP {r.status_code}.", "Try again in a minute.")
    skip = ("embedding", "whisper", "tts", "dall-e", "moderation", "davinci", "babbage", "audio", "realtime", "image", "transcribe")
    ids = sorted(m["id"] for m in r.json().get("data", []) if not any(s in m["id"] for s in skip))
    return _model_result("OpenAI", ids, model)


def _model_result(name: str, ids: list[str], model: str | None) -> dict:
    if not ids:
        return _res(True, "ok", f"Key accepted by {name}, but no models were listed for it.",
                    "Check that the key's project has model access.", verified=True, models=[])
    if model and model not in ids:
        return _res(False, "ok", f"Key works, but '{model}' is not available to it.",
                    "Pick a model from the list below.", verified=True, models=ids)
    if model:
        return _res(True, "ok", f"Connected. '{model}' is available.", verified=True, models=ids)
    return _res(True, "ok", f"Connected. {len(ids)} models available — pick one below.",
                "Choose a model, then press Save.", verified=True, models=ids)


# ---------------------------------------------------------- vendor checks
def _splunk(v, spec, model):
    base = _get(v, "SPLUNK_BASE_URL").rstrip("/")
    r = requests.get(f"{base}/services/server/info?output_mode=json",
                     headers={"Authorization": f"Bearer {_get(v, 'SPLUNK_TOKEN')}"}, timeout=TIMEOUT, verify=True)
    bad = _http_state(r)
    if bad:
        return bad
    if r.status_code == 200:
        return _res(True, "ok", "Connected to Splunk and the token was accepted.", verified=True)
    return _res(False, "error", f"Splunk answered HTTP {r.status_code}.", "Use the management port URL (usually :8089).")


def _elastic(v, spec, model):
    base = _get(v, "ELASTIC_URL").rstrip("/")
    r = requests.get(base + "/", headers={"Authorization": f"ApiKey {_get(v, 'ELASTIC_API_KEY')}"}, timeout=TIMEOUT)
    bad = _http_state(r)
    if bad:
        return bad
    if r.status_code == 200:
        return _res(True, "ok", "Connected to Elasticsearch and the API key was accepted.", verified=True)
    return _res(False, "error", f"Elasticsearch answered HTTP {r.status_code}.", "Check the URL and port (usually :9200).")


def _crowdstrike(v, spec, model):
    base = _get(v, "FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
    r = requests.post(base + "/oauth2/token", data={"client_id": _get(v, "FALCON_CLIENT_ID"),
                      "client_secret": _get(v, "FALCON_CLIENT_SECRET")}, timeout=TIMEOUT)
    if r.status_code in (200, 201):
        return _res(True, "ok", "Connected to CrowdStrike and the API client was accepted.", verified=True)
    if r.status_code in (400, 401, 403):
        return _res(False, "rejected", "CrowdStrike refused the client ID/secret.",
                    "Re-copy both values, and confirm the base URL matches your cloud (us-1, us-2, eu-1…).")
    return _res(False, "error", f"CrowdStrike answered HTTP {r.status_code}.", "Check the base URL.")


def _defender(v, spec, model):
    r = requests.get("https://api.securitycenter.microsoft.com/api/machines?$top=1",
                     headers={"Authorization": f"Bearer {_get(v, 'DEFENDER_TOKEN')}"}, timeout=TIMEOUT)
    bad = _http_state(r)
    if bad:
        bad["fix"] = "Defender tokens expire after about an hour — generate a fresh one and test again."
        return bad
    if r.status_code == 200:
        return _res(True, "ok", "Connected to Defender for Endpoint and the token was accepted.", verified=True)
    return _res(False, "error", f"Defender answered HTTP {r.status_code}.", "Check the token's API permissions.")


def _generic(v, spec, model):
    """Vendors without a documented read-only 'whoami' we can rely on: prove the
    address is reachable and say honestly that credentials are not yet proven."""
    url_field = next((f for f in spec["fields"] if f["kind"] == "text" and "URL" in f["env"]), None)
    if not url_field:
        return _res(True, "reachable", "All fields are filled in. Credentials will be proven on the first run.",
                    "Run a single stratum to confirm.", verified=False)
    url = _get(v, url_field["env"], url_field.get("default", "")).rstrip("/")
    r = requests.get(url, timeout=TIMEOUT)
    if r.status_code >= 500:
        return _res(False, "unreachable", f"The server at that address answered HTTP {r.status_code}.", "Check the URL.")
    return _res(True, "reachable", f"{spec['label']} is reachable at that address. It has no safe read-only "
                "credential check, so the key is proven on the first run.",
                "Run one stratum from the Strata tabs to confirm end to end.", verified=False)


_TESTS = {
    ("llm", "anthropic"): _anthropic, ("llm", "openai"): _openai,
    ("siem", "splunk"): _splunk, ("siem", "elastic"): _elastic,
    ("edr", "crowdstrike"): _crowdstrike, ("edr", "defender"): _defender,
}
