"""
XETRA's dashboard web server — stdlib only, no extra dependencies.

Serves the dashboard (dashboard/index.html) at `/`, and the evidence
files an orchestrator run produced at `/api/evidence` (listing) and
`/evidence/<filename>` (one file), so the dashboard can auto-load the
latest cycle instead of requiring drag-and-drop every time. Drag-and-drop
still works too — this server doesn't change the dashboard's offline
capability, it just adds a convenient online one.

Usage:
    python -m xetra.server --port 8420 --evidence-dir evidence_output
"""
from __future__ import annotations
import argparse
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
STALENESS_THRESHOLD_MINUTES = 15

# What env vars each provider needs — shown directly in the dashboard so
# "where do I set the LLM / BAS / etc." has one visible answer instead
# of requiring a docs hunt.
_ENV_VAR_HINTS = {
    "attackiq": ["ATTACKIQ_BASE_URL", "ATTACKIQ_API_TOKEN"],
    "pentera": ["PENTERA_BASE_URL", "PENTERA_API_KEY"],
    "safebreach": ["SAFEBREACH_BASE_URL", "SAFEBREACH_API_KEY"],
    "cymulate": ["CYMULATE_API_KEY"],
    "splunk": ["SPLUNK_BASE_URL", "SPLUNK_TOKEN"],
    "sentinel": ["SENTINEL_WORKSPACE_ID", "AZURE_TOKEN"],
    "elastic": ["ELASTIC_URL", "ELASTIC_API_KEY"],
    "tines": ["(webhook URLs configured directly in config.yaml, no env var)"],
    "xsoar": ["XSOAR_BASE_URL", "XSOAR_API_KEY"],
    "crowdstrike": ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"],
    "defender": ["DEFENDER_TOKEN"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "mock": [], "none": [],
}

# In-memory job tracking for manually-triggered cycles. Single-process
# server, so a plain dict is sufficient — no external state needed.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _run_cycle_job(job_id: str, config_path: str, stratum_filter: str | None = None):
    with _jobs_lock:
        _jobs[job_id]["status"] = "running"
    try:
        from .orchestrator import XetraOrchestrator
        orch = XetraOrchestrator(config_path)
        label = f"manual-{job_id[:8]}" + (f"-{stratum_filter}" if stratum_filter else "")
        out_path = orch.run_cycle(cycle_label=label, stratum_filter=stratum_filter)
        with _jobs_lock:
            _jobs[job_id]["status"] = "completed"
            _jobs[job_id]["result_file"] = out_path.name
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = str(e)


def make_handler(evidence_dir: Path, config_path: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print(f"[xetra.server] {self.address_string()} - {fmt % args}")

        def _no_cache_headers(self):
            # Without this, browsers will happily keep serving a cached
            # copy of the dashboard HTML (and even API responses) after
            # a rebuild/restart, making real changes look like they never
            # landed. Every response from this server is always fresh.
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")

        def _send_json(self, payload, status=200):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self._no_cache_headers()
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, path: Path, content_type: str):
            if not path.exists() or not path.is_file():
                self.send_error(404, "Not found")
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._no_cache_headers()
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html", "/dashboard", "/dashboard/"):
                self._send_file(_DASHBOARD_DIR / "index.html", "text/html; charset=utf-8")
                return

            if self.path == "/api/evidence":
                if not evidence_dir.exists():
                    self._send_json({"files": []})
                    return
                files = sorted(
                    (p.name for p in evidence_dir.glob("xetra-attest-*.json")),
                    reverse=True,
                )
                self._send_json({"files": files, "latest": files[0] if files else None})
                return

            if self.path.startswith("/evidence/"):
                name = os.path.basename(self.path[len("/evidence/"):])  # no path traversal
                self._send_file(evidence_dir / name, "application/json")
                return

            if self.path == "/healthz":
                self._send_json({"status": "ok"})
                return

            if self.path == "/api/status":
                self._send_json(self._compute_status())
                return

            if self.path == "/api/config":
                self._send_json(self._compute_config_view())
                return

            if self.path == "/api/history":
                self._send_json({"history": self._compute_history()})
                return

            if self.path.startswith("/api/job/"):
                job_id = self.path[len("/api/job/"):]
                with _jobs_lock:
                    job = _jobs.get(job_id)
                if job is None:
                    self.send_error(404, "Unknown job id")
                    return
                self._send_json(job)
                return

            self.send_error(404, "Not found")

        def _compute_status(self):
            files = sorted(evidence_dir.glob("xetra-attest-*.json"))
            if not files:
                return {"has_data": False, "can_trigger": config_path is not None}
            latest = json.loads(files[-1].read_text())
            gen_at = datetime.fromisoformat(latest["generated_at"])
            age_minutes = (datetime.now(timezone.utc) - gen_at).total_seconds() / 60
            return {
                "has_data": True,
                "cycle_label": latest.get("cycle_label"),
                "generated_at": latest.get("generated_at"),
                "age_minutes": round(age_minutes, 1),
                "stale": age_minutes > STALENESS_THRESHOLD_MINUTES,
                "mock_mode": latest.get("mock_mode", True),
                "mock_mode_warning": latest.get("mock_mode_warning"),
                "adapter_modes": latest.get("adapter_modes", {}),
                "summary": latest.get("summary", {}),
                "total_cycles_on_disk": len(files),
                "can_trigger": config_path is not None,
            }

        def _compute_config_view(self):
            if config_path is None:
                return {"available": False,
                        "message": "Server started without --config — config view unavailable. "
                                   "Restart with `xetra serve --config config/config.yaml`."}
            try:
                from .orchestrator import load_config, _build_adapter, \
                    _BAS_ADAPTERS, _SIEM_ADAPTERS, _SOAR_ADAPTERS, _EDR_ADAPTERS, _LLM_ADAPTERS
                config = load_config(config_path)
            except Exception as e:
                return {"available": False, "message": f"Could not read {config_path}: {e}"}

            categories = {
                "bas": (_BAS_ADAPTERS, "config.yaml: bas.provider / bas.options"),
                "siem": (_SIEM_ADAPTERS, "config.yaml: siem.provider / siem.options"),
                "soar": (_SOAR_ADAPTERS, "config.yaml: soar.provider / soar.options"),
                "edr": (_EDR_ADAPTERS, "config.yaml: edr.provider / edr.options"),
                "llm": (_LLM_ADAPTERS, "config.yaml: llm.provider / llm.options"),
            }
            out = {"available": True, "config_path": config_path, "categories": {}}
            for key, (registry, where) in categories.items():
                cat_cfg = config.get(key, {})
                provider = cat_cfg.get("provider", "none" if key == "llm" else "mock")
                entry = {
                    "provider": provider,
                    "where_to_set": where,
                    "env_vars_needed": _ENV_VAR_HINTS.get(provider, []),
                    "is_live": provider not in ("mock", "none"),
                    "configured": None,
                }
                if provider not in ("mock", "none"):
                    try:
                        adapter = _build_adapter(provider, registry, cat_cfg.get("options", {}))
                        entry["configured"] = adapter.is_configured()
                    except Exception as e:
                        entry["configured"] = False
                        entry["error"] = str(e)
                out["categories"][key] = entry

            scope = config.get("scope", {})
            out["scope"] = {
                "authorized_by": scope.get("authorized_by", ""),
                "targets_count": len(scope.get("targets", [])),
            }
            return out

        def _compute_history(self, limit: int = 20):
            files = sorted(evidence_dir.glob("xetra-attest-*.json"))[-limit:]
            out = []
            for f in files:
                try:
                    d = json.loads(f.read_text())
                    out.append({
                        "file": f.name,
                        "generated_at": d.get("generated_at"),
                        "cycle_label": d.get("cycle_label"),
                        "mock_mode": d.get("mock_mode", True),
                        "summary": d.get("summary", {}),
                    })
                except Exception:
                    continue
            return out

        def do_POST(self):
            if self.path == "/api/trigger":
                if config_path is None:
                    self._send_json({"error": "No config path configured on this server instance — "
                                               "cannot trigger a cycle. Run `xetra run` manually instead."}, 400)
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(body) if body else {}
                except json.JSONDecodeError:
                    payload = {}
                stratum = payload.get("stratum")  # optional — None means full cycle

                job_id = str(uuid.uuid4())
                with _jobs_lock:
                    _jobs[job_id] = {"status": "queued", "job_id": job_id, "stratum": stratum}
                t = threading.Thread(target=_run_cycle_job, args=(job_id, config_path, stratum), daemon=True)
                t.start()
                self._send_json({"job_id": job_id, "status": "queued", "stratum": stratum})
                return
            self.send_error(404, "Not found")

    return Handler


def main():
    parser = argparse.ArgumentParser(prog="xetra-server", description="XETRA dashboard web server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("XETRA_PORT", "8420")))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--evidence-dir", default=os.environ.get("XETRA_EVIDENCE_DIR", "evidence_output"))
    parser.add_argument("--config", default=os.environ.get("XETRA_CONFIG_PATH"),
                         help="If set, enables the dashboard's 'Run cycle now' trigger.")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    handler = make_handler(evidence_dir, config_path=args.config)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"XETRA dashboard serving at http://localhost:{args.port}  "
          f"(evidence dir: {evidence_dir.resolve()})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
