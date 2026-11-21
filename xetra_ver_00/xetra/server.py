"""
XETRA dashboard server — Python standard library only.

  python -m xetra.cli serve --config config/config.yaml     → http://localhost:8420

Everything the dashboard shows or does goes through the JSON API below, so
anything you can click you can also script.

  GET  /api/overview            everything on the home screen, incl. "what to do next"
  GET  /api/stratum/<id>        one stratum: every technique, its last result, its fix
  GET  /api/catalog             providers, fields, strata (drives the Setup forms)
  GET  /api/config              current choices + which fields are set (never secret values)
  POST /api/config              scope, controls (live playbooks, extended library)
  POST /api/connections/test    test a connection (optionally with unsaved values)
  POST /api/connections/save    save provider + credentials for one category
  POST /api/run                 {strata:[...]|null}   start a run
  POST /api/run/stop            stop the current run
  GET  /api/run                 live status of the current/last run (poll this)
  POST /api/pause               {paused:true|false}
  POST /api/schedule            {enabled, every_minutes}
  GET  /api/fixes               the fix list
  POST /api/fixes/<id>          {status, actor, note}
  GET  /api/runs                run history
  GET  /api/events              audit trail   (?limit=&kind=&level=)   /api/events.jsonl to download
  GET  /api/doctor              the pre-flight checks
  GET  /api/posture/export      complete current posture of all 7 strata (download)
  GET  /evidence/<file>         one evidence package
  GET  /api/findings            every finding across all 7 strata (the All findings table)
  GET  /healthz

Compatibility with v0.1 (scripts and CI keep working):
  GET /api/status · GET /api/history · GET /api/evidence · POST /api/trigger {stratum} · GET /api/job/<id>

Safety defaults: binds to 127.0.0.1; rejects requests whose Host or Origin
is not local (stops DNS-rebinding and drive-by web pages); POST bodies must
be application/json; secrets are write-only.
"""
from __future__ import annotations
import argparse
import json
import os
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .core.connect import test_connection
from .core.engine import Engine, Busy, Paused
from .core.settings import (load_config_file, save_config_file, state_dir_for, evidence_dir_for,
                            SecretsFile, field_states, validate_provider_choice)
from .core.store import now_iso
from .core import views
from .providers import PROVIDERS, CATEGORIES, STRATUM_IDS, public_catalog, env_names

_DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
MAX_BODY = 256 * 1024
_ALLOWED_ENV = {n for c in PROVIDERS for p in PROVIDERS[c] for n in env_names(c, p)}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, fix: str | None = None):
        super().__init__(message)
        self.status, self.fix = status, fix


def _allowed_hosts() -> set[str]:
    extra = {h.strip().lower() for h in os.environ.get("XETRA_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return {"localhost", "127.0.0.1", "[::1]", "::1"} | extra


def make_handler(config_path: str, engine: Engine | None = None):
    config_path = str(config_path)
    engine = engine or Engine(config_path)
    store = engine.store

    def cfg() -> dict:
        return load_config_file(config_path)

    def secrets() -> SecretsFile:
        return SecretsFile(store.dir / "secrets.env")

    secrets().apply_to_environ()

    class Handler(BaseHTTPRequestHandler):
        server_version = "XETRA"

        def log_message(self, fmt, *args):  # quiet by default; audit trail lives in events.jsonl
            if os.environ.get("XETRA_HTTP_LOG"):
                print(f"[xetra.server] {self.address_string()} - {fmt % args}")

        # ---------------------------------------------------------- plumbing
        def _headers(self, status, ctype, length, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _json(self, payload, status=200):
            body = json.dumps(payload, default=str).encode()
            self._headers(status, "application/json", len(body))
            self.wfile.write(body)

        def _file(self, path: Path, ctype: str, download_name: str | None = None):
            if not path.is_file():
                return self._json({"error": "Not found."}, 404)
            body = path.read_bytes()
            extra = {"Content-Disposition": f'attachment; filename="{download_name}"'} if download_name else None
            self._headers(200, ctype, len(body), extra)
            self.wfile.write(body)

        def _guard(self) -> bool:
            """Reject non-local Host/Origin. Returns True if the request may proceed."""
            host = (self.headers.get("Host") or "").lower()
            hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
            if hostname not in _allowed_hosts():
                self._json({"error": "Host not allowed.", "fix": "Open XETRA at http://localhost:8420, or set XETRA_ALLOWED_HOSTS."}, 403)
                return False
            origin = self.headers.get("Origin")
            if origin:
                o = urlparse(origin)
                if (o.hostname or "").lower() not in {h.strip("[]") for h in _allowed_hosts()}:
                    self._json({"error": "Cross-site request blocked."}, 403)
                    return False
            return True

        def _body(self) -> dict:
            if self.command == "POST" and "application/json" not in (self.headers.get("Content-Type") or ""):
                raise ApiError("Send JSON (Content-Type: application/json).", 415)
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ApiError("Request too large.", 413)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                data = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                raise ApiError("That wasn't valid JSON.")
            if not isinstance(data, dict):
                raise ApiError("Expected a JSON object.")
            return data

        def _dispatch(self, table):
            if not self._guard():
                return
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            try:
                for pattern, fn in table:
                    m = re.fullmatch(pattern, path)
                    if m:
                        return fn(self, query, *m.groups())
                self._json({"error": "Not found."}, 404)
            except ApiError as e:
                self._json({"error": str(e), "fix": e.fix}, e.status)
            except Busy as e:
                self._json({"error": str(e), "fix": "Wait for it to finish, or press Stop."}, 409)
            except Paused as e:
                self._json({"error": str(e), "fix": "Press Resume in the top bar."}, 423)
            except KeyError as e:
                self._json({"error": f"Not found: {e}"}, 404)
            except ValueError as e:
                self._json({"error": str(e)}, 400)
            except Exception as e:  # never leak a stack trace to the browser; log it in the audit trail
                store.event("server.error", f"{type(e).__name__}: {e}", level="error", path=path)
                self._json({"error": "Something went wrong on the server.", "fix": "Check the Activity tab for details."}, 500)

        def do_GET(self):
            self._dispatch(GET)

        def do_POST(self):
            self._dispatch(POST)

    # ------------------------------------------------------------- GET routes
    def g_index(h, q):
        h._file(_DASHBOARD_DIR / "index.html", "text/html; charset=utf-8")

    def g_health(h, q):
        h._json({"status": "ok"})

    def connections() -> dict:
        return store.app_state().get("connections", {})

    def g_overview(h, q):
        h._json(views.overview(cfg(), store, engine, config_path, connections()))

    def g_stratum(h, q, sid):
        if sid not in STRATUM_IDS:
            raise ApiError(f"Unknown stratum '{sid}'.", 404)
        h._json(views.stratum_detail(sid, cfg(), store))

    def g_catalog(h, q):
        h._json(public_catalog())

    def g_config(h, q):
        c = cfg()
        out = {"config_path": config_path, "state_dir": str(store.dir), "categories": {}}
        for k in CATEGORIES:
            p = c[k]["provider"]
            conn = connections().get(k)
            out["categories"][k] = {
                "provider": p, "fields": field_states(k, p, secrets()) if p in PROVIDERS[k] else [],
                "model": c[k].get("options", {}).get("model", "") if k == "llm" else None,
                "last_test": conn if conn and conn.get("provider") == p else None,
            }
        out["scope"] = c["scope"]
        out["respond"] = c["respond"]
        out["include_extended_attack_library"] = c["include_extended_attack_library"]
        h._json(out)

    def g_run(h, q):
        h._json({"job": engine.job(), "paused": bool(store.app_state().get("paused"))})

    def g_fixes(h, q):
        h._json({"fixes": sorted(store.remediations(), key=lambda r: (r["status"] != "open", r["stratum"], r["technique_id"]))})

    def g_runs(h, q):
        h._json({"runs": list(reversed(store.runs()))})

    def g_events(h, q):
        limit = min(int((q.get("limit") or ["200"])[0]), 1000)
        h._json({"events": store.events(limit, (q.get("kind") or [None])[0], (q.get("level") or [None])[0])})

    def g_events_dl(h, q):
        h._file(store.dir / "events.jsonl", "application/x-ndjson", "xetra-activity.jsonl")

    def g_doctor(h, q):
        from .doctor import run_doctor
        checks = run_doctor(config_path)
        h._json({"checks": [c.to_dict() for c in checks]})

    def g_posture_export(h, q):
        post, ov = store.posture(), views.overview(cfg(), store, engine, config_path, connections())
        snap = {"program": "XETRA", "kind": "posture-snapshot", "generated_at": now_iso(),
                "mock_mode": ov["mode"] == "mock", "adapter_modes": ov["adapter_modes"], "totals": ov["totals"],
                "note": "Latest result for every technique across all seven strata. Techniques never tested are absent, not passing.",
                "strata": {s: {"summary": next(x for x in ov["strata"] if x["id"] == s),
                               "techniques": post[s]["techniques"]} for s in STRATUM_IDS}}
        body = json.dumps(snap, indent=2, default=str).encode()
        h._headers(200, "application/json", len(body),
                   {"Content-Disposition": 'attachment; filename="xetra-posture-snapshot.json"'})
        h.wfile.write(body)

    def g_evidence_file(h, q, name):
        name = os.path.basename(name)
        d = evidence_dir_for(cfg(), config_path)
        h._file(d / name, "application/json", name)

    # ------------------------------------------------------------ POST routes
    def p_run(h, q):
        b = h._body()
        r = engine.start(b.get("strata") or None, b.get("label"), trigger="manual")
        store.event("control.run", f"Run requested from the dashboard ({', '.join(b.get('strata') or ['all strata'])}).", run_id=r["run_id"])
        h._json(r, 202)

    def p_stop(h, q):
        h._body()
        h._json({"stopping": engine.cancel()})

    def p_pause(h, q):
        b = h._body()
        h._json(engine.set_paused(bool(b.get("paused"))))

    def p_schedule(h, q):
        b = h._body()
        h._json(engine.set_schedule(bool(b.get("enabled")), int(b.get("every_minutes", 60))))

    def p_fix(h, q, rem_id):
        b = h._body()
        item = store.set_remediation_status(rem_id, str(b.get("status", "")), str(b.get("actor", "")), str(b.get("note", "")))
        if item["status"] == "approved" and cfg()["bas"]["provider"] == "mock":
            store.mock_mark_fixed([item["technique_id"]])   # simulated: lets you watch retest → verified
        h._json(item)

    def p_conn_test(h, q):
        b = h._body()
        cat, prov = str(b.get("category", "")), str(b.get("provider", ""))
        validate_provider_choice(cat, prov)
        vals = {k: str(v) for k, v in (b.get("values") or {}).items() if k in _ALLOWED_ENV}
        res = test_connection(cat, prov, vals, b.get("model") or None)
        st = store.app_state()
        conns = st.get("connections", {})
        conns[cat] = {"provider": prov, "ok": res["ok"], "verified": res["verified"], "state": res["state"],
                      "message": res["message"], "tested_at": now_iso()}
        store.set_app_state(connections=conns)
        store.event("connection.tested", f"{CATEGORIES[cat]['label']} / {prov}: {res['state']}.",
                    level="info" if res["ok"] else "warn", category=cat, provider=prov)
        h._json(res)

    def p_conn_save(h, q):
        b = h._body()
        cat, prov = str(b.get("category", "")), str(b.get("provider", ""))
        validate_provider_choice(cat, prov)
        updates = {k: str(v).strip() for k, v in (b.get("values") or {}).items() if k in _ALLOWED_ENV and str(v).strip()}
        if updates:
            secrets().set_many(updates)
        c = cfg()
        changed = c[cat]["provider"] != prov
        c[cat]["provider"] = prov
        if cat == "llm":
            opts = c["llm"].setdefault("options", {})
            if b.get("model"):
                opts["model"] = str(b["model"]).strip()
            if prov in ("none", "mock"):
                opts.pop("model", None)
        if cat == "bas" and prov != "mock" and not (c["scope"].get("authorized_by") or "").strip():
            pass  # the Scope step prompts for this; doctor FAILs a live BAS without it
        save_config_file(config_path, c)
        store.event("config.saved", f"{CATEGORIES[cat]['label']} set to {prov}"
                    + (f" (credentials updated: {', '.join(sorted(updates))})" if updates else "") + ".",
                    category=cat, provider=prov, credentials_changed=sorted(updates))
        if changed:
            conns = store.app_state().get("connections", {}); conns.pop(cat, None)
            store.set_app_state(connections=conns)
        h._json({"saved": True})

    def p_config(h, q):
        b = h._body()
        c = cfg()
        if "scope" in b:
            s = b["scope"]
            if "authorized_by" in s: c["scope"]["authorized_by"] = str(s["authorized_by"]).strip()
            if "environment" in s:
                if s["environment"] not in ("staging", "production"):
                    raise ApiError("Environment must be 'staging' or 'production'.")
                c["scope"]["environment"] = s["environment"]
            if "targets" in s:
                t = s["targets"]
                c["scope"]["targets"] = [x.strip() for x in (t.split(",") if isinstance(t, str) else t) if str(x).strip()]
        if "allow_live_playbooks" in b:
            c["respond"]["allow_live_playbooks"] = bool(b["allow_live_playbooks"])
            store.event("control.playbooks", "Real containment playbooks " + ("ENABLED." if b["allow_live_playbooks"] else "disabled."),
                        level="warn" if b["allow_live_playbooks"] else "info")
        if "include_extended_attack_library" in b:
            c["include_extended_attack_library"] = bool(b["include_extended_attack_library"])
        save_config_file(config_path, c)
        store.event("config.saved", "Scope/controls updated.", scope=c["scope"])
        h._json({"saved": True})


    # ---- v0.2 additions -------------------------------------------------
    def g_findings(h, q):
        post = store.posture()
        fixes = {(r["stratum"], r["technique_id"]): r for r in store.remediations()}
        rows = []
        for sid in STRATUM_IDS:
            for tid, t in post[sid]["techniques"].items():
                rows.append({"stratum": sid, "technique_id": tid, "status": t["status"], "bas_outcome": t["bas_outcome"],
                             "siem_alerted": t["siem_alerted"], "tested_at": t["tested_at"], "mode": t.get("mode"),
                             "ttp_id": t.get("ttp_id"), "fix": (fixes.get((sid, tid)) or {}).get("status")})
        h._json({"findings": rows})

    # ---- v0.1 compatibility ---------------------------------------------
    def g_status(h, q):
        ov = views.overview(cfg(), store, engine, config_path, connections())
        lr = ov["last_run"]
        if not lr:
            return h._json({"has_data": False, "can_trigger": True})
        h._json({"has_data": True, "cycle_label": lr.get("label"), "generated_at": lr["finished_at"],
                 "age_minutes": ov["stale"]["last_run_age_minutes"], "stale": ov["stale"]["stale"],
                 "mock_mode": ov["mode"] == "mock", "adapter_modes": ov["adapter_modes"],
                 "summary": {"techniques_tested": ov["totals"]["tested"], "gaps_found": ov["totals"]["gaps"],
                             "not_tested": ov["totals"]["not_tested"]},
                 "total_cycles_on_disk": len(store.runs()), "can_trigger": True})

    def g_history(h, q):
        h._json({"history": [{"file": r.get("file"), "generated_at": r.get("finished_at"), "cycle_label": r.get("label"),
                              "mock_mode": r.get("mode") == "mock",
                              "summary": {"techniques_tested": r.get("tested"), "gaps_found": r.get("gaps")}}
                             for r in store.runs()[-20:] if r.get("state") == "completed"]})

    def g_evidence_list(h, q):
        d = evidence_dir_for(cfg(), config_path)
        files = sorted((p.name for p in d.glob("xetra-attest-*.json")), reverse=True) if d.exists() else []
        h._json({"files": files, "latest": files[0] if files else None})

    def g_job(h, q, job_id):
        j = engine.job()
        if not j or j["run_id"] != job_id:
            raise ApiError("Unknown job id.", 404)
        state = {"running": "running", "stopping": "running", "completed": "completed"}.get(j["state"], "failed")
        h._json({"job_id": job_id, "status": state, "result_file": j.get("result_file"), "error": j.get("error")})

    def p_trigger(h, q):
        b = h._body()
        st = b.get("stratum")
        r = engine.start([st] if st else None, trigger="manual")
        h._json({"job_id": r["run_id"], "status": "queued", "stratum": st}, 202)

    GET = [
        (r"/", g_index), (r"/index\.html", g_index), (r"/healthz", g_health),
        (r"/api/overview", g_overview), (r"/api/stratum/([a-z_]+)", g_stratum),
        (r"/api/catalog", g_catalog), (r"/api/config", g_config), (r"/api/run", g_run),
        (r"/api/fixes", g_fixes), (r"/api/runs", g_runs), (r"/api/events", g_events),
        (r"/api/events\.jsonl", g_events_dl), (r"/api/doctor", g_doctor),
        (r"/api/posture/export", g_posture_export), (r"/api/findings", g_findings),
        (r"/api/status", g_status), (r"/api/history", g_history), (r"/api/evidence", g_evidence_list), (r"/api/job/([0-9a-f]+)", g_job), (r"/evidence/([^/]+)", g_evidence_file),
    ]
    POST = [
        (r"/api/run", p_run), (r"/api/run/stop", p_stop), (r"/api/pause", p_pause),
        (r"/api/schedule", p_schedule), (r"/api/fixes/([0-9a-f]+)", p_fix),
        (r"/api/connections/test", p_conn_test), (r"/api/connections/save", p_conn_save),
        (r"/api/config", p_config), (r"/api/trigger", p_trigger),
    ]
    Handler.engine = engine
    return Handler


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="xetra-server", description="XETRA dashboard")
    parser.add_argument("--port", type=int, default=int(os.environ.get("XETRA_PORT", "8420")))
    parser.add_argument("--host", default=os.environ.get("XETRA_HOST", "127.0.0.1"),
                        help="Default 127.0.0.1 (this machine only). Use 0.0.0.0 only behind your own authentication.")
    parser.add_argument("--config", default=os.environ.get("XETRA_CONFIG_PATH", "config/config.yaml"))
    parser.add_argument("--evidence-dir", default=None, help="Where evidence packages are written (default: evidence_output).")
    args = parser.parse_args(argv)
    if args.evidence_dir:
        os.environ["XETRA_EVIDENCE_DIR"] = args.evidence_dir

    load_config_file(args.config)          # creates an all-simulated config on first run
    engine = Engine(args.config)
    handler = make_handler(args.config, engine)
    if os.environ.get("XETRA_SCHEDULE_MINUTES"):
        engine.apply_env_schedule(int(os.environ["XETRA_SCHEDULE_MINUTES"]))
    engine.start_scheduler()
    server = ThreadingHTTPServer((args.host, args.port), handler)
    engine.store.event("server.started", f"Dashboard started on {args.host}:{args.port}.")
    print(f"\n  XETRA is running →  http://localhost:{args.port}\n  (press Ctrl+C to stop)\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
