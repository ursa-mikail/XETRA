"""
XETRA command line.

  xetra start                 ← the one command most people need. Sets itself up and opens the dashboard.
  xetra run [--strata a,b]    run a cycle from the terminal
  xetra status                what's true right now, all 7 strata, one screen
  xetra doctor                pre-flight checks with fixes
  xetra init                  terminal setup wizard (the dashboard's Setup tab does the same)
  xetra list-ttps             every technique XETRA validates
"""
from __future__ import annotations
import argparse
import logging
import sys
import threading
import webbrowser

from .orchestrator import XetraOrchestrator, load_all_ttps
from .providers import STRATUM_IDS


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="xetra", description="XETRA — the structural inverse of ARTEX")
    sub = parser.add_subparsers(dest="command", required=True)
    cfg_default = "config/config.yaml"

    st = sub.add_parser("start", help="Create config if needed and open the dashboard (recommended)")
    st.add_argument("--config", default=cfg_default); st.add_argument("--port", type=int, default=8420)
    st.add_argument("--host", default="127.0.0.1"); st.add_argument("--no-browser", action="store_true")

    sv = sub.add_parser("serve", help="Run the dashboard server")
    sv.add_argument("--config", default=cfg_default); sv.add_argument("--port", type=int, default=8420)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--evidence-dir", default=None)

    r = sub.add_parser("run", help="Run one cycle")
    r.add_argument("--config", default=cfg_default); r.add_argument("--label", default="cli")
    r.add_argument("--strata", default="", help=f"Comma list. Any of: {', '.join(STRATUM_IDS)}. Default: all.")
    r.add_argument("--verbose", action="store_true")

    for name, helptext in (("status", "Current state of all 7 strata"), ("doctor", "Pre-flight checks"),
                           ("list-ttps", "List every technique")):
        p = sub.add_parser(name, help=helptext); p.add_argument("--config", default=cfg_default)
    i = sub.add_parser("init", help="Terminal setup wizard")
    i.add_argument("--config", default=cfg_default); i.add_argument("--non-interactive", action="store_true")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if args.command in ("start", "serve"):
        from . import server
        sargs = ["--config", args.config, "--port", str(args.port), "--host", args.host]
        if getattr(args, "evidence_dir", None):
            sargs += ["--evidence-dir", args.evidence_dir]
        if args.command == "start" and not args.no_browser:
            threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{args.port}")).start()
        server.main(sargs)
    elif args.command == "run":
        strata = [s.strip() for s in args.strata.split(",") if s.strip()] or None
        orch = XetraOrchestrator(args.config)
        done = {"n": 0}
        def prog(stage, payload):
            if stage == "stage" and payload["state"] == "running":
                print(f"  {payload['name'].upper():<8} …", flush=True)
            if stage == "technique" and payload["i"] % 25 == 0:
                print(f"  tested {payload['i']}/{payload['n']}", flush=True)
        out = orch.run_cycle(cycle_label=args.label, strata=strata, progress=prog, trigger="cli")
        print(f"\nDone. Evidence package: {out}\nSee all strata: xetra status --config {args.config}\n")
    elif args.command == "list-ttps":
        from .core.settings import load_config_file
        all_ttps = load_all_ttps(load_config_file(args.config).get("include_extended_attack_library", True))
        for t in all_ttps:
            print(f"{t['id']:<22} [{t['stratum']:<13}] {', '.join(t['attack_ids'])}")
        print(f"\n{len(all_ttps)} entries, {sum(len(t['attack_ids']) for t in all_ttps)} ATT&CK technique IDs.")
    elif args.command == "doctor":
        from .doctor import main as m
        sys.argv = ["xetra-doctor", args.config]; m()
    elif args.command == "init":
        from .init_wizard import run_wizard
        run_wizard(args.config, non_interactive=args.non_interactive)
    elif args.command == "status":
        from .status import render_status
        print(render_status(args.config))


if __name__ == "__main__":
    main()
