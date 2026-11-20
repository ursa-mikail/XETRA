"""
XETRA command-line entry point.

Usage:
    python -m xetra.cli run --config config/config.yaml --label weekly-run
    python -m xetra.cli list-ttps --config config/config.yaml
"""
from __future__ import annotations
import argparse
import logging

from .orchestrator import XetraOrchestrator, load_ttp_library
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(prog="xetra", description="XETRA — the structural inverse of ARTEX")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run one full HUNT->HARDEN->RESPOND->RECOVER->ATTEST cycle")
    run_p.add_argument("--config", default="config/config.yaml")
    run_p.add_argument("--label", default="manual")
    run_p.add_argument("--verbose", action="store_true")

    list_p = sub.add_parser("list-ttps", help="List the loaded TTP library")
    list_p.add_argument("--config", default="config/config.yaml")

    serve_p = sub.add_parser("serve", help="Run the dashboard web server (see xetra.server)")
    serve_p.add_argument("--port", type=int, default=8420)
    serve_p.add_argument("--evidence-dir", default="evidence_output")
    serve_p.add_argument("--config", default=None,
                          help="If set, enables the dashboard's 'Run cycle now' trigger.")

    doctor_p = sub.add_parser("doctor", help="Pre-flight validation — run this before `run` or `serve`")
    doctor_p.add_argument("--config", default="config/config.yaml")

    init_p = sub.add_parser("init", help="Guided setup wizard — writes config.yaml step by step")
    init_p.add_argument("--config", default="config/config.yaml")
    init_p.add_argument("--non-interactive", action="store_true",
                         help="Write an all-mock config with no prompts (for scripting/CI)")

    status_p = sub.add_parser("status", help="Current state at a glance: last cycle, mode, open gaps")
    status_p.add_argument("--config", default="config/config.yaml")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "run":
        orch = XetraOrchestrator(args.config)
        out_path = orch.run_cycle(cycle_label=args.label)
        print(f"\nEvidence package written to: {out_path}\n")
    elif args.command == "list-ttps":
        lib_dir = Path(__file__).parent / "ttp_library"
        all_ttps = load_ttp_library(str(lib_dir / "artex_ttps.yaml"))
        all_ttps += load_ttp_library(str(lib_dir / "attack_enterprise.yaml"))
        total_ids = sum(len(t["attack_ids"]) for t in all_ttps)
        for t in all_ttps:
            print(f"{t['id']:<22} [{t['stratum']:<14}] {', '.join(t['attack_ids'])}")
        print(f"\n{len(all_ttps)} TTP entries, {total_ids} ATT&CK technique IDs total.")
    elif args.command == "serve":
        from . import server
        import sys
        argv = ["xetra-server", "--port", str(args.port), "--evidence-dir", args.evidence_dir]
        if args.config:
            argv += ["--config", args.config]
        sys.argv = argv
        server.main()
    elif args.command == "doctor":
        from .doctor import main as doctor_main
        import sys
        sys.argv = ["xetra-doctor", args.config]
        doctor_main()
    elif args.command == "init":
        from .init_wizard import run_wizard
        run_wizard(args.config, non_interactive=args.non_interactive)
    elif args.command == "status":
        from .status import render_status
        print(render_status(args.config))


if __name__ == "__main__":
    main()
