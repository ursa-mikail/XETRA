"""
`xetra init` — guided setup. Walks through BAS/SIEM/SOAR/EDR/LLM choice
by choice, writes config.yaml, tells you exactly which env vars to
export for whatever you picked, then runs `doctor` automatically so you
see the result immediately instead of wondering if it worked.

Never asks you to type a secret into the terminal — those always go in
environment variables (shown, not collected), so they never land in
shell history or a config file by accident.
"""
from __future__ import annotations
import sys
from pathlib import Path

import yaml

_ENV_HINTS = {
    "attackiq": ["ATTACKIQ_BASE_URL", "ATTACKIQ_API_TOKEN"],
    "pentera": ["PENTERA_BASE_URL", "PENTERA_API_KEY"],
    "safebreach": ["SAFEBREACH_BASE_URL", "SAFEBREACH_API_KEY"],
    "cymulate": ["CYMULATE_API_KEY"],
    "splunk": ["SPLUNK_BASE_URL", "SPLUNK_TOKEN"],
    "sentinel": ["SENTINEL_WORKSPACE_ID", "AZURE_TOKEN"],
    "elastic": ["ELASTIC_URL", "ELASTIC_API_KEY"],
    "tines": [],  # webhook URLs go directly in config, not env vars
    "xsoar": ["XSOAR_BASE_URL", "XSOAR_API_KEY"],
    "crowdstrike": ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"],
    "defender": ["DEFENDER_TOKEN"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
}

_CATEGORY_CHOICES = {
    "bas": ["mock", "attackiq", "pentera", "safebreach", "cymulate"],
    "siem": ["mock", "splunk", "sentinel", "elastic"],
    "soar": ["mock", "tines", "xsoar"],
    "edr": ["mock", "crowdstrike", "defender"],
    "llm": ["none", "mock", "anthropic", "openai"],
}

_CATEGORY_LABELS = {
    "bas": "BAS — HUNT's attack-emulation source",
    "siem": "SIEM — HUNT's detection-confirmation source",
    "soar": "SOAR — RESPOND's containment trigger",
    "edr": "EDR — HARDEN/RECOVER's endpoint coverage+isolation",
    "llm": "LLM — optional advisory summaries in ATTEST (never decides anything)",
}


def _ask_choice(prompt: str, options: list[str], default: str) -> str:
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        marker = " (default)" if opt == default else ""
        print(f"  {i}. {opt}{marker}")
    raw = input(f"Choose [1-{len(options)}, default={default}]: ").strip()
    if not raw:
        return default
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            return options[idx]
    except ValueError:
        pass
    print(f"  Not understood — using default: {default}")
    return default


def run_wizard(config_path: str = "config/config.yaml", non_interactive: bool = False) -> None:
    print("=" * 60)
    print("XETRA setup wizard")
    print("=" * 60)
    print("This writes config.yaml. It never asks for secrets here —")
    print("those always go in environment variables, shown at the end.")

    config: dict = {"evidence_output_dir": "evidence_output",
                     "include_extended_attack_library": True}

    for key in ["bas", "siem", "soar", "edr"]:
        if non_interactive:
            choice = "mock"
        else:
            choice = _ask_choice(_CATEGORY_LABELS[key], _CATEGORY_CHOICES[key], "mock")
        config[key] = {"provider": choice, "options": {}}

    if non_interactive:
        llm_choice = "none"
    else:
        llm_choice = _ask_choice(_CATEGORY_LABELS["llm"], _CATEGORY_CHOICES["llm"], "none")
    llm_options = {}
    if llm_choice in ("anthropic", "openai") and not non_interactive:
        model = input(f"  Model ID for {llm_choice} (see provider's docs for current IDs, "
                       f"leave blank to fill in later): ").strip()
        if model:
            llm_options["model"] = model
    config["llm"] = {"provider": llm_choice, "options": llm_options}

    authorized_by = "CHANGE ME — name/role of the approver who signed the RoE"
    targets: list[str] = []
    if not non_interactive and any(config[k]["provider"] != "mock" for k in ["bas", "siem", "soar", "edr"]):
        print("\nAt least one category is set to a live provider. Scope is required for live BAS runs.")
        ab = input("  Who authorized this (name/role)? ").strip()
        if ab:
            authorized_by = ab
        t = input("  Authorized target list (comma-separated, blank if scope lives in the BAS console): ").strip()
        if t:
            targets = [x.strip() for x in t.split(",") if x.strip()]

    config["scope"] = {
        "authorized_by": authorized_by,
        "environment": "staging",
        "targets": targets,
        "attackiq_assessment_map": {},
    }

    out_path = Path(config_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump(config, sort_keys=False))
    print(f"\nWrote {out_path}")

    print("\n" + "=" * 60)
    print("Environment variables needed for what you chose:")
    print("=" * 60)
    any_env_needed = False
    for key in ["bas", "siem", "soar", "edr", "llm"]:
        provider = config[key]["provider"]
        env_vars = _ENV_HINTS.get(provider, [])
        if env_vars:
            any_env_needed = True
            print(f"\n  {key} ({provider}):")
            for v in env_vars:
                print(f"    export {v}=...")
    if not any_env_needed:
        print("\n  None — everything selected runs in mock/none mode.")

    print("\n" + "=" * 60)
    print("Running `doctor` now to confirm the result:")
    print("=" * 60 + "\n")
    from .doctor import run_doctor
    checks = run_doctor(str(out_path))
    for c in checks:
        print(c.render())
    fails = sum(1 for c in checks if c.status == "FAIL")
    if fails:
        print(f"\n{fails} FAIL(s) above — set the env vars just listed, then re-run: "
              f"python -m xetra.cli doctor --config {config_path}")
    else:
        print(f"\nSetup complete. Next: python -m xetra.cli run --config {config_path}")


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    non_interactive = "--non-interactive" in sys.argv
    run_wizard(config_path, non_interactive=non_interactive)


if __name__ == "__main__":
    main()
