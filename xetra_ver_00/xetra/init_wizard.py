"""
`xetra init` — terminal setup wizard. (The dashboard's Setup tab does the
same thing with buttons; this is for people who live in a terminal.)

Secrets are never typed here — they go into the dashboard or the
environment — so they never land in shell history.
"""
from __future__ import annotations
import sys
from pathlib import Path

from .core.settings import DEFAULT_CONFIG, save_config_file, _deep_merge
from .providers import PROVIDERS, CATEGORIES, env_names


def _ask(prompt: str, options: list[tuple[str, str]], default: str) -> str:
    print(f"\n{prompt}")
    for i, (k, label) in enumerate(options, 1):
        print(f"  {i}. {label}{'  (default)' if k == default else ''}")
    raw = input(f"Choose 1-{len(options)} [Enter = default]: ").strip()
    if not raw:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1][0]
    print(f"  Not understood — using the default ({default}).")
    return default


def run_wizard(config_path: str = "config/config.yaml", non_interactive: bool = False) -> None:
    print("=" * 60 + "\nXETRA setup\n" + "=" * 60)
    print("Tip: the dashboard's Setup tab does all of this with buttons:  xetra start")
    cfg = _deep_merge(DEFAULT_CONFIG, {})
    if not non_interactive:
        for cat, meta in CATEGORIES.items():
            opts = [(k, v["label"]) for k, v in PROVIDERS[cat].items()]
            default = "none" if cat == "llm" else "mock"
            cfg[cat]["provider"] = _ask(f"{meta['label']} — {meta['role']}", opts, default)
        if any(cfg[c]["provider"] not in ("mock", "none") for c in ("bas", "siem", "soar", "edr")):
            cfg["scope"]["authorized_by"] = input("\nWho authorised testing (name/role)? ").strip()
    save_config_file(config_path, cfg)
    print(f"\nWrote {config_path}")
    needed = {c: env_names(c, cfg[c]["provider"]) for c in CATEGORIES if env_names(c, cfg[c]["provider"])}
    if needed:
        print("\nCredentials needed (enter them in the dashboard → Setup, or export them):")
        for c, names in needed.items():
            print(f"  {c}: " + ", ".join(names))
    from .doctor import run_doctor
    print("\nChecking your setup:\n")
    for c in run_doctor(config_path):
        print(c.render())
    print("\nNext: xetra start")


def main():
    run_wizard(sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml", "--non-interactive" in sys.argv)


if __name__ == "__main__":
    main()
