"""
`xetra doctor` — the check you run before trusting anything else.

Every result is PASS / WARN / FAIL with a plain explanation and, for
anything not PASS, the exact fix. Exit code 0 only if there are zero FAILs.
The same checks power the dashboard's Setup tab (/api/doctor).
"""
from __future__ import annotations
import sys
from pathlib import Path

from .core.settings import load_config_file, state_dir_for, SecretsFile
from .orchestrator import (load_all_ttps, _build_adapter,
                           _BAS_ADAPTERS, _SIEM_ADAPTERS, _SOAR_ADAPTERS, _EDR_ADAPTERS, _LLM_ADAPTERS)
from .providers import PROVIDERS, STRATUM_IDS, env_names

_REGISTRIES = {"bas": _BAS_ADAPTERS, "siem": _SIEM_ADAPTERS, "soar": _SOAR_ADAPTERS,
               "edr": _EDR_ADAPTERS, "llm": _LLM_ADAPTERS}
_ROLES = {"bas": "HUNT's attack-emulation source", "siem": "HUNT's detection-confirmation source",
          "soar": "RESPOND's containment trigger", "edr": "endpoint coverage + isolation",
          "llm": "optional AI summaries"}


class Check:
    def __init__(self, name: str, status: str, message: str, fix: str | None = None):
        self.name, self.status, self.message, self.fix = name, status, message, fix

    def render(self) -> str:
        icon = {"PASS": "✅", "WARN": "⚠️ ", "FAIL": "❌"}[self.status]
        line = f"{icon} [{self.status:<4}] {self.name}: {self.message}"
        if self.fix:
            line += f"\n         → Fix: {self.fix}"
        return line

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "message": self.message, "fix": self.fix}


def run_doctor(config_path: str) -> list[Check]:
    checks: list[Check] = []
    existed = Path(config_path).exists()
    try:
        config = load_config_file(config_path)   # creates an all-simulated config if absent
        checks.append(Check("config file", "PASS",
                            f"{config_path} is valid." if existed else f"{config_path} did not exist — created an all-simulated one."))
    except Exception as e:
        return [Check("config file", "FAIL", f"{config_path} could not be read: {e}",
                      "Fix the YAML error shown, or delete the file and run `xetra init` to recreate it.")]

    sd = state_dir_for(config, config_path)
    try:
        sd.mkdir(parents=True, exist_ok=True)
        (sd / ".write-test").write_text("ok"); (sd / ".write-test").unlink()
        checks.append(Check("state folder", "PASS", f"{sd} is writable."))
    except Exception as e:
        checks.append(Check("state folder", "FAIL", f"Cannot write to {sd}: {e}", "Choose a writable folder: state_dir in config.yaml."))
    SecretsFile(sd / "secrets.env").apply_to_environ()

    try:
        total = load_all_ttps(config.get("include_extended_attack_library", True))
        ids = [t["id"] for t in total]
        per = {s: sum(len(t["attack_ids"]) for t in total if t["stratum"] == s) for s in STRATUM_IDS}
        empty = [s for s, n in per.items() if n == 0]
        if len(ids) != len(set(ids)):
            checks.append(Check("TTP library", "FAIL", "Duplicate TTP entry IDs.", "Look for a copy-pasted 'id' in xetra/ttp_library/*.yaml."))
        elif empty:
            checks.append(Check("TTP library", "FAIL", f"No techniques for: {', '.join(empty)}.", "Restore the library files."))
        else:
            checks.append(Check("TTP library", "PASS", f"{sum(per.values())} techniques across all 7 strata."))
    except Exception as e:
        checks.append(Check("TTP library", "FAIL", f"Failed to load: {e}", "Check the YAML in xetra/ttp_library/."))

    any_mock = False
    for key in ("bas", "siem", "soar", "edr", "llm"):
        provider = config[key].get("provider", "mock" if key != "llm" else "none")
        if provider not in PROVIDERS[key]:
            checks.append(Check(f"{key}", "FAIL", f"'{provider}' is not a valid choice.",
                                f"Choose one of: {', '.join(PROVIDERS[key])} (dashboard → Setup)."))
            continue
        if key == "llm":
            if provider == "none":
                checks.append(Check("llm", "PASS", "Off — no AI text will be generated. Everything else works the same."))
                continue
            if provider == "mock":
                checks.append(Check("llm", "WARN", "Template text only (no AI call).", "Dashboard → Setup → AI summaries to connect a real one."))
                continue
        elif provider == "mock":
            any_mock = True
            checks.append(Check(key, "WARN", f"Simulated ({_ROLES[key]}). Results are demo data, not evidence.",
                                f"Dashboard → Setup → {key.upper()} to connect: {', '.join(k for k in PROVIDERS[key] if k != 'mock')}."))
            continue
        try:
            adapter = _build_adapter(provider, _REGISTRIES[key], config[key].get("options", {}))
            if adapter.is_configured():
                note = "" if key != "llm" else f" (model: {adapter.model})"
                checks.append(Check(key, "PASS", f"{provider} is configured{note}. Use 'Test connection' in the dashboard to prove it works."))
            else:
                missing = [n for n in env_names(key, provider) if not __import__("os").environ.get(n)]
                checks.append(Check(key, "FAIL", f"{provider} is selected but not fully configured.",
                                    "Missing: " + ", ".join(missing) + ". Enter them in dashboard → Setup (or export them)."))
        except Exception as e:
            checks.append(Check(key, "FAIL", f"{provider} failed to initialise: {e}"))

    scope = config.get("scope", {})
    ab = (scope.get("authorized_by") or "").strip()
    live_bas = config["bas"]["provider"] != "mock"
    if live_bas:
        if not ab or "CHANGE ME" in ab:
            checks.append(Check("scope authorization", "FAIL", "A live BAS is selected but nobody is recorded as having authorised testing.",
                                "Dashboard → Setup → Scope: enter who signed the Rules of Engagement."))
        else:
            checks.append(Check("scope authorization", "PASS", f"Authorised by: {ab}"))
        if not scope.get("targets"):
            checks.append(Check("scope targets", "WARN", "No targets listed. That is fine only if your scope lives entirely in the BAS console."))
    else:
        checks.append(Check("scope authorization", "PASS", "Not needed — nothing live to authorise."))

    if config.get("respond", {}).get("allow_live_playbooks") and config["soar"]["provider"] != "mock":
        checks.append(Check("live playbooks", "WARN", "XETRA is allowed to trigger REAL containment playbooks.",
                            "Turn off in dashboard → Controls if this is not intended."))

    if any_mock:
        checks.append(Check("OVERALL MODE", "WARN", "Simulated. Evidence will be marked mock_mode: true and must not go to an auditor."))
    else:
        checks.append(Check("OVERALL MODE", "PASS", "All four core categories are live — evidence will be real."))
    return checks


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    print(f"XETRA doctor — checking {config_path}\n")
    checks = run_doctor(config_path)
    for c in checks:
        print(c.render()); print()
    fails = sum(c.status == "FAIL" for c in checks)
    warns = sum(c.status == "WARN" for c in checks)
    print(f"{len(checks)} checks: {len(checks) - fails - warns} passed, {warns} warnings, {fails} failed.")
    if fails:
        print("\nFix the FAIL items above, then run doctor again."); sys.exit(1)
    print("\nNo blocking problems." + (" Warnings above are normal in simulated mode." if warns else " All clear."))


if __name__ == "__main__":
    main()
