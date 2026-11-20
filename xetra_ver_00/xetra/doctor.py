"""
`xetra doctor` — the single command you run before trusting anything
else XETRA produces. Checks config validity, adapter configuration
state, TTP library integrity, and scope sanity, and reports each check
as PASS / WARN / FAIL with an explicit, actionable next step — never
just a stack trace.

Exit code 0 only if there are zero FAILs. WARNs (e.g. running in mock
mode) don't block you, but are designed to be impossible to miss.
"""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Any

from .orchestrator import load_config, load_ttp_library, _build_adapter, \
    _BAS_ADAPTERS, _SIEM_ADAPTERS, _SOAR_ADAPTERS, _EDR_ADAPTERS, _LLM_ADAPTERS


class Check:
    def __init__(self, name: str, status: str, message: str, fix: str | None = None):
        self.name = name
        self.status = status  # "PASS" | "WARN" | "FAIL"
        self.message = message
        self.fix = fix

    def render(self) -> str:
        icon = {"PASS": "✅", "WARN": "⚠️ ", "FAIL": "❌"}[self.status]
        line = f"{icon} [{self.status:<4}] {self.name}: {self.message}"
        if self.fix:
            line += f"\n         → Fix: {self.fix}"
        return line


def run_doctor(config_path: str) -> list[Check]:
    checks: list[Check] = []

    # 1. Config file exists and parses
    cfg_file = Path(config_path)
    if not cfg_file.exists():
        checks.append(Check(
            "config file", "FAIL", f"{config_path} does not exist.",
            fix=f"cp config/config.example.yaml {config_path}",
        ))
        return checks  # nothing else is checkable without it
    try:
        config = load_config(config_path)
        checks.append(Check("config file", "PASS", f"{config_path} parses as valid YAML."))
    except Exception as e:
        checks.append(Check(
            "config file", "FAIL", f"{config_path} failed to parse: {e}",
            fix="Fix the YAML syntax error above, or restore from config.example.yaml.",
        ))
        return checks

    # 2. TTP library loads and is internally consistent
    try:
        lib_dir = Path(__file__).parent / "ttp_library"
        core = load_ttp_library(str(lib_dir / "artex_ttps.yaml"))
        ext = load_ttp_library(str(lib_dir / "attack_enterprise.yaml")) \
            if config.get("include_extended_attack_library", True) else []
        total = core + ext
        ids = [t["id"] for t in total]
        total_attack_ids = sum(len(t["attack_ids"]) for t in total)
        if len(ids) != len(set(ids)):
            checks.append(Check(
                "TTP library", "FAIL", "Duplicate TTP entry IDs found.",
                fix="Check xetra/ttp_library/*.yaml for a copy-pasted 'id' field.",
            ))
        else:
            checks.append(Check(
                "TTP library", "PASS",
                f"{len(total)} entries loaded, {total_attack_ids} ATT&CK technique IDs total.",
            ))
    except Exception as e:
        checks.append(Check(
            "TTP library", "FAIL", f"Failed to load: {e}",
            fix="Check xetra/ttp_library/*.yaml for YAML syntax errors.",
        ))

    # 3. Each adapter category — mock vs live, and if live, actually configured
    categories = [
        ("bas", _BAS_ADAPTERS, "HUNT's attack-emulation source"),
        ("siem", _SIEM_ADAPTERS, "HUNT's detection-confirmation source"),
        ("soar", _SOAR_ADAPTERS, "RESPOND's containment trigger"),
        ("edr", _EDR_ADAPTERS, "HARDEN/RECOVER's endpoint coverage+isolation"),
    ]
    any_mock = False
    for key, registry, role in categories:
        cat_cfg = config.get(key, {})
        provider = cat_cfg.get("provider", "mock")
        if provider == "mock":
            any_mock = True
            checks.append(Check(
                f"{key} adapter", "WARN",
                f"Running in MOCK mode ({role}). Results are simulated, not real evidence.",
                fix=f"See docs/GOING_LIVE.md to configure a real {key} provider "
                    f"({', '.join(k for k in registry if k != 'mock')}).",
            ))
            continue
        try:
            adapter = _build_adapter(provider, registry, cat_cfg.get("options", {}))
            if adapter.is_configured():
                checks.append(Check(f"{key} adapter", "PASS",
                                     f"{provider} configured and ready ({role})."))
            else:
                checks.append(Check(
                    f"{key} adapter", "FAIL",
                    f"{provider} selected but not configured (missing credentials/env vars).",
                    fix=f"See docs/GOING_LIVE.md for {provider}'s required env vars.",
                ))
        except Exception as e:
            checks.append(Check(f"{key} adapter", "FAIL", f"{provider} failed to initialize: {e}"))

    # 4. LLM (optional, but validate if enabled)
    llm_cfg = config.get("llm", {})
    llm_provider = llm_cfg.get("provider", "none")
    if llm_provider not in ("none", "mock"):
        try:
            adapter = _build_adapter(llm_provider, _LLM_ADAPTERS, llm_cfg.get("options", {}))
            if adapter.is_configured():
                checks.append(Check("llm adapter", "PASS", f"{llm_provider} configured."))
            else:
                checks.append(Check(
                    "llm adapter", "FAIL",
                    f"{llm_provider} selected but not configured.",
                    fix="See docs/LLM_INTEGRATION.md for required env vars.",
                ))
        except Exception as e:
            checks.append(Check("llm adapter", "FAIL", f"{llm_provider} failed to initialize: {e}"))
    elif llm_provider == "mock":
        checks.append(Check("llm adapter", "WARN", "Running in MOCK mode — summaries are templated, not real."))
    else:
        checks.append(Check("llm adapter", "PASS", "Disabled (no analyst_summary will be generated)."))

    # 5. Scope sanity — the thing most likely to cause a quietly-incomplete
    # audit if wrong: a live BAS adapter with an empty/placeholder scope.
    scope = config.get("scope", {})
    authorized_by = scope.get("authorized_by", "")
    targets = scope.get("targets", [])
    bas_provider = config.get("bas", {}).get("provider", "mock")
    if bas_provider != "mock":
        if not authorized_by or "CHANGE ME" in authorized_by:
            checks.append(Check(
                "scope authorization", "FAIL",
                "Live BAS adapter configured but scope.authorized_by is unset/placeholder.",
                fix="Set scope.authorized_by to the name/role of whoever signed the Rules of Engagement.",
            ))
        else:
            checks.append(Check("scope authorization", "PASS", f"Authorized by: {authorized_by}"))
        if not targets:
            checks.append(Check(
                "scope targets", "WARN",
                "scope.targets is empty — confirm this is intentional (e.g. scope lives entirely "
                "in the BAS platform's own console) before running live.",
            ))
    else:
        checks.append(Check("scope authorization", "PASS", "N/A — mock mode, no live targets."))

    if any_mock:
        checks.append(Check(
            "OVERALL MODE", "WARN",
            "This configuration will produce mock_mode: true evidence. "
            "Not usable for certification evidence until all four categories are live.",
        ))
    else:
        checks.append(Check("OVERALL MODE", "PASS", "All adapter categories live — evidence will be real."))

    return checks


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    print(f"XETRA doctor — checking {config_path}\n")
    checks = run_doctor(config_path)
    for c in checks:
        print(c.render())
        print()
    fails = sum(1 for c in checks if c.status == "FAIL")
    warns = sum(1 for c in checks if c.status == "WARN")
    print(f"{len(checks)} checks: {len(checks) - fails - warns} passed, {warns} warnings, {fails} failed.")
    if fails:
        print("\nResolve FAIL items above before running `xetra run`.")
        sys.exit(1)
    elif warns:
        print("\nNo blocking issues, but review WARN items above — most commonly, mock mode.")
        sys.exit(0)
    else:
        print("\nAll clear.")
        sys.exit(0)


if __name__ == "__main__":
    main()
