"""`xetra status` — all seven strata on one screen. Never ambiguous: if
nothing has run, it says so and gives the exact next command."""
from __future__ import annotations
import sys
from datetime import datetime, timezone

from .core.settings import load_config_file, state_dir_for
from .core.store import StateStore
from .core import views
from .orchestrator import load_all_ttps
from .providers import STRATA, STRATUM_IDS

_ICON = {"healthy": "✅", "gaps": "❌", "not_tested": "⚠️ ", "partial": "◐ ", "never_run": "· "}


def render_status(config_path: str = "config/config.yaml") -> str:
    config = load_config_file(config_path)
    store = StateStore(state_dir_for(config, config_path))
    post = store.posture()
    ttps = load_all_ttps(config.get("include_extended_attack_library", True))
    if not any(post[s]["techniques"] for s in STRATUM_IDS):
        return ("No checks have run yet.\n"
                f"   → Next: xetra run --config {config_path}      (safe: everything is simulated until you connect real tools)\n"
                f"     or:   xetra start --config {config_path}    (opens the dashboard)")
    mode = "LIVE" if all(config[k]["provider"] != "mock" for k in ("bas", "siem", "soar", "edr")) else "SIMULATED (not audit evidence)"
    lines = [f"Mode: {mode}", ""]
    lines.append(f"{'':3}{'Stratum':<26}{'Tested':>10}{'Caught':>8}{'Gaps':>6}{'Unknown':>9}   Last tested")
    for s in STRATA:
        defined = sum(len(t["attack_ids"]) for t in ttps if t["stratum"] == s["id"])
        sm = views.stratum_summary(post[s["id"]], defined)
        last = "never"
        if sm["last_tested_at"]:
            mins = (datetime.now(timezone.utc) - datetime.fromisoformat(sm["last_tested_at"])).total_seconds() / 60
            last = f"{mins:.0f} min ago" if mins < 120 else f"{mins/60:.1f} h ago"
        lines.append(f"{_ICON[sm['health']]} {s['n']} {s['name']:<23}{sm['tested']:>5}/{defined:<4}{sm['caught']:>8}{sm['gaps']:>6}{sm['not_tested']:>9}   {last}")
    rems = store.remediations()
    lines += ["", f"Fix list: {sum(r['status']=='open' for r in rems)} open · {sum(r['status']=='approved' for r in rems)} approved · "
                  f"{sum(r['status']=='verified' for r in rems)} verified",
              "Dashboard: xetra start"]
    return "\n".join(lines)


def main():
    print(render_status(sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"))


if __name__ == "__main__":
    main()
