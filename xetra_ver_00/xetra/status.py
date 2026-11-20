"""
`xetra status` — what's actually true right now, in one screen.
No ambiguity: if there's no data yet, it says so and tells you the exact
next command. If the last cycle is old, it says exactly how old and
what "too old" means for this config.
"""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .orchestrator import load_config

STALENESS_THRESHOLD_MINUTES = 15  # default cycle cadence is 5 min; 3 missed = stale


def _latest_evidence(evidence_dir: Path) -> dict | None:
    files = sorted(evidence_dir.glob("xetra-attest-*.json"))
    if not files:
        return None
    data = json.loads(files[-1].read_text())
    data["_file"] = files[-1].name
    data["_all_files_count"] = len(files)
    return data


def render_status(config_path: str = "config/config.yaml") -> str:
    lines = []
    try:
        config = load_config(config_path)
    except Exception as e:
        return (f"❌ Cannot read {config_path}: {e}\n"
                f"   → Fix: cp config/config.example.yaml {config_path}")

    evidence_dir = Path(config.get("evidence_output_dir", "evidence_output"))
    data = _latest_evidence(evidence_dir)

    if data is None:
        return (
            "No cycles have run yet.\n"
            "   → Next step: python -m xetra.cli doctor --config " + config_path + "\n"
            "               then: python -m xetra.cli run --config " + config_path
        )

    gen_at = datetime.fromisoformat(data["generated_at"])
    age_minutes = (datetime.now(timezone.utc) - gen_at).total_seconds() / 60
    stale = age_minutes > STALENESS_THRESHOLD_MINUTES

    lines.append(f"Last cycle:   {data['cycle_label']}  ({data['_file']})")
    lines.append(f"Generated:    {data['generated_at']}  ({age_minutes:.1f} min ago)"
                  + ("  ⚠️  STALE — no recent cycle, check the scheduler is running" if stale else "  ✅ fresh"))
    lines.append(f"Total cycles on disk: {data['_all_files_count']}")
    lines.append("")

    mock = data.get("mock_mode", True)
    lines.append(f"Mode: {'⚠️  MOCK (not real evidence)' if mock else '✅ LIVE (real evidence)'}")
    if data.get("adapter_modes"):
        for k, v in data["adapter_modes"].items():
            # "mock" is always worth flagging. "none" only applies to llm
            # (an optional advisory add-on, not a validation source) and
            # is its normal, fully-supported default — not a problem.
            flag = "⚠️ " if v == "mock" else "✅"
            lines.append(f"  {flag} {k}: {v}")
    lines.append("")

    s = data.get("summary", {})
    lines.append(f"Techniques tested:      {s.get('techniques_tested', '?')}")
    lines.append(f"Gaps found:             {s.get('gaps_found', '?')}")
    lines.append(f"Recoveries validated:   {s.get('recoveries_validated', '?')}")
    still_gapped = s.get('recoveries_still_gapped', 0)
    flag = " ⚠️  ACTION NEEDED" if still_gapped else ""
    lines.append(f"Recoveries still open:  {still_gapped}{flag}")
    lines.append("")

    if data.get("mock_mode_warning"):
        lines.append("⚠️  " + data["mock_mode_warning"])
        lines.append("")

    lines.append(f"Dashboard: http://localhost:{config.get('_port', 8420)}  "
                  "(run `python -m xetra.cli serve` if not already running)")
    return "\n".join(lines)


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    print(render_status(config_path))


if __name__ == "__main__":
    main()
