"""Read-only views assembled for the dashboard: one place that turns raw
state into 'what is true right now' — including the single next action."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..providers import STRATA, STRATUM_IDS, CATEGORIES
from ..orchestrator import load_all_ttps

STALE_AFTER_MIN_DEFAULT = 24 * 60


def _age_min(iso: str | None) -> float | None:
    if not iso:
        return None
    return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds() / 60


def stratum_summary(post_s: dict, total_defined: int) -> dict:
    techs = post_s["techniques"]
    caught = sum(1 for t in techs.values() if t["status"] == "caught")
    gaps = sum(1 for t in techs.values() if t["status"] == "gap")
    nt = sum(1 for t in techs.values() if t["status"] == "not_tested")
    last = max((t["tested_at"] for t in techs.values()), default=None)
    if not techs:
        health = "never_run"
    elif gaps:
        health = "gaps"
    elif nt:
        health = "not_tested"
    elif len(techs) < total_defined:
        health = "partial"
    else:
        health = "healthy"
    return {"defined": total_defined, "tested": len(techs), "caught": caught, "gaps": gaps,
            "not_tested": nt, "last_tested_at": last, "health": health,
            "modes": sorted({t.get("mode", "mock") for t in techs.values()})}


def overview(config: dict, store, engine, config_path: str, connections: dict) -> dict:
    ttps = load_all_ttps(config.get("include_extended_attack_library", True))
    defined = {s: len({a for t in ttps if t["stratum"] == s for a in t["attack_ids"]}) for s in STRATUM_IDS}
    post = store.posture()
    sch = engine.schedule_view()
    threshold = config.get("stale_after_minutes") or (int(sch["every_minutes"]) * 3 if sch["enabled"] else STALE_AFTER_MIN_DEFAULT)
    strata = []
    for s in STRATA:
        summ = stratum_summary(post[s["id"]], defined[s["id"]])
        hist = post[s["id"]]["history"][-12:]
        age = _age_min(summ["last_tested_at"])
        strata.append({**s, **summ, "trend": [h["gaps_total"] for h in hist],
                       "age_minutes": None if age is None else round(age, 1),
                       "stale": age is not None and age > threshold})
    rems = store.remediations()
    open_fixes = [r for r in rems if r["status"] in ("open",)]
    approved = [r for r in rems if r["status"] == "approved"]
    modes = {k: config[k]["provider"] for k in ("bas", "siem", "soar", "edr", "llm")}
    live_core = all(modes[k] != "mock" for k in ("bas", "siem", "soar", "edr"))
    app = store.app_state()
    runs = store.runs()
    last_full = next((r for r in reversed(runs) if r.get("state") == "completed" and not r.get("partial")), None)
    last_any = next((r for r in reversed(runs) if r.get("state") == "completed"), None)
    job = engine.job()
    last_age = _age_min(last_any["finished_at"]) if last_any else None
    running_now = bool(job and job["state"] in ("running", "stopping"))
    stale = {"threshold_minutes": threshold, "stale": bool(last_age is not None and last_age > threshold and not running_now),
             "last_run_age_minutes": None if last_age is None else round(last_age, 1),
             "scheduler_overdue": bool(sch["enabled"] and last_age is not None and last_age > threshold and not running_now)}
    trend = [{"ts": r["finished_at"], **r["posture"]} for r in runs if r.get("state") == "completed" and r.get("posture")][-20:]
    total_tested = sum(s["tested"] for s in strata)

    # ---- the one thing to do next (no guessing)
    nxt: dict[str, Any]
    if app.get("paused"):
        nxt = {"title": "XETRA is paused", "body": "No runs will start until you resume.", "action": "resume", "label": "Resume XETRA"}
    elif job and job["state"] in ("running", "stopping"):
        nxt = {"title": "A run is in progress", "body": "Watch it below. You can stop it at any time.", "action": None}
    elif total_tested == 0:
        nxt = {"title": "Run your first check", "body": "Everything is simulated right now, so this is safe and takes a few seconds. You'll see all seven strata fill in.",
               "action": "run_all", "label": "Run all 7 strata"}
    elif open_fixes:
        nxt = {"title": f"{len(open_fixes)} gap{'s' if len(open_fixes) != 1 else ''} need a decision",
               "body": "Each one is a technique your controls did not catch. Approve the proposed fix, or record why you accept the risk.",
               "action": "goto", "target": "fixes", "label": "Open the fix list"}
    elif not live_core:
        nxt = {"title": "Connect your real tools", "body": "You're still on simulated data, which is not audit evidence. Switch one category at a time, testing each.",
               "action": "goto", "target": "setup", "label": "Go to Setup"}
    elif any(s["health"] in ("never_run", "partial") for s in strata):
        nxt = {"title": "Some strata haven't been fully tested", "body": "Run all strata so every band is filled in.", "action": "run_all", "label": "Run all 7 strata"}
    else:
        nxt = {"title": "All clear", "body": "Everything tested is caught. XETRA keeps checking on your schedule.", "action": None}

    setup_items = []
    for k, c in CATEGORIES.items():
        p = config[k]["provider"]
        conn = connections.get(k, {})
        state = ("off" if p == "none" else "simulated" if p in ("mock",) else
                 "verified" if conn.get("provider") == p and conn.get("ok") and conn.get("verified") else
                 "reachable" if conn.get("provider") == p and conn.get("ok") else
                 "failed" if conn.get("provider") == p and conn.get("ok") is False else "untested")
        setup_items.append({"category": k, "label": c["label"], "provider": p, "state": state, "required": c["required"]})

    return {
        "now": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if live_core else "mock",
        "adapter_modes": modes,
        "paused": bool(app.get("paused")),
        "schedule": sch, "stale": stale, "trend": trend,
        "job": job,
        "strata": strata,
        "totals": {"defined": sum(defined.values()), "tested": total_tested,
                   "caught": sum(s["caught"] for s in strata), "gaps": sum(s["gaps"] for s in strata),
                   "not_tested": sum(s["not_tested"] for s in strata)},
        "fixes": {"open": len(open_fixes), "approved": len(approved),
                  "verified": sum(1 for r in rems if r["status"] == "verified"),
                  "risk_accepted": sum(1 for r in rems if r["status"] == "risk_accepted")},
        "last_full_run": last_full, "last_run": last_any,
        "next": nxt, "setup": setup_items,
        "live_playbooks": bool(config.get("respond", {}).get("allow_live_playbooks")),
    }


def stratum_detail(sid: str, config: dict, store) -> dict:
    ttps = [t for t in load_all_ttps(config.get("include_extended_attack_library", True)) if t["stratum"] == sid]
    post = store.posture()[sid]
    rems = {(r["stratum"], r["technique_id"]): r for r in store.remediations()}
    rows, seen = [], set()
    for t in ttps:
        for a in t["attack_ids"]:
            if a in seen:      # same technique listed under two entries: one row, one result
                continue
            seen.add(a)
            res = post["techniques"].get(a)
            rows.append({
                "technique_id": a, "ttp_id": t["id"], "description": " ".join(t.get("description", "").split()),
                "expected_control": t.get("expected_control", ""),
                "status": res["status"] if res else "untested",
                "bas_outcome": res["bas_outcome"] if res else None,
                "siem_alerted": res["siem_alerted"] if res else None,
                "tested_at": res["tested_at"] if res else None,
                "mode": res.get("mode") if res else None,
                "detail": res["detail"] if res else None,
                "fix": rems.get((sid, a)),
            })
    meta = next(s for s in STRATA if s["id"] == sid)
    from ..agents.respond import PLAYBOOK_MAP
    from ..agents.harden import REMEDIATION_HINTS
    return {**meta, **stratum_summary(post, len(rows)), "rows": rows, "history": post["history"],
            "playbook": PLAYBOOK_MAP.get(sid), "hint": REMEDIATION_HINTS.get(sid)}
