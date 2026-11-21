"""
StateStore — everything XETRA remembers between runs, in plain files you
can open, diff and back up. No database.

  <state_dir>/events.jsonl        append-only audit trail (every action, who/what/when)
  <state_dir>/posture.json        latest result per TECHNIQUE, grouped by stratum
  <state_dir>/remediations.json   the fix list and its human decisions
  <state_dir>/runs.json           history of runs (small summaries)
  <state_dir>/mock_state.json     which simulated gaps a human has "fixed" (mock mode only)
  <state_dir>/secrets.env         credentials (chmod 600) — never returned by any API

WHY posture is keyed per technique and not per run: a run of one stratum
must never hide what earlier runs learned about the others. The previous
version showed only the most recent evidence file, so running one stratum
made the other six disappear from the dashboard. Here, a run only ever
*updates* the techniques it actually tested.
"""
from __future__ import annotations
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..providers import STRATUM_IDS

_lock = threading.RLock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex[:6]}.tmp")
    tmp.write_text(text)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


class StateStore:
    HISTORY_PER_STRATUM = 60
    MAX_RUNS = 200

    def __init__(self, state_dir: str | Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ helpers
    def _read(self, name: str, default):
        p = self.dir / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except Exception:
            # A corrupt state file must never take the dashboard down.
            # Keep the broken copy for forensics and start clean.
            p.rename(p.with_suffix(".corrupt-" + uuid.uuid4().hex[:4]))
            return default

    def _write(self, name: str, data) -> None:
        _atomic_write(self.dir / name, json.dumps(data, indent=2, default=str))

    # ------------------------------------------------------------- events
    def event(self, kind: str, message: str, level: str = "info", **data) -> dict:
        ev = {"ts": now_iso(), "kind": kind, "level": level, "message": message}
        if data:
            ev["data"] = data
        with _lock:
            with open(self.dir / "events.jsonl", "a") as f:
                f.write(json.dumps(ev, default=str) + "\n")
        return ev

    def events(self, limit: int = 200, kind_prefix: str | None = None, level: str | None = None) -> list[dict]:
        p = self.dir / "events.jsonl"
        if not p.exists():
            return []
        out: list[dict] = []
        with _lock:
            lines = p.read_text().splitlines()
        for line in reversed(lines):
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if kind_prefix and not ev.get("kind", "").startswith(kind_prefix):
                continue
            if level and ev.get("level") != level:
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return out

    # ------------------------------------------------------------ posture
    def posture(self) -> dict:
        data = self._read("posture.json", {})
        for sid in STRATUM_IDS:
            data.setdefault(sid, {"techniques": {}, "history": []})
        return data

    def update_posture(self, findings: list[dict], run_id: str, mode: str, ttp_meta: dict[str, dict]) -> None:
        """Merge findings into posture. Only techniques present in `findings` change."""
        ts = now_iso()
        with _lock:
            post = self.posture()
            touched: dict[str, list[dict]] = {}
            for f in findings:
                sid = f["stratum"]
                post[sid]["techniques"][f["technique_id"]] = {
                    **f, "tested_at": ts, "run_id": run_id, "mode": mode,
                    "ttp_id": ttp_meta.get(f["technique_id"], {}).get("ttp_id"),
                }
                touched.setdefault(sid, []).append(f)
            for sid, fs in touched.items():
                techs = post[sid]["techniques"].values()
                post[sid]["history"].append({
                    "ts": ts, "run_id": run_id, "mode": mode,
                    "tested_now": len(fs),
                    "gaps_now": sum(1 for f in fs if f["status"] == "gap"),
                    "tracked": len(post[sid]["techniques"]),
                    "gaps_total": sum(1 for t in techs if t["status"] == "gap"),
                    "not_tested_total": sum(1 for t in techs if t["status"] == "not_tested"),
                })
                post[sid]["history"] = post[sid]["history"][-self.HISTORY_PER_STRATUM:]
            self._write("posture.json", post)

    # ------------------------------------------------------- remediations
    def remediations(self) -> list[dict]:
        return self._read("remediations.json", [])

    def sync_remediations(self, findings: list[dict], hint_for, run_id: str) -> dict[str, int]:
        """Open items for new gaps; auto-verify items whose technique now passes;
        re-open verified items that regress. Never touches human decisions otherwise."""
        counts = {"opened": 0, "verified": 0, "regressed": 0}
        with _lock:
            items = self.remediations()
            by_tech = {f"{i['stratum']}:{i['technique_id']}": i for i in items}
            for f in findings:
                tid, st = f["technique_id"], f["status"]
                key = f"{f['stratum']}:{tid}"
                item = by_tech.get(key)
                if st == "gap":
                    if item is None:
                        item = {"id": uuid.uuid4().hex[:8], "technique_id": tid, "stratum": f["stratum"],
                                "recommended_action": hint_for(f["stratum"]), "status": "open",
                                "opened_at": now_iso(), "opened_in_run": run_id, "history": [], "note": ""}
                        items.append(item); by_tech[key] = item; counts["opened"] += 1
                        self.event("fix.opened", f"New gap on {tid} ({f['stratum']}) added to the fix list.", technique=tid)
                    elif item["status"] == "verified":
                        item["status"] = "open"; counts["regressed"] += 1
                        item["history"].append({"ts": now_iso(), "to": "open", "by": "xetra", "note": "Regressed: gap seen again after verification."})
                        self.event("fix.regressed", f"{tid} regressed — it was verified fixed, now missed again.", level="warn", technique=tid)
                elif st == "caught" and item and item["status"] in ("open", "approved"):
                    item["status"] = "verified"; counts["verified"] += 1
                    item["verified_at"] = now_iso()
                    item["history"].append({"ts": now_iso(), "to": "verified", "by": "xetra", "note": f"Retest in {run_id} caught the technique."})
                    self.event("fix.verified", f"{tid} is now caught — fix verified by retest.", technique=tid)
            self._write("remediations.json", items)
        return counts

    def set_remediation_status(self, rem_id: str, status: str, actor: str, note: str = "") -> dict:
        allowed = {"open", "approved", "risk_accepted"}
        if status not in allowed:
            raise ValueError(f"Status must be one of {sorted(allowed)} (xetra sets 'verified' itself after a passing retest).")
        if status == "risk_accepted" and (not actor.strip() or not note.strip()):
            raise ValueError("Accepting a risk needs your name and a reason — it goes into the audit record.")
        if not actor.strip():
            raise ValueError("Enter your name so the decision is attributable.")
        with _lock:
            items = self.remediations()
            for it in items:
                if it["id"] == rem_id:
                    it["status"] = status
                    it["note"] = note
                    it["history"].append({"ts": now_iso(), "to": status, "by": actor.strip(), "note": note})
                    self._write("remediations.json", items)
                    self.event("fix.decision", f"{actor.strip()} set {it['technique_id']} → {status}.",
                               technique=it["technique_id"], status=status, note=note)
                    return it
        raise KeyError(rem_id)

    # --------------------------------------------------------------- runs
    def runs(self) -> list[dict]:
        return self._read("runs.json", [])

    def record_run(self, summary: dict) -> None:
        with _lock:
            runs = self.runs()
            runs = [r for r in runs if r.get("run_id") != summary.get("run_id")]
            runs.append(summary)
            self._write("runs.json", runs[-self.MAX_RUNS:])

    # ------------------------------------------------------- mock "fixes"
    def mock_fixed(self) -> set[str]:
        return set(self._read("mock_state.json", {}).get("fixed", []))

    def mock_mark_fixed(self, technique_ids: list[str]) -> None:
        with _lock:
            cur = self.mock_fixed() | set(technique_ids)
            self._write("mock_state.json", {"fixed": sorted(cur)})

    # ---------------------------------------------------------- app state
    def app_state(self) -> dict:
        return self._read("app_state.json", {"paused": False, "schedule": {"enabled": False, "every_minutes": 60}})

    def set_app_state(self, **patch) -> dict:
        with _lock:
            st = self.app_state(); st.update(patch)
            self._write("app_state.json", st)
            return st
