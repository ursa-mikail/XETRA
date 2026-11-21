"""
Engine — runs cycles in the background, one at a time, and lets a person
watch, stop, pause and schedule them.

Controllability guarantees (each is tested):
  * One run at a time; a second request gets a clear "already running" answer.
  * Stop takes effect between techniques (seconds, not minutes) and a stopped
    run saves NO partial results, so half a run can never look like a result.
  * Pause blocks every trigger — manual and scheduled — until resumed.
  * The scheduler is visible: next run time is always shown, and it can be
    turned off with one switch.
"""
from __future__ import annotations
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .store import StateStore, now_iso
from .settings import load_config_file, state_dir_for
from ..agents.hunt import RunCancelled
from ..providers import STRATUM_IDS

STAGES = ["hunt", "harden", "respond", "recover", "attest"]


class Busy(Exception):
    pass


class Paused(Exception):
    pass


class Engine:
    def __init__(self, config_path: str):
        self.config_path = str(config_path)
        cfg = load_config_file(config_path)
        self.store = StateStore(state_dir_for(cfg, config_path))
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._job: dict[str, Any] | None = None       # current or most recent
        self._thread: threading.Thread | None = None
        self._sched_thread: threading.Thread | None = None
        self._stop_sched = threading.Event()
        self._next_run_at: datetime | None = None

    # ------------------------------------------------------------- job view
    def job(self) -> dict[str, Any] | None:
        with self._lock:
            if self._job is None:
                return None
            j = dict(self._job)
            j["log"] = list(self._job["log"])[-120:]
            j["stages"] = dict(self._job["stages"])
            return j

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._job and self._job["state"] in ("running", "stopping"))

    # -------------------------------------------------------------- start/stop
    def start(self, strata: list[str] | None = None, label: str | None = None, trigger: str = "manual") -> dict:
        if self.store.app_state().get("paused"):
            raise Paused("XETRA is paused. Resume it (top bar) before starting a run.")
        strata = [s for s in (strata or []) if s] or None
        if strata:
            bad = [s for s in strata if s not in STRATUM_IDS]
            if bad:
                raise ValueError(f"Unknown stratum {bad}.")
        with self._lock:
            if self._job and self._job["state"] in ("running", "stopping"):
                raise Busy("A run is already in progress. Wait for it to finish or press Stop.")
            run_id = uuid.uuid4().hex[:8]
            scope_name = "all" if not strata or set(strata) == set(STRATUM_IDS) else "+".join(strata)
            label = label or f"{trigger}-{scope_name}"
            self._cancel.clear()
            self._job = {"run_id": run_id, "state": "running", "label": label, "trigger": trigger,
                         "requested_strata": strata or list(STRATUM_IDS), "started_at": now_iso(),
                         "stages": {s: "pending" for s in STAGES}, "progress": {"i": 0, "n": 0},
                         "technique_status": {}, "log": deque(maxlen=400), "error": None, "result_file": None}
            self._thread = threading.Thread(target=self._run, args=(run_id, strata, label, trigger), daemon=True)
            self._thread.start()
        return {"run_id": run_id, "state": "running"}

    def cancel(self) -> bool:
        with self._lock:
            if not (self._job and self._job["state"] == "running"):
                return False
            self._job["state"] = "stopping"
            self._job["log"].append({"ts": now_iso(), "msg": "Stop requested — finishing the current technique…"})
        self._cancel.set()
        self.store.event("run.stop_requested", "A person pressed Stop.", level="warn", run_id=self._job["run_id"])
        return True

    def _progress(self, stage: str, payload: dict) -> None:
        with self._lock:
            j = self._job
            if j is None:
                return
            if stage == "start":
                j["progress"]["n"] = payload["total"]
                j["mode"] = payload["mode"]
                j["covered"] = payload["strata"]
                j["log"].append({"ts": now_iso(), "msg": f"Starting: {len(payload['strata'])} strata, {payload['total']} techniques ({payload['mode']})."})
            elif stage == "stage":
                j["stages"][payload["name"]] = payload["state"]
                extra = ""
                if payload["name"] == "respond" and payload["state"] == "done":
                    extra = f" — {payload.get('triggered', 0)} playbook(s) run" + (f", {payload['held']} held until you enable live playbooks" if payload.get("held") else "")
                if payload["name"] == "harden" and payload["state"] == "done":
                    extra = f" — {payload.get('items', 0)} fix(es) proposed"
                if payload["name"] == "recover" and payload["state"] == "done":
                    extra = f" — {payload.get('retested', 0)} gap(s) retested"
                j["log"].append({"ts": now_iso(), "msg": f"{payload['name'].upper()} {payload['state']}{extra}"})
            elif stage == "technique":
                j["progress"]["i"] = payload["i"]
                j["technique_status"][payload["technique"]] = payload["status"]
                if payload["status"] != "caught":
                    j["log"].append({"ts": now_iso(), "msg": f"{payload['technique']} ({payload['stratum']}): {payload['status'].replace('_', ' ')}"})

    def _run(self, run_id: str, strata, label: str, trigger: str) -> None:
        from ..orchestrator import XetraOrchestrator   # late import: config re-read every run
        final: dict[str, Any] = {}
        try:
            orch = XetraOrchestrator(self.config_path)
            path = orch.run_cycle(cycle_label=label, strata=strata, progress=self._progress,
                                  should_cancel=self._cancel.is_set, run_id=run_id, trigger=trigger)
            final = {"state": "completed", "result_file": path.name}
        except RunCancelled:
            final = {"state": "cancelled"}
        except Exception as e:
            final = {"state": "failed", "error": str(e)}
        with self._lock:
            self._job.update(final)
            self._job["finished_at"] = now_iso()
            msg = {"completed": "Run complete. Results saved.", "cancelled": "Run stopped. Nothing from it was saved.",
                   "failed": f"Run failed: {final.get('error')}"}[final["state"]]
            self._job["log"].append({"ts": now_iso(), "msg": msg})

    # ------------------------------------------------------------ pause
    def set_paused(self, paused: bool, actor: str = "dashboard") -> dict:
        st = self.store.set_app_state(paused=paused)
        self.store.event("control.paused" if paused else "control.resumed",
                         "XETRA paused — no runs (manual or scheduled) will start." if paused else "XETRA resumed.",
                         level="warn" if paused else "info")
        return st

    # --------------------------------------------------------- scheduler
    def set_schedule(self, enabled: bool, every_minutes: int) -> dict:
        every = int(every_minutes)
        if not 5 <= every <= 10080:
            raise ValueError("Choose an interval between 5 minutes and 7 days.")
        self.store.set_app_state(schedule={"enabled": bool(enabled), "every_minutes": every}, schedule_user_set=True)
        self.store.event("control.schedule", f"Schedule {'on, every ' + str(every) + ' min' if enabled else 'off'}.")
        self._next_run_at = datetime.now(timezone.utc) + timedelta(minutes=every) if enabled else None
        return self.schedule_view()

    def apply_env_schedule(self, minutes: int) -> None:
        """Docker: XETRA_SCHEDULE_MINUTES turns the schedule on at start-up and runs
        once immediately if nothing has run yet. A person's own choice in the
        dashboard (including switching it off) always wins over the variable."""
        if self.store.app_state().get("schedule_user_set"):
            return
        self.store.set_app_state(schedule={"enabled": True, "every_minutes": int(minutes)})
        self._next_run_at = datetime.now(timezone.utc) if not self.store.runs() else \
            datetime.now(timezone.utc) + timedelta(minutes=int(minutes))
        self.store.event("control.schedule", f"Schedule on, every {minutes} min (from XETRA_SCHEDULE_MINUTES).")

    def schedule_view(self) -> dict:
        sch = self.store.app_state().get("schedule", {"enabled": False, "every_minutes": 60})
        return {**sch, "next_run_at": self._next_run_at.isoformat() if (sch["enabled"] and self._next_run_at) else None}

    def start_scheduler(self, tick_seconds: float = 5.0) -> None:
        if self._sched_thread and self._sched_thread.is_alive():
            return
        sch = self.store.app_state().get("schedule", {})
        if sch.get("enabled") and self._next_run_at is None:
            self._next_run_at = datetime.now(timezone.utc) + timedelta(minutes=int(sch.get("every_minutes", 60)))

        def loop():
            while not self._stop_sched.wait(tick_seconds):
                st = self.store.app_state()
                sch = st.get("schedule", {})
                if not sch.get("enabled") or st.get("paused") or self._next_run_at is None:
                    continue
                if datetime.now(timezone.utc) >= self._next_run_at and not self.is_running():
                    try:
                        self.start(None, trigger="scheduled")
                    except (Busy, Paused):
                        pass
                    except Exception as e:  # never let the scheduler thread die
                        self.store.event("run.failed", f"Scheduled run could not start: {e}", level="error")
                    self._next_run_at = datetime.now(timezone.utc) + timedelta(minutes=int(sch.get("every_minutes", 60)))
        self._sched_thread = threading.Thread(target=loop, daemon=True)
        self._sched_thread.start()

    def shutdown(self) -> None:
        self._stop_sched.set()
        self._cancel.set()
