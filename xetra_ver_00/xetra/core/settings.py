"""
Settings — reading/writing config.yaml and the secrets file, safely.

 * config.yaml holds choices and non-secret values (which provider, scope,
   model name). Safe to commit to a private repo.
 * <state_dir>/secrets.env holds credentials AND vendor URLs/IDs as
   environment-variable lines. chmod 600. Loaded into os.environ so the
   adapters (which read env vars) just work. No API ever returns a secret
   value — only whether it is set and its last four characters.
"""
from __future__ import annotations
import copy
import os
import shutil
from pathlib import Path
from typing import Any

import yaml

from ..providers import CATEGORIES, PROVIDERS
from .store import _atomic_write

DEFAULT_CONFIG: dict[str, Any] = {
    "state_dir": ".xetra",
    "evidence_output_dir": "evidence_output",
    "include_extended_attack_library": True,
    "stale_after_minutes": None,      # None = 3x the schedule interval, or 24 h if no schedule
    "bas": {"provider": "mock", "options": {}},
    "siem": {"provider": "mock", "options": {}},
    "soar": {"provider": "mock", "options": {}},
    "edr": {"provider": "mock", "options": {}},
    "llm": {"provider": "none", "options": {}},
    "respond": {"allow_live_playbooks": False},
    "scope": {
        "authorized_by": "",
        "environment": "staging",
        "targets": [],
        "attackiq_assessment_map": {},
    },
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config_file(path: str | Path) -> dict:
    """Load config, filling anything missing from defaults. Creates an
    all-simulated config if the file does not exist — so a first run never
    dead-ends on 'file not found'."""
    p = Path(path)
    if not p.exists():
        save_config_file(p, DEFAULT_CONFIG)
    raw = yaml.safe_load(p.read_text()) or {}
    return _deep_merge(DEFAULT_CONFIG, raw)


def save_config_file(path: str | Path, config: dict) -> None:
    p = Path(path)
    if p.exists():
        shutil.copy2(p, p.with_suffix(p.suffix + ".bak"))
    _atomic_write(p, yaml.safe_dump(config, sort_keys=False))


def state_dir_for(config: dict, config_path: str | Path) -> Path:
    """State lives next to the project root: the parent of config/ when the
    config sits in a folder called config, otherwise beside the config file."""
    sd = Path(config.get("state_dir", ".xetra"))
    if sd.is_absolute():
        return sd
    cfg_dir = Path(config_path).resolve().parent
    root = cfg_dir.parent if cfg_dir.name == "config" else cfg_dir
    return root / sd


# ---------------------------------------------------------------- secrets
class SecretsFile:
    def __init__(self, path: Path):
        self.path = path

    def read(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if not self.path.exists():
            return out
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
        return out

    def write(self, values: dict[str, str]) -> None:
        body = "# XETRA credentials — written by the dashboard. Keep private (chmod 600).\n"
        body += "".join(f'{k}="{v}"\n' for k, v in sorted(values.items()) if v != "")
        _atomic_write(self.path, body, mode=0o600)

    def apply_to_environ(self) -> None:
        for k, v in self.read().items():
            # Real environment variables win — so Docker/K8s secrets keep working
            # and an operator can always override the file.
            os.environ.setdefault(k, v)

    def set_many(self, updates: dict[str, str | None]) -> None:
        cur = self.read()
        for k, v in updates.items():
            if v is None or v == "":
                cur.pop(k, None)
                os.environ.pop(k, None)
            else:
                cur[k] = v
                os.environ[k] = v          # explicit user action: applies immediately
        self.write(cur)


def mask(value: str) -> str:
    if not value:
        return ""
    return "•" * 8 + value[-4:] if len(value) > 8 else "•" * len(value)


def field_states(category: str, provider: str, secrets: SecretsFile) -> list[dict]:
    """What the UI needs to render the form: per field, is it set, and (if not
    secret) its value. Secret values are never included."""
    saved = secrets.read()
    out = []
    for f in PROVIDERS[category][provider]["fields"]:
        val = os.environ.get(f["env"], "") or saved.get(f["env"], "")
        src = "environment" if f["env"] in os.environ and f["env"] not in saved else ("file" if f["env"] in saved else "")
        if not val and f.get("default"):
            val_for_ui, is_set = f["default"], False
        else:
            val_for_ui, is_set = val, bool(val)
        out.append({
            "env": f["env"], "label": f["label"], "kind": f["kind"], "help": f["help"],
            "placeholder": f["placeholder"], "set": is_set, "source": src,
            "value": val_for_ui if f["kind"] == "text" else "",
            "masked": mask(val) if f["kind"] == "secret" and val else "",
        })
    return out


def validate_provider_choice(category: str, provider: str) -> None:
    if category not in CATEGORIES:
        raise ValueError(f"Unknown category '{category}'.")
    if provider not in PROVIDERS[category]:
        raise ValueError(f"'{provider}' is not a {category} option. Choose one of: {', '.join(PROVIDERS[category])}.")


def evidence_dir_for(config: dict, config_path: str | Path) -> Path:
    ed = Path(os.environ.get("XETRA_EVIDENCE_DIR") or config.get("evidence_output_dir", "evidence_output"))
    if ed.is_absolute():
        return ed
    cfg_dir = Path(config_path).resolve().parent
    root = cfg_dir.parent if cfg_dir.name == "config" else cfg_dir
    return root / ed
