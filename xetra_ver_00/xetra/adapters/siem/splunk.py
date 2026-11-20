"""
Splunk adapter — shaped to Splunk's documented REST search API
(/services/search/jobs). Requires a real Splunk instance, a token, and
a saved search / SPL query per ATT&CK technique mapped in your config
(see docs/DETECTION_CONTENT.md).
"""
from __future__ import annotations
import os
import time
from typing import Any

from .base import SIEMAdapter, AlertCheckResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class SplunkAdapter(SIEMAdapter):
    name = "splunk"

    def __init__(self, base_url: str | None = None, token: str | None = None,
                 query_map: dict[str, str] | None = None):
        self.base_url = base_url or os.environ.get("SPLUNK_BASE_URL", "")
        self.token = token or os.environ.get("SPLUNK_TOKEN", "")
        self.query_map = query_map or {}

    def is_configured(self) -> bool:
        return bool(self.base_url and self.token and requests is not None)

    def check_alert(self, attack_id: str, time_window_minutes: int = 30) -> AlertCheckResult:
        if not self.is_configured():
            raise RuntimeError(
                "SplunkAdapter not configured. Set SPLUNK_BASE_URL and "
                "SPLUNK_TOKEN and provide a query_map entry for this "
                "technique in config.yaml under siem.splunk.query_map."
            )
        spl = self.query_map.get(attack_id)
        if not spl:
            raise ValueError(f"No Splunk query mapped for {attack_id}.")

        headers = {"Authorization": f"Bearer {self.token}"}
        search = f"search earliest=-{time_window_minutes}m {spl}"
        job = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=headers, data={"search": search, "output_mode": "json"}, timeout=30,
        )
        job.raise_for_status()
        sid = job.json()["sid"]

        for _ in range(10):
            status = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}",
                headers=headers, params={"output_mode": "json"}, timeout=30,
            ).json()
            if status.get("entry", [{}])[0].get("content", {}).get("isDone"):
                break
            time.sleep(1)

        results = requests.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            headers=headers, params={"output_mode": "json"}, timeout=30,
        ).json()
        rows = results.get("results", [])
        return AlertCheckResult(
            technique_id=attack_id,
            alert_found=len(rows) > 0,
            alert_count=len(rows),
            query_used=search,
            detail={"rows": rows[:5]},
        )
