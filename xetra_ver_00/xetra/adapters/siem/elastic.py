"""
Elastic adapter — shaped to the Elasticsearch Query DSL via the
_search API (https://www.elastic.co/guide/.../search-search.html).

Setup: set ELASTIC_URL + ELASTIC_API_KEY, map attack_id -> an index +
DSL query in config.yaml under siem.elastic.query_map.
"""
from __future__ import annotations
import os
from typing import Any

from .base import SIEMAdapter, AlertCheckResult

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    requests = None


class ElasticAdapter(SIEMAdapter):
    name = "elastic"

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 query_map: dict[str, dict] | None = None):
        self.base_url = base_url or os.environ.get("ELASTIC_URL", "")
        self.api_key = api_key or os.environ.get("ELASTIC_API_KEY", "")
        self.query_map = query_map or {}

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and requests is not None)

    def check_alert(self, attack_id: str, time_window_minutes: int = 30) -> AlertCheckResult:
        if not self.is_configured():
            raise RuntimeError("ElasticAdapter not configured. Set ELASTIC_URL and ELASTIC_API_KEY.")
        q = self.query_map.get(attack_id)
        if not q:
            raise ValueError(f"No Elastic query mapped for {attack_id}.")
        index = q.get("index", "logs-*")
        body = q.get("query", {"match_all": {}})
        resp = requests.post(
            f"{self.base_url}/{index}/_search",
            headers={"Authorization": f"ApiKey {self.api_key}"},
            json={"query": body, "size": 5}, timeout=30,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return AlertCheckResult(
            technique_id=attack_id, alert_found=len(hits) > 0, alert_count=len(hits),
            query_used=f"{index}: {body}", detail={"hits": hits},
        )
