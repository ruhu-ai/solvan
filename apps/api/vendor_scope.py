"""Bounded vendor scope-inspection transport and deployment host mapping."""

from __future__ import annotations

from typing import Any

import httpx

VENDOR_SCOPE_HOSTS = {
    "DATADOG": "SOLVAN_DATADOG_API_HOST",
    "GRAFANA": "SOLVAN_GRAFANA_API_HOST",
}


class VendorTransport:
    """One bounded outbound read, with no Google credential attached."""

    def get(self, url: str, **kwargs: Any) -> Any:
        return httpx.get(url, **kwargs)
