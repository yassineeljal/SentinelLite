"""Turns an alert's source address into what an analyst wants to know about it.

Enrichment is best effort and never on the detection path: alerts are stored first, then enriched
asynchronously (`workers/enricher.py`), so a missing database or a slow provider can only leave an
alert without context, never lose or delay it.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from sentinel_core.enrichment.geoip import GeoInfo, GeoIpResolver


class Enrichment(BaseModel):
    """Stored as JSON on the alert. New providers add fields here (all optional)."""

    model_config = ConfigDict(frozen=True)

    # "public": a routable address (geo may still be unknown); "non_public": private, loopback,
    # link-local, documentation or other reserved range: there is nothing to look up.
    ip_scope: Literal["public", "non_public"]
    geo: GeoInfo | None = None


class Enricher:
    def __init__(self, geoip: GeoIpResolver) -> None:
        self._geoip = geoip

    def enrich(self, src_ip: str | None) -> Enrichment | None:
        """None when the alert has no source address (nothing to say about it)."""
        if not src_ip:
            return None
        if not self._geoip.is_public(src_ip):
            return Enrichment(ip_scope="non_public")
        return Enrichment(ip_scope="public", geo=self._geoip.lookup(src_ip))
