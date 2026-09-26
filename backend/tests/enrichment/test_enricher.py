from pathlib import Path

import pytest

from sentinel_core.enrichment.enricher import Enricher, Enrichment
from sentinel_core.enrichment.geoip import GeoIpResolver
from tests.enrichment.geodb import PARIS_IP, UNKNOWN_IP, asn_db, city_db


@pytest.fixture
def enricher(tmp_path: Path) -> Enricher:
    return Enricher(GeoIpResolver(city_db(tmp_path / "c.mmdb"), asn_db(tmp_path / "a.mmdb")))


def test_a_public_address_is_located(enricher: Enricher) -> None:
    result = enricher.enrich(PARIS_IP)

    assert result is not None and result.ip_scope == "public"
    assert result.geo is not None and (result.geo.country_code, result.geo.asn) == ("FR", 64500)


def test_a_public_address_unknown_to_the_databases_is_still_public(enricher: Enricher) -> None:
    assert enricher.enrich(UNKNOWN_IP) == Enrichment(ip_scope="public", geo=None)


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.139.12", "203.0.113.7", "::1"])
def test_a_non_public_address_says_so_and_has_no_location(enricher: Enricher, ip: str) -> None:
    assert enricher.enrich(ip) == Enrichment(ip_scope="non_public", geo=None)


@pytest.mark.parametrize("ip", [None, ""])
def test_no_source_address_means_nothing_to_add(enricher: Enricher, ip: str | None) -> None:
    assert enricher.enrich(ip) is None


def test_the_enrichment_serialises_to_plain_json(enricher: Enricher) -> None:
    result = enricher.enrich(PARIS_IP)

    assert result is not None
    assert result.model_dump(mode="json") == {
        "ip_scope": "public",
        "geo": {
            "country_code": "FR",
            "country": "France",
            "city": "Paris",
            "latitude": 48.85,
            "longitude": 2.35,
            "asn": 64500,
            "as_org": "Example Hosting SARL",
        },
    }
