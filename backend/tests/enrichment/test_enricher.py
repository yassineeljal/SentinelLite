from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel_core.enrichment.abuseipdb import Reputation
from sentinel_core.enrichment.enricher import Enricher, Enrichment
from sentinel_core.enrichment.geoip import GeoIpResolver
from tests.enrichment.geodb import PARIS_IP, UNKNOWN_IP, asn_db, city_db


@pytest.fixture
def enricher(tmp_path: Path) -> Enricher:
    return Enricher(GeoIpResolver(city_db(tmp_path / "c.mmdb"), asn_db(tmp_path / "a.mmdb")))


async def test_a_public_address_is_located(enricher: Enricher) -> None:
    result = await enricher.enrich(PARIS_IP)

    assert result is not None and result.ip_scope == "public"
    assert result.geo is not None and (result.geo.country_code, result.geo.asn) == ("FR", 64500)


async def test_a_public_address_unknown_to_the_databases_is_still_public(
    enricher: Enricher,
) -> None:
    assert await enricher.enrich(UNKNOWN_IP) == Enrichment(ip_scope="public", geo=None)


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.139.12", "203.0.113.7", "::1"])
async def test_a_non_public_address_says_so_and_has_no_location(
    enricher: Enricher, ip: str
) -> None:
    assert await enricher.enrich(ip) == Enrichment(ip_scope="non_public", geo=None)


@pytest.mark.parametrize("ip", [None, ""])
async def test_no_source_address_means_nothing_to_add(enricher: Enricher, ip: str | None) -> None:
    assert await enricher.enrich(ip) is None


async def test_the_enrichment_serialises_to_plain_json(enricher: Enricher) -> None:
    result = await enricher.enrich(PARIS_IP)

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
        "reputation": None,
    }


class FakeReputation:
    def __init__(self, answer: Reputation | None) -> None:
        self.answer = answer
        self.asked: list[str] = []

    async def lookup(self, ip: str) -> Reputation | None:
        self.asked.append(ip)
        return self.answer


def rep() -> Reputation:
    return Reputation(
        score=97,
        total_reports=500,
        distinct_reporters=80,
        checked_at=datetime(2026, 9, 26, tzinfo=UTC),
    )


@pytest.fixture
def geoip(tmp_path: Path) -> GeoIpResolver:
    return GeoIpResolver(city_db(tmp_path / "c.mmdb"), asn_db(tmp_path / "a.mmdb"))


async def test_a_public_address_gets_its_reputation(geoip: GeoIpResolver) -> None:
    reputation = FakeReputation(rep())

    result = await Enricher(geoip, reputation).enrich(PARIS_IP)

    assert result is not None and result.reputation == rep()
    assert result.geo is not None and reputation.asked == [PARIS_IP]


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.139.12", "203.0.113.7", "127.0.0.1", "::1"])
async def test_a_non_public_address_is_never_sent_to_the_provider(
    geoip: GeoIpResolver, ip: str
) -> None:
    reputation = FakeReputation(rep())

    result = await Enricher(geoip, reputation).enrich(ip)

    assert result == Enrichment(ip_scope="non_public") and reputation.asked == []


async def test_no_answer_from_the_provider_leaves_the_rest_of_the_enrichment(
    geoip: GeoIpResolver,
) -> None:
    result = await Enricher(geoip, FakeReputation(None)).enrich(PARIS_IP)

    assert result is not None and result.reputation is None and result.geo is not None


async def test_without_a_provider_nothing_is_asked(geoip: GeoIpResolver) -> None:
    result = await Enricher(geoip).enrich(PARIS_IP)

    assert result is not None and result.reputation is None
