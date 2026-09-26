from pathlib import Path

import pytest

from sentinel_core.enrichment.geoip import GeoIpError, GeoIpResolver
from tests.enrichment.geodb import (
    ASN_ONLY_IP,
    PARIS_IP,
    TORONTO_IP,
    UNKNOWN_IP,
    asn_db,
    city_db,
    write_db,
)


@pytest.fixture
def resolver(tmp_path: Path) -> GeoIpResolver:
    return GeoIpResolver(city_db(tmp_path / "city.mmdb"), asn_db(tmp_path / "asn.mmdb"))


def test_a_public_address_gets_location_and_network(resolver: GeoIpResolver) -> None:
    result = resolver.lookup(PARIS_IP)

    assert result is not None
    assert (result.country_code, result.country, result.city) == ("FR", "France", "Paris")
    assert (result.latitude, result.longitude) == (48.85, 2.35)
    assert (result.asn, result.as_org) == (64500, "Example Hosting SARL")


def test_the_two_databases_are_independent(tmp_path: Path) -> None:
    only_city = GeoIpResolver(city_db(tmp_path / "c.mmdb"), None)
    only_asn = GeoIpResolver(None, asn_db(tmp_path / "a.mmdb"))

    assert only_city.lookup(PARIS_IP) is not None
    assert only_city.lookup(PARIS_IP).asn is None  # type: ignore[union-attr]
    found = only_asn.lookup(PARIS_IP)
    assert found is not None and found.country_code is None and found.asn == 64500


def test_a_record_without_a_city_or_coordinates_keeps_what_it_has(resolver: GeoIpResolver) -> None:
    result = resolver.lookup(ASN_ONLY_IP)

    assert result is not None
    assert (result.country_code, result.city, result.latitude) == ("AU", None, None)
    assert result.asn == 64501


def test_an_address_absent_from_the_databases_gives_nothing(resolver: GeoIpResolver) -> None:
    assert resolver.lookup(UNKNOWN_IP) is None


@pytest.mark.parametrize(
    "ip",
    [
        "10.1.2.3",
        "192.168.139.12",
        "172.16.0.9",
        "127.0.0.1",
        "169.254.1.1",
        "203.0.113.7",  # documentation range
        "::1",
        "fe80::1",
        "fd00::5",
        "0.0.0.0",  # noqa: S104 (an address to be refused, not a bind)
        "224.0.0.1",
    ],
)
def test_private_and_reserved_addresses_are_never_looked_up(
    resolver: GeoIpResolver, ip: str
) -> None:
    assert resolver.lookup(ip) is None
    assert resolver.is_public(ip) is False


def test_a_value_that_is_not_an_address_is_ignored(resolver: GeoIpResolver) -> None:
    assert resolver.lookup("not-an-ip") is None
    assert resolver.is_public("not-an-ip") is False


def test_ipv6_addresses_are_supported(tmp_path: Path) -> None:
    db = write_db(
        tmp_path / "v6.mmdb",
        "DBIP-City-Lite",
        {"2001:4860::/32": {"country": {"iso_code": "US", "names": {"en": "United States"}}}},
    )

    result = GeoIpResolver(db, None).lookup("2001:4860:4860::8888")

    assert result is not None and result.country_code == "US"


def test_odd_values_in_the_database_are_bounded_and_typed(tmp_path: Path) -> None:
    db = write_db(
        tmp_path / "odd.mmdb",
        "DBIP-City-Lite",
        {
            "9.9.9.0/24": {
                "country": {"iso_code": "FRANCE-IS-TOO-LONG", "names": {"en": "F" * 1000}},
                "city": {"names": {"en": "Par\x1b[31mis\n"}},
                "location": {"latitude": 999.0, "longitude": "east"},
            }
        },
    )

    result = GeoIpResolver(db, None).lookup(PARIS_IP)

    assert result is not None
    assert result.country_code is None  # not a two-letter code
    assert result.country is not None and len(result.country) <= 100
    assert result.city == "Par[31mis"  # the escape and newline characters are gone
    assert result.latitude is None and result.longitude is None  # out of range / not a number


def test_a_missing_or_invalid_database_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(GeoIpError, match=r"missing\.mmdb"):
        GeoIpResolver(tmp_path / "missing.mmdb", None)
    junk = tmp_path / "junk.mmdb"
    junk.write_bytes(b"this is not a database")
    with pytest.raises(GeoIpError, match=r"junk\.mmdb"):
        GeoIpResolver(junk, None)


def test_the_wrong_kind_of_database_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GeoIpError, match="ASN"):
        GeoIpResolver(asn_db(tmp_path / "asn.mmdb"), None)  # an ASN file given as the city one
    with pytest.raises(GeoIpError, match="city"):
        GeoIpResolver(None, city_db(tmp_path / "city.mmdb"))


def test_no_database_at_all_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GeoIpError):
        GeoIpResolver(None, None)


def test_the_databases_can_be_closed(tmp_path: Path) -> None:
    resolver = GeoIpResolver(city_db(tmp_path / "c.mmdb"), None)

    resolver.close()
    resolver.close()  # idempotent
    with pytest.raises(GeoIpError, match="closed"):
        resolver.lookup(TORONTO_IP)
