"""Local GeoIP lookups (country, city, coordinates, network) from MaxMind-format databases.

No address ever leaves the machine: the databases are files (DB-IP Lite or GeoLite2, both use this
format) read through `maxminddb`. Only public addresses are looked up: private, loopback,
link-local, documentation and other reserved ranges have no location, and resolving them would
only produce noise.

The databases are operator-supplied files, but what they contain ends up in alerts and, later, in
a web page, so every value is type-checked, stripped of control characters and bounded.
"""

import ipaddress
from pathlib import Path
from typing import Any

import maxminddb
from maxminddb.reader import Reader
from pydantic import BaseModel, ConfigDict

from sentinel_core.enrichment.text import clean_text


class GeoIpError(Exception):
    """A database cannot be used (missing, not a database, wrong kind, closed)."""


class GeoInfo(BaseModel):
    """Everything known about the location and network of an address; any field may be absent."""

    model_config = ConfigDict(frozen=True)

    country_code: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    as_org: str | None = None


def _name(record: Any) -> str | None:
    """English name of a `{"names": {"en": ...}}` record."""
    names = record.get("names") if isinstance(record, dict) else None
    return clean_text(names.get("en")) if isinstance(names, dict) else None


def _country_code(value: Any) -> str | None:
    return value.upper() if isinstance(value, str) and len(value) == 2 and value.isalpha() else None


def _coordinate(value: Any, limit: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if -limit <= value <= limit else None


def _asn(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value < 2**32 else None


def _open(path: Path, kind: str) -> Reader:
    try:
        reader = maxminddb.open_database(str(path))
    except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
        raise GeoIpError(f"cannot open the {kind} database {path}: {exc}") from exc
    database_type = reader.metadata().database_type
    is_asn = "ASN" in database_type.upper()
    if (kind == "ASN") != is_asn:
        reader.close()
        raise GeoIpError(
            f"{path} is a {database_type!r} database, not a {kind} one "
            f"(city database: GeoLite2-City or DBIP-City-Lite; ASN: GeoLite2-ASN or DBIP-ASN-Lite)"
        )
    return reader


class GeoIpResolver:
    def __init__(self, city_db: Path | None, asn_db: Path | None) -> None:
        if city_db is None and asn_db is None:
            raise GeoIpError("no GeoIP database configured")
        self._city: Reader | None = _open(city_db, "city") if city_db else None
        try:
            self._asn: Reader | None = _open(asn_db, "ASN") if asn_db else None
        except GeoIpError:
            if self._city is not None:
                self._city.close()
            raise
        self._closed = False

    @staticmethod
    def is_public(ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
            return address.is_global and not address.is_multicast
        except ValueError:
            return False

    def lookup(self, ip: str) -> GeoInfo | None:
        """Location and network of a public address; None for others or when nothing is known."""
        if self._closed:
            raise GeoIpError("the GeoIP databases are closed")
        if not self.is_public(ip):
            return None
        fields: dict[str, Any] = {}
        city = self._city.get(ip) if self._city else None
        if isinstance(city, dict):
            country = city.get("country")
            location = city.get("location")
            fields["country_code"] = _country_code(
                country.get("iso_code") if isinstance(country, dict) else None
            )
            fields["country"] = _name(country)
            fields["city"] = _name(city.get("city"))
            if isinstance(location, dict):
                fields["latitude"] = _coordinate(location.get("latitude"), 90)
                fields["longitude"] = _coordinate(location.get("longitude"), 180)
        network = self._asn.get(ip) if self._asn else None
        if isinstance(network, dict):
            fields["asn"] = _asn(network.get("autonomous_system_number"))
            fields["as_org"] = clean_text(network.get("autonomous_system_organization"))
        info = GeoInfo(**fields)
        return info if info.model_dump(exclude_none=True) else None

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()
        self._closed = True
