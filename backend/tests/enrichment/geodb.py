"""Builds tiny MaxMind-format databases for tests (real ones are large and not redistributable).

The addresses are public ranges (the resolver ignores private and documentation ranges) and the
data is invented: it exercises the reader, not the accuracy of any provider.
"""

from pathlib import Path
from typing import Any

from mmdb_writer import MMDBWriter
from netaddr import IPSet

PARIS_IP = "9.9.9.9"
TORONTO_IP = "8.8.4.4"
ASN_ONLY_IP = "1.1.1.1"
UNKNOWN_IP = "5.5.5.5"


def write_db(path: Path, database_type: str, records: dict[str, dict[str, Any]]) -> Path:
    writer = MMDBWriter(
        ip_version=6,
        ipv4_compatible=True,
        database_type=database_type,
        languages=["en"],
        description={"en": "test database"},
    )
    for network, data in records.items():
        writer.insert_network(IPSet([network]), data)
    writer.to_db_file(str(path))
    return path


def city_db(path: Path) -> Path:
    return write_db(
        path,
        "DBIP-City-Lite",
        {
            "9.9.9.0/24": {
                "country": {"iso_code": "FR", "names": {"en": "France"}},
                "city": {"names": {"en": "Paris"}},
                "location": {"latitude": 48.85, "longitude": 2.35},
            },
            "8.8.4.0/24": {
                "country": {"iso_code": "CA", "names": {"en": "Canada"}},
                "city": {"names": {"en": "Toronto"}},
                "location": {"latitude": 43.65, "longitude": -79.38},
            },
            # A record with only a country (common for the coarsest entries).
            "1.1.1.0/24": {"country": {"iso_code": "AU", "names": {"en": "Australia"}}},
        },
    )


def asn_db(path: Path) -> Path:
    return write_db(
        path,
        "DBIP-ASN-Lite",
        {
            "9.9.9.0/24": {
                "autonomous_system_number": 64500,
                "autonomous_system_organization": "Example Hosting SARL",
            },
            "1.1.1.0/24": {
                "autonomous_system_number": 64501,
                "autonomous_system_organization": "Example Networks",
            },
        },
    )
