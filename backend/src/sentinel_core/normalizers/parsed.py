from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sentinel_core.schema.event import Action, Category, Outcome


@dataclass(frozen=True)
class Parsed:
    """What a per-process parser extracts from one message; the normalizer builds the Event."""

    category: Category
    action: Action
    outcome: Outcome
    severity: int
    user_name: str | None
    extra: dict[str, Any] = field(default_factory=dict)
    src_ip: IPv4Address | IPv6Address | None = None
    dst_port: int | None = None
