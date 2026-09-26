"""Time-of-day conditions: is an event inside a local-time schedule?

Used by rules such as off-hours logins. Timestamps are stored in UTC, so a schedule names the
IANA timezone it is written in (there is no default: silently reading "22:00" as UTC would
misplace every alert by the host's offset). Daylight saving time is handled by `zoneinfo`.
"""

import re
from datetime import datetime
from functools import lru_cache
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Day = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_DAYS: tuple[Day, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_HOURS = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$")
_TIMEZONE = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*$")


@lru_cache(maxsize=64)
def _zone(name: str) -> ZoneInfo:
    return ZoneInfo(name)


@lru_cache(maxsize=256)
def _parse_hours(value: str) -> tuple[int, int]:
    """'22:00-06:00' -> (start, end) in minutes since midnight."""
    found = _HOURS.match(value)
    if not found:
        raise ValueError(f"invalid hours {value!r} (use HH:MM-HH:MM, e.g. 22:00-06:00)")
    start = int(found[1]) * 60 + int(found[2])
    end = int(found[3]) * 60 + int(found[4])
    if start == end:
        raise ValueError(f"empty or whole-day range {value!r}: give two different times")
    return start, end


class ScheduleEntry(BaseModel):
    """`hours` and `days` must BOTH hold when both are given."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # "HH:MM-HH:MM" on a 24 h clock; the start is included, the end excluded; a start after the end
    # crosses midnight ("22:00-06:00" is the night).
    hours: str | None = None
    # Local weekday OF THE EVENT (an event at 01:00 on Saturday is a Saturday event, even inside a
    # range that started on Friday evening).
    days: list[Day] | None = Field(default=None, min_length=1)

    @field_validator("hours")
    @classmethod
    def _check_hours(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _parse_hours(value)
        return value

    @field_validator("days")
    @classmethod
    def _check_days(cls, value: list[Day] | None) -> list[Day] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("days contains duplicates")
        return value

    @model_validator(mode="after")
    def _needs_a_condition(self) -> "ScheduleEntry":
        if self.hours is None and self.days is None:
            raise ValueError("an entry needs 'hours', 'days' or both")
        return self

    def contains(self, local: datetime) -> bool:
        if self.days is not None and _DAYS[local.weekday()] not in self.days:
            return False
        if self.hours is None:
            return True
        start, end = _parse_hours(self.hours)
        now = local.hour * 60 + local.minute
        return start <= now < end if start < end else now >= start or now < end


class Schedule(BaseModel):
    """Holds when the event's local time matches ANY entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timezone: str
    any_of: list[ScheduleEntry] = Field(min_length=1)

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, name: str) -> str:
        # Only IANA names: ZoneInfo would also read files by relative path.
        if not _TIMEZONE.match(name):
            raise ValueError(f"invalid timezone {name!r} (use an IANA name, e.g. America/Toronto)")
        try:
            _zone(name)
        except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
            raise ValueError(f"unknown timezone {name!r}") from exc
        return name

    def contains(self, ts: datetime) -> bool:
        local = ts.astimezone(_zone(self.timezone))
        return any(entry.contains(local) for entry in self.any_of)
