from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinel_core.detection.schedule import Schedule

TORONTO = "America/Toronto"


def schedule(*entries: dict[str, object], timezone: str = TORONTO) -> Schedule:
    return Schedule.model_validate({"timezone": timezone, "any_of": list(entries)})


def utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def test_hours_are_read_in_the_schedule_timezone_not_in_utc() -> None:
    night = schedule({"hours": "22:00-06:00"})

    assert night.contains(utc("2026-09-24 03:00:00"))  # 23:00 in Toronto (UTC-4 in September)
    assert not night.contains(utc("2026-09-24 15:00:00"))  # 11:00 in Toronto


def test_a_range_that_crosses_midnight_holds_on_both_sides_of_it() -> None:
    night = schedule({"hours": "22:00-06:00"})

    assert night.contains(utc("2026-09-24 02:30:00"))  # 22:30 the evening before
    assert night.contains(utc("2026-09-24 08:00:00"))  # 04:00 in the morning
    assert not night.contains(utc("2026-09-24 12:00:00"))  # noon


def test_the_start_is_included_and_the_end_excluded() -> None:
    business = schedule({"hours": "09:00-17:00"})

    assert business.contains(utc("2026-09-24 13:00:00"))  # 09:00:00 exactly
    assert business.contains(utc("2026-09-24 20:59:59"))
    assert not business.contains(utc("2026-09-24 21:00:00"))  # 17:00:00 exactly
    assert not business.contains(utc("2026-09-24 12:59:59"))


def test_days_are_local_weekdays_of_the_event() -> None:
    weekend = schedule({"days": ["sat", "sun"]})

    assert weekend.contains(utc("2026-09-26 16:00:00"))  # Saturday noon in Toronto
    assert not weekend.contains(utc("2026-09-25 16:00:00"))  # Friday
    # The local day decides, not the UTC one: this is Saturday 22:00 in Toronto, already Sunday UTC.
    assert weekend.contains(utc("2026-09-27 02:00:00"))
    assert not weekend.contains(utc("2026-09-28 05:00:00"))  # Monday 01:00 locally


def test_hours_and_days_in_one_entry_must_both_hold() -> None:
    saturday_night = schedule({"hours": "22:00-06:00", "days": ["sat"]})

    assert saturday_night.contains(utc("2026-09-27 03:00:00"))  # Saturday 23:00 locally
    assert not saturday_night.contains(utc("2026-09-26 03:00:00"))  # Friday 23:00 locally
    assert not saturday_night.contains(utc("2026-09-26 16:00:00"))  # Saturday noon


def test_several_entries_are_alternatives() -> None:
    off_hours = schedule({"hours": "22:00-06:00"}, {"days": ["sat", "sun"]})

    assert off_hours.contains(utc("2026-09-24 03:00:00"))  # a weekday night
    assert off_hours.contains(utc("2026-09-26 16:00:00"))  # Saturday noon
    assert not off_hours.contains(utc("2026-09-24 16:00:00"))  # a weekday afternoon


def test_daylight_saving_time_moves_the_local_hour() -> None:
    evening = schedule({"hours": "22:00-23:00"})

    # Toronto is UTC-5 until 2026-03-08 07:00 UTC, then UTC-4.
    assert evening.contains(utc("2026-03-08 03:30:00"))  # 22:30 on the 7th (UTC-5)
    assert not evening.contains(utc("2026-03-08 02:30:00"))  # 21:30 on the 7th
    assert evening.contains(utc("2026-03-10 02:30:00"))  # 22:30 on the 9th (UTC-4)
    assert not evening.contains(utc("2026-03-10 03:30:00"))  # 23:30 on the 9th


@pytest.mark.parametrize(
    "entry",
    [
        {},  # neither hours nor days
        {"hours": "9-17"},
        {"hours": "09:00-9:00"},
        {"hours": "25:00-06:00"},
        {"hours": "09:60-10:00"},
        {"hours": "09:00-09:00"},  # empty or whole day: ambiguous
        {"hours": "09:00"},
        {"days": []},
        {"days": ["monday"]},
        {"days": ["mon", "mon"]},
        {"hours": "09:00-17:00", "weekdays": ["mon"]},
    ],
)
def test_invalid_entries_are_refused(entry: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        schedule(entry)


def test_an_unknown_timezone_is_refused() -> None:
    with pytest.raises(ValidationError, match="unknown timezone"):
        schedule({"hours": "09:00-17:00"}, timezone="Mars/Olympus")


@pytest.mark.parametrize("name", ["", "../../etc/passwd", "/etc/localtime"])
def test_a_timezone_that_is_not_an_iana_name_is_refused(name: str) -> None:
    with pytest.raises(ValidationError):
        schedule({"hours": "09:00-17:00"}, timezone=name)


def test_at_least_one_entry_is_required() -> None:
    with pytest.raises(ValidationError):
        Schedule.model_validate({"timezone": TORONTO, "any_of": []})
