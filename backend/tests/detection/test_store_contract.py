"""Contract tests: the in-memory store and the Redis store must behave identically.

The Redis variant needs SENTINEL_TEST_REDIS_URL (see docs/OPERATIONS.md).
"""

from collections.abc import AsyncGenerator, Sequence
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from sentinel_core.detection.store import (
    LATE_TOLERANCE_MS,
    MAX_EVIDENCE,
    InMemoryWindowStore,
    RedisWindowStore,
    WindowStore,
)
from tests.support import REDIS_URL

WINDOW = 60_000
S = 1_000  # one second in ms
BASE = 1_800_000_000_000  # an arbitrary epoch-ms origin


@pytest.fixture(
    params=[
        "memory",
        pytest.param(
            "redis",
            marks=[
                pytest.mark.integration,
                pytest.mark.skipif(REDIS_URL is None, reason="SENTINEL_TEST_REDIS_URL not set"),
            ],
        ),
    ]
)
async def store(request: pytest.FixtureRequest) -> AsyncGenerator[WindowStore]:
    if request.param == "memory":
        yield InMemoryWindowStore()
        return
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield RedisWindowStore(client)
    await client.aclose()


@pytest.fixture
def key() -> str:
    return f"test:{uuid4()}"  # unique per test: no cleanup needed


async def feed(
    store: WindowStore,
    key: str,
    offsets_s: Sequence[float],
    *,
    count: int = 5,
    cooldown_ms: int = 0,
    window_ms: int = WINDOW,
) -> list[bool]:
    hits = []
    for i, offset in enumerate(offsets_s):
        result = await store.record_and_check(
            key,
            f"e{i}",
            BASE + int(offset * S),
            window_ms=window_ms,
            count=count,
            cooldown_ms=cooldown_ms,
        )
        hits.append(result.hit)
    return hits


async def test_hits_exactly_when_the_count_is_reached(store: WindowStore, key: str) -> None:
    assert await feed(store, key, [0, 1, 2, 3, 4, 5]) == [False, False, False, False, True, True]


async def test_result_carries_the_count_and_the_evidence_newest_first(
    store: WindowStore, key: str
) -> None:
    for i in range(4):
        await store.record_and_check(
            key, f"e{i}", BASE + i * S, window_ms=WINDOW, count=5, cooldown_ms=0
        )

    result = await store.record_and_check(
        key, "e4", BASE + 4 * S, window_ms=WINDOW, count=5, cooldown_ms=0
    )

    assert result.hit and result.count == 5
    assert result.evidence == ["e4", "e3", "e2", "e1", "e0"]


async def test_events_outside_the_sliding_window_do_not_count(store: WindowStore, key: str) -> None:
    # One failure every 20 s: never more than 4 inside any 60 s window.
    assert not any(await feed(store, key, [i * 20 for i in range(30)], count=5))


async def test_window_boundary_is_inclusive(store: WindowStore, key: str) -> None:
    hits = await feed(store, key, [0, 15, 30, 45, 60], count=5)

    assert hits[-1] is True  # 0 and 60 are exactly one window apart


async def test_replaying_the_same_event_does_not_double_count(store: WindowStore, key: str) -> None:
    for _ in range(10):
        result = await store.record_and_check(
            key, "same-event", BASE, window_ms=WINDOW, count=5, cooldown_ms=0
        )

    assert result.count == 1 and not result.hit


async def test_cooldown_suppresses_repeats_until_it_elapses(store: WindowStore, key: str) -> None:
    burst_1 = [0, 1, 2, 3, 4, 5, 6]  # hit at the 5th event, then suppressed
    burst_2 = [1000, 1001, 1002, 1003, 1004]  # long after the cooldown: hits again

    hits = await feed(store, key, burst_1 + burst_2, count=5, cooldown_ms=300_000)

    assert hits == [False] * 4 + [True] + [False] * 2 + [False] * 4 + [True]


async def test_late_events_neither_evict_newer_ones_nor_trigger_alerts(
    store: WindowStore, key: str
) -> None:
    await feed(store, key, [100, 101, 102, 103, 104])  # hit at 104

    late = await store.record_and_check(
        key, "late", BASE + 50 * S, window_ms=WINDOW, count=5, cooldown_ms=0
    )
    after = await store.record_and_check(
        key, "next", BASE + 105 * S, window_ms=WINDOW, count=5, cooldown_ms=0
    )

    assert not late.hit and late.count == 1  # only itself lies in [50-60s, 50s]
    # Window [45, 105]: the five originals (100..104), the late one (50) and the new one.
    assert after.hit and after.count == 7


async def test_late_events_within_tolerance_still_count_against_their_own_window(
    store: WindowStore, key: str
) -> None:
    await feed(store, key, [10, 11, 12, 13])  # 4 events, no hit yet
    await store.record_and_check(
        key, "newest", BASE + 40 * S, window_ms=WINDOW, count=99, cooldown_ms=0
    )

    late = await store.record_and_check(
        key, "late", BASE + 14 * S, window_ms=WINDOW, count=5, cooldown_ms=0
    )

    assert late.hit and late.count == 5  # 10, 11, 12, 13 and itself, all in [14-60, 14]


async def test_entries_far_behind_the_newest_are_evicted(store: WindowStore, key: str) -> None:
    await feed(store, key, [0, 1, 2, 3])
    far = BASE + WINDOW + LATE_TOLERANCE_MS + 10 * S  # 100 s: the first four fall out of tolerance

    result = await store.record_and_check(key, "far", far, window_ms=WINDOW, count=5, cooldown_ms=0)
    too_late = await store.record_and_check(
        key, "too-late", BASE + 2 * S, window_ms=WINDOW, count=1, cooldown_ms=0
    )
    next_one = await store.record_and_check(
        key, "next", far + S, window_ms=WINDOW, count=5, cooldown_ms=0
    )

    assert result.count == 1  # the first four are gone
    # Older than (newest - window - tolerance): dropped on arrival, never counted, never alerts.
    assert too_late.count == 0 and not too_late.hit
    assert next_one.count == 2  # only "far" and "next": the too-late event left no trace


async def test_keys_are_isolated(store: WindowStore, key: str) -> None:
    other = f"{key}:other"

    await feed(store, key, [0, 1, 2, 3])
    result = await store.record_and_check(
        other, "x", BASE + 4 * S, window_ms=WINDOW, count=5, cooldown_ms=0
    )

    assert not result.hit and result.count == 1


async def test_evidence_is_capped(store: WindowStore, key: str) -> None:
    result = None
    for i in range(MAX_EVIDENCE + 25):
        result = await store.record_and_check(
            key, f"e{i}", BASE + i * 100, window_ms=WINDOW, count=5, cooldown_ms=0
        )

    assert result is not None
    assert result.count == MAX_EVIDENCE + 25  # the true count is still reported
    assert len(result.evidence) == MAX_EVIDENCE
    assert result.evidence[0] == f"e{MAX_EVIDENCE + 24}"  # newest first


async def test_acquire_cooldown_allows_once_per_period(store: WindowStore, key: str) -> None:
    async def acquire(offset_s: int, member: str, cooldown_s: int = 60) -> bool:
        return await store.acquire_cooldown(key, BASE + offset_s * S, cooldown_s * S, member)

    assert await acquire(0, "a") is True
    assert await acquire(30, "b") is False
    assert await acquire(59, "c") is False
    assert await acquire(60, "d") is True
    assert await acquire(61, "e") is False


async def test_acquire_cooldown_with_zero_always_allows(store: WindowStore, key: str) -> None:
    assert await store.acquire_cooldown(key, BASE, 0, "a") is True
    assert await store.acquire_cooldown(key, BASE, 0, "b") is True


async def test_redelivery_of_the_event_that_raised_an_alert_raises_it_again(
    store: WindowStore, key: str
) -> None:
    """At-least-once delivery: if the worker crashed after evaluating but before persisting
    the alert, the redelivered event must not find the alert 'already raised' and lose it.
    Alert ids are deterministic, so raising it twice is harmless downstream."""
    for i in range(4):
        await store.record_and_check(
            key, f"e{i}", BASE + i * S, window_ms=WINDOW, count=5, cooldown_ms=300_000
        )
    first = await store.record_and_check(
        key, "e4", BASE + 4 * S, window_ms=WINDOW, count=5, cooldown_ms=300_000
    )
    suppressed = await store.record_and_check(
        key, "e5", BASE + 5 * S, window_ms=WINDOW, count=5, cooldown_ms=300_000
    )

    again = await store.record_and_check(
        key, "e4", BASE + 4 * S, window_ms=WINDOW, count=5, cooldown_ms=300_000
    )
    suppressed_again = await store.record_and_check(
        key, "e5", BASE + 5 * S, window_ms=WINDOW, count=5, cooldown_ms=300_000
    )

    assert first.hit and not suppressed.hit
    assert again.hit and again.count == 5  # the trigger re-raises
    assert not suppressed_again.hit  # any other event of the cooldown stays suppressed


async def test_acquire_cooldown_redelivery_of_the_same_member(store: WindowStore, key: str) -> None:
    async def acquire(offset_s: int, member: str) -> bool:
        return await store.acquire_cooldown(key, BASE + offset_s * S, 60 * S, member)

    assert await acquire(0, "a") is True
    assert await acquire(10, "b") is False
    assert await acquire(0, "a") is True  # redelivery of the event that started the cooldown
    assert await acquire(70, "c") is True  # a new period starts...
    assert await acquire(0, "a") is False  # ...and the old trigger no longer re-raises
