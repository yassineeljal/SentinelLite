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
    MAX_WINDOW_ENTRIES,
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
async def small_store(request: pytest.FixtureRequest) -> AsyncGenerator[WindowStore]:
    """Same stores, capacity of 20 entries per window."""
    if request.param == "memory":
        yield InMemoryWindowStore(max_entries=20)
        return
    assert REDIS_URL is not None
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    yield RedisWindowStore(client, max_entries=20)
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


# --- distinct counting ---------------------------------------------------------------------------


async def add(
    store: WindowStore, key: str, value: str, event: str, at: float, *, count: int = 3
) -> object:
    """Record `event` for the distinct `value` (member = the value, evidence = the event)."""
    return await store.record_and_check(
        key, value, BASE + int(at * S), window_ms=WINDOW, count=count, cooldown_ms=0, evidence=event
    )


async def test_distinct_counts_values_not_events(store: WindowStore, key: str) -> None:
    for i in range(10):
        await add(store, key, "alice", f"a{i}", i)  # the same value ten times
    await add(store, key, "bob", "b0", 10)
    result = await add(store, key, "carol", "c0", 11)

    assert result.count == 3  # type: ignore[attr-defined]
    assert result.hit  # type: ignore[attr-defined]


async def test_distinct_below_the_count_does_not_hit(store: WindowStore, key: str) -> None:
    await add(store, key, "alice", "a0", 0)
    result = await add(store, key, "alice", "a1", 1)

    assert result.count == 1 and not result.hit  # type: ignore[attr-defined]


async def test_distinct_evidence_is_the_latest_event_of_each_value_newest_first(
    store: WindowStore, key: str
) -> None:
    await add(store, key, "alice", "a0", 0)
    await add(store, key, "bob", "b0", 5)
    await add(store, key, "alice", "a1", 10)  # alice again: her evidence is now a1

    result = await add(store, key, "carol", "c0", 15)

    assert result.evidence == ["c0", "a1", "b0"]  # type: ignore[attr-defined]


async def test_a_value_falls_out_of_the_window_when_not_seen_again(
    store: WindowStore, key: str
) -> None:
    await add(store, key, "alice", "a0", 0)
    await add(store, key, "bob", "b0", 30)
    result = await add(
        store, key, "carol", "c0", 61
    )  # window [1, 61]: alice (last seen at 0) is out

    assert result.count == 2  # type: ignore[attr-defined]
    assert result.evidence == ["c0", "b0"]  # type: ignore[attr-defined]


async def test_distinct_replay_of_the_same_event_is_idempotent(
    store: WindowStore, key: str
) -> None:
    for _ in range(5):
        result = await add(store, key, "alice", "a0", 0)

    assert result.count == 1  # type: ignore[attr-defined]


async def test_distinct_evidence_of_evicted_values_is_not_returned(
    store: WindowStore, key: str
) -> None:
    await add(store, key, "old", "o0", 0)
    far = 200  # beyond window + tolerance: "old" is evicted from the window and from the evidence
    await add(store, key, "new1", "n1", far)
    result = await add(store, key, "new2", "n2", far + 1)

    assert result.evidence == ["n2", "n1"]  # type: ignore[attr-defined]


# --- capacity: a flood cannot make a window grow without bound ------------------------------


async def test_the_window_keeps_only_the_newest_entries_up_to_its_capacity(
    small_store: WindowStore, key: str
) -> None:
    result = None
    for i in range(30):
        result = await small_store.record_and_check(
            key, f"e{i:02d}", BASE + i * 100, window_ms=WINDOW, count=5, cooldown_ms=0
        )

    assert result is not None
    assert result.count == 20  # the ten oldest were dropped
    assert result.evidence[0] == "e29"


async def test_the_capacity_also_bounds_distinct_windows(
    small_store: WindowStore, key: str
) -> None:
    result = None
    for i in range(30):
        result = await small_store.record_and_check(
            key,
            f"v{i:02d}",
            BASE + i * 100,
            window_ms=WINDOW,
            count=5,
            cooldown_ms=0,
            evidence=f"e{i:02d}",
        )

    assert result is not None
    assert result.count == 20 and result.evidence[0] == "e29"


def test_the_default_capacity_is_generous_but_finite() -> None:
    assert 1000 <= MAX_WINDOW_ENTRIES <= 100_000


# --- peek: read a window without writing to it -------------------------------------------------


async def test_peek_counts_without_recording_anything(store: WindowStore, key: str) -> None:
    for i in range(3):
        await store.record_and_check(
            key, f"e{i}", BASE + i * S, window_ms=WINDOW, count=99, cooldown_ms=0
        )

    first = await store.peek(key, BASE + 10 * S, window_ms=WINDOW)
    again = await store.peek(key, BASE + 10 * S, window_ms=WINDOW)

    assert first.count == again.count == 3 and not first.hit
    assert first.evidence == ["e2", "e1", "e0"]


async def test_peek_respects_the_window_of_the_event_it_is_asked_for(
    store: WindowStore, key: str
) -> None:
    for i in range(3):
        await store.record_and_check(
            key, f"e{i}", BASE + i * S, window_ms=WINDOW, count=99, cooldown_ms=0
        )

    later = await store.peek(key, BASE + 100 * S, window_ms=WINDOW)  # window [40, 100]: all older

    assert later.count == 0 and later.evidence == []


async def test_peeking_an_unknown_key_is_empty(store: WindowStore, key: str) -> None:
    result = await store.peek(key, BASE, window_ms=WINDOW)

    assert result.count == 0 and result.evidence == [] and not result.hit


async def test_peek_returns_the_evidence_strings_written_by_record_and_check(
    store: WindowStore, key: str
) -> None:
    """A caller may store arbitrary state in `evidence` (impossible-travel encodes a location
    there) and read it back through `peek`, not only through `record_and_check`'s own result."""
    await store.record_and_check(
        key, "member-1", BASE, window_ms=WINDOW, count=99, cooldown_ms=0, evidence="lat=1,lon=2"
    )
    await store.record_and_check(
        key, "member-2", BASE + S, window_ms=WINDOW, count=99, cooldown_ms=0
    )  # no evidence: falls back to the member itself, like record_and_check does

    result = await store.peek(key, BASE + 10 * S, window_ms=WINDOW)

    assert result.evidence == ["member-2", "lat=1,lon=2"]


async def test_distinct_cooldown_identifies_the_trigger_by_its_event_not_by_its_value(
    store: WindowStore, key: str
) -> None:
    """sshd logs two lines for one attempt on a name (`Invalid user X`, then `Failed password for
    invalid user X`): both carry the same distinct value. The second event is NOT the trigger
    coming back after a crash, it is a new event inside the cooldown: no second alert."""
    for i in range(2):
        await store.record_and_check(
            key,
            f"v{i}",
            BASE + i * S,
            window_ms=WINDOW,
            count=3,
            cooldown_ms=300_000,
            evidence=f"e{i}",
        )
    trigger = await store.record_and_check(
        key, "v2", BASE + 2 * S, window_ms=WINDOW, count=3, cooldown_ms=300_000, evidence="e2"
    )

    same_value_new_event = await store.record_and_check(
        key, "v2", BASE + 3 * S, window_ms=WINDOW, count=3, cooldown_ms=300_000, evidence="e3"
    )
    redelivered_trigger = await store.record_and_check(
        key, "v2", BASE + 2 * S, window_ms=WINDOW, count=3, cooldown_ms=300_000, evidence="e2"
    )

    assert trigger.hit
    assert not same_value_new_event.hit  # a new event of the same value: cooldown applies
    assert redelivered_trigger.hit  # the trigger event itself, redelivered: raised again
