"""`db.incidents`: create/list/detail/status/assignee/notes/alert-linking, against real Postgres."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel_core.auth.user_registry import PostgresUserRepository
from sentinel_core.db.alerts import insert_alerts
from sentinel_core.db.incidents import (
    AlertLinkError,
    IncidentNotFound,
    add_note,
    claim_incident,
    close_incident,
    create_incident,
    get_incident,
    link_alerts,
    list_incidents,
    reopen_incident,
    set_status,
    unassign_incident,
    unlink_alert,
)
from sentinel_core.detection.alerts import Alert
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

T0 = datetime(2026, 9, 24, 15, 0, tzinfo=UTC)
PASSWORD = "correct horse battery staple"  # noqa: S105


def alert(alert_id: str, severity: int = 60) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="ssh-bruteforce",
        title="test alert",
        mitre=["T1110"],
        severity=severity,
        ts=T0,
        group={},
        event_ids=["00" * 32],
        match_count=1,
    )


@pytest.fixture
def sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
async def users(sessions: async_sessionmaker[AsyncSession]) -> PostgresUserRepository:
    return PostgresUserRepository(sessions)


async def test_a_new_incident_starts_with_status_new_and_no_assignee(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        created = await create_incident(session, "brute force spike")

    assert created.status == "new"
    assert created.assignee_email is None
    assert created.title == "brute force spike"


async def test_an_incident_can_be_created_with_alerts_already_linked(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("a" * 64), alert("b" * 64)])

    async with sessions() as session:
        created = await create_incident(session, "spike", alert_ids=["a" * 64, "b" * 64])

    async with sessions() as session:
        detail = await get_incident(session, created.id)
    assert detail is not None
    assert {a.alert_id for a in detail.alerts} == {"a" * 64, "b" * 64}


async def test_unknown_alert_rolls_back_creation(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    with pytest.raises(AlertLinkError):
        async with sessions() as session:
            await create_incident(session, "x", alert_ids=["ff" * 32])
    async with sessions() as session:
        assert await list_incidents(session) == []


async def test_status_transitions_and_closed_at(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        created = await create_incident(session, "y")

    async with sessions() as session:
        await set_status(session, created.id, "investigating")
    async with sessions() as session:
        investigating = await get_incident(session, created.id)
    assert investigating is not None
    assert (
        investigating.summary.status == "investigating" and investigating.summary.closed_at is None
    )

    async with sessions() as session:
        await close_incident(session, created.id)
    async with sessions() as session:
        closed = await get_incident(session, created.id)
    assert closed is not None
    assert closed.summary.status == "closed" and closed.summary.closed_at is not None

    async with sessions() as session:
        await reopen_incident(session, created.id)
    async with sessions() as session:
        reopened = await get_incident(session, created.id)
    assert reopened is not None
    assert reopened.summary.status == "new" and reopened.summary.closed_at is None


async def test_an_invalid_status_is_refused(sessions: async_sessionmaker[AsyncSession]) -> None:
    async with sessions() as session:
        created = await create_incident(session, "z")

    async with sessions() as session:
        with pytest.raises(ValueError, match="status"):
            await set_status(session, created.id, "archived")


async def test_claim_assigns_the_caller_and_unassign_clears_it(
    sessions: async_sessionmaker[AsyncSession], users: PostgresUserRepository
) -> None:
    user = await users.create_user("claimer@example.com", PASSWORD, "analyst")
    async with sessions() as session:
        created = await create_incident(session, "w")

    async with sessions() as session:
        await claim_incident(session, created.id, user.id)
    async with sessions() as session:
        claimed = await get_incident(session, created.id)
    assert claimed is not None
    assert claimed.summary.assignee_email == "claimer@example.com"

    async with sessions() as session:
        await unassign_incident(session, created.id)
    async with sessions() as session:
        unassigned = await get_incident(session, created.id)
    assert unassigned is not None
    assert unassigned.summary.assignee_email is None


async def test_notes_are_returned_oldest_first_with_their_author(
    sessions: async_sessionmaker[AsyncSession], users: PostgresUserRepository
) -> None:
    user = await users.create_user("noter@example.com", PASSWORD, "analyst")
    async with sessions() as session:
        created = await create_incident(session, "v")

    async with sessions() as session:
        await add_note(session, created.id, user.id, "first note")
    async with sessions() as session:
        await add_note(session, created.id, user.id, "second note")

    async with sessions() as session:
        detail = await get_incident(session, created.id)
    assert detail is not None
    assert [n.body for n in detail.notes] == ["first note", "second note"]
    assert all(n.author_email == "noter@example.com" for n in detail.notes)


async def test_link_and_unlink_alerts_after_creation(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("c" * 64), alert("d" * 64)])
    async with sessions() as session:
        created = await create_incident(session, "u")

    async with sessions() as session:
        await link_alerts(session, created.id, ["c" * 64, "d" * 64])
    async with sessions() as session:
        detail = await get_incident(session, created.id)
    assert detail is not None
    assert {a.alert_id for a in detail.alerts} == {"c" * 64, "d" * 64}

    async with sessions() as session:
        await unlink_alert(session, created.id, "c" * 64)
    async with sessions() as session:
        after = await get_incident(session, created.id)
    assert after is not None
    assert {a.alert_id for a in after.alerts} == {"d" * 64}


async def test_the_incident_severity_is_derived_from_its_worst_linked_alert(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("e" * 64, severity=40), alert("f" * 64, severity=90)])
        for aid, sev in (("e" * 64, 40), ("f" * 64, 90)):
            await session.execute(
                text("UPDATE alerts SET risk_score = :s WHERE alert_id = :id"),
                {"s": sev, "id": aid},
            )

    async with sessions() as session:
        created = await create_incident(session, "worst", alert_ids=["e" * 64, "f" * 64])
    async with sessions() as session:
        detail = await get_incident(session, created.id)

    assert detail is not None
    assert detail.summary.max_risk_score == 90


async def test_an_incident_with_no_alerts_has_no_risk_score(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        created = await create_incident(session, "empty")
    async with sessions() as session:
        detail = await get_incident(session, created.id)

    assert detail is not None
    assert detail.summary.max_risk_score is None


async def test_list_incidents_can_filter_by_status(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        a = await create_incident(session, "open one")
        b = await create_incident(session, "closed one")
    async with sessions() as session:
        await close_incident(session, b.id)

    async with sessions() as session:
        new_only = await list_incidents(session, status="new")
        all_incidents = await list_incidents(session)

    assert a.id in {i.id for i in new_only}
    assert b.id not in {i.id for i in new_only}
    assert {a.id, b.id} <= {i.id for i in all_incidents}


async def test_get_unknown_incident_returns_none(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        assert await get_incident(session, uuid4()) is None


async def test_acting_on_an_unknown_incident_raises(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions() as session:
        with pytest.raises(IncidentNotFound):
            await set_status(session, uuid4(), "investigating")


async def test_concurrent_linking_has_one_winner_and_no_alert_is_stolen(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    import asyncio

    async with sessions.begin() as session:
        await insert_alerts(session, [alert("a" * 64)])
    async with sessions() as session:
        first = await create_incident(session, "first")
        second = await create_incident(session, "second")

    async def attempt(incident_id: UUID) -> bool:
        try:
            async with sessions() as session:
                await link_alerts(session, incident_id, ["a" * 64])
        except AlertLinkError:
            return False
        return True

    outcomes = await asyncio.gather(attempt(first.id), attempt(second.id))
    assert sorted(outcomes) == [False, True]
    async with sessions() as session:
        rows = await list_incidents(session)
    assert {row.id for row in rows if row.alert_count == 1} == {
        first.id if outcomes[0] else second.id
    }


async def test_unlink_recomputes_risk_without_removing_the_alert(
    sessions: async_sessionmaker[AsyncSession],
) -> None:
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("a" * 64), alert("b" * 64)])
        await session.execute(
            text("UPDATE alerts SET risk_score = 90 WHERE alert_id = :id"), {"id": "a" * 64}
        )
        await session.execute(
            text("UPDATE alerts SET risk_score = 40 WHERE alert_id = :id"), {"id": "b" * 64}
        )
    async with sessions() as session:
        incident = await create_incident(session, "risk", alert_ids=["a" * 64, "b" * 64])
        assert incident.max_risk_score == 90
        await unlink_alert(session, incident.id, "a" * 64)
        detail = await get_incident(session, incident.id)
        assert detail is not None
        assert detail.summary.max_risk_score == 40
        assert (await session.execute(text("SELECT count(*) FROM alerts"))).scalar_one() == 2
